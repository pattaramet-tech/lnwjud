using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace Lnwjud.Containment;

internal sealed record UpdateStartupDisposition(string Kind, string Reason);

internal sealed class UpdateStartupGate : IDisposable
{
    private readonly string installationRoot;
    private readonly string serviceStore;
    private readonly Func<bool> machineEnrolled;
    private readonly Func<bool> maintenancePresent;
    private readonly WindowsServiceUpdateRuntime? updates;
    private UpdateStartupGate(string installationRoot, string serviceStore, Func<bool> machineEnrolled,
        WindowsServiceUpdateRuntime? updates = null, Func<bool>? maintenancePresent = null)
        => (this.installationRoot, this.serviceStore, this.machineEnrolled, this.updates, this.maintenancePresent)
            = (installationRoot, serviceStore, machineEnrolled, updates, maintenancePresent ?? CoordinatedMaintenancePresent);

    internal static UpdateStartupGate Installed(ServiceEndpointIdentity.ProductionServiceAuthority owner, string serviceStore)
    {
        owner.RequireActive();
        return new(owner.InstallationRoot, serviceStore, MachineEnrolled, WindowsServiceUpdateRuntime.Installed(owner, serviceStore));
    }

#if NATIVE_CONTAINMENT_TESTS
    internal static UpdateStartupGate Isolated(string install, string state, Func<bool> registrationPresent, Func<bool>? maintenancePresent = null)
        => new(install, state, registrationPresent, maintenancePresent: maintenancePresent ?? (() => false));
#endif

    internal static readonly UpdateStartupDisposition Unavailable = new("held", "UPDATE_STARTUP_INSPECTION_UNAVAILABLE");
    private static readonly UpdateStartupDisposition Unverified = new("held", "UPDATE_ENROLLMENT_UNVERIFIED");
    private static readonly UpdateStartupDisposition Unmanaged = new("unmanaged", "MANUAL_INSTALLATION");

    [DllImport("shell32.dll", ExactSpelling = true)]
    private static extern int SHGetKnownFolderPath(in Guid folder, uint flags, nint token, out nint path);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegOpenKeyExW(SafeRegistryHandle parent, string name, uint options, int access, out SafeRegistryHandle result);

    internal static UpdateStartupDisposition? InspectCoordinatedMaintenance(Func<bool> present)
    {
        try
        {
            return present() ? new("held", "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE") : null;
        }
        catch (Exception)
        {
            return new("held", "UPDATE_TRANSACTION_COORDINATED_INSPECTION_UNAVAILABLE");
        }
    }

    internal static UpdateStartupDisposition? InspectMachineMaintenance()
        => InspectCoordinatedMaintenance(CoordinatedMaintenancePresent);

    internal UpdateStartupDisposition? InspectMaintenance()
        => InspectCoordinatedMaintenance(maintenancePresent);

    internal void RequireMaintenanceOpen()
    {
        if (InspectMaintenance() is { } held) throw new IOException(held.Reason);
    }

    internal UpdateStartupDisposition Inspect()
    {
        if (InspectMaintenance() is { } held) return held;
        try
        {
            using var install = ServiceEndpointIdentity.OpenProtected(installationRoot, directory: true);
            using var store = ServiceEndpointIdentity.OpenProtected(serviceStore, directory: true);
            // A slot layout or a service ledger without the protected machine registration is a
            // manual installation: no update authority is enrolled, so no transaction can be
            // pending and writable startup must not be held forever.
            return machineEnrolled() ? Unverified : Unmanaged;
        }
        catch (IOException) { return Unavailable; }
        catch (UnauthorizedAccessException) { return Unavailable; }
        catch (System.ComponentModel.Win32Exception) { return Unavailable; }
        catch (System.Security.SecurityException) { return Unavailable; }
    }

    internal void BeforeOpaqueDispatch(string authenticatedCallerSid)
    {
        RequireMaintenanceOpen();
        var disposition = Inspect();
        if (disposition.Reason.StartsWith("UPDATE_TRANSACTION_COORDINATED_", StringComparison.Ordinal))
            throw new IOException(disposition.Reason);
        if (disposition.Kind == "unmanaged") return;
        if (updates is null) throw new IOException(disposition.Reason);
        updates.BeforeOpaqueDispatch(authenticatedCallerSid);
    }

    internal System.Text.Json.Nodes.JsonObject InspectUpdate(string authenticatedCallerSid) => updates?.Inspect(authenticatedCallerSid)
        ?? new() { ["kind"] = "unavailable", ["reason"] = Inspect().Reason };

    internal System.Text.Json.Nodes.JsonObject HandleUpdate(string command, System.Text.Json.JsonElement arguments, AuthenticatedPipeCaller caller)
        => (updates ?? throw new IOException("SERVICE_UPDATE_AUTHORITY_UNAVAILABLE")).Handle(command, arguments, caller);

    internal Task RunUpdateSessionAsync(System.Text.Json.JsonElement arguments, AuthenticatedPipeCaller caller, ServiceMcpPipes pipes,
        Stream control, Func<object, Task> reply, CancellationToken stopping)
        => (updates ?? throw new IOException("SERVICE_UPDATE_AUTHORITY_UNAVAILABLE")).RunSessionAsync(arguments, caller, pipes, control, reply, stopping);

    internal Task<System.Text.Json.Nodes.JsonObject> UpdateHealthAsync(System.Text.Json.JsonElement arguments, string sid)
        => (updates ?? throw new IOException("SERVICE_UPDATE_AUTHORITY_UNAVAILABLE")).HealthAsync(arguments, sid);

    public void Dispose() => updates?.Dispose();

    internal static UpdateStartupDisposition InspectFootprint()
    {
        if (InspectMachineMaintenance() is { } held) return held;
        try
        {
            if (MachineEnrolled()) return Unverified;
            var programFiles = KnownFolder(new("905e63b6-c1bf-494e-b29c-65b732d3d21a"));
            var programData = KnownFolder(new("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97"));
            using var programs = ServiceEndpointIdentity.OpenProtected(programFiles, directory: true);
            if (ServiceEndpointIdentity.CurrentSlotHold(programFiles) is { } slotHold) return new("held", slotHold);
            using var data = ServiceEndpointIdentity.PinKnownFolder(programData);
            if (MachineEnrolled() && HasSlots(programFiles, Path.Combine(programFiles, "lnwjud"), required: false)) return Unverified;
            using var service = OpenMachineKey(@"SYSTEM\CurrentControlSet\Services\LnwjudContainment");
            if (service is not null)
            {
                VerifyRegistryProtection(service);
                var command = service.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                if (command is null || command.Length > 32767) return Unavailable;
                var image = WindowsContainmentServiceInstaller.ParseRegisteredImagePath(command);
                var root = WindowsContainmentServiceInstaller.ValidateImagePath(image, programFiles);
                if (MachineEnrolled() && HasSlots(programFiles, root, required: true)) return Unverified;
            }
            // Existing installations keep the ledger accessible only to SYSTEM and administrators.
            // The protected machine registration precedes all managed files and survives rollback.
            _ = HasPrivateAuthority(programData);
            return MachineEnrolled() ? Unverified : Unmanaged;
        }
        catch (Exception) { return Unavailable; }
    }

    internal static bool HasPrivateAuthority(string programData)
    {
        var store = Path.Combine(programData, "lnwjud-containment");
        var attributes = ReadAttributesIfPresent(store);
        if (attributes is null) return false;
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
            throw new IOException("SERVICE_FOOTPRINT_DIRECTORY_UNSAFE");
        if (ReadAttributesIfPresent(Path.Combine(store, "update-authority")) is not null) return true;
        if (ReadAttributesIfPresent(store) != attributes) throw new IOException("SERVICE_FOOTPRINT_DIRECTORY_CHANGED");
        return false;
    }

    private static bool HasSlots(string programs, string installation, bool required)
    {
        var handles = new List<SafeFileHandle>();
        try
        {
            var path = programs;
            foreach (var component in Path.GetRelativePath(programs, installation).Split(Path.DirectorySeparatorChar))
            {
                path = Path.Combine(path, component);
                if (ReadAttributesIfPresent(path) is null)
                {
                    if (required) throw new IOException("SERVICE_FOOTPRINT_INSTALLATION_MISSING");
                    return false;
                }
                handles.Add(ServiceEndpointIdentity.OpenProtected(path, directory: true));
            }
            return ExistsInPinnedDirectory(installation, "slots");
        }
        finally { foreach (var handle in handles) handle.Dispose(); }
    }

    private static string KnownFolder(Guid folder)
    {
        var result = SHGetKnownFolderPath(in folder, 0, 0, out var path);
        try
        {
            if (result != 0 || Marshal.PtrToStringUni(path) is not { } directory || !Path.IsPathFullyQualified(directory)
                || directory.StartsWith('\\') || Path.GetPathRoot(directory)?.Length != 3)
                throw new IOException("SERVICE_FOOTPRINT_KNOWN_FOLDER_UNAVAILABLE");
            return Path.GetFullPath(directory);
        }
        finally { Marshal.FreeCoTaskMem(path); }
    }

    private static RegistryKey? OpenMachineKey(string name)
    {
        using var machine = new SafeRegistryHandle(unchecked((nint)(int)0x80000002), ownsHandle: false);
        return OpenKey(machine, name);
    }

    private static RegistryKey? OpenKey(SafeRegistryHandle parent, string name)
    {
        const int read64 = 0x20019 | 0x0100;
        var error = RegOpenKeyExW(parent, name, 8, read64, out var handle);
        if (error == 0) return RegistryKey.FromHandle(handle, RegistryView.Registry64);
        handle.Dispose();
        if (error == 2) return null;
        throw new IOException("SERVICE_FOOTPRINT_REGISTRY_UNAVAILABLE");
    }

    // Presence is deliberately sticky, including an incomplete or malformed
    // registration. Only a future authenticated coordinator may publish/clear it.
    // Query the fixed protected 64-bit key, never an environment-controlled path.
    private static bool CoordinatedMaintenancePresent()
    {
        using var product = OpenMachineKey(@"SOFTWARE\lnwjud");
        if (product is null) return false;
        VerifyRegistryProtection(product);
        using var marker = OpenKey(product.Handle, "CoordinatedMaintenance");
        if (marker is null) return false;
        VerifyRegistryProtection(marker);
        return true;
    }

    private static bool MachineEnrolled()
    {
        using var product = OpenMachineKey(@"SOFTWARE\lnwjud");
        if (product is null) return false;
        VerifyRegistryProtection(product);
        using var registration = OpenKey(product.Handle, "UpdateAuthority");
        return registration is not null;
    }

    private static void VerifyRegistryProtection(RegistryKey key)
    {
        var security = key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        const int registryMutation = 0x500d0026;
        ServiceEndpointIdentity.ValidateProtectedAccess(new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0), registryMutation);
        uint size = 0;
        if (RegQueryValueExW(key.Handle, "SymbolicLinkValue", 0, out _, 0, ref size) != 2)
            throw new IOException("SERVICE_FOOTPRINT_REGISTRY_UNVERIFIED");
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegQueryValueExW(SafeRegistryHandle key, string name, nint reserved, out uint type, nint data, ref uint size);

    private static bool ExistsInPinnedDirectory(string parent, string name)
        => ReadAttributesIfPresent(Path.Combine(parent, name)) is not null;

    private static FileAttributes? ReadAttributesIfPresent(string path)
    {
        try { return File.GetAttributes(path); }
        catch (FileNotFoundException) { return null; }
    }
}
