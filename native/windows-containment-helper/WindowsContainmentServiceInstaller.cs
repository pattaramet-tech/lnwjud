using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Lnwjud.Containment;

internal static class WindowsContainmentServiceInstaller
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint ServiceAllAccess = 0xF01FF;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceDemandStart = 0x00000003;
    private const uint ServiceDisabled = 0x00000004;
    private const uint ServiceQueryConfigAccess = 0x0001;
    private const uint ServiceQueryStatusAccess = 0x0004;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceControlStop = 1;
    private const uint ServiceStopped = 1;
    private const uint ServiceRunning = 4;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint SecurityDescriptorRevision = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorServiceCannotAcceptControl = 1061;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceMarkedForDelete = 1072;
    private const int MaximumManifestBytes = 64 * 1024;
    private const string ServiceSecurityDescriptor = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;AU)";
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier AuthenticatedUsersSid = new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier TrustedInstallerSid =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        internal uint ServiceType;
        internal uint CurrentState;
        internal uint ControlsAccepted;
        internal uint Win32ExitCode;
        internal uint ServiceSpecificExitCode;
        internal uint CheckPoint;
        internal uint WaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        internal uint ServiceType;
        internal uint CurrentState;
        internal uint ControlsAccepted;
        internal uint Win32ExitCode;
        internal uint ServiceSpecificExitCode;
        internal uint CheckPoint;
        internal uint WaitHint;
        internal uint ProcessId;
        internal uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfiguration
    {
        internal uint ServiceType;
        internal uint StartType;
        internal uint ErrorControl;
        internal nint BinaryPathName;
        internal nint LoadOrderGroup;
        internal nint TagId;
        internal nint Dependencies;
        internal nint ServiceStartName;
        internal nint DisplayName;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenSCManagerW")]
    private static extern SafeServiceHandle OpenSCManager(string? machine, string? database, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "OpenServiceW")]
    private static extern SafeServiceHandle OpenService(SafeServiceHandle manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateServiceW")]
    private static extern SafeServiceHandle CreateService(
        SafeServiceHandle manager,
        string serviceName,
        string displayName,
        uint desiredAccess,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPathName,
        string? loadOrderGroup,
        nint tagId,
        string? dependencies,
        string? serviceStartName,
        string? password);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ChangeServiceConfigW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(
        SafeServiceHandle service,
        uint serviceType,
        uint startType,
        uint errorControl,
        string? binaryPathName,
        string? loadOrderGroup,
        nint tagId,
        string? dependencies,
        string? serviceStartName,
        string? password,
        string? displayName);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryServiceConfigW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(SafeServiceHandle service, nint config, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "QueryServiceStatusEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        SafeServiceHandle service,
        int infoLevel,
        out ServiceStatusProcess status,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "ControlService")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(SafeServiceHandle service, uint control, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "StartServiceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(SafeServiceHandle service, uint argumentCount, nint arguments);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "DeleteService")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(SafeServiceHandle service);

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "SetServiceObjectSecurity")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceObjectSecurity(SafeServiceHandle service, uint securityInformation, nint securityDescriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint revision,
        out nint securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(nint handle);

    [DllImport("kernel32.dll")]
    private static extern nint LocalFree(nint memory);

    // Candidate preflight runs before NSIS invokes an old uninstaller or extracts
    // application files. It never stops a service, changes SCM, or saves authority state.
    internal static void PreflightInstallation()
    {
        EnsureWindows();
        using var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid) throw new IOException("SERVICE_INSTALL_SCM_UNAVAILABLE");
        using var service = OpenService(manager, WindowsContainmentService.ServiceName, ServiceQueryConfigAccess | ServiceQueryStatusAccess);
        if (service.IsInvalid && Marshal.GetLastWin32Error() != ErrorServiceDoesNotExist)
            throw new IOException("SERVICE_INSTALL_EXISTING_SERVICE_UNVERIFIED");
        if (!service.IsInvalid) RequireDisabledStoppedService(service, "SERVICE_INSTALL_EXISTING_SERVICE_NOT_QUIESCED");
        VerifyProtectedStoreForReplacement(allowLegacyImportHold: false, install: true, requireLedger: !service.IsInvalid);
        if (!service.IsInvalid) RequireDisabledStoppedService(service, "SERVICE_INSTALL_EXISTING_SERVICE_NOT_QUIESCED");
    }

    internal static void VerifyProtectedStoreForReplacement(bool allowLegacyImportHold, bool install, bool requireLedger = false, bool forwardReplacement = false)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "lnwjud-containment");
        try { InspectStoreForReplacementCore(root, allowLegacyImportHold, verifyAcl: true, requireLedger: requireLedger, forwardReplacement: forwardReplacement); }
        catch (Exception exception)
        {
            var suffix = exception is IOException io && io.Message is "NATIVE_SCHEMA_FORWARD_ONLY" or "NATIVE_RESERVATION_UNVERIFIED" or "NATIVE_IMPORT_UNVERIFIED"
                ? exception.Message : "NATIVE_STORE_UNVERIFIED";
            throw new IOException((install ? "SERVICE_INSTALL_" : "SERVICE_REMOVE_") + suffix);
        }
    }

    // The test assembly calls the exact read-only policy with isolated store
    // files. Only the production entry above selects the protected machine root.
 #if NATIVE_CONTAINMENT_TESTS
    internal static void InspectStoreForReplacement(string root, bool allowLegacyImportHold, bool verifyAcl, bool requireLedger = false, bool forwardReplacement = false)
        => InspectStoreForReplacementCore(root, allowLegacyImportHold, verifyAcl, requireLedger, forwardReplacement);
 #endif
    private static void InspectStoreForReplacementCore(string root, bool allowLegacyImportHold, bool verifyAcl, bool requireLedger, bool forwardReplacement)
    {
        ServiceAttemptLedgerPersistence.EnsureNoReparsePoints(root);
        static bool Exists(string name, bool directory)
        {
            FileAttributes attrs;
            try { attrs = File.GetAttributes(name); }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
            if ((attrs & FileAttributes.ReparsePoint) != 0 || ((attrs & FileAttributes.Directory) != 0) != directory)
                throw new IOException("NATIVE_STORE_UNVERIFIED");
            return true;
        }
        if (!Exists(root, true))
        {
            if (requireLedger) throw new IOException("NATIVE_STORE_UNVERIFIED");
            return;
        }
        if (verifyAcl) WindowsContainmentService.EnsureStoreAcl(new DirectoryInfo(root).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        var ledgerPath = Path.Combine(root, "attempts.json");
        var importsPath = Path.Combine(root, "imports");
        if (!Exists(ledgerPath, false))
        {
            // Existing nonempty authority without its ledger is not fresh.
            if (requireLedger || Directory.EnumerateFileSystemEntries(root).Any()) throw new IOException("NATIVE_STORE_UNVERIFIED");
            return;
        }
        if (verifyAcl) WindowsContainmentService.EnsureStoreAcl(new FileInfo(ledgerPath).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        var persistence = new ServiceAttemptLedgerPersistence(ledgerPath);
        var records = persistence.Load();
        if (persistence.LoadedSchemaVersion >= 3 && !forwardReplacement) throw new IOException("NATIVE_SCHEMA_FORWARD_ONLY");
        var attempts = new Dictionary<string, PersistedServiceAttempt>(StringComparer.Ordinal);
        var expectedImports = new Dictionary<string, PersistedServiceAttempt>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in records)
        {
            ServiceAttemptLedger.ValidateStored(record);
            if (!attempts.TryAdd(record.Request.Identity.AttemptId, record)) throw new IOException("NATIVE_STORE_UNVERIFIED");
            if (record.Phase is not (ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted))
                throw new IOException("NATIVE_RESERVATION_UNVERIFIED");
            if (record.Request.ImportValidationPending == true)
                throw new IOException("NATIVE_RESERVATION_UNVERIFIED");
            if (record.ReservationHeld || record.Request.HoldForImport)
            {
                // Only a candidate upgrade can carry the exact terminal legacy
                // hold forward. Neither replacement nor uninstall releases it.
                if (!allowLegacyImportHold || !record.ReservationHeld || !record.Request.HoldForImport
                    || record.Phase != ServiceAttemptPhase.TerminalVerified || record.Request.Shared || record.Request.RegistryOnly
                    || record.Request.PublicationCommitted != false || (!forwardReplacement && record.Request.ImportValidationPending is not null)
                    || !String.Equals(record.Request.ReservationKey, ServiceAttemptLedger.GlobalReservationKey, StringComparison.OrdinalIgnoreCase)
                    || ContainedProcess.QueryJob(ContainedProcess.GetJobName(record.Request.Identity.AttemptId)).Status != ContainedProcess.JobProbeStatus.NotFound)
                    throw new IOException("NATIVE_RESERVATION_UNVERIFIED");
            }
            expectedImports.Add(ServiceImportTransactionRuntime.RecordFilename(importsPath, record.Request.Identity), record);
        }
        if (records.Count(record => record.ReservationHeld) > 1) throw new IOException("NATIVE_RESERVATION_UNVERIFIED");
        var observed = new HashSet<string>(StringComparer.Ordinal);
        if (Exists(importsPath, true))
        {
            if (verifyAcl) WindowsContainmentService.EnsureStoreAcl(new DirectoryInfo(importsPath).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
            foreach (var filename in Directory.EnumerateFileSystemEntries(importsPath))
            {
                if (!expectedImports.TryGetValue(filename, out var record) || !Exists(filename, false))
                    throw new IOException("NATIVE_IMPORT_UNVERIFIED");
                if (verifyAcl) WindowsContainmentService.EnsureStoreAcl(new FileInfo(filename).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
                var transaction = ServiceImportTransactionRuntime.ReadRecord(filename, record.Request.Identity, record.Request.AuthenticatedCallerSid);
                if (transaction is null) throw new IOException("NATIVE_IMPORT_UNVERIFIED");
                if (transaction.Phase == ServiceImportPhase.Aborted && forwardReplacement)
                {
                    if (record.Phase != ServiceAttemptPhase.TerminalVerified || record.Request.PublicationCommitted != false
                        || record.Request.Shared || record.Request.RegistryOnly || record.Request.HoldForImport != record.ReservationHeld
                        || !String.Equals(record.Request.ReservationKey, ServiceAttemptLedger.GlobalReservationKey, StringComparison.OrdinalIgnoreCase)
                        || (record.Request.ImportValidationPending != false && !ServiceAttemptLedger.HasLegacyBootProof(record.Request)))
                        throw new IOException("NATIVE_IMPORT_UNVERIFIED");
                }
                else if (transaction.Version != 1
                    || (record.ReservationHeld ? transaction.Phase != ServiceImportPhase.Prepared : transaction.Phase != ServiceImportPhase.Published)
                    || (transaction.Phase == ServiceImportPhase.Published && record.Request.PublicationCommitted != true))
                    throw new IOException("NATIVE_IMPORT_UNVERIFIED");
                observed.Add(record.Request.Identity.AttemptId);
            }
        }
        // V2 ordinary shared attempts serialized PublicationCommitted=false by
        // default. That alone is not import evidence and must not require a
        // transaction record. Explicit validation/boot evidence or an exclusive
        // global publication fence still requires its exact durable record.
        if (records.Any(record => (record.ReservationHeld || record.Request.PublicationCommitted == true
                || record.Request.ImportValidationPending is not null || record.Request.LegacyImportObservedBoot is not null
                || (!record.Request.Shared && !record.Request.RegistryOnly && record.Request.PublicationCommitted == false
                    && String.Equals(record.Request.ReservationKey, ServiceAttemptLedger.GlobalReservationKey, StringComparison.OrdinalIgnoreCase)))
                && !observed.Contains(record.Request.Identity.AttemptId)))
            throw new IOException("NATIVE_IMPORT_UNVERIFIED");
    }

    // Explicit maintenance lane; not invoked by ordinary NSIS or the managed
    // updater. The candidate must already be staged in a protected full package
    // tree. Never overwrite old files or delete/recreate the SCM service.
    internal static void Replace(string expectedCurrentHash, string expectedCandidateHash, bool preflightOnly)
    {
        EnsureWindows();
        ValidateSha256(expectedCurrentHash);
        ValidateSha256(expectedCandidateHash);
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new IOException("SERVICE_INSTALL_REPLACEMENT_ADMIN_REQUIRED");
        var programFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var programData = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var image = Path.GetFullPath(Environment.ProcessPath ?? throw new IOException("SERVICE_INSTALL_IMAGE_UNAVAILABLE"));
        var candidateRoot = ValidateImagePath(image, programFiles);
        if (UpdateStartupGate.InspectFootprint().Kind != "unmanaged" || UpdateStartupGate.HasPrivateAuthority(programData))
            throw new IOException("SERVICE_INSTALL_REPLACEMENT_MANAGED_AUTHORITY_REFUSED");
        using var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid) throw new IOException("SERVICE_INSTALL_SCM_UNAVAILABLE");
        using var service = OpenService(manager, WindowsContainmentService.ServiceName, ServiceAllAccess);
        if (service.IsInvalid) throw new IOException("SERVICE_INSTALL_EXISTING_SERVICE_UNVERIFIED");
        RequireDisabledStoppedService(service, "SERVICE_INSTALL_EXISTING_SERVICE_NOT_QUIESCED");
        var oldImage = QueryImagePath(service);
        var oldRoot = ValidateImagePath(oldImage, programFiles);
        RequireSeparateReplacementRoots(candidateRoot, oldRoot);
        if (ServiceEndpointIdentity.InspectSlotImage(image, programFiles) is not null
            || ServiceEndpointIdentity.InspectSlotImage(oldImage, programFiles) is not null)
            throw new IOException("SERVICE_INSTALL_REPLACEMENT_LAYOUT_REFUSED");
        // Retain non-delete-sharing handles through the switch and readback.
        var pins = new List<SafeFileHandle>();
        try
        {
            void PinTree(string path, string root)
            {
                pins.Add(ServiceEndpointIdentity.OpenProtected(path, directory: false));
                for (var parent = Path.GetDirectoryName(path); parent is not null; parent = Path.GetDirectoryName(parent))
                {
                    pins.Add(ServiceEndpointIdentity.OpenProtected(parent, directory: true));
                    if (String.Equals(parent, programFiles, StringComparison.OrdinalIgnoreCase)) break;
                }
                VerifyProtectedAncestors(root, programFiles);
            }
            PinTree(oldImage, oldRoot);
            PinTree(image, candidateRoot);
            pins.Add(ServiceEndpointIdentity.OpenProtected(Path.Combine(Path.GetDirectoryName(image)!, "manifest.json"), directory: false));
            pins.Add(ServiceEndpointIdentity.OpenProtected(Path.Combine(Path.GetDirectoryName(image)!, "lnwjud-containment-pin.node"), directory: false));
            ServiceEndpointIdentity.ValidateImage(oldImage, programFiles, expectedCurrentHash);
            ServiceEndpointIdentity.ValidateImage(image, programFiles, expectedCandidateHash);
            VerifyPackageManifest(image);
            VerifyProtectedStoreForReplacement(allowLegacyImportHold: true, install: true, requireLedger: true, forwardReplacement: true);
            RequireDisabledStoppedService(service, "SERVICE_INSTALL_EXISTING_SERVICE_NOT_QUIESCED");
            if (!String.Equals(QueryImagePath(service), oldImage, StringComparison.OrdinalIgnoreCase)
                || UpdateStartupGate.InspectFootprint().Kind != "unmanaged" || UpdateStartupGate.HasPrivateAuthority(programData))
                throw new IOException("SERVICE_INSTALL_REPLACEMENT_AUTHORITY_CHANGED");
            if (preflightOnly) return;
            // First switch while disabled. Any interruption before activation
            // leaves the candidate registered but unable to start automatically.
            ConfigureReplacement(service, image, ServiceDisabled);
            RequireDisabledStoppedService(service, "SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
            if (!String.Equals(QueryImagePath(service), image, StringComparison.OrdinalIgnoreCase))
                throw new IOException("SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
            ApplyServiceSecurity(service);
            VerifyProtectedStoreForReplacement(allowLegacyImportHold: true, install: true, requireLedger: true, forwardReplacement: true);
            RequireDisabledStoppedService(service, "SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
            ConfigureReplacement(service, image, ServiceDemandStart);
            RequireReplacementState(service, image, ServiceDemandStart, running: false);
            StartAndWait(service);
            var activatedPid = RequireReplacementState(service, image, ServiceDemandStart, running: true);
            // SCM running is not readiness. Authenticate the actual peer image
            // and require its native startup result before enabling auto-start.
            using var reply = JsonDocument.Parse(WindowsContainmentServiceClient.SendAsync(expectedCandidateHash,
                JsonSerializer.SerializeToUtf8Bytes(new { protocol = 3, command = "update_startup" })).GetAwaiter().GetResult());
            var result = reply.RootElement;
            if (result.GetProperty("protocol").GetInt32() != 3 || !result.GetProperty("ok").GetBoolean()
                || result.GetProperty("result").GetProperty("kind").GetString() != "unmanaged"
                || RequireReplacementState(service, image, ServiceDemandStart, running: true) != activatedPid)
                throw new IOException("SERVICE_INSTALL_REPLACEMENT_READINESS_UNVERIFIED");
            ConfigureReplacement(service, image, ServiceAutoStart);
            if (RequireReplacementState(service, image, ServiceAutoStart, running: true) != activatedPid)
                throw new IOException("SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
        }
        finally
        {
            foreach (var pin in pins) pin.Dispose();
            // Never roll back to the old image, stop a possibly admitted writer,
            // restore an older ledger, or delete a registration after failure.
        }
    }

    private static uint RequireReplacementState(SafeServiceHandle service, string image, uint startType, bool running)
    {
        var config = ReadServiceConfiguration(service);
        var status = QueryStatus(service);
        return ValidateReplacementState(image, startType, running, config.ImagePath, config.StartType, config.ServiceType,
            config.Account, status.CurrentState, status.ProcessId);
    }

    internal static uint ValidateReplacementState(string image, uint startType, bool running, string observedImage,
        uint observedStartType, uint serviceType, string account, uint state, uint pid)
    {
        if (!String.Equals(image, observedImage, StringComparison.OrdinalIgnoreCase) || observedStartType != startType
            || serviceType != ServiceWin32OwnProcess || !String.Equals(account, "LocalSystem", StringComparison.OrdinalIgnoreCase)
            || (running ? state != ServiceRunning || pid == 0 : state != ServiceStopped || pid != 0))
            throw new IOException("SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
        return pid;
    }

    private static void ConfigureReplacement(SafeServiceHandle service, string image, uint startType)
    {
        if (!ChangeServiceConfig(service, ServiceWin32OwnProcess, startType, ServiceErrorNormal,
                BuildServiceCommand(image), null, 0, null, "LocalSystem", null, "lnwjud Windows Containment"))
            throw new IOException("SERVICE_INSTALL_REPLACEMENT_CONFIGURE_FAILED");
    }

    internal static void Install()
    {
        EnsureWindows();
        PreflightInstallation();
        var imagePath = Path.GetFullPath(Environment.ProcessPath ?? throw new IOException("SERVICE_INSTALL_IMAGE_UNAVAILABLE"));
        var programFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var installRoot = ValidateImagePath(imagePath, programFiles);
        EnsureNoReparsePoints(imagePath);
        VerifyProtectedAncestors(installRoot, programFiles);
        SecureInstalledImage(installRoot, imagePath);
        VerifyPackageManifest(imagePath);

        using var manager = OpenSCManager(null, null, ScManagerConnect | ScManagerCreateService);
        if (manager.IsInvalid) throw new IOException("SERVICE_INSTALL_SCM_UNAVAILABLE");

        var service = OpenService(manager, WindowsContainmentService.ServiceName, ServiceAllAccess);
        var created = false;
        if (service.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            service.Dispose();
            if (error != ErrorServiceDoesNotExist) throw new IOException("SERVICE_INSTALL_OPEN_FAILED");
            service = CreateService(
                manager,
                WindowsContainmentService.ServiceName,
                "lnwjud Windows Containment",
                ServiceAllAccess,
                ServiceWin32OwnProcess,
                ServiceDisabled,
                ServiceErrorNormal,
                BuildServiceCommand(imagePath),
                null,
                0,
                null,
                null,
                null);
            if (service.IsInvalid) throw new IOException("SERVICE_INSTALL_CREATE_FAILED");
            created = true;
        }

        using (service)
        {
            var activationAttempted = false;
            try
            {
                var installedImage = QueryImagePath(service);
                if (!String.Equals(installedImage, imagePath, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("SERVICE_INSTALL_EXISTING_IMAGE_MISMATCH");
                // The newly created service is already stopped. For existing
                // service registrations repeat the no-stop preflight before replacement.
                if (!created)
                {
                    RequireDisabledStoppedService(service, "SERVICE_INSTALL_EXISTING_SERVICE_NOT_QUIESCED");
                    VerifyProtectedStoreForReplacement(allowLegacyImportHold: false, install: true, requireLedger: true);
                    RequireDisabledStoppedService(service, "SERVICE_INSTALL_EXISTING_SERVICE_NOT_QUIESCED");
                }
                if (created) InitializeFreshStoreIfAbsent();
                if (!ChangeServiceConfig(
                        service,
                        ServiceWin32OwnProcess,
                        ServiceAutoStart,
                        ServiceErrorNormal,
                        BuildServiceCommand(imagePath),
                        null,
                        0,
                        null,
                        "LocalSystem",
                        null,
                        "lnwjud Windows Containment"))
                    throw new IOException("SERVICE_INSTALL_CONFIGURE_FAILED");
                ApplyServiceSecurity(service);
                activationAttempted = true;
                StartAndWait(service);
            }
            catch
            {
                // Once activation was attempted, preserve SCM and authority for
                // inspection; never stop/delete a potentially admitted writer.
                if (created && !activationAttempted)
                {
                    try
                    {
                        var status = QueryStatus(service);
                        if (status.CurrentState == ServiceStopped && status.ProcessId == 0) _ = DeleteService(service);
                    }
                    catch { /* preserve the original failure and uncertain registration */ }
                }
                throw;
            }
        }
    }

    private static void InitializeFreshStoreIfAbsent()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "lnwjud-containment");
        ServiceAttemptLedgerPersistence.EnsureNoReparsePoints(root);
        // Reinstall retains an existing ledger; never manufacture a missing
        // ledger in an existing directory or overwrite any authority bytes.
        if (Directory.Exists(root))
        {
            VerifyProtectedStoreForReplacement(allowLegacyImportHold: false, install: true, requireLedger: true);
            return;
        }
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(AdministratorsSid);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { SystemSid, AdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        var directory = security.CreateDirectory(root);
        WindowsContainmentService.EnsureStoreAcl(directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        ServiceAttemptLedgerPersistence.EnsureNoReparsePoints(root);
        if (Directory.EnumerateFileSystemEntries(root).Any()) throw new IOException("SERVICE_INSTALL_NATIVE_STORE_UNVERIFIED");
        var filename = Path.Combine(root, "attempts.json");
        WriteFreshLedger(filename);
        var fileSecurity = new FileSecurity();
        fileSecurity.SetAccessRuleProtection(true, false);
        fileSecurity.SetOwner(AdministratorsSid);
        foreach (var sid in new[] { SystemSid, AdministratorsSid })
            fileSecurity.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(filename).SetAccessControl(fileSecurity);
        VerifyProtectedStoreForReplacement(allowLegacyImportHold: false, install: true, requireLedger: true);
    }

    internal static void WriteFreshLedger(string filename)
    {
        using var stream = new FileStream(filename, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write("{\"schemaVersion\":2,\"attempts\":[]}"u8);
        stream.Flush(true);
    }

    internal static void Uninstall()
    {
        EnsureWindows();
        // A previous installer invokes the currently installed uninstaller. Never
        // permit ordinary removal of V3 authority, even when all attempts settled.
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (UpdateStartupGate.InspectFootprint().Kind != "unmanaged" || UpdateStartupGate.HasPrivateAuthority(programData))
            throw new IOException("SERVICE_REMOVE_MANAGED_AUTHORITY_REFUSED");
        VerifyProtectedStoreForReplacement(allowLegacyImportHold: false, install: false);
        using var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid) throw new IOException("SERVICE_REMOVE_SCM_UNAVAILABLE");
        var service = OpenService(manager, WindowsContainmentService.ServiceName, ServiceAllAccess);
        if (service.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            service.Dispose();
            if (error == ErrorServiceDoesNotExist) return;
            throw new IOException("SERVICE_REMOVE_OPEN_FAILED");
        }

        using (service)
        {
            var image = Path.GetFullPath(Environment.ProcessPath ?? throw new IOException("SERVICE_REMOVE_IMAGE_UNAVAILABLE"));
            if (!String.Equals(QueryImagePath(service), image, StringComparison.OrdinalIgnoreCase))
                throw new IOException("SERVICE_REMOVE_EXISTING_IMAGE_MISMATCH");
            var config = ReadServiceConfiguration(service);
            var status = QueryStatus(service);
            if (config.ServiceType != ServiceWin32OwnProcess || !String.Equals(config.Account, "LocalSystem", StringComparison.OrdinalIgnoreCase))
                throw new IOException("SERVICE_REMOVE_EXISTING_SERVICE_NOT_QUIESCED");
            if (UpdateStartupGate.InspectFootprint().Kind != "unmanaged" || UpdateStartupGate.HasPrivateAuthority(programData))
                throw new IOException("SERVICE_REMOVE_MANAGED_AUTHORITY_REFUSED");
            if (status.CurrentState == ServiceRunning && status.ProcessId != 0)
            {
                using var process = Process.GetProcessById(checked((int)status.ProcessId));
                _ = process.Handle; // Hold exact process identity across SCM readback.
                if (process.HasExited) throw new IOException("SERVICE_REMOVE_AUTHORITY_CHANGED");
                var hash = HashFile(image);
                using var reply = JsonDocument.Parse(WindowsContainmentServiceClient.SendAsync(hash,
                    JsonSerializer.SerializeToUtf8Bytes(new { protocol = 3, command = "maintenance_remove" })).GetAwaiter().GetResult());
                var response = reply.RootElement;
                if (response.GetProperty("protocol").GetInt32() != 3 || !response.GetProperty("ok").GetBoolean()
                    || response.GetProperty("result").GetProperty("kind").GetString() != "removal_fenced"
                    || response.GetProperty("result").GetProperty("pid").GetUInt32() != status.ProcessId)
                    throw new IOException("SERVICE_REMOVE_ADMISSION_NOT_FENCED");
                VerifyProtectedStoreForReplacement(allowLegacyImportHold: false, install: false, requireLedger: true);
                if (process.HasExited || RequireReplacementState(service, image, config.StartType, running: true) != status.ProcessId)
                    throw new IOException("SERVICE_REMOVE_AUTHORITY_CHANGED");
                ConfigureReplacement(service, image, ServiceDisabled);
                if (process.HasExited || RequireReplacementState(service, image, ServiceDisabled, running: true) != status.ProcessId)
                    throw new IOException("SERVICE_REMOVE_AUTHORITY_CHANGED");
                StopAndWait(service);
            }
            RequireDisabledStoppedService(service, "SERVICE_REMOVE_EXISTING_SERVICE_NOT_QUIESCED");
            VerifyProtectedStoreForReplacement(allowLegacyImportHold: false, install: false, requireLedger: true);
            RequireDisabledStoppedService(service, "SERVICE_REMOVE_EXISTING_SERVICE_NOT_QUIESCED");
            if (!String.Equals(QueryImagePath(service), image, StringComparison.OrdinalIgnoreCase)
                || UpdateStartupGate.InspectFootprint().Kind != "unmanaged" || UpdateStartupGate.HasPrivateAuthority(programData))
                throw new IOException("SERVICE_REMOVE_AUTHORITY_CHANGED");
            if (!DeleteService(service))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != ErrorServiceMarkedForDelete) throw new IOException("SERVICE_REMOVE_DELETE_FAILED");
            }
        }

        // DeleteService only marks an entry for deletion. The service may still
        // be present while SCM holds its final references, and NSIS must not
        // proceed to delete its protected image until disappearance is proven.
        WaitForServiceDeletion(manager);
    }

    private static void WaitForServiceDeletion(SafeServiceHandle manager)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(30))
        {
            using var observed = OpenService(manager, WindowsContainmentService.ServiceName, ServiceAllAccess);
            if (observed.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ErrorServiceDoesNotExist) return;
                if (error != ErrorServiceMarkedForDelete)
                    throw new IOException("SERVICE_REMOVE_CONFIRMATION_UNAVAILABLE");
            }
            Thread.Sleep(100);
        }
        throw new IOException("SERVICE_REMOVE_DELETION_TIMEOUT");
    }

    internal static string ValidateImagePath(string helperPath, string programFilesRoot)
    {
        if (!OperatingSystem.IsWindows()) throw new IOException("SERVICE_INSTALL_WINDOWS_REQUIRED");
        if (String.IsNullOrWhiteSpace(helperPath) || String.IsNullOrWhiteSpace(programFilesRoot)
            || helperPath.Contains('"') || helperPath.Contains('\0') || programFilesRoot.Contains('\0'))
            throw new IOException("SERVICE_INSTALL_PATH_INVALID");

        var fullPath = Path.GetFullPath(helperPath);
        var root = Path.GetFullPath(programFilesRoot);
        var relative = Path.GetRelativePath(root, fullPath);
        if (relative == "." || relative == ".."
            || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || Path.IsPathRooted(relative))
            throw new IOException("SERVICE_INSTALL_ROOT_UNPROTECTED");
        if (!String.Equals(Path.GetFileName(fullPath), "lnwjud-containment.exe", StringComparison.OrdinalIgnoreCase))
            throw new IOException("SERVICE_INSTALL_IMAGE_INVALID");

        var containment = new DirectoryInfo(Path.GetDirectoryName(fullPath)!);
        var resources = containment.Parent;
        var installRoot = resources?.Parent;
        if (!String.Equals(containment.Name, "native-containment", StringComparison.OrdinalIgnoreCase)
            || !String.Equals(resources?.Name, "resources", StringComparison.OrdinalIgnoreCase)
            || installRoot is null
            || !IsBelowRoot(installRoot.FullName, root))
            throw new IOException("SERVICE_INSTALL_LAYOUT_INVALID");
        return Path.GetFullPath(installRoot.FullName);
    }

    internal static string BuildServiceCommand(string helperPath)
    {
        if (String.IsNullOrWhiteSpace(helperPath) || helperPath.Contains('"') || helperPath.Contains('\0'))
            throw new IOException("SERVICE_INSTALL_IMAGE_INVALID");
        return "\"" + Path.GetFullPath(helperPath) + "\" service";
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new IOException("SERVICE_INSTALL_WINDOWS_REQUIRED");
    }

    private static void VerifyPackageManifest(string imagePath)
    {
        try
        {
            var directory = Path.GetDirectoryName(imagePath) ?? throw new IOException();
            var manifestPath = Path.Combine(directory, "manifest.json");
            var pinPath = Path.Combine(directory, "lnwjud-containment-pin.node");
            EnsureNoReparsePoints(manifestPath);
            EnsureNoReparsePoints(pinPath);
            var manifestInfo = new FileInfo(manifestPath);
            if (!manifestInfo.Exists || manifestInfo.Length is < 2 or > MaximumManifestBytes)
                throw new IOException("SERVICE_PACKAGE_MANIFEST_INVALID");
            using var manifest = JsonDocument.Parse(File.ReadAllBytes(manifestPath), new JsonDocumentOptions { MaxDepth = 8 });
            var root = manifest.RootElement;
            if (root.GetProperty("schemaVersion").GetInt32() != 2
                || root.GetProperty("buildId").GetString() != Program.BuildId
                || root.GetProperty("platform").GetString() != "win32"
                || root.GetProperty("architecture").GetString() != "x64"
                || root.GetProperty("filename").GetString() != "lnwjud-containment.exe"
                || root.GetProperty("pinFilename").GetString() != "lnwjud-containment-pin.node")
                throw new IOException("SERVICE_PACKAGE_MANIFEST_INVALID");
            var helperHash = root.GetProperty("sha256").GetString() ?? throw new IOException();
            var pinHash = root.GetProperty("pinSha256").GetString() ?? throw new IOException();
            ValidateSha256(helperHash);
            ValidateSha256(pinHash);
            if (!String.Equals(HashFile(imagePath), helperHash, StringComparison.OrdinalIgnoreCase)
                || !String.Equals(HashFile(pinPath), pinHash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("SERVICE_PACKAGE_HASH_MISMATCH");
        }
        catch (Exception exception) when (exception is not IOException { Message: "SERVICE_PACKAGE_MANIFEST_INVALID" or "SERVICE_PACKAGE_HASH_MISMATCH" })
        {
            throw new IOException("SERVICE_PACKAGE_MANIFEST_INVALID");
        }
    }

    private static string HashFile(string filename)
    {
        using var input = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
    }

    private static void ValidateSha256(string value)
    {
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
            throw new IOException("SERVICE_PACKAGE_MANIFEST_INVALID");
    }

    private static void VerifyProtectedAncestors(string installRoot, string programFilesRoot)
    {
        var current = new DirectoryInfo(installRoot).Parent;
        var reachedProgramFiles = false;
        while (current is not null)
        {
            VerifyTrustedAcl(current);
            if (String.Equals(Path.GetFullPath(current.FullName), Path.GetFullPath(programFilesRoot), StringComparison.OrdinalIgnoreCase))
            {
                reachedProgramFiles = true;
                break;
            }
            current = current.Parent;
        }
        if (!reachedProgramFiles) throw new IOException("SERVICE_INSTALL_ROOT_UNPROTECTED");
    }

    private static void VerifyTrustedAcl(DirectoryInfo directory)
    {
        if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("SERVICE_INSTALL_PATH_UNPROTECTED");
        var security = directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!IsTrusted(owner)) throw new IOException("SERVICE_INSTALL_OWNER_UNTRUSTED");
        EnsureNoUntrustedWriteRules(security);
    }

    private static void SecureInstalledImage(string installRoot, string imagePath)
    {
        var resources = Path.Combine(installRoot, "resources");
        var containment = Path.Combine(resources, "native-containment");
        foreach (var directoryPath in new[] { installRoot, resources, containment })
        {
            if (!Directory.Exists(directoryPath) || (File.GetAttributes(directoryPath) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("SERVICE_INSTALL_PATH_UNPROTECTED");
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(AdministratorsSid);
            var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsersSid, FileSystemRights.ReadAndExecute, inheritance, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(directoryPath).SetAccessControl(security);
            EnsureProtectedAcl(new DirectoryInfo(directoryPath).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
        }

        SecurePackageFile(imagePath);
        SecurePackageFile(Path.Combine(containment, "manifest.json"));
        SecurePackageFile(Path.Combine(containment, "lnwjud-containment-pin.node"));
    }

    private static void SecurePackageFile(string path)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("SERVICE_INSTALL_IMAGE_UNAVAILABLE");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(AdministratorsSid);
        security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AuthenticatedUsersSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
        EnsureProtectedAcl(new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access));
    }

    private static void EnsureProtectedAcl(FileSystemSecurity security)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (!IsTrusted(owner)) throw new IOException("SERVICE_INSTALL_OWNER_UNTRUSTED");
        EnsureNoUntrustedWriteRules(security);
    }

    private static void EnsureNoUntrustedWriteRules(FileSystemSecurity security)
    {
        const FileSystemRights genericWrite = (FileSystemRights)0x40000000;
        const FileSystemRights genericAll = (FileSystemRights)0x10000000;
        const FileSystemRights writeRights = FileSystemRights.WriteData | FileSystemRights.AppendData
            | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | genericWrite | genericAll;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (!IsTrusted(sid) && (rule.FileSystemRights & writeRights) != 0)
                throw new IOException("SERVICE_INSTALL_ACL_UNTRUSTED");
        }
    }

    private static bool IsTrusted(SecurityIdentifier? sid) =>
        sid is not null && (sid.Equals(SystemSid) || sid.Equals(AdministratorsSid) || sid.Equals(TrustedInstallerSid));

    internal static void RequireSeparateReplacementRoots(string candidateRoot, string oldRoot)
    {
        candidateRoot = Path.GetFullPath(candidateRoot);
        oldRoot = Path.GetFullPath(oldRoot);
        if (String.Equals(candidateRoot, oldRoot, StringComparison.OrdinalIgnoreCase)
            || IsBelowRoot(candidateRoot, oldRoot) || IsBelowRoot(oldRoot, candidateRoot))
            throw new IOException("SERVICE_INSTALL_REPLACEMENT_LAYOUT_REFUSED");
    }

    private static bool IsBelowRoot(string path, string root)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        return relative != "." && relative != ".."
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !Path.IsPathRooted(relative);
    }

    private static void EnsureNoReparsePoints(string path)
    {
        var current = Path.GetFullPath(path);
        while (true)
        {
            if ((File.Exists(current) || Directory.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("SERVICE_INSTALL_REPARSE_REFUSED");
            var parent = Directory.GetParent(current);
            if (parent is null) return;
            current = parent.FullName;
        }
    }

    private static void ApplyServiceSecurity(SafeServiceHandle service)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                ServiceSecurityDescriptor,
                SecurityDescriptorRevision,
                out var descriptor,
                out _))
            throw new IOException("SERVICE_INSTALL_SECURITY_DESCRIPTOR_INVALID");
        try
        {
            if (!SetServiceObjectSecurity(service, DaclSecurityInformation, descriptor))
                throw new IOException("SERVICE_INSTALL_SECURITY_FAILED");
        }
        finally { _ = LocalFree(descriptor); }
    }

    private static string QueryImagePath(SafeServiceHandle service) => ReadServiceConfiguration(service).ImagePath;

    private static (string ImagePath, uint StartType, uint ServiceType, string Account) ReadServiceConfiguration(SafeServiceHandle service)
    {
        if (QueryServiceConfig(service, 0, 0, out var required)
            || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer
            || required == 0)
            throw new IOException("SERVICE_INSTALL_CONFIG_UNAVAILABLE");
        var buffer = Marshal.AllocHGlobal(checked((int)required));
        try
        {
            if (!QueryServiceConfig(service, buffer, required, out _))
                throw new IOException("SERVICE_INSTALL_CONFIG_UNAVAILABLE");
            var configuration = Marshal.PtrToStructure<QueryServiceConfiguration>(buffer);
            var command = Marshal.PtrToStringUni(configuration.BinaryPathName) ?? throw new IOException("SERVICE_INSTALL_CONFIG_INVALID");
            return (ParseRegisteredImagePath(command), configuration.StartType, configuration.ServiceType,
                Marshal.PtrToStringUni(configuration.ServiceStartName) ?? throw new IOException("SERVICE_INSTALL_CONFIG_INVALID"));
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static void RequireDisabledStoppedService(SafeServiceHandle service, string reason)
    {
        var configuration = ReadServiceConfiguration(service);
        var status = QueryStatus(service);
        if (configuration.StartType != ServiceDisabled || configuration.ServiceType != ServiceWin32OwnProcess
            || !String.Equals(configuration.Account, "LocalSystem", StringComparison.OrdinalIgnoreCase)
            || status.CurrentState != ServiceStopped || status.ProcessId != 0)
            throw new IOException(reason);
    }

    internal static string ParseRegisteredImagePath(string command)
    {
        if (command.Length < 3 || command[0] != '"') throw new IOException("SERVICE_INSTALL_CONFIG_INVALID");
        var endQuote = command.IndexOf('"', 1);
        if (endQuote <= 1 || command[(endQuote + 1)..].Trim() != "service"
            || !Path.IsPathFullyQualified(command[1..endQuote])) throw new IOException("SERVICE_INSTALL_CONFIG_INVALID");
        return Path.GetFullPath(command[1..endQuote]);
    }

    private static void StopAndWait(SafeServiceHandle service)
    {
        var deadline = Stopwatch.StartNew();
        var stopRequested = false;
        while (deadline.Elapsed < TimeSpan.FromSeconds(30))
        {
            var status = QueryStatus(service);
            if (status.CurrentState == ServiceStopped) return;
            if (status.CurrentState == ServiceRunning && !stopRequested)
            {
                if (!ControlService(service, ServiceControlStop, out _))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != ErrorServiceNotActive && error != ErrorServiceCannotAcceptControl)
                        throw new IOException("SERVICE_STOP_REQUEST_FAILED");
                }
                else stopRequested = true;
            }
            Thread.Sleep(100);
        }
        throw new IOException("SERVICE_STOP_TIMEOUT");
    }

    private static void StartAndWait(SafeServiceHandle service)
    {
        var status = QueryStatus(service);
        if (status.CurrentState == ServiceStopped && !StartService(service, 0, 0))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ErrorServiceAlreadyRunning) throw new IOException("SERVICE_START_REQUEST_FAILED");
        }

        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(30))
        {
            if (QueryStatus(service).CurrentState == ServiceRunning) return;
            Thread.Sleep(100);
        }
        throw new IOException("SERVICE_START_TIMEOUT");
    }

    private static ServiceStatusProcess QueryStatus(SafeServiceHandle service)
    {
        if (!QueryServiceStatusEx(
                service,
                0,
                out var status,
                (uint)Marshal.SizeOf<ServiceStatusProcess>(),
                out _))
            throw new IOException("SERVICE_STATUS_UNAVAILABLE");
        return status;
    }
}
