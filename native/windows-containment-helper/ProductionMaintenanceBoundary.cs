using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Lnwjud.Containment;

// Cooperative machine-store lifetime lease. Covers the new service's startup,
// runtime/background writes and shutdown, not old binaries or arbitrary admin
// processes. No production maintenance grant or mutation endpoint exists.
[SupportedOSPlatform("windows")]
internal sealed class ProductionMaintenanceBoundary : IDisposable
{
    private readonly List<SafeFileHandle> pins = [];
    private readonly Func<UpdateStartupDisposition?> inspect;
    private SafeFileHandle? lease;
    private readonly bool recoveryInspection;
    private ProductionMaintenanceBoundary(Func<UpdateStartupDisposition?> inspect, bool recoveryInspection)
        => (this.inspect, this.recoveryInspection) = (inspect, recoveryInspection);

    internal static void RequireOpenStartup()
    {
        if (UpdateStartupGate.InspectMachineMaintenance() is { } held) throw new IOException(held.Reason);
    }

    internal static ProductionMaintenanceBoundary EnterServiceLifetime()
        => Enter(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "lnwjud-containment"), UpdateStartupGate.InspectMachineMaintenance);

#if NATIVE_CONTAINMENT_TESTS
    internal static ProductionMaintenanceBoundary EnterLifetimeFixture(string root, Func<UpdateStartupDisposition?> inspect)
        => Enter(MaintenanceBoundaryFixture.ScopeRoot(root), inspect);
#endif

    // This mode requires a durable maintenance marker AND an already
    // provisioned protected lock. It never creates or clears authority.
    // Acquiring the cooperative lock does NOT attest legacy desktop isolation.
    internal static ProductionMaintenanceBoundary EnterReadOnlyRecoveryInspection()
        => Enter(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "lnwjud-containment"), RequireHeldMarker, provision: false);

    private static UpdateStartupDisposition? RequireHeldMarker()
        => UpdateStartupGate.InspectMachineMaintenance() is { Kind: "held", Reason: "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE" }
            ? null : new("held", "SERVICE_MAINTENANCE_MARKER_UNVERIFIED");

#if NATIVE_CONTAINMENT_TESTS
    internal static ProductionMaintenanceBoundary EnterReadOnlyInspectionFixture(string root, Func<UpdateStartupDisposition?> observed)
        => Enter(MaintenanceBoundaryFixture.ScopeRoot(root), () =>
            observed() is { Kind: "held", Reason: "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE" }
                ? null : new("held", "SERVICE_MAINTENANCE_MARKER_UNVERIFIED"), provision: false);
#endif

    private static ProductionMaintenanceBoundary Enter(string root, Func<UpdateStartupDisposition?> inspect, bool provision = true)
    {
        var gate = new ProductionMaintenanceBoundary(inspect, recoveryInspection: !provision);
        try
        {
            gate.RequireOpen();
            // The installer must already have initialized the protected store.
            // Pin every existing ancestor without delete sharing.
            var full = Path.GetFullPath(root);
            var volume = Path.GetPathRoot(full)!;
            var current = volume;
            gate.pins.Add(ServiceEndpointIdentity.PinKnownFolder(current));
            foreach (var part in Path.GetRelativePath(volume, full).Split(Path.DirectorySeparatorChar))
            {
                current = Path.Combine(current, part);
                gate.pins.Add(String.Equals(current, full, StringComparison.OrdinalIgnoreCase)
                    ? ServiceEndpointIdentity.OpenProtected(current, true)
                    : ServiceEndpointIdentity.PinKnownFolder(current));
            }
            var path = Path.Combine(full, "maintenance-lifetime.lock");
            try
            {
                // Never truncate or replace a pre-existing authority file.
                if (provision && !File.Exists(path))
                {
                    using var created = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                        4096, FileOptions.WriteThrough);
                    created.Flush(true);
                }
            }
            catch (IOException e) when ((e.HResult & 0xffff) is 80 or 183) { }
            gate.lease = ServiceEndpointIdentity.OpenProtected(path, false);
            if (!GetStandard(gate.lease, 1, out var info, (uint)Marshal.SizeOf<StandardInfo>())
                || info.Directory != 0 || info.DeletePending != 0 || info.Links != 1 || info.Length != 0)
                throw new IOException("SERVICE_MAINTENANCE_LOCK_UNVERIFIED");
            var overlap = new NativeOverlappedData();
            if (!LockFileEx(gate.lease, 3, 0, 1, 0, ref overlap))
                throw new IOException(Marshal.GetLastWin32Error() == 33
                    ? "SERVICE_MAINTENANCE_LIFETIME_BUSY" : "SERVICE_MAINTENANCE_LOCK_UNVERIFIED");
            gate.RequireOpen(); // after acquisition, before ledger creation
            return gate;
        }
        catch { gate.Dispose(); throw; }
    }

    internal void RequireOpen()
    {
        if (inspect() is { } held) throw new IOException(held.Reason);
    }

    internal void RequireHeldLease()
    {
        if (!recoveryInspection || lease is null || lease.IsClosed || lease.IsInvalid)
            throw new IOException("SERVICE_MAINTENANCE_LOCK_UNVERIFIED");
        RequireOpen();
    }

    public void Dispose()
    {
        // Windows releases the byte-range lock when this handle closes.
        lease?.Dispose();
        lease = null;
        foreach (var pin in pins) pin.Dispose();
        pins.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StandardInfo { internal long Allocation, Length; internal uint Links; internal byte DeletePending, Directory; }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlappedData { internal nuint Internal, InternalHigh; internal uint Offset, OffsetHigh; internal nint Event; }
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetStandard(SafeFileHandle handle, int kind, out StandardInfo info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LockFileEx(SafeFileHandle handle, uint flags, uint reserved, uint low, uint high, ref NativeOverlappedData overlap);
}
