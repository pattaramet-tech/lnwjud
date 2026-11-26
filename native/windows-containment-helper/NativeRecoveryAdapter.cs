using System.Runtime.Versioning;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// Composition boundary. Production has exactly one operation: a read-only
// local review. No production recovery grant or mutation path is composed.
// The integrated fixture demonstrates sequencing, not machine-wide authority.
[SupportedOSPlatform("windows")]
internal static class NativeRecoveryAdapter
{
    internal static NativeMaintenanceReview ReviewLocal(ServiceAttemptIdentity expected, OrphanImportAction action)
    {
        LocalMaintenanceDialog.RequireInteractiveDesktop();
        var marker = UpdateStartupGate.InspectMachineMaintenance();
        // Ordinary diagnostic review remains available without a fence.
        if (marker is null) return NativeMaintenanceAuthority.ForLocalOperator(expected, action).Review();
        // With maintenance present, do not fall back to an ordinary review
        // if the protected cooperative boundary cannot be independently read.
        using var boundary = ProductionMaintenanceBoundary.EnterReadOnlyRecoveryInspection();
        WindowsContainmentServiceInstaller.InspectCurrentHelperStoppedService();
        var review = NativeMaintenanceAuthority.ForLocalOperator(expected, action).Review();
        boundary.RequireHeldLease();
        WindowsContainmentServiceInstaller.InspectCurrentHelperStoppedService();
        LocalMaintenanceDialog.RequireInteractiveDesktop();
        boundary.RequireHeldLease();
        return review with { CooperativeBoundaryVerified = true };
    }

#if NATIVE_CONTAINMENT_TESTS
    internal static NativeAtomicFixtureResult ExecuteRecoveryFixture(string fixtureRoot,
        ServiceAttemptIdentity expected, OrphanImportAction action,
        Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token, MaintenanceBoundaryFixture boundary,
        string exactFenceDigest, ServiceImportTransactionRuntime runtime,
        QualifiedRecoveryConsentFixture consent, Func<TimeSpan>? elapsed = null)
    {
        var root = Path.GetDirectoryName(MaintenanceBoundaryFixture.ScopeRoot(Path.Combine(fixtureRoot, "maintenance")))!;
        var store = Path.Combine(root, "native");
        // Read directly from this exact fixture and current token. A supplied
        // review result cannot authorize mutation through this composition root.
        var authority = NativeMaintenanceAuthority.ForFixture(expected, action, () =>
        {
            boundary.RequireRecoveryFixture(root, exactFenceDigest);
            var evidence = OrphanImportPreflight.InspectFixture(store, expected, token, true);
            var logon = NativeMaintenanceAuthority.ReadAuthenticationId(token);
            consent.Revalidate(evidence, logon, exactFenceDigest);
            return (evidence, logon);
        }, consent);
        authority.ElapsedForTest = elapsed;
        return boundary.RunRecoveryFixture(exactFenceDigest, expected, action, authority, runtime, token);
    }
#endif
}
