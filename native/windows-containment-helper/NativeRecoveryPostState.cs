using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Lnwjud.UpdateWorker;
using Microsoft.Win32.SafeHandles;

namespace Lnwjud.Containment;

// A claim is not an authorization or a receipt issuer. This read-only verifier
// must be called under independent maintenance authority. A successful
// observation never changes the ledger, import transaction or admission.
internal sealed record NativeRecoveryPostClaim(ServiceAttemptIdentity Identity,
    string OwnerSid, string ExpectedPostDigest, string? ReleasedWitness);

[SupportedOSPlatform("windows")]
internal static class NativeRecoveryPostState
{
    private static readonly JsonSerializerOptions Json = new() {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static string SemanticDigest(PersistedServiceAttempt[] rows, ServiceImportRecord record, int schema)
        => WindowsStoreIO.Hash(JsonSerializer.SerializeToUtf8Bytes(new ServiceAttemptLedgerDocument(schema,
            rows.OrderBy(x => x.Request.Identity.AttemptId, StringComparer.Ordinal).ToArray()), Json)
            .Concat(JsonSerializer.SerializeToUtf8Bytes(record, Json)).ToArray());

    // The caller cannot select an alternate production store. This is an
    // internal evidence primitive; no CLI or RPC dispatch routes to it.
    internal static string InspectReleased(NativeRecoveryPostClaim claim, ProductionMaintenanceBoundary boundary)
    {
        using var user = WindowsIdentity.GetCurrent();
        _ = NativeMaintenanceAuthority.RequireLocalOperator(user);
        LocalMaintenanceDialog.RequireInteractiveDesktop();
        boundary.RequireHeldLease();
        WindowsContainmentServiceInstaller.InspectCurrentHelperStoppedService();
        var witness = InspectCore(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "lnwjud-containment"), claim, user.AccessToken);
        WindowsContainmentServiceInstaller.InspectCurrentHelperStoppedService();
        LocalMaintenanceDialog.RequireInteractiveDesktop();
        boundary.RequireHeldLease();
        return witness;
    }

#if NATIVE_CONTAINMENT_TESTS
    internal static string InspectReleasedFixture(string store, NativeRecoveryPostClaim claim,
        SafeAccessTokenHandle token, Action? whilePinned = null)
    {
        var parent = Path.GetDirectoryName(store) ?? throw new Refusal("RECOVERY_RECEIPT_SCOPE_INVALID");
        if (Path.GetFileName(store) != "native"
            || !String.Equals(parent, Path.GetDirectoryName(MaintenanceBoundaryFixture.ScopeRoot(Path.Combine(parent, "maintenance"))),
                StringComparison.OrdinalIgnoreCase))
            throw new Refusal("RECOVERY_RECEIPT_SCOPE_INVALID");
        return InspectCore(store, claim, token, whilePinned);
    }
#endif

    private static string InspectCore(string store, NativeRecoveryPostClaim intent, SafeAccessTokenHandle token
#if NATIVE_CONTAINMENT_TESTS
        , Action? whilePinned = null
#endif
        )
    {
        if (!Wire.Digest(intent.ExpectedPostDigest)
            || (intent.ReleasedWitness is not null && !Wire.Digest(intent.ReleasedWitness)))
            throw new Refusal("RECOVERY_RECEIPT_INVALID");
        using var user = new WindowsIdentity(token.DangerousGetHandle());
        if (user.User?.Value != intent.OwnerSid) throw new Refusal("RECOVERY_RECEIPT_OWNER_MISMATCH");
        var imports = Path.Combine(store, "imports");
        var recordPath = ServiceImportTransactionRuntime.RecordFilename(imports, intent.Identity);
        using var pin = new CoordinatedProtectedWitness(store, ["attempts.json", "imports/" + Path.GetFileName(recordPath)]);
        var witness = pin.Digest();
        var persistence = new ServiceAttemptLedgerPersistence(Path.Combine(store, "attempts.json"));
        var rows = persistence.Load();
        foreach (var row in rows) ServiceAttemptLedger.ValidateStored(row);
        var matches = rows.Where(x => x.Request.Identity == intent.Identity).ToArray();
        if (matches.Length != 1 || rows.Select(x => x.Request.Identity.AttemptId).Distinct(StringComparer.Ordinal).Count() != rows.Length
            || rows.Any(x => x.ReservationHeld || x.Request.HoldForImport || x.Request.ImportValidationPending == true
                || x.Phase is not (ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted))
            || Directory.EnumerateFileSystemEntries(imports).Any(x => !String.Equals(x, recordPath, StringComparison.OrdinalIgnoreCase)))
            throw new Refusal("RECOVERY_RECEIPT_POST_STATE_UNVERIFIED");
        var attempt = matches[0];
        var record = ServiceImportTransactionRuntime.ReadRecord(recordPath, intent.Identity, intent.OwnerSid)
            ?? throw new Refusal("RECOVERY_RECEIPT_POST_STATE_UNVERIFIED");
        if (attempt.Request.AuthenticatedCallerSid != intent.OwnerSid
            || attempt.Request.PublicationCommitted != false || attempt.Request.Shared || attempt.Request.RegistryOnly
            || attempt.Request.ReservationKey != ServiceAttemptLedger.GlobalReservationKey
            || attempt.Phase != ServiceAttemptPhase.TerminalVerified || attempt.ActiveProcesses != 0
            || attempt.Outcome is null || attempt.ExitCode is null || !ServiceAttemptLedger.HasLegacyBootProof(attempt.Request)
            || record.Phase != ServiceImportPhase.Aborted || record.Version != 2 || record.AbortDestinationIdentity is null
            || SemanticDigest(rows, record, persistence.LoadedSchemaVersion) != intent.ExpectedPostDigest
            || ContainedProcess.QueryJob(ContainedProcess.GetJobName(intent.Identity.AttemptId)).Status != ContainedProcess.JobProbeStatus.NotFound)
            throw new Refusal("RECOVERY_RECEIPT_POST_STATE_UNVERIFIED");
        RepositoryImportAnchor? stage = null, destination = null;
        try
        {
            WindowsIdentity.RunImpersonated(token, () => {
                destination = new RepositoryImportAnchor(record.Arguments.WorkspaceRoot, record.Arguments.Destination, false);
                stage = new RepositoryImportAnchor(Path.GetDirectoryName(record.Arguments.StagePath!)!, "stage", false);
                if (destination.ParentIdentity != record.ParentIdentity
                    || stage.PinAbortStage(Path.GetFileName(record.Arguments.StagePath!)) != record.StageIdentity
                    || destination.PinAbortDestinationIdentityOrMissing() != record.AbortDestinationIdentity)
                    throw new Refusal("RECOVERY_RECEIPT_DIRECTORY_CHANGED");
            });
            if (pin.Digest() != witness || (intent.ReleasedWitness is not null && intent.ReleasedWitness != witness))
                throw new Refusal("RECOVERY_RECEIPT_WITNESS_CHANGED");
#if NATIVE_CONTAINMENT_TESTS
            whilePinned?.Invoke();
#endif
            if (pin.Digest() != witness) throw new Refusal("RECOVERY_RECEIPT_WITNESS_CHANGED");
            return witness;
        }
        finally { stage?.Dispose(); destination?.Dispose(); }
    }
}
