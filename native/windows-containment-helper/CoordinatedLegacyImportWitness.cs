using Microsoft.Win32.SafeHandles;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// Read-only native authority proof. It does not establish MCP client ownership,
// admit a writer, prove a second boot, or authorize abort/recovery.
[SupportedOSPlatform("windows")]
internal sealed class CoordinatedLegacyImportWitness : IDisposable
{
    private readonly CoordinatedProtectedWitness pinned;
    private RepositoryImportAnchor? stage;
    private RepositoryImportAnchor? destination;
    private readonly string initialDigest;
    private readonly string? destinationIdentity;
    internal ServiceAttemptIdentity Identity { get; }
    internal int SchemaVersion { get; }

    internal CoordinatedLegacyImportWitness(string store, ServiceAttemptIdentity expected,
        ServiceImportArguments expectedArguments, SafeAccessTokenHandle ownerToken)
    {
        if (ownerToken.IsInvalid || ownerToken.IsClosed) throw new Refusal("COORDINATED_OWNER_UNVERIFIED");
        using var owner = new WindowsIdentity(ownerToken.DangerousGetHandle());
        var sid = owner.User?.Value ?? throw new Refusal("COORDINATED_OWNER_UNVERIFIED");
        var record = ServiceImportTransactionRuntime.RecordFilename(Path.Combine(store, "imports"), expected);
        pinned = new CoordinatedProtectedWitness(store, ["attempts.json", "imports/" + Path.GetFileName(record)]);
        try
        {
            var persistence = new ServiceAttemptLedgerPersistence(Path.Combine(store, "attempts.json"));
            var records = persistence.Load();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in records)
            {
                ServiceAttemptLedger.ValidateStored(item);
                if (!ids.Add(item.Request.Identity.AttemptId)
                    || item.Phase is not (ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)
                    || item.Request.ImportValidationPending == true)
                    throw new Refusal("COORDINATED_NATIVE_HISTORY_UNVERIFIED");
            }
            var held = records.Where(item => item.ReservationHeld || item.Request.HoldForImport).ToArray();
            if (held.Length != 1) throw new Refusal("COORDINATED_NATIVE_HOLD_UNVERIFIED");
            var attempt = held[0];
            // Narrow lane: only the one exact prepared transaction may be
            // carried. Additional import history requires a separate full-store
            // witness, not an assumption that unpinned records are harmless.
            if (Directory.EnumerateFileSystemEntries(Path.Combine(store, "imports")).Any(path =>
                    !String.Equals(path, record, StringComparison.OrdinalIgnoreCase))
                || records.Any(item => item != attempt && (item.Request.PublicationCommitted == true
                    || item.Request.ImportValidationPending is not null || item.Request.LegacyImportObservedBoot is not null
                    || (!item.Request.Shared && !item.Request.RegistryOnly && item.Request.PublicationCommitted == false
                        && String.Equals(item.Request.ReservationKey, ServiceAttemptLedger.GlobalReservationKey, StringComparison.OrdinalIgnoreCase)))))
                throw new Refusal("COORDINATED_NATIVE_HISTORY_UNVERIFIED");
            if (attempt.Request.Identity != expected || attempt.Request.AuthenticatedCallerSid != sid)
                throw new Refusal("COORDINATED_OWNER_UNVERIFIED");
            if (!attempt.ReservationHeld || !attempt.Request.HoldForImport || attempt.Request.Shared || attempt.Request.RegistryOnly
                || attempt.Request.ReservationKey != ServiceAttemptLedger.GlobalReservationKey
                || attempt.Request.PublicationCommitted != false || attempt.Phase != ServiceAttemptPhase.TerminalVerified
                || attempt.ActiveProcesses != 0 || attempt.Outcome is null || attempt.ExitCode is null
                || ContainedProcess.QueryJob(ContainedProcess.GetJobName(expected.AttemptId)).Status != ContainedProcess.JobProbeStatus.NotFound)
                throw new Refusal("COORDINATED_NATIVE_HOLD_UNVERIFIED");
            var transaction = ServiceImportTransactionRuntime.ReadRecord(record, expected, sid)
                ?? throw new Refusal("COORDINATED_NATIVE_IMPORT_UNVERIFIED");
            if (transaction.Version != 1 || transaction.Phase != ServiceImportPhase.Prepared
                || transaction.Arguments != expectedArguments || transaction.Arguments.StagePath is null)
                throw new Refusal("COORDINATED_NATIVE_IMPORT_UNVERIFIED");
            // Use the authenticated owner's token; no stage/destination creation,
            // rename, repair, or acquisition of publication/delete access.
            destinationIdentity = WindowsIdentity.RunImpersonated(ownerToken, () =>
            {
                destination = new RepositoryImportAnchor(transaction.Arguments.WorkspaceRoot, transaction.Arguments.Destination, false);
                stage = new RepositoryImportAnchor(Path.GetDirectoryName(transaction.Arguments.StagePath)!, "stage", false);
                if (destination.ParentIdentity != transaction.ParentIdentity
                    || stage.PinAbortStage(Path.GetFileName(transaction.Arguments.StagePath)) != transaction.StageIdentity)
                    throw new Refusal("COORDINATED_IMPORT_DIRECTORY_CHANGED");
                var observed = destination.PinAbortDestinationIdentityOrMissing();
                if (observed == transaction.StageIdentity) throw new Refusal("COORDINATED_IMPORT_PUBLICATION_POSSIBLE");
                return observed;
            });
            Identity = expected;
            SchemaVersion = persistence.LoadedSchemaVersion;
            initialDigest = pinned.Digest();
        }
        catch { Dispose(); throw; }
    }

    internal string Digest()
    {
        var actual = pinned.Digest();
        if (actual != initialDigest) throw new Refusal("COORDINATED_NATIVE_AUTHORITY_CHANGED");
        // A missing destination is only a point-in-time observation. There is
        // no handle to pin its absence; the external isolation must prove no
        // writers and the next observation must re-probe it.
        return WindowsStoreIO.Hash(Wire.Encode(new JsonObject
        {
            ["nativeAuthority"] = actual, ["schema"] = SchemaVersion,
            ["destinationIdentity"] = destinationIdentity,
        }));
    }

    public void Dispose()
    {
        stage?.Dispose();
        destination?.Dispose();
        pinned.Dispose();
    }
}
