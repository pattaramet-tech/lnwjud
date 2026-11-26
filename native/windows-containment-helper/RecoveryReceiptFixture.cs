#if NATIVE_CONTAINMENT_TESTS
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Lnwjud.UpdateWorker;
using Microsoft.Win32.SafeHandles;

namespace Lnwjud.Containment;

// Intent commits to the entire expected semantic native post-state, not just
// the absence of a hold. The receipt also binds the actual protected files.
// This is a fixture journal, not a production authorization token.
internal sealed record RecoveryReceiptFixture(string Scope, string FenceEpoch,
    ServiceAttemptIdentity Identity, string OwnerSid, OrphanImportAction Action,
    string EvidenceDigest, string ExpectedPostDigest, string? ReleasedWitness)
{
    private static readonly JsonSerializerOptions Json = new() {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    internal byte[] Encode()
    {
        if (!Wire.Digest(Scope) || !Guid.TryParseExact(FenceEpoch, "D", out var epoch) || epoch == Guid.Empty
            || Identity is null || !Wire.Digest(Identity.RequestDigest) || String.IsNullOrEmpty(OwnerSid)
            || Action is not (OrphanImportAction.AbortPreparedImport or OrphanImportAction.FinishAbortedHold)
            || !Wire.Digest(EvidenceDigest) || !Wire.Digest(ExpectedPostDigest)
            || (ReleasedWitness is not null && !Wire.Digest(ReleasedWitness)))
            throw new Refusal("RECOVERY_RECEIPT_INVALID");
        return JsonSerializer.SerializeToUtf8Bytes(this, Json);
    }
    internal static RecoveryReceiptFixture Decode(byte[] bytes)
    {
        var value = JsonSerializer.Deserialize<RecoveryReceiptFixture>(bytes, Json)
            ?? throw new Refusal("RECOVERY_RECEIPT_INVALID");
        if (!bytes.AsSpan().SequenceEqual(value.Encode())) throw new Refusal("RECOVERY_RECEIPT_INVALID");
        return value;
    }
    internal string Digest => WindowsStoreIO.Hash(Encode());
    internal static string SemanticDigest(PersistedServiceAttempt[] rows, ServiceImportRecord record, int schema)
        => NativeRecoveryPostState.SemanticDigest(rows, record, schema);

    [SupportedOSPlatform("windows")]
    internal static string ExpectedPost(PersistedServiceAttempt[] rows, ServiceImportRecord entry,
        OrphanImportEvidence approved, string destination)
    {
        var old = rows.Single(row => row.Request.Identity == approved.Identity);
        var expected = old with { ReservationHeld = false,
            Request = old.Request with { HoldForImport = false,
                LegacyImportVerifiedBoot = old.Request.LegacyImportVerifiedBoot ?? approved.BootId } };
        var post = entry.Phase == ServiceImportPhase.Aborted ? entry
            : entry with { Version = 2, Phase = ServiceImportPhase.Aborted,
                AbortDestinationIdentity = destination, AbortDestinationMissing = false };
        return SemanticDigest(rows.Select(row => row == old ? expected : row).ToArray(), post, 3);
    }

    // A staged initial intent can be published only against the unchanged
    // held native evidence. This does not dispatch an abort.
    [SupportedOSPlatform("windows")]
    internal static void ObservePendingIntent(string store, RecoveryReceiptFixture intent, SafeAccessTokenHandle token,
        Action publish)
    {
        OrphanImportPreflight.InspectFixture(store, intent.Identity, token, true, approved =>
        {
            if (approved.NativeDigest != intent.EvidenceDigest || approved.OwnerSid != intent.OwnerSid
                || approved.Action != intent.Action || intent.ReleasedWitness is not null)
                throw new Refusal("RECOVERY_PENDING_INTENT_UNVERIFIED");
            var rows = new ServiceAttemptLedgerPersistence(Path.Combine(store, "attempts.json")).Load();
            var filename = ServiceImportTransactionRuntime.RecordFilename(Path.Combine(store, "imports"), intent.Identity);
            var record = ServiceImportTransactionRuntime.ReadRecord(filename, intent.Identity, intent.OwnerSid)
                ?? throw new Refusal("RECOVERY_PENDING_INTENT_UNVERIFIED");
            RepositoryImportAnchor? dest = null;
            try
            {
                string? identity = null;
                WindowsIdentity.RunImpersonated(token, () =>
                {
                    dest = new RepositoryImportAnchor(record.Arguments.WorkspaceRoot, record.Arguments.Destination, false);
                    identity = dest.PinAbortDestinationIdentityOrMissing();
                    if (dest.ParentIdentity != record.ParentIdentity || identity is null || identity == record.StageIdentity)
                        throw new Refusal("RECOVERY_PENDING_INTENT_UNVERIFIED");
                });
                if (ExpectedPost(rows, record, approved, identity!) != intent.ExpectedPostDigest)
                    throw new Refusal("RECOVERY_PENDING_INTENT_UNVERIFIED");
                publish();
            }
            finally { dest?.Dispose(); }
        });
    }

    [SupportedOSPlatform("windows")]
    internal static string ObserveReleased(string store, RecoveryReceiptFixture intent, SafeAccessTokenHandle token,
        Action? whilePinned = null)
        => NativeRecoveryPostState.InspectReleasedFixture(store,
            new(intent.Identity, intent.OwnerSid, intent.ExpectedPostDigest, intent.ReleasedWitness), token, whilePinned);
}
#endif
