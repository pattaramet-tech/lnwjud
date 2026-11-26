using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

internal enum OrphanImportAction { RecordBootWitness, AbortPreparedImport, FinishAbortedHold }
internal sealed record OrphanImportEvidence(ServiceAttemptIdentity Identity, string OwnerSid,
    string OperatorSecurityDigest, uint WindowsSession, string NativeDigest, string BootId,
    OrphanImportAction Action, int SchemaVersion, ServiceImportArguments Arguments);

// No production RPC, CLI, grant transport, or mutation is exposed here.
// Native-only evidence is not proof that the application manifest is absent.
[SupportedOSPlatform("windows")]
internal static class OrphanImportPreflight
{
    internal static OrphanImportEvidence Inspect(ServiceAttemptIdentity expected, SafeAccessTokenHandle localOperator)
        => InspectCore(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "lnwjud-containment"), expected, localOperator, null);

#if NATIVE_CONTAINMENT_TESTS
    // Only the elevation decision can be simulated in a disposable fixture;
    // SID, protected file handles, ledger parser, Job and directory proof are real.
    internal static OrphanImportEvidence InspectFixture(string store, ServiceAttemptIdentity expected,
        SafeAccessTokenHandle token, bool elevated, Action<OrphanImportEvidence>? whilePinned = null)
        => InspectCore(store, expected, token, elevated, whilePinned);
#endif

    private static OrphanImportEvidence InspectCore(string store, ServiceAttemptIdentity expected,
        SafeAccessTokenHandle token, bool? fixtureElevation, Action<OrphanImportEvidence>? whilePinned = null)
    {
        if (token.IsInvalid || token.IsClosed) throw new Refusal("ORPHAN_OPERATOR_UNVERIFIED");
        using var user = new WindowsIdentity(token.DangerousGetHandle());
        var sid = user.User?.Value ?? throw new Refusal("ORPHAN_OPERATOR_UNVERIFIED");
        var admin = new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator);
#if NATIVE_CONTAINMENT_TESTS
        admin = fixtureElevation ?? admin;
#else
        if (fixtureElevation is not null) throw new Refusal("ORPHAN_OPERATOR_UNVERIFIED");
#endif
        if (!admin) throw new Refusal("ORPHAN_ADMIN_REQUIRED");
        var session = AuthenticatedPipeCaller.ReadSessionId(token.DangerousGetHandle());
        if (session == 0) throw new Refusal("ORPHAN_INTERACTIVE_SESSION_REQUIRED");
        if (!expected.TaskId.StartsWith("repository-import-", StringComparison.Ordinal)
            || !Guid.TryParseExact(expected.TaskId["repository-import-".Length..], "D", out var id) || id == Guid.Empty
            || expected.TaskId != "repository-import-" + id.ToString("D")
            || expected.AttemptId != expected.TaskId || expected.ReservationId != expected.TaskId
            || expected.Generation != 1 || !Wire.Digest(expected.RequestDigest))
            throw new Refusal("ORPHAN_ATTEMPT_INVALID");

        var recordPath = ServiceImportTransactionRuntime.RecordFilename(Path.Combine(store, "imports"), expected);
        using var pinned = new CoordinatedProtectedWitness(store, ["attempts.json", "imports/" + Path.GetFileName(recordPath)]);
        var before = pinned.Digest();
        var persistence = new ServiceAttemptLedgerPersistence(Path.Combine(store, "attempts.json"));
        var records = persistence.Load();
        var matches = records.Where(row => row.Request.Identity.AttemptId == expected.AttemptId).ToArray();
        if (matches.Length != 1 || matches[0].Request.Identity != expected
            || matches[0].Request.AuthenticatedCallerSid != sid)
            throw new Refusal("ORPHAN_OWNER_UNVERIFIED");
        var attempt = matches[0];
        ServiceAttemptLedger.ValidateStored(attempt);
        if (attempt.Request.ImportValidationPending is not null)
            throw new Refusal("ORPHAN_LEGACY_ONLY");
        var transaction = ServiceImportTransactionRuntime.ReadRecord(recordPath, expected, sid)
            ?? throw new Refusal("ORPHAN_IMPORT_UNVERIFIED");
        // Arguments come exclusively from the protected transaction record.
        // Keep the witnesses pinned through the read-only contract callback.
        using var witness = transaction.Phase == ServiceImportPhase.Prepared
            ? new CoordinatedLegacyImportWitness(store, expected, transaction.Arguments, token) : null;
        using var aborted = transaction.Phase == ServiceImportPhase.Aborted
            ? new AbortedHoldWitness(store, records, attempt, transaction, token) : null;
        if (witness is null && aborted is null) throw new Refusal("ORPHAN_IMPORT_PHASE_UNVERIFIED");
        if (before != pinned.Digest()) throw new Refusal("ORPHAN_EVIDENCE_CHANGED");
        var boot = NativeBootIdentity.Read();
        if (!Guid.TryParseExact(boot, "D", out var bootId) || bootId == Guid.Empty)
            throw new Refusal("ORPHAN_BOOT_UNVERIFIED");
        var observed = attempt.Request.LegacyImportObservedBoot;
        if (observed is not null && String.Equals(observed, boot, StringComparison.OrdinalIgnoreCase))
            throw new Refusal("ORPHAN_NEW_BOOT_REQUIRED");
        var action = aborted is not null ? OrphanImportAction.FinishAbortedHold
            : observed is null ? OrphanImportAction.RecordBootWitness : OrphanImportAction.AbortPreparedImport;
        var securityDigest = WindowsStoreIO.Hash(System.Text.Encoding.UTF8.GetBytes(AuthenticatedPipeCaller.SecurityFingerprint(token)));
        var nativeDigest = witness?.Digest() ?? WindowsStoreIO.Hash(Wire.Encode(new JsonObject
        {
            ["nativeAuthority"] = before, ["destinationIdentity"] = transaction.AbortDestinationIdentity,
            ["schema"] = persistence.LoadedSchemaVersion, ["phase"] = "aborted-held",
        }));
        var result = new OrphanImportEvidence(expected, sid, securityDigest, session, nativeDigest, boot, action, persistence.LoadedSchemaVersion, transaction.Arguments);
        whilePinned?.Invoke(result);
        if (before != pinned.Digest() || (witness is not null && witness.Digest() != nativeDigest))
            throw new Refusal("ORPHAN_EVIDENCE_CHANGED");
        return result;
    }
}

// Contract-only proof for an aborted tombstone whose native hold remains.
// No recovery is performed; conservative directory revalidation may refuse
// an otherwise recoverable tombstone if the stage was moved after the abort.
[SupportedOSPlatform("windows")]
internal sealed class AbortedHoldWitness : IDisposable
{
    private RepositoryImportAnchor? stage, destination;
    internal AbortedHoldWitness(string store, PersistedServiceAttempt[] records, PersistedServiceAttempt attempt,
        ServiceImportRecord transaction, SafeAccessTokenHandle token)
    {
        try
        {
            foreach (var row in records) ServiceAttemptLedger.ValidateStored(row);
            if (records.Select(row => row.Request.Identity.AttemptId).Distinct(StringComparer.Ordinal).Count() != records.Length
                || records.Any(row => row.Phase is not (ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)
                    || row.Request.ImportValidationPending == true)
                || records.Count(row => row.ReservationHeld || row.Request.HoldForImport) != 1
                || Directory.EnumerateFileSystemEntries(Path.Combine(store, "imports")).Any(file =>
                    !String.Equals(file, ServiceImportTransactionRuntime.RecordFilename(Path.Combine(store, "imports"), attempt.Request.Identity),
                        StringComparison.OrdinalIgnoreCase))
                || records.Any(row => row != attempt && (row.Request.PublicationCommitted == true
                    || row.Request.ImportValidationPending is not null || row.Request.LegacyImportObservedBoot is not null
                    || (!row.Request.Shared && !row.Request.RegistryOnly && row.Request.PublicationCommitted == false
                        && String.Equals(row.Request.ReservationKey, ServiceAttemptLedger.GlobalReservationKey, StringComparison.OrdinalIgnoreCase)))))
                throw new Refusal("ORPHAN_ABORT_HISTORY_UNVERIFIED");
            var request = attempt.Request;
            if (transaction.Version != 2 || transaction.Phase != ServiceImportPhase.Aborted
                || transaction.Identity != request.Identity || transaction.CallerSid != request.AuthenticatedCallerSid
                || !attempt.ReservationHeld || !request.HoldForImport || request.Shared || request.RegistryOnly
                || request.PublicationCommitted != false || request.ReservationKey != ServiceAttemptLedger.GlobalReservationKey
                || attempt.Phase != ServiceAttemptPhase.TerminalVerified || attempt.ActiveProcesses != 0
                || attempt.Outcome is null || attempt.ExitCode is null || !ServiceAttemptLedger.HasLegacyBootProof(request)
                || ContainedProcess.QueryJob(ContainedProcess.GetJobName(request.Identity.AttemptId)).Status != ContainedProcess.JobProbeStatus.NotFound)
                throw new Refusal("ORPHAN_ABORT_HOLD_UNVERIFIED");
            WindowsIdentity.RunImpersonated(token, () =>
            {
                destination = new RepositoryImportAnchor(transaction.Arguments.WorkspaceRoot, transaction.Arguments.Destination, false);
                stage = new RepositoryImportAnchor(Path.GetDirectoryName(transaction.Arguments.StagePath!)!, "stage", false);
                if (destination.ParentIdentity != transaction.ParentIdentity
                    || stage.PinAbortStage(Path.GetFileName(transaction.Arguments.StagePath!)) != transaction.StageIdentity
                    || destination.PinAbortDestinationIdentityOrMissing() != transaction.AbortDestinationIdentity)
                    throw new Refusal("ORPHAN_ABORT_DIRECTORY_CHANGED");
            });
        }
        catch { Dispose(); throw; }
    }

    public void Dispose() { stage?.Dispose(); destination?.Dispose(); }
}

#if NATIVE_CONTAINMENT_TESTS
// Approval issuance and consumption are fixture-only until a trusted
// local-consent and authoritative profile-inventory adapter is implemented.
// A native preflight result is NOT an authorization capability.
// In-memory, single-challenge contract. A process/service restart discards all
// grants; they are never serialized or restored. No approval is a writer lease.
// The future trusted local UI must invoke ConfirmFromTrustedLocalUi ONLY after
// explicit human confirmation of the exact displayed evidence. This class does
// not implement that UI, authenticate a remote caller, or accept a user flag.
internal sealed class OrphanImportApprovalSession
{
    private readonly object gate = new();
    private readonly OrphanImportEvidence evidence;
    private readonly long issued = Stopwatch.GetTimestamp();
    private readonly TimeSpan ttl = TimeSpan.FromMinutes(2);
    private readonly string challenge;
    private bool confirmed, closed;

#if NATIVE_CONTAINMENT_TESTS
    internal Func<TimeSpan>? ElapsedForTest { get; set; }
#endif

    internal OrphanImportApprovalSession(OrphanImportEvidence evidence)
    {
        this.evidence = evidence;
        var identity = evidence.Identity;
        challenge = WindowsStoreIO.Hash(Wire.Encode(new JsonObject
        {
            ["purpose"] = "orphan-import-approval-v1",
            ["nonce"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(),
            ["taskId"] = identity.TaskId, ["reservationId"] = identity.ReservationId,
            ["attemptId"] = identity.AttemptId, ["generation"] = identity.Generation,
            ["workspaceId"] = identity.WorkspaceId, ["clientId"] = identity.OwnerClientId,
            ["sessionId"] = identity.OwnerSessionId, ["requestDigest"] = identity.RequestDigest,
            ["ownerSid"] = evidence.OwnerSid, ["operatorSecurity"] = evidence.OperatorSecurityDigest,
            ["windowsSession"] = evidence.WindowsSession, ["nativeDigest"] = evidence.NativeDigest,
            ["bootId"] = evidence.BootId, ["action"] = evidence.Action.ToString(), ["schema"] = evidence.SchemaVersion,
        }));
    }

    internal string Challenge => challenge;

    private bool Expired()
    {
#if NATIVE_CONTAINMENT_TESTS
        var elapsed = ElapsedForTest?.Invoke() ?? Stopwatch.GetElapsedTime(issued);
#else
        var elapsed = Stopwatch.GetElapsedTime(issued);
#endif
        return elapsed < TimeSpan.Zero || elapsed >= ttl;
    }

    // No caller-supplied grant can be imported. The host must retain this
    // instance privately; this is not an externally callable authorization API.
    internal void ConfirmFromTrustedLocalUi(string displayedChallenge, OrphanImportEvidence fresh)
    {
        lock (gate)
        {
            if (closed || confirmed || Expired() || displayedChallenge != challenge || fresh != evidence)
            {
                closed = true;
                throw new Refusal("ORPHAN_APPROVAL_REFUSED");
            }
            confirmed = true;
        }
    }

    // Consume BEFORE any future effect. On interruption, a fresh preflight and
    // explicit approval are required. Never retry a mutation using this grant.
    // This validates a contract only; it performs no recovery.
    internal void ConsumeForContractTest(string approvedChallenge, OrphanImportEvidence fresh)
    {
        lock (gate)
        {
            var valid = !closed && confirmed && !Expired() && approvedChallenge == challenge && fresh == evidence;
            closed = true;
            if (!valid) throw new Refusal("ORPHAN_APPROVAL_REFUSED");
        }
    }
}


// Models one service-owned broker, not a distributed machine lock. Each broker
// has private challenge state; no serialized grants or caller evidence are
// accepted. Fresh evidence is read inside the serialized decision boundary.
// The fixture adapter must invoke the callback while native evidence is pinned.
// The real authority inventory, interactive consent and mutation boundary are
// intentionally absent from the production assembly in this round.
internal sealed record OrphanFixtureScope(string InventoryDigest, bool Complete,
    bool ManifestAbsent, bool WorkerSpecAbsent, bool RuntimeMarkerAbsent, bool WorkspaceAbsent,
    bool LocalConsentChannelVerified);

internal sealed class OrphanApprovalBrokerFixture
{
    private readonly object gate = new();
    private readonly Action<Action<OrphanImportEvidence, OrphanFixtureScope>> inspect;
    private OrphanImportApprovalSession? session;
    private OrphanFixtureScope? scope;

    internal OrphanApprovalBrokerFixture(Action<Action<OrphanImportEvidence, OrphanFixtureScope>> inspect)
        => this.inspect = inspect;

    private static void RequireScope(OrphanFixtureScope proof)
    {
        if (!proof.Complete || !proof.ManifestAbsent || !proof.WorkerSpecAbsent
            || !proof.RuntimeMarkerAbsent || !proof.WorkspaceAbsent || !Wire.Digest(proof.InventoryDigest))
            throw new Refusal("ORPHAN_PROFILE_AUTHORITY_UNVERIFIED");
        if (!proof.LocalConsentChannelVerified) throw new Refusal("ORPHAN_LOCAL_CONSENT_UNVERIFIED");
    }

    internal string Begin()
    {
        lock (gate)
        {
            if (session is not null) throw new Refusal("ORPHAN_APPROVAL_IN_FLIGHT");
            OrphanImportApprovalSession? created = null;
            OrphanFixtureScope? observed = null;
            inspect((native, inventory) =>
            {
                RequireScope(inventory);
                created = new OrphanImportApprovalSession(native);
                observed = inventory;
            });
            session = created ?? throw new Refusal("ORPHAN_PREFLIGHT_UNAVAILABLE");
            scope = observed;
            return session.Challenge;
        }
    }

    internal void Confirm(string challenge)
    {
        lock (gate)
        {
            var active = session ?? throw new Refusal("ORPHAN_APPROVAL_REFUSED");
            try
            {
                var visited = false;
                inspect((native, inventory) =>
                {
                    RequireScope(inventory);
                    if (inventory != scope) throw new Refusal("ORPHAN_PROFILE_AUTHORITY_CHANGED");
                    active.ConfirmFromTrustedLocalUi(challenge, native);
                    visited = true;
                });
                if (!visited) throw new Refusal("ORPHAN_PREFLIGHT_UNAVAILABLE");
            }
            catch { session = null; scope = null; throw; }
        }
    }

    internal void ConsumeReadOnly(string challenge)
    {
        lock (gate)
        {
            var active = session ?? throw new Refusal("ORPHAN_APPROVAL_REFUSED");
            var approvedScope = scope;
            // Drop the only broker reference even when fresh evidence refuses,
            // the callback fails, or the response is lost. No mutation callback.
            session = null;
            scope = null;
            var visited = false;
            inspect((native, inventory) =>
            {
                RequireScope(inventory);
                if (inventory != approvedScope) throw new Refusal("ORPHAN_PROFILE_AUTHORITY_CHANGED");
                active.ConsumeForContractTest(challenge, native);
                visited = true;
            });
            if (!visited) throw new Refusal("ORPHAN_PREFLIGHT_UNAVAILABLE");
        }
    }
}
#endif
