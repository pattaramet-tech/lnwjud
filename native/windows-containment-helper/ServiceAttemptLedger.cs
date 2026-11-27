using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace Lnwjud.Containment;

internal enum ServiceAttemptPhase
{
    Prepared,
    DispatchCommitted,
    LaunchNotStarted,
    Running,
    TerminalVerified,
    TerminationUnknown,
    // Append only: phase numbers are part of protocol 3 and persisted snapshots.
    AdmissionRegistered,
}

internal enum ServiceProcessOutcome
{
    Completed,
    Cancelled,
    TimedOut,
    // Zero live Job processes after a service restart; actual target exit status was not observed.
    Interrupted,
}

internal enum ReservationRelease
{
    Released,
    AlreadyReleased,
    Retained,
}

internal sealed record ServiceAttemptIdentity(
    string TaskId,
    string ReservationId,
    string AttemptId,
    int Generation,
    string RequestDigest,
    string OwnerClientId,
    string OwnerSessionId,
    string WorkspaceId);

internal sealed record ServiceAttemptObservation(
    ServiceAttemptIdentity Identity,
    ServiceAttemptPhase Phase,
    int? TargetPid,
    ServiceProcessOutcome? Outcome,
    int? ExitCode,
    int? ActiveProcesses,
    string? Reason,
    bool ReservationHeld,
    bool CancellationRequested = false,
    bool PublicationCommitted = false);

internal sealed record ServiceAttemptRequest(
    ServiceAttemptIdentity Identity,
    string AuthenticatedCallerSid,
    string ReservationKey,
    string OperationDigest,
    bool Shared = false,
    bool HoldForImport = false,
    bool CancellationRequested = false,
    bool PublicationCommitted = false,
    bool RegistryOnly = false,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    Guid? NativeDispatchBootId = null);

internal sealed class ServiceAttemptLedger
{
    private sealed class Entry(ServiceAttemptRequest request)
    {
        internal ServiceAttemptRequest Request = request;
        internal ServiceAttemptPhase Phase = ServiceAttemptPhase.Prepared;
        internal int? TargetPid;
        internal ServiceProcessOutcome? Outcome;
        internal int? ExitCode;
        internal int? ActiveProcesses;
        internal string? Reason;
        internal bool ReservationHeld = true;
    }

    private static readonly Regex Digest = new("^[a-f0-9]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Sid = new("^S-1-[0-9]+(?:-[0-9]+)+$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private readonly object gate = new();
    private readonly Dictionary<string, Entry> attempts = new(StringComparer.Ordinal);
    private readonly ServiceAttemptLedgerPersistence? persistence;
    private bool unavailable;
#if NATIVE_CONTAINMENT_TESTS
    internal Action? AfterImportHoldClearedForTest { get; set; }
    internal Func<Guid>? BootIdentityForTest { get; set; }
#endif

    internal ServiceAttemptLedger() { }

    internal static string GlobalReservationKey { get; } = Path.Combine(
#if NATIVE_CONTAINMENT_TESTS
        Path.GetFullPath(Path.GetTempPath()),
#else
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
#endif
        "lnwjud-containment",
        "managed-writers");

    internal string? ImportStoreDirectory { get; }
    internal string? OutputStoreDirectory => persistence?.OutputStoreDirectory;

    internal ServiceAttemptLedger(ServiceAttemptLedgerPersistence persistence, string? importStoreDirectory = null)
    {
        this.persistence = persistence ?? throw new ArgumentNullException(nameof(persistence));
        ImportStoreDirectory = importStoreDirectory;
        var recovered = false;
        foreach (var stored in persistence.Load())
        {
            ValidateStored(stored);
            var entry = new Entry(stored.Request)
            {
                Phase = stored.Phase,
                TargetPid = stored.TargetPid,
                Outcome = stored.Outcome,
                ExitCode = stored.ExitCode,
                ActiveProcesses = stored.ActiveProcesses,
                Reason = stored.Reason,
                ReservationHeld = stored.ReservationHeld,
            };
            if (entry.Phase is ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.Running)
            {
                entry.Phase = ServiceAttemptPhase.TerminationUnknown;
                entry.Reason = "SERVICE_RESTART_REQUIRES_RECONCILIATION";
                entry.ActiveProcesses = null;
                recovered = true;
            }
            if (IsMcp(entry.Request.Identity) && entry.Phase == ServiceAttemptPhase.Prepared)
            {
                entry.Phase = ServiceAttemptPhase.LaunchNotStarted;
                entry.ReservationHeld = false;
                recovered = true;
            }
            if (!attempts.TryAdd(entry.Request.Identity.AttemptId, entry))
                throw new IOException("ATTEMPT_STORE_CORRUPT");
            if (entry.ReservationHeld && HasConflict(entry.Request, entry.Request.Identity.AttemptId))
                throw new IOException("ATTEMPT_STORE_CORRUPT");
        }
        // Reconstruct missing admission holds before accepting any new native
        // work. Otherwise a lost main ledger could bypass an exclusive import
        // hold or admit work while an earlier dispatch is still unresolved.
        foreach (var stored in persistence.LoadManagedWriterWitnesses())
        {
            ValidateStored(stored);
            var witness = ReadManagedWitness(stored.Request.Identity, stored.Request.AuthenticatedCallerSid)
                ?? throw new IOException("SERVICE_WRITER_WITNESS_INVALID");
            if (attempts.TryGetValue(witness.Request.Identity.AttemptId, out var existing))
            {
                if (existing.Request.Identity != witness.Request.Identity
                    || existing.Request.AuthenticatedCallerSid != witness.Request.AuthenticatedCallerSid)
                    throw new IOException("ATTEMPT_STORE_CORRUPT");
                if (witness.Request.HoldForImport && !existing.Request.HoldForImport)
                {
                    existing.Request = existing.Request with { HoldForImport = true, Shared = false };
                    existing.ReservationHeld = true;
                    recovered = true;
                }
                if (witness.Phase == ServiceAttemptPhase.DispatchCommitted
                    && existing.Phase is ServiceAttemptPhase.AdmissionRegistered or ServiceAttemptPhase.Prepared)
                {
                    existing.Request = witness.Request;
                    existing.Phase = ServiceAttemptPhase.TerminationUnknown;
                    existing.Reason = "SERVICE_RESTART_REQUIRES_RECONCILIATION";
                    existing.ReservationHeld = true;
                    recovered = true;
                }
                continue;
            }
            if (witness.Phase == ServiceAttemptPhase.DispatchCommitted)
            {
                witness.Phase = ServiceAttemptPhase.TerminationUnknown;
                witness.Reason = "SERVICE_RESTART_REQUIRES_RECONCILIATION";
            }
            else if (IsVerifiedWitness(witness))
            {
                // An unexpected live or inaccessible job is not a terminal
                // observation. Refuse service startup rather than drop a hold.
                VerifyRestoredWitnessJob(witness);
            }
            if (witness.Request.HoldForImport) witness.ReservationHeld = true;
            attempts.Add(witness.Request.Identity.AttemptId, witness);
            recovered = true;
        }
        foreach (var entry in attempts.Values)
            if (entry.ReservationHeld && HasConflict(entry.Request, entry.Request.Identity.AttemptId))
                throw new IOException("ATTEMPT_STORE_CORRUPT");
        if (recovered) Persist();
    }

    // A service-owned, durable binding must exist before the host publishes a
    // managed-writer marker. This phase does not admit or dispatch a process.
    internal ServiceAttemptObservation RegisterManagedWriter(ServiceAttemptIdentity identity, string callerSid)
    {
        if (!IsManagedWriter(identity)) throw new IOException("SERVICE_WRITER_IDENTITY_INVALID");
        Validate(new ServiceAttemptRequest(identity, callerSid, GlobalReservationKey, identity.RequestDigest, Shared: true));
        // The caller may propose owner/task identity but cannot recreate a lost
        // attempt or reservation by choosing its old ID or request digest.
        var reservationId = "managed-writer-" + Guid.NewGuid().ToString("D");
        var attemptId = Guid.NewGuid().ToString("D");
        var digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new[] {
                reservationId, attemptId, identity.TaskId, identity.OwnerClientId, identity.OwnerSessionId, identity.WorkspaceId
            }))).ToLowerInvariant();
        identity = identity with { ReservationId = reservationId, AttemptId = attemptId, RequestDigest = digest, Generation = 1 };
        var request = new ServiceAttemptRequest(identity, callerSid, GlobalReservationKey, digest, Shared: true);
        lock (gate)
        {
            EnsureAvailable();
            if (attempts.ContainsKey(identity.AttemptId)) throw new IOException("ATTEMPT_ID_CONFLICT");
            var entry = new Entry(request) { Phase = ServiceAttemptPhase.AdmissionRegistered, ReservationHeld = false };
            if (ReadManagedWitness(identity, callerSid) is not null) throw new IOException("ATTEMPT_ID_CONFLICT");
            WriteManagedWitness(entry);
            attempts.Add(identity.AttemptId, entry);
            Persist();
            return Observe(entry);
        }
    }

    private static bool IsManagedWriter(ServiceAttemptIdentity identity) =>
        identity.ReservationId.StartsWith("managed-writer-", StringComparison.Ordinal);

    [StructLayout(LayoutKind.Sequential)]
    private struct BootEnvironmentInformation
    {
        internal Guid BootIdentifier;
        internal uint FirmwareType;
        internal ulong BootFlags;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass,
        out BootEnvironmentInformation information, int length, out int returned);

    private Guid ReadBootIdentity()
    {
#if NATIVE_CONTAINMENT_TESTS
        if (BootIdentityForTest is not null)
        {
            var test = BootIdentityForTest();
            if (test != Guid.Empty) return test;
            throw new IOException("SERVICE_RECOVERY_BOOT_UNVERIFIED");
        }
#endif
        // SystemBootEnvironmentInformation: native boot GUID, not wall clock
        // or a timestamp supplied by a host marker. Unknown is fail-closed.
        if (!OperatingSystem.IsWindows()
            || NtQuerySystemInformation(90, out var info, Marshal.SizeOf<BootEnvironmentInformation>(), out _) != 0
            || info.BootIdentifier == Guid.Empty)
            throw new IOException("SERVICE_RECOVERY_BOOT_UNVERIFIED");
        return info.BootIdentifier;
    }

    private static PersistedServiceAttempt Snapshot(Entry entry) => new(
        entry.Request, entry.Phase, entry.TargetPid, entry.Outcome, entry.ExitCode,
        entry.ActiveProcesses, entry.Reason, entry.ReservationHeld);

    private Entry? ReadManagedWitness(ServiceAttemptIdentity identity, string callerSid)
    {
        if (persistence is null) return null;
        var records = persistence.ManagedWriterWitness(identity.AttemptId).Load();
        if (records.Length == 0) return null;
        if (records.Length != 1) throw new IOException("SERVICE_WRITER_WITNESS_INVALID");
        var stored = records[0];
        ValidateStored(stored);
        if (stored.Request.Identity != identity
            || !String.Equals(stored.Request.AuthenticatedCallerSid, callerSid, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("ATTEMPT_OWNER_MISMATCH");
        if (!IsManagedWriter(identity) || stored.Request.RegistryOnly
            || !String.Equals(stored.Request.ReservationKey, GlobalReservationKey, StringComparison.OrdinalIgnoreCase)
            || stored.Phase is not (ServiceAttemptPhase.AdmissionRegistered or ServiceAttemptPhase.DispatchCommitted
                or ServiceAttemptPhase.LaunchNotStarted or ServiceAttemptPhase.TerminalVerified)
            || stored.Phase == ServiceAttemptPhase.DispatchCommitted && stored.Request.NativeDispatchBootId is null)
            throw new IOException("SERVICE_WRITER_WITNESS_INVALID");
        return new Entry(stored.Request) { Phase = stored.Phase, TargetPid = stored.TargetPid,
            Outcome = stored.Outcome, ExitCode = stored.ExitCode, ActiveProcesses = stored.ActiveProcesses,
            Reason = stored.Reason, ReservationHeld = stored.ReservationHeld };
    }

    private void WriteManagedWitness(Entry entry)
    {
        if (persistence is null) throw new IOException("SERVICE_WRITER_WITNESS_UNAVAILABLE");
        try
        {
            persistence.ManagedWriterWitness(entry.Request.Identity.AttemptId).Save([Snapshot(entry)]);
        }
        catch (Exception exception)
        {
            // A partial witness commit must not permit subsequent admission
            // using stale in-memory state. Restart must reconcile both stores.
            unavailable = true;
            throw new IOException("SERVICE_WRITER_WITNESS_UNAVAILABLE", exception);
        }
    }

    private static bool IsVerifiedWitness(Entry witness) =>
        !witness.Request.HoldForImport && witness.Phase is ServiceAttemptPhase.LaunchNotStarted or ServiceAttemptPhase.TerminalVerified;

    private static void RequireAbsentJob(ServiceAttemptIdentity identity)
    {
        if (ContainedProcess.QueryJob(ContainedProcess.GetJobName(identity.AttemptId)).Status
            != ContainedProcess.JobProbeStatus.NotFound)
            throw new IOException("SERVICE_RECOVERY_JOB_UNVERIFIED");
    }

    private static void VerifyRestoredWitnessJob(Entry witness)
    {
        // Only a protected, exact-attempt collision tombstone records that the
        // existing named Job belonged to another launch. No target was created.
        // Never query, stop or adopt that foreign Job as our own terminal proof.
        if (witness.Phase == ServiceAttemptPhase.LaunchNotStarted
            && witness.Reason == "CONTAINMENT_JOB_NAME_IN_USE"
            && witness.TargetPid is null && witness.Request.NativeDispatchBootId is not null)
            return;
        RequireAbsentJob(witness.Request.Identity);
    }

    private ServiceAttemptObservation RestoreVerifiedWitness(Entry witness)
    {
        if (!IsVerifiedWitness(witness)) throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
        VerifyRestoredWitnessJob(witness);
        witness.ReservationHeld = false;
        attempts[witness.Request.Identity.AttemptId] = witness;
        Persist();
        return Observe(witness);
    }

    private ServiceAttemptObservation AbortRegisteredWitness(Entry witness)
    {
        if (witness.Phase != ServiceAttemptPhase.AdmissionRegistered || witness.Request.HoldForImport)
            throw new IOException("SERVICE_RECOVERY_DISPATCH_UNVERIFIED");
        RequireAbsentJob(witness.Request.Identity);
        witness.Phase = ServiceAttemptPhase.LaunchNotStarted;
        witness.ReservationHeld = false;
        WriteManagedWitness(witness); // durable no-replay evidence before main ledger
        return RestoreVerifiedWitness(witness);
    }

    internal ServiceAttemptObservation Prepare(ServiceAttemptRequest request)
    {
        Validate(request);
        lock (gate)
        {
            EnsureAvailable();
            if (attempts.TryGetValue(request.Identity.AttemptId, out var existing))
            {
                if (existing.Phase == ServiceAttemptPhase.AdmissionRegistered)
                {
                    if (existing.Request.Identity != request.Identity
                        || !String.Equals(existing.Request.AuthenticatedCallerSid, request.AuthenticatedCallerSid, StringComparison.Ordinal)
                        || !String.Equals(existing.Request.ReservationKey, request.ReservationKey, StringComparison.OrdinalIgnoreCase)
                        || !request.Shared || request.HoldForImport || request.RegistryOnly)
                        throw new IOException("ATTEMPT_ID_CONFLICT");
                    var witness = ReadManagedWitness(request.Identity, request.AuthenticatedCallerSid);
                    if (witness?.Phase != ServiceAttemptPhase.AdmissionRegistered)
                        throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                    if (HasConflict(request, request.Identity.AttemptId)) throw new IOException("WRITER_RESERVATION_BUSY");
                    existing.Request = request;
                    existing.Phase = ServiceAttemptPhase.Prepared;
                    existing.ReservationHeld = true;
                    Persist();
                    return Observe(existing);
                }
                if (!SameRequest(existing.Request, request)) throw new IOException("ATTEMPT_ID_CONFLICT");
                return Observe(existing);
            }
            if (IsManagedWriter(request.Identity)) throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
            if (HasConflict(request)) throw new IOException("WRITER_RESERVATION_BUSY");
            var entry = new Entry(request) { ReservationHeld = !request.RegistryOnly };
            attempts.Add(request.Identity.AttemptId, entry);
            Persist();
            return Observe(entry);
        }
    }

    // The old process may have run before reboot. Never call this LaunchNotStarted.
    internal ServiceAttemptObservation RecoverAfterReboot(
        ServiceAttemptIdentity identity, string callerSid, DateTimeOffset recordedAt,
        DateTimeOffset bootTime, ContainedProcess.JobProbeResult job)
    {
        var request = new ServiceAttemptRequest(identity, callerSid, GlobalReservationKey, identity.RequestDigest, Shared: true);
        Validate(request);
        if (!IsManagedWriter(identity) && (recordedAt.Offset != TimeSpan.Zero || recordedAt > DateTimeOffset.UtcNow
            || bootTime <= recordedAt.AddSeconds(5)))
            throw new IOException("SERVICE_RECOVERY_NEW_BOOT_REQUIRED");
        if (job.Status != ContainedProcess.JobProbeStatus.NotFound)
            throw new IOException("SERVICE_RECOVERY_JOB_UNVERIFIED");
        lock (gate)
        {
            EnsureAvailable();
            if (IsManagedWriter(identity))
            {
                // Never trust a host clock to authorize recovery. An exact
                // protected witness is mandatory, even when the main ledger
                // was lost. Live phases never enter reboot reconciliation.
                if (attempts.TryGetValue(identity.AttemptId, out var managedExisting))
                {
                    _ = Require(identity, callerSid);
                    if (managedExisting.Request.HoldForImport
                        || managedExisting.Phase is ServiceAttemptPhase.Running or ServiceAttemptPhase.DispatchCommitted)
                        throw new IOException("SERVICE_RECOVERY_EXISTING_ATTEMPT_UNVERIFIED");
                    if (managedExisting.Phase is ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)
                    {
                        if (managedExisting.ReservationHeld) _ = Release(identity, callerSid);
                        return Observe(managedExisting);
                    }
                }
                var witness = ReadManagedWitness(identity, callerSid)
                    ?? throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                if (witness.Request.HoldForImport) throw new IOException("SERVICE_RECOVERY_IMPORT_HOLD_UNVERIFIED");
                if (IsVerifiedWitness(witness)) return RestoreVerifiedWitness(witness);
                if (witness.Phase == ServiceAttemptPhase.AdmissionRegistered) return AbortRegisteredWitness(witness);
                if (witness.Phase != ServiceAttemptPhase.DispatchCommitted
                    || witness.Request.NativeDispatchBootId is not { } dispatchBoot || dispatchBoot == Guid.Empty)
                    throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                if (dispatchBoot == ReadBootIdentity()) throw new IOException("SERVICE_RECOVERY_NEW_BOOT_REQUIRED");
                RequireAbsentJob(identity);
                witness.Phase = ServiceAttemptPhase.TerminalVerified;
                witness.Outcome = ServiceProcessOutcome.Interrupted;
                witness.ExitCode = 125;
                witness.ActiveProcesses = 0;
                witness.Reason = null;
                witness.ReservationHeld = false;
                WriteManagedWitness(witness);
                return RestoreVerifiedWitness(witness);
            }
            if (attempts.TryGetValue(identity.AttemptId, out var existing))
            {
                if (existing.Request.Identity != identity
                    || !String.Equals(existing.Request.AuthenticatedCallerSid, callerSid, StringComparison.Ordinal))
                    throw new UnauthorizedAccessException("ATTEMPT_OWNER_MISMATCH");
                if (existing.Phase is ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)
                {
                    if (existing.ReservationHeld) _ = Release(identity, callerSid);
                    return Observe(existing);
                }
                // A persisted record that the service already downgraded to TerminationUnknown
                // after its own restart can be finalized only through this new-boot request,
                // which the caller has already bound to the original marker timestamp and an
                // absent attempt-named Job. No process from before that boot can still run.
                // Other live phases keep their runtime handle and stay refused. Import holds
                // remain retained until service-owned publication evidence clears them.
                if (existing.Phase == ServiceAttemptPhase.TerminationUnknown)
                {
                    if (existing.Request.HoldForImport) throw new IOException("SERVICE_RECOVERY_IMPORT_HOLD_UNVERIFIED");
                    existing.Phase = ServiceAttemptPhase.TerminalVerified;
                    existing.Outcome = ServiceProcessOutcome.Interrupted;
                    existing.ExitCode = 125;
                    existing.ActiveProcesses = 0;
                    existing.Reason = null;
                    existing.ReservationHeld = false;
                    Persist();
                    return Observe(existing);
                }
                throw new IOException("SERVICE_RECOVERY_EXISTING_ATTEMPT_UNVERIFIED");
            }
            var recovered = new Entry(request)
            {
                Phase = ServiceAttemptPhase.TerminalVerified,
                Outcome = ServiceProcessOutcome.Interrupted,
                ExitCode = 125,
                ActiveProcesses = 0,
                ReservationHeld = false,
            };
            attempts.Add(identity.AttemptId, recovered);
            Persist();
            return Observe(recovered);
        }
    }

    internal bool TryCommitDispatch(ServiceAttemptIdentity identity, string callerSid, string operationDigest)
    {
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (!string.Equals(entry.Request.OperationDigest, operationDigest, StringComparison.Ordinal))
                throw new IOException("SERVICE_OPERATION_DIGEST_MISMATCH");
            if (entry.Phase == ServiceAttemptPhase.Prepared)
            {
                if (IsManagedWriter(identity))
                {
                    var witness = ReadManagedWitness(identity, callerSid);
                    if (witness?.Phase != ServiceAttemptPhase.AdmissionRegistered)
                        throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                    var boot = ReadBootIdentity();
                    witness.Request = entry.Request with { NativeDispatchBootId = boot };
                    witness.Phase = ServiceAttemptPhase.DispatchCommitted;
                    witness.ReservationHeld = true;
                    WriteManagedWitness(witness); // write-ahead: no launch until both stores persist
                    entry.Request = witness.Request;
                }
                entry.Phase = ServiceAttemptPhase.DispatchCommitted;
                Persist();
                return true;
            }
            if (entry.Phase == ServiceAttemptPhase.LaunchNotStarted) throw new IOException("ATTEMPT_ALREADY_ABORTED");
            return false;
        }
    }

    internal ServiceAttemptObservation MarkRunning(ServiceAttemptIdentity identity, string callerSid, int targetPid)
    {
        if (targetPid <= 0) throw new IOException("TARGET_PID_INVALID");
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (entry.Phase == ServiceAttemptPhase.Running && entry.TargetPid == targetPid) return Observe(entry);
            if (entry.Phase != ServiceAttemptPhase.DispatchCommitted) throw new IOException("ATTEMPT_PHASE_CONFLICT");
            entry.TargetPid = targetPid;
            entry.Phase = ServiceAttemptPhase.Running;
            Persist();
            return Observe(entry);
        }
    }

    internal ServiceAttemptObservation AbortBeforeLaunch(ServiceAttemptRequest request)
    {
        Validate(request);
        lock (gate)
        {
            EnsureAvailable();
            var identity = request.Identity;
            if (attempts.TryGetValue(identity.AttemptId, out var existing))
            {
                if (existing.Request.Identity != identity
                    || !String.Equals(existing.Request.AuthenticatedCallerSid, request.AuthenticatedCallerSid, StringComparison.Ordinal)
                    || !String.Equals(existing.Request.ReservationKey, request.ReservationKey, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("ATTEMPT_ID_CONFLICT");
                if (existing.Phase != ServiceAttemptPhase.AdmissionRegistered
                    && !String.Equals(existing.Request.OperationDigest, request.OperationDigest, StringComparison.Ordinal)
                    && !String.Equals(identity.RequestDigest, request.OperationDigest, StringComparison.Ordinal))
                    throw new IOException("SERVICE_OPERATION_DIGEST_MISMATCH");
                if (IsManagedWriter(identity) && existing.Phase is ServiceAttemptPhase.AdmissionRegistered or ServiceAttemptPhase.Prepared)
                {
                    var witness = ReadManagedWitness(identity, request.AuthenticatedCallerSid)
                        ?? throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                    if (IsVerifiedWitness(witness)) return RestoreVerifiedWitness(witness);
                    return AbortRegisteredWitness(witness);
                }
                if (existing.Phase == ServiceAttemptPhase.Prepared)
                {
                    existing.Phase = ServiceAttemptPhase.LaunchNotStarted;
                    Persist();
                }
                return Observe(existing);
            }

            if (HasConflict(request)) throw new IOException("WRITER_RESERVATION_BUSY");
            // Missing main ledger alone is not evidence. An independent exact
            // native no-dispatch/terminal witness can recover the binding.
            if (IsManagedWriter(identity))
            {
                var witness = ReadManagedWitness(identity, request.AuthenticatedCallerSid)
                    ?? throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                if (IsVerifiedWitness(witness)) return RestoreVerifiedWitness(witness);
                return AbortRegisteredWitness(witness);
            }
            var tombstone = new Entry(request) { Phase = ServiceAttemptPhase.LaunchNotStarted };
            attempts.Add(identity.AttemptId, tombstone);
            Persist();
            return Observe(tombstone);
        }
    }

    internal ServiceAttemptObservation MarkJobCollisionBeforeLaunch(ServiceAttemptIdentity identity, string callerSid, ContainedProcess.JobNameInUseException proof)
    {
        ArgumentNullException.ThrowIfNull(proof);
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (!proof.Consume(identity)
                || entry.Phase is not (ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.TerminationUnknown)
                || entry.TargetPid is not null || !entry.ReservationHeld)
                throw new IOException("ATTEMPT_PHASE_CONFLICT");
            if (IsManagedWriter(identity))
            {
                var witness = ReadManagedWitness(identity, callerSid);
                if (witness?.Phase != ServiceAttemptPhase.DispatchCommitted
                    || witness.Request.NativeDispatchBootId is null)
                    throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                var collision = new Entry(entry.Request) { Phase = ServiceAttemptPhase.LaunchNotStarted,
                    Reason = "CONTAINMENT_JOB_NAME_IN_USE", ReservationHeld = entry.Request.HoldForImport };
                WriteManagedWitness(collision); // consume native proof, then durable tombstone before main release
            }
            entry.Phase = ServiceAttemptPhase.LaunchNotStarted;
            entry.Reason = "CONTAINMENT_JOB_NAME_IN_USE";
            entry.ReservationHeld = entry.Request.HoldForImport;
            Persist();
            return Observe(entry);
        }
    }

    internal ServiceAttemptObservation MarkUnknown(ServiceAttemptIdentity identity, string callerSid, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 128) throw new IOException("ATTEMPT_REASON_INVALID");
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (entry.Phase is ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.Running)
            {
                entry.Phase = ServiceAttemptPhase.TerminationUnknown;
                entry.Reason = reason;
                Persist();
            }
            return Observe(entry);
        }
    }

    internal ServiceAttemptObservation RecordTerminal(
        ServiceAttemptIdentity identity,
        string callerSid,
        ServiceProcessOutcome outcome,
        int exitCode,
        int activeProcesses)
    {
        if (activeProcesses != 0) throw new IOException("ACTIVE_PROCESSES_REMAIN");
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (entry.Phase == ServiceAttemptPhase.TerminalVerified)
            {
                if (entry.Outcome != outcome || entry.ExitCode != exitCode) throw new IOException("TERMINAL_PROOF_CONFLICT");
                return Observe(entry);
            }
            if (entry.Phase is not (ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.Running or ServiceAttemptPhase.TerminationUnknown))
                throw new IOException("ATTEMPT_PHASE_CONFLICT");
            if (IsManagedWriter(identity))
            {
                // Record only actual native zero-active termination. Never
                // clear an import hold via this independent receipt.
                var terminalRequest = outcome is ServiceProcessOutcome.Cancelled or ServiceProcessOutcome.TimedOut
                    ? entry.Request with { CancellationRequested = true } : entry.Request;
                var terminalWitness = new Entry(terminalRequest) { Phase = ServiceAttemptPhase.TerminalVerified,
                    TargetPid = entry.TargetPid, Outcome = outcome, ExitCode = exitCode,
                    ActiveProcesses = 0, ReservationHeld = entry.Request.HoldForImport };
                if (persistence is not null) WriteManagedWitness(terminalWitness);
            }
            entry.Phase = ServiceAttemptPhase.TerminalVerified;
            entry.Outcome = outcome;
            entry.ExitCode = exitCode;
            entry.ActiveProcesses = 0;
            entry.Reason = null;
            if (outcome is ServiceProcessOutcome.Cancelled or ServiceProcessOutcome.TimedOut)
                entry.Request = entry.Request with { CancellationRequested = true };
            Persist();
            return Observe(entry);
        }
    }

    internal ReservationRelease Release(ServiceAttemptIdentity identity, string callerSid)
    {
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (!entry.ReservationHeld) return ReservationRelease.AlreadyReleased;
            if (entry.Request.HoldForImport) return ReservationRelease.Retained;
            if (entry.Phase is not (ServiceAttemptPhase.LaunchNotStarted or ServiceAttemptPhase.TerminalVerified))
                return ReservationRelease.Retained;
            entry.ReservationHeld = false;
            Persist();
            return ReservationRelease.Released;
        }
    }

    internal void AcquireImportReservation(ServiceAttemptIdentity identity, string callerSid)
    {
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (entry.Request.CancellationRequested) throw new IOException("SERVICE_IMPORT_CANCELLED");
            if (entry.Request.HoldForImport) return;
            if (!entry.ReservationHeld || entry.Phase is not (ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.Running))
                throw new IOException("ATTEMPT_IMPORT_PHASE_INVALID");
            var exclusive = entry.Request with { ReservationKey = GlobalReservationKey, Shared = false, HoldForImport = true };
            if (HasConflict(exclusive, identity.AttemptId)) throw new IOException("WRITER_RESERVATION_BUSY");
            if (IsManagedWriter(identity))
            {
                var witness = ReadManagedWitness(identity, callerSid)
                    ?? throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                witness.Request = exclusive;
                WriteManagedWitness(witness); // hold is durable before import publication can begin
            }
            entry.Request = exclusive;
            Persist();
        }
    }

    internal ServiceAttemptObservation RequestCancellation(ServiceAttemptIdentity identity, string callerSid)
    {
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (!entry.ReservationHeld) return Observe(entry);
            if (!entry.Request.CancellationRequested)
            {
                entry.Request = entry.Request with { CancellationRequested = true };
                if (entry.Phase == ServiceAttemptPhase.Prepared)
                {
                    if (IsManagedWriter(identity))
                    {
                        var witness = ReadManagedWitness(identity, callerSid)
                            ?? throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                        return AbortRegisteredWitness(witness);
                    }
                    entry.Phase = ServiceAttemptPhase.LaunchNotStarted;
                }
                Persist();
            }
            if (entry.Phase == ServiceAttemptPhase.LaunchNotStarted) _ = Release(identity, callerSid);
            return Observe(entry);
        }
    }

    internal T StartImportValidation<T>(ServiceAttemptIdentity identity, string callerSid, Func<T> start)
    {
        lock (gate)
        {
            EnsureImportMayValidate(Require(identity, callerSid));
            return start();
        }
    }

    internal void CheckImportValidation(ServiceAttemptIdentity identity, string callerSid)
    {
        lock (gate) EnsureImportMayValidate(Require(identity, callerSid));
    }

    internal void CommitImportPublication(ServiceAttemptIdentity identity, string callerSid, Action persistIntent)
    {
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            EnsureImportMayValidate(entry);
            entry.Request = entry.Request with { PublicationCommitted = true };
            Persist();
            persistIntent();
        }
    }

    private static void EnsureImportMayValidate(Entry entry)
    {
        if (entry.Request.CancellationRequested) throw new IOException("SERVICE_IMPORT_CANCELLED");
        if (entry.Phase is not (ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.Running)
            || !entry.ReservationHeld || !entry.Request.HoldForImport) throw new IOException("SERVICE_IMPORT_OWNER_NOT_RUNNING");
        if (entry.Request.PublicationCommitted) throw new IOException("SERVICE_IMPORT_PUBLICATION_ALREADY_COMMITTED");
    }

    internal void CompleteImportReservation(ServiceAttemptIdentity identity, string callerSid)
    {
        lock (gate)
        {
            var entry = Require(identity, callerSid);
            if (entry.Request.HoldForImport)
            {
                entry.Request = entry.Request with { HoldForImport = false };
                Persist();
                if (IsManagedWriter(identity) && persistence is not null)
                {
                    var witness = ReadManagedWitness(identity, callerSid)
                        ?? throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                    witness.Request = witness.Request with { HoldForImport = false };
                    if (witness.Phase is ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)
                        witness.ReservationHeld = false;
                    WriteManagedWitness(witness);
                }
#if NATIVE_CONTAINMENT_TESTS
                AfterImportHoldClearedForTest?.Invoke();
#endif
            }
            if (entry.Phase is ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)
                _ = Release(identity, callerSid);
        }
    }

    private bool HasConflict(ServiceAttemptRequest request, string? exceptAttemptId = null) => attempts.Values.Any(entry =>
        entry.Request.Identity.AttemptId != exceptAttemptId && entry.ReservationHeld
        && (String.Equals(entry.Request.ReservationKey, request.ReservationKey, StringComparison.OrdinalIgnoreCase)
            || String.Equals(entry.Request.ReservationKey, GlobalReservationKey, StringComparison.OrdinalIgnoreCase)
            || String.Equals(request.ReservationKey, GlobalReservationKey, StringComparison.OrdinalIgnoreCase))
        && !(entry.Request.Shared && request.Shared));

    internal ServiceAttemptObservation Inspect(ServiceAttemptIdentity identity, string callerSid)
    {
        lock (gate)
        {
            EnsureAvailable();
            if (IsManagedWriter(identity) && !attempts.ContainsKey(identity.AttemptId))
            {
                var witness = ReadManagedWitness(identity, callerSid)
                    ?? throw new IOException("SERVICE_RECOVERY_NATIVE_BINDING_REQUIRED");
                if (witness.Request.HoldForImport) throw new IOException("SERVICE_RECOVERY_IMPORT_HOLD_UNVERIFIED");
                if (IsVerifiedWitness(witness)) return RestoreVerifiedWitness(witness);
                if (witness.Phase == ServiceAttemptPhase.AdmissionRegistered) return Observe(witness);
                return Observe(witness) with { Phase = ServiceAttemptPhase.TerminationUnknown,
                    Reason = "SERVICE_RECOVERY_NATIVE_BOOT_REQUIRED" };
            }
            // Missing non-managed attempt is not owner mismatch or proof of no dispatch.
            if (!attempts.ContainsKey(identity.AttemptId))
                throw new IOException("SERVICE_ATTEMPT_NOT_FOUND");
            var entry = Require(identity, callerSid);
            // A crash after the independent terminal write but before the main
            // ledger commit can be recovered without inventing an exit code.
            if (IsManagedWriter(identity) && !entry.Request.HoldForImport
                && entry.Phase is ServiceAttemptPhase.AdmissionRegistered or ServiceAttemptPhase.Prepared or ServiceAttemptPhase.TerminationUnknown)
            {
                var witness = ReadManagedWitness(identity, callerSid);
                if (witness is not null && IsVerifiedWitness(witness)) return RestoreVerifiedWitness(witness);
            }
            return Observe(entry);
        }
    }

    internal static bool IsMcp(ServiceAttemptIdentity identity) => identity.TaskId.StartsWith("mcp:", StringComparison.Ordinal);

    internal ServiceAttemptIdentity PrepareMcpConnection(string callerSid, string operationDigest, uint sessionId = 0)
    {
        var id = Guid.NewGuid().ToString("N");
        var identity = new ServiceAttemptIdentity("mcp:" + id, id, id, 1, operationDigest, id,
            sessionId.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(), id);
        _ = Prepare(new(identity, callerSid, GlobalReservationKey, operationDigest, Shared: true, RegistryOnly: true));
        return identity;
    }

    internal ServiceAttemptIdentity PrepareMcpChild(ServiceAttemptIdentity connection, string callerSid)
    {
        lock (gate)
        {
            var owner = RequireMcpConnection(connection, callerSid);
            if (owner.Phase != ServiceAttemptPhase.Prepared) throw new IOException("SERVICE_MCP_CONNECTION_CLOSED");
            var siblings = McpChildren(connection, callerSid);
            if (siblings.Length >= 64) throw new IOException("SERVICE_MCP_CHILD_LIMIT");
            if (siblings.Any(child => child.Phase is not (ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)))
                throw new IOException("SERVICE_MCP_SIBLING_UNRESOLVED");
            var id = Guid.NewGuid().ToString("N");
            var child = connection with { AttemptId = id, ReservationId = id, Generation = siblings.Length + 2 };
            _ = Prepare(new(child, callerSid, GlobalReservationKey, owner.Request.OperationDigest, Shared: true, RegistryOnly: true));
            return child;
        }
    }

    internal bool TryCommitMcpDispatch(ServiceAttemptIdentity connection, ServiceAttemptIdentity child, string callerSid, string digest)
    {
        lock (gate)
        {
            var owner = RequireMcpConnection(connection, callerSid);
            _ = RequireMcpChild(connection, child, callerSid);
            if (owner.Phase != ServiceAttemptPhase.Prepared)
            {
                _ = AbortBeforeLaunch(new(child, callerSid, GlobalReservationKey, digest, Shared: true, RegistryOnly: true));
                return false;
            }
            if (owner.Request.OperationDigest != digest) throw new IOException("SERVICE_MCP_OPERATION_MISMATCH");
            return TryCommitDispatch(child, callerSid, digest);
        }
    }

    internal ServiceAttemptObservation[] McpChildren(ServiceAttemptIdentity connection, string callerSid)
    {
        lock (gate)
        {
            _ = RequireMcpConnection(connection, callerSid);
            return attempts.Values.Where(entry => entry.Request.Identity.TaskId == connection.TaskId
                && entry.Request.Identity.AttemptId != connection.AttemptId)
                .Select(entry => Observe(RequireMcpChild(connection, entry.Request.Identity, callerSid))).ToArray();
        }
    }

    internal void CloseMcpConnection(ServiceAttemptIdentity connection, string callerSid)
    {
        lock (gate)
        {
            var owner = RequireMcpConnection(connection, callerSid);
            _ = AbortBeforeLaunch(owner.Request);
            _ = Release(connection, callerSid);
        }
    }

    internal ServiceAttemptObservation AbortMcpChild(ServiceAttemptIdentity connection, ServiceAttemptIdentity child, string callerSid)
    {
        lock (gate)
        {
            var entry = RequireMcpChild(connection, child, callerSid);
            var observation = AbortBeforeLaunch(entry.Request);
            if (observation.Phase == ServiceAttemptPhase.LaunchNotStarted) _ = Release(child, callerSid);
            return Inspect(child, callerSid);
        }
    }

    private Entry RequireMcpConnection(ServiceAttemptIdentity connection, string callerSid)
    {
        var owner = Require(connection, callerSid);
        if (!IsMcp(connection) || !owner.Request.RegistryOnly || connection.Generation != 1 || connection.ReservationId != connection.AttemptId)
            throw new IOException("SERVICE_MCP_CONNECTION_INVALID");
        return owner;
    }

    private Entry RequireMcpChild(ServiceAttemptIdentity connection, ServiceAttemptIdentity child, string callerSid)
    {
        _ = RequireMcpConnection(connection, callerSid);
        var entry = Require(child, callerSid);
        if (!entry.Request.RegistryOnly || child.TaskId != connection.TaskId || child.Generation < 2 || child.AttemptId == connection.AttemptId
            || child.OwnerClientId != connection.OwnerClientId || child.OwnerSessionId != connection.OwnerSessionId
            || child.WorkspaceId != connection.WorkspaceId || child.RequestDigest != connection.RequestDigest)
            throw new IOException("SERVICE_MCP_CHILD_INVALID");
        return entry;
    }

    private Entry Require(ServiceAttemptIdentity identity, string callerSid)
    {
        EnsureAvailable();
        if (!attempts.TryGetValue(identity.AttemptId, out var entry)
            || entry.Request.Identity != identity
            || !String.Equals(entry.Request.AuthenticatedCallerSid, callerSid, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("ATTEMPT_OWNER_MISMATCH");
        return entry;
    }

    private static ServiceAttemptObservation Observe(Entry entry) => new(
        entry.Request.Identity,
        entry.Phase,
        entry.TargetPid,
        entry.Outcome,
        entry.ExitCode,
        entry.ActiveProcesses,
        entry.Reason,
        entry.ReservationHeld,
        entry.Request.CancellationRequested,
        entry.Request.PublicationCommitted);

    private static bool SameRequest(ServiceAttemptRequest left, ServiceAttemptRequest right) =>
        left.Identity == right.Identity
        && left.RegistryOnly == right.RegistryOnly
        && String.Equals(left.AuthenticatedCallerSid, right.AuthenticatedCallerSid, StringComparison.Ordinal)
        && String.Equals(left.ReservationKey, right.ReservationKey, StringComparison.OrdinalIgnoreCase)
        && String.Equals(left.OperationDigest, right.OperationDigest, StringComparison.Ordinal);

    private static void Validate(ServiceAttemptRequest request)
    {
        var identity = request.Identity;
        if (String.IsNullOrWhiteSpace(identity.TaskId) || identity.TaskId.Length > 256
            || String.IsNullOrWhiteSpace(identity.ReservationId) || identity.ReservationId.Length > 256
            || String.IsNullOrWhiteSpace(identity.AttemptId) || identity.AttemptId.Length > 256
            || identity.Generation < 1 || !Digest.IsMatch(identity.RequestDigest)
            || String.IsNullOrWhiteSpace(identity.OwnerClientId) || identity.OwnerClientId.Length > 256
            || String.IsNullOrWhiteSpace(identity.OwnerSessionId) || identity.OwnerSessionId.Length > 256
            || String.IsNullOrWhiteSpace(identity.WorkspaceId) || identity.WorkspaceId.Length > 256
            || !Sid.IsMatch(request.AuthenticatedCallerSid)
            || !Path.IsPathFullyQualified(request.ReservationKey)
            || request.HoldForImport && request.Shared
            || request.RegistryOnly != IsMcp(identity) || request.RegistryOnly && (!request.Shared || request.HoldForImport)
            || request.NativeDispatchBootId == Guid.Empty
            || !Digest.IsMatch(request.OperationDigest))
            throw new IOException("ATTEMPT_REQUEST_INVALID");
    }

    private void Persist()
    {
        if (persistence is null) return;
        try
        {
            // FIX-07 can read schema 2, but not phase 6 or the boot GUID.
            // Keep a version-3 fence whenever a managed intent/hold remains.
            // At a fully settled managed boundary, the main ledger can retain
            // the exact legacy terminal rows; boot evidence stays in witnesses.
            var requiresNewFormat = attempts.Values.Any(entry => IsManagedWriter(entry.Request.Identity)
                && (entry.ReservationHeld || entry.Request.HoldForImport
                    || entry.Phase is not (ServiceAttemptPhase.LaunchNotStarted or ServiceAttemptPhase.TerminalVerified)));
            var snapshot = attempts.Values
                .OrderBy(entry => entry.Request.Identity.AttemptId, StringComparer.Ordinal)
                .Select(entry =>
                {
                    var stored = Snapshot(entry);
                    return !requiresNewFormat && IsManagedWriter(entry.Request.Identity)
                        ? stored with { Request = stored.Request with { NativeDispatchBootId = null } }
                        : stored;
                })
                .ToArray();
            persistence.Save(snapshot, requiresNewFormat);
        }
        catch (Exception exception)
        {
            unavailable = true;
            throw new IOException("ATTEMPT_STORE_UNAVAILABLE", exception);
        }
    }

    private void EnsureAvailable()
    {
        if (unavailable) throw new IOException("ATTEMPT_STORE_UNAVAILABLE");
    }

    private static void ValidateStored(PersistedServiceAttempt stored)
    {
        if (stored is null) throw new IOException("ATTEMPT_STORE_CORRUPT");
        try { Validate(stored.Request); }
        catch { throw new IOException("ATTEMPT_STORE_CORRUPT"); }
        if (!Enum.IsDefined(stored.Phase)
            || (stored.Outcome is not null && !Enum.IsDefined(stored.Outcome.Value))
            || (stored.TargetPid is <= 0)
            || (stored.Reason is { Length: > 128 })
            || (stored.Phase == ServiceAttemptPhase.Running && stored.TargetPid is null)
            || (stored.Phase == ServiceAttemptPhase.TerminationUnknown && String.IsNullOrWhiteSpace(stored.Reason))
            || (stored.Phase == ServiceAttemptPhase.TerminalVerified
                ? stored.Outcome is null || stored.ExitCode is null || stored.ActiveProcesses != 0
                : stored.Outcome is not null || stored.ExitCode is not null || stored.ActiveProcesses is not null)
            || (stored.Phase is ServiceAttemptPhase.Prepared or ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.LaunchNotStarted
                && stored.TargetPid is not null)
            || (stored.Phase == ServiceAttemptPhase.AdmissionRegistered
                && (stored.ReservationHeld || !IsManagedWriter(stored.Request.Identity) || !stored.Request.Shared
                    || stored.Request.HoldForImport || stored.Request.RegistryOnly || stored.TargetPid is not null
                    || stored.Request.OperationDigest != stored.Request.Identity.RequestDigest))
            || (!stored.ReservationHeld && stored.Phase is not (ServiceAttemptPhase.LaunchNotStarted or ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.AdmissionRegistered)
                && !stored.Request.RegistryOnly))
            throw new IOException("ATTEMPT_STORE_CORRUPT");
    }
}
