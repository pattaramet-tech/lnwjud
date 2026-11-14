using System.Diagnostics;
using System.IO.Pipes;

namespace Lnwjud.Containment;

internal sealed record ServiceProcessOperation(
    string? Kind,
    string? Executable,
    string[]? Args,
    string? Cwd,
    int TimeoutMs,
    bool WindowsVerbatimArguments,
    Dictionary<string, string>? Environment,
    int MaximumOutputBytes);

internal sealed record ServiceOutputCursor(long StdoutOffset, long StderrOffset);

internal sealed record ServiceOutputObservation(
    string StdoutBase64,
    string StderrBase64,
    bool StdoutTruncated,
    bool StderrTruncated,
    bool Complete,
    ServiceOutputCursor NextCursor,
    ServiceOutputCursor? FinalCursor,
    bool Persisted,
    string PersistenceStatus,
    string? IncompleteReason,
    ServiceAttemptIdentity Identity);

/// <summary>
/// Owns every Windows Job handle, process handle, and output pipe for service-launched work.
/// Terminal proof requires both the retained root handle and the owned Job; shutdown
/// additionally joins startup, readers and native resource disposal for every attempt.
/// </summary>
internal sealed class WindowsServiceProcessRuntime
{
    private const int MaximumConcurrentProcesses = 64;
    private const int MaximumRetainedOutputs = 128;
    private const int TerminationWaitMilliseconds = 15_000;
    private const int ReaderWaitMilliseconds = 5_000;
    private readonly ServiceAttemptLedger ledger;
    private readonly ServiceOutputStore? outputStore;
    private readonly bool useCurrentUserTestLauncher;
    private readonly object gate = new();
    private readonly Dictionary<string, RuntimeAttempt> attempts = new(StringComparer.Ordinal);
    private readonly Queue<string> completedAttempts = new();
    private bool stopping;
#if NATIVE_CONTAINMENT_TESTS
    internal Action? BeforeCollisionRecovery { get; set; }
    internal Action<string, uint>? LifecycleForTest { get; set; }
    internal Func<ContainedProcess, int, bool>? RootWaitForTest { get; set; }
    internal Func<ContainedProcess, uint>? JobActiveProcessesForTest { get; set; }
#endif

    internal WindowsServiceProcessRuntime(ServiceAttemptLedger ledger, bool useCurrentUserTestLauncher = false)
    {
        this.ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        this.useCurrentUserTestLauncher = useCurrentUserTestLauncher;
        if (ledger.OutputStoreDirectory is { } directory)
        {
            try { outputStore = new ServiceOutputStore(directory); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { }
        }
    }

    internal ServiceAttemptObservation Run(
        ServiceAttemptIdentity identity,
        string callerSid,
        string operationDigest,
        ServiceProcessOperation operation,
        nint primaryToken)
    {
        var current = ledger.Inspect(identity, callerSid);
        if (current.Phase != ServiceAttemptPhase.Prepared)
            return current;

        var stdoutPipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.None);
        AnonymousPipeServerStream stderrPipe;
        try { stderrPipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.None); }
        catch { stdoutPipe.Dispose(); throw; }

        var attempt = new RuntimeAttempt(identity, callerSid, operation, stdoutPipe, stderrPipe, outputStore);
        var registered = false;
        try
        {
            lock (gate)
            {
                if (stopping)
                {
                    throw new IOException("SERVICE_RUNTIME_STOPPING");
                }
                if (attempts.TryGetValue(identity.AttemptId, out _))
                {
                    attempt.DisposePipes();
                    return ledger.Inspect(identity, callerSid);
                }
                if (attempts.Values.Count(value => !value.IsTerminal || !value.MonitorTask.IsCompletedSuccessfully) >= MaximumConcurrentProcesses)
                {
                    throw new IOException("SERVICE_CAPACITY_REACHED");
                }
                if (!ledger.TryCommitDispatch(identity, callerSid, operationDigest))
                {
                    attempt.DisposePipes();
                    return ledger.Inspect(identity, callerSid);
                }
                attempts.Add(identity.AttemptId, attempt);
                registered = true;
            }
        }
        catch (Exception admissionFailure) when (!registered)
        {
            try { attempt.DisposePipes(); }
            catch (Exception cleanupFailure)
            {
                throw new IOException("SERVICE_ADMISSION_CLEANUP_FAILED", new AggregateException(admissionFailure, cleanupFailure));
            }
            throw;
        }

        var launchReturned = false;
        var monitorOwnsAttempt = false;
        ContainedProcess? process = null;
        try
        {
            attempt.PersistOutput();
            var jobName = ContainedProcess.GetJobName(identity.AttemptId);
#if NATIVE_CONTAINMENT_TESTS
            if (useCurrentUserTestLauncher)
            {
                process = ContainedProcess.Start(
                    operation.Executable!,
                    operation.Args!,
                    operation.Cwd!,
                    operation.WindowsVerbatimArguments,
                    operation.Environment!,
                    stdoutPipe.ClientSafePipeHandle.DangerousGetHandle(),
                    stderrPipe.ClientSafePipeHandle.DangerousGetHandle(),
                    () => attempt.CancelRequested,
                    pid => _ = ledger.MarkRunning(identity, callerSid, checked((int)pid)),
                    jobName, identity);
            }
            else
#endif
            {
                process = ContainedProcess.StartAsUser(
                    primaryToken,
                    operation.Executable!,
                    operation.Args!,
                    operation.Cwd!,
                    operation.WindowsVerbatimArguments,
                    operation.Environment!,
                    stdoutPipe.ClientSafePipeHandle.DangerousGetHandle(),
                    stderrPipe.ClientSafePipeHandle.DangerousGetHandle(),
                    () => attempt.CancelRequested,
                    pid => _ = ledger.MarkRunning(identity, callerSid, checked((int)pid)),
                    jobName, identity);
            }

            launchReturned = true;
#if NATIVE_CONTAINMENT_TESTS
            LifecycleForTest?.Invoke("after_launch_before_attach", process.ProcessId);
#endif
            attempt.Attach(process);
            attempt.DisposeLocalClientHandles();
            attempt.StartOutputReaders();
#if NATIVE_CONTAINMENT_TESTS
            LifecycleForTest?.Invoke("before_monitor_assignment", process.ProcessId);
#endif
            _ = Task.Run(() => OwnMonitorAsync(attempt));
            monitorOwnsAttempt = true;
            return ledger.Inspect(identity, callerSid);
        }
        catch (ContainedProcess.JobNameInUseException proof) when (!launchReturned)
        {
            try
            {
#if NATIVE_CONTAINMENT_TESTS
                BeforeCollisionRecovery?.Invoke();
#endif
                attempt.DisposeLocalClientHandles();
                attempt.DisposePipes();
                var result = ledger.MarkJobCollisionBeforeLaunch(identity, callerSid, proof);
                lock (gate)
                {
                    attempt.MarkTerminal();
                    attempts.Remove(identity.AttemptId);
                    attempt.Complete();
                }
                return result;
            }
            catch (Exception exception)
            {
                _ = FailAttemptAsync(attempt, exception, "SERVICE_LAUNCH_OUTCOME_UNKNOWN");
                return ledger.Inspect(identity, callerSid);
            }
        }
        catch (Exception exception)
        {
            if (monitorOwnsAttempt) throw new IOException("SERVICE_LAUNCH_RESPONSE_UNAVAILABLE", exception);
            // Retain ownership even if startup was interrupted before Attach or
            // between Attach and monitor scheduling. Only this owner may dispose.
            if (process is not null) attempt.Attach(process);
            _ = FailAttemptAsync(attempt, exception, "SERVICE_LAUNCH_OUTCOME_UNKNOWN");
            return ledger.Inspect(identity, callerSid);
        }
    }

    internal ServiceAttemptObservation Inspect(ServiceAttemptIdentity identity, string callerSid)
    {
        var observation = ledger.Inspect(identity, callerSid);
        if (observation.Phase is ServiceAttemptPhase.TerminalVerified or ServiceAttemptPhase.LaunchNotStarted)
        {
            if (!observation.ReservationHeld) return observation;
            _ = ledger.Release(identity, callerSid);
            return ledger.Inspect(identity, callerSid);
        }

        RuntimeAttempt? activeAttempt;
        lock (gate) attempts.TryGetValue(identity.AttemptId, out activeAttempt);

        if (activeAttempt is not null && !activeAttempt.IsTerminal)
            return observation;

        if (observation.Phase == ServiceAttemptPhase.TerminationUnknown)
        {
            var jobName = ContainedProcess.GetJobName(identity.AttemptId);
            var probe = ContainedProcess.QueryJob(jobName);
            if (probe.Status is ContainedProcess.JobProbeStatus.NotFound or ContainedProcess.JobProbeStatus.Empty)
            {
                // The PID is recorded only after verified Job membership. A committed
                // dispatch without that marker could have failed before containment;
                // missing Job state alone does not prove no target survived.
                if (observation.TargetPid is null)
                    return observation with { Reason = "SERVICE_RESTART_LAUNCH_UNVERIFIED" };
                // Kill-on-close and zero-active Job evidence prove termination, not
                // the process exit status. Never fabricate successful exit code 0.
                _ = ledger.RecordTerminal(identity, callerSid, ServiceProcessOutcome.Interrupted, 125, 0);
                _ = ledger.Release(identity, callerSid);
                return ledger.Inspect(identity, callerSid);
            }
            if (probe.Status == ContainedProcess.JobProbeStatus.Active)
            {
                return observation with { ActiveProcesses = checked((int)probe.ActiveProcesses), Reason = "ACTIVE_PROCESSES_REMAIN" };
            }
        }

        return observation;
    }

    internal ServiceAttemptObservation Cancel(ServiceAttemptIdentity identity, string callerSid)
    {
        var observation = ledger.RequestCancellation(identity, callerSid);
        if (observation.Phase is not (ServiceAttemptPhase.DispatchCommitted or ServiceAttemptPhase.Running or ServiceAttemptPhase.TerminationUnknown))
            return observation;

        RuntimeAttempt? attempt;
        lock (gate) attempts.TryGetValue(identity.AttemptId, out attempt);
        if (attempt is not null)
        {
            attempt.RequestCancellation();
            attempt.CancelProcess();
            return ledger.Inspect(identity, callerSid);
        }

        return observation with { Reason = "SERVICE_CANCELLATION_HANDLE_UNAVAILABLE" };
    }

    internal ServiceOutputObservation ReadOutput(ServiceAttemptIdentity identity, string callerSid, ServiceOutputCursor? cursor = null)
    {
        _ = ledger.Inspect(identity, callerSid);
        RuntimeAttempt? attempt;
        lock (gate) attempts.TryGetValue(identity.AttemptId, out attempt);
        var persisted = attempt?.OutputPersisted ?? outputStore is not null;
        var snapshot = persisted
            ? outputStore!.Load(identity, callerSid)
            : attempt?.SnapshotOutput() ?? throw new IOException("SERVICE_OUTPUT_UNAVAILABLE");
        cursor ??= new ServiceOutputCursor(0, 0);
        if (cursor.StdoutOffset < 0 || cursor.StderrOffset < 0
            || cursor.StdoutOffset > snapshot.Stdout.Length || cursor.StderrOffset > snapshot.Stderr.Length)
            throw new IOException("SERVICE_OUTPUT_CURSOR_INVALID");
        var next = new ServiceOutputCursor(snapshot.Stdout.Length, snapshot.Stderr.Length);
        var complete = snapshot.Complete && persisted;
        return new ServiceOutputObservation(
            Convert.ToBase64String(snapshot.Stdout.AsSpan((int)cursor.StdoutOffset)),
            Convert.ToBase64String(snapshot.Stderr.AsSpan((int)cursor.StderrOffset)),
            snapshot.StdoutTruncated,
            snapshot.StderrTruncated,
            complete,
            next,
            complete ? next : null,
            persisted,
            persisted ? "persisted" : "unavailable",
            persisted ? snapshot.IncompleteReason : "SERVICE_OUTPUT_PERSISTENCE_FAILED",
            identity);
    }

    internal async Task StopAsync()
    {
        var shutdown = Stopwatch.StartNew();
        RuntimeAttempt[] retained;
        lock (gate)
        {
            stopping = true;
            retained = attempts.Values.ToArray();
        }

        var failures = new List<Exception>();
        foreach (var attempt in retained.Where(value => !value.IsTerminal && !value.MonitorTask.IsCompleted))
        {
            attempt.RequestCancellation();
            try { _ = ledger.RequestCancellation(attempt.Identity, attempt.CallerSid); }
            catch (Exception exception) { failures.Add(exception); }
            try { attempt.CancelProcess(); }
            catch (Exception exception) { failures.Add(exception); }
        }

        try
        {
            // This task exists before dispatch. A terminal flag or an unassigned
            // background monitor cannot make startup/disposal disappear here.
            await Task.WhenAll(retained.Select(value => value.MonitorTask))
                .WaitAsync(TimeSpan.FromMilliseconds(Math.Max(0, TerminationWaitMilliseconds - shutdown.ElapsedMilliseconds))).ConfigureAwait(false);
        }
        catch (Exception exception) { failures.Add(exception); }
        if (failures.Count != 0)
            throw new IOException("SERVICE_STOP_INCOMPLETE", new AggregateException(failures));
    }

#if NATIVE_CONTAINMENT_TESTS
    internal static bool FailOutputReadsForTest { get; set; }
#endif

    private uint ActiveProcesses(ContainedProcess process)
    {
#if NATIVE_CONTAINMENT_TESTS
        if (JobActiveProcessesForTest is { } query) return query(process);
#endif
        return process.ActiveProcesses;
    }

    private bool WaitForRootExit(ContainedProcess process, int remainingMilliseconds)
    {
#if NATIVE_CONTAINMENT_TESTS
        if (RootWaitForTest is { } wait) return wait(process, remainingMilliseconds);
#endif
        return process.WaitForRootExit(remainingMilliseconds);
    }

    private async Task OwnMonitorAsync(RuntimeAttempt attempt)
    {
        try
        {
            await MonitorAsync(attempt).ConfigureAwait(false);
            lock (gate)
            {
                RetainCompletedOutput(attempt);
                attempt.Complete();
            }
        }
        catch (Exception exception)
        {
            await FailAttemptAsync(attempt, exception, "SERVICE_TERMINAL_OUTCOME_UNRESOLVED").ConfigureAwait(false);
        }
    }

    private async Task FailAttemptAsync(RuntimeAttempt attempt, Exception failure, string reason)
    {
        var failures = new List<Exception> { failure };
        // MarkUnknown preserves an already durable terminal proof. A failure
        // before publication remains held; a later cleanup failure is still an
        // error, without rewriting genuine terminal/release history.
        try { _ = ledger.MarkUnknown(attempt.Identity, attempt.CallerSid, reason); }
        catch (Exception exception) { failures.Add(exception); }
        try
        {
            attempt.DisposeLocalClientHandles();
            if (attempt.Process is { } process)
            {
                attempt.RequestCancellation();
                try { _ = ledger.RequestCancellation(attempt.Identity, attempt.CallerSid); }
                catch (Exception exception) { failures.Add(exception); }
                attempt.CancelProcess();
                // Physical cleanup uses the actual retained handles, never an
                // injected observation or PID lookup, and never publishes proof.
                if (!process.WaitForRootExit(attempt.RemainingTerminationWait()))
                    throw new IOException("SERVICE_CLEANUP_ROOT_EXIT_UNVERIFIED");
                while (process.ActiveProcesses != 0)
                {
                    if (attempt.RemainingTerminationWait() == 0)
                        throw new IOException("SERVICE_CLEANUP_JOB_EXIT_UNVERIFIED");
                    await Task.Delay(20).ConfigureAwait(false);
                }
            }
            attempt.DisposePipes();
            await attempt.JoinReadersAsync().ConfigureAwait(false);
#if NATIVE_CONTAINMENT_TESTS
            var pid = attempt.Process?.ProcessId ?? 0;
#endif
            attempt.DisposeProcessAndPipes();
#if NATIVE_CONTAINMENT_TESTS
            LifecycleForTest?.Invoke("after_dispose", pid);
#endif
        }
        catch (Exception exception)
        {
            // Unverified resources stay owned/quarantined. Stop must not race
            // this owner by closing a handle beneath a native wait.
            failures.Add(exception);
        }
        lock (gate) attempt.Complete(new IOException(reason, new AggregateException(failures)));
    }

    private async Task MonitorAsync(RuntimeAttempt attempt)
    {
        var stopwatch = Stopwatch.StartNew();
        var terminationStartedAt = -1L;
        var process = attempt.Process ?? throw new IOException("SERVICE_PROCESS_HANDLE_UNAVAILABLE");
        while (true)
        {
            var active = ActiveProcesses(process);
            if (active == 0) break;

            if (attempt.CancelRequested || stopwatch.ElapsedMilliseconds >= attempt.Operation.TimeoutMs)
            {
                if (!attempt.CancelRequested) attempt.MarkTimedOut();
                if (terminationStartedAt < 0)
                {
                    _ = ledger.RequestCancellation(attempt.Identity, attempt.CallerSid);
                    terminationStartedAt = stopwatch.ElapsedMilliseconds;
                    _ = attempt.RemainingTerminationWait();
                    try { attempt.CancelProcess(); }
                    catch
                    {
                        if (ActiveProcesses(process) != 0)
                        {
                            throw new IOException("SERVICE_TERMINATION_REQUEST_UNRESOLVED");
                        }
                    }
                }
                else if (attempt.RemainingTerminationWait() == 0)
                {
                    throw new IOException("SERVICE_TERMINATION_UNVERIFIED");
                }
            }

            await Task.Delay(20).ConfigureAwait(false);
        }

        if (ActiveProcesses(process) != 0)
            throw new IOException("ACTIVE_PROCESSES_REMAIN");
#if NATIVE_CONTAINMENT_TESTS
        LifecycleForTest?.Invoke("before_root_wait", process.ProcessId);
#endif
        if (!WaitForRootExit(process, attempt.RemainingTerminationWait()))
            throw new IOException("SERVICE_ROOT_EXIT_UNVERIFIED");
        if (ActiveProcesses(process) != 0)
            throw new IOException("ACTIVE_PROCESSES_REMAIN");

        var outcome = attempt.TimedOut
            ? ServiceProcessOutcome.TimedOut
            : attempt.CancelRequested
                ? ServiceProcessOutcome.Cancelled
                : ServiceProcessOutcome.Completed;
        _ = ledger.RecordTerminal(attempt.Identity, attempt.CallerSid, outcome, process.ExitCode, 0);
        var release = ledger.Release(attempt.Identity, attempt.CallerSid);
        if (release is not (ReservationRelease.Released or ReservationRelease.AlreadyReleased or ReservationRelease.Retained))
            throw new IOException("SERVICE_RESERVATION_RELEASE_UNRESOLVED");

        // Native terminal proof is independent of output completeness. A later
        // reader/disposal failure faults shutdown without rewriting that proof.
        await attempt.JoinReadersAsync().ConfigureAwait(false);
        attempt.MarkTerminal();
#if NATIVE_CONTAINMENT_TESTS
        LifecycleForTest?.Invoke("after_terminal_before_dispose", process.ProcessId);
#endif
        attempt.DisposeProcessAndPipes();
#if NATIVE_CONTAINMENT_TESTS
        LifecycleForTest?.Invoke("after_dispose", process.ProcessId);
#endif
    }

    private void RetainCompletedOutput(RuntimeAttempt attempt)
    {
        lock (gate)
        {
            completedAttempts.Enqueue(attempt.Identity.AttemptId);
            while (completedAttempts.Count > MaximumRetainedOutputs)
            {
                var expiredId = completedAttempts.Dequeue();
                if (attempts.TryGetValue(expiredId, out var expired) && expired.IsTerminal && expired.MonitorTask.IsCompletedSuccessfully)
                    attempts.Remove(expiredId);
            }
        }
    }

    private sealed class RuntimeAttempt(
        ServiceAttemptIdentity identity,
        string callerSid,
        ServiceProcessOperation operation,
        AnonymousPipeServerStream stdoutPipe,
        AnonymousPipeServerStream stderrPipe,
        ServiceOutputStore? outputStore)
    {
        private int cancelRequested;
        private int timedOut;
        private int terminal;
        private int localClientHandlesDisposed;
        private readonly object outputGate = new();
        private bool stdoutComplete;
        private bool stderrComplete;
        private bool outputFailed;
        private bool persistenceFailed;
        private bool outputPersisted;
        private readonly object nativeGate = new();
        private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private long terminationWaitStarted;
        private long readerWaitStarted;

        internal ServiceAttemptIdentity Identity { get; } = identity;
        internal string CallerSid { get; } = callerSid;
        internal ServiceProcessOperation Operation { get; } = operation;
        internal BoundedOutput Stdout { get; } = new(operation.MaximumOutputBytes);
        internal BoundedOutput Stderr { get; } = new(operation.MaximumOutputBytes);
        internal ContainedProcess? Process { get; private set; }
        internal Task? StdoutReader { get; private set; }
        internal Task? StderrReader { get; private set; }
        // Published with the attempt, before launch or any background scheduling.
        internal Task MonitorTask => completion.Task;
        internal bool CancelRequested => Volatile.Read(ref cancelRequested) != 0;
        internal bool TimedOut => Volatile.Read(ref timedOut) != 0;
        internal bool IsTerminal => Volatile.Read(ref terminal) != 0;
        internal bool OutputPersisted { get { lock (outputGate) return outputPersisted; } }

        internal ServiceOutputSnapshot SnapshotOutput()
        {
            lock (outputGate)
            {
                var complete = stdoutComplete && stderrComplete && !outputFailed;
                return new ServiceOutputSnapshot(1, Identity, CallerSid, Stdout.Snapshot(), Stderr.Snapshot(),
                    Stdout.Truncated, Stderr.Truncated, complete,
                    complete ? null : outputFailed ? "SERVICE_OUTPUT_READ_FAILED" : "SERVICE_OUTPUT_READERS_INCOMPLETE");
            }
        }

        internal void PersistOutput()
        {
            lock (outputGate)
            {
                if (persistenceFailed || outputStore is null) return;
                try
                {
                    outputStore.Save(SnapshotOutput());
                    outputPersisted = true;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    persistenceFailed = true;
                    outputPersisted = false;
                }
            }
        }

        internal void FailOutputReaders()
        {
            lock (outputGate)
            {
                outputFailed = true;
                PersistOutput();
            }
        }

        internal void Attach(ContainedProcess process)
        {
            lock (nativeGate)
            {
                if (Process is not null && !ReferenceEquals(Process, process))
                    throw new IOException("SERVICE_PROCESS_OWNERSHIP_CONFLICT");
                Process = process;
            }
        }
        internal void RequestCancellation()
        {
            Interlocked.Exchange(ref cancelRequested, 1);
            _ = RemainingTerminationWait();
        }
        internal void CancelProcess()
        {
            lock (nativeGate)
            {
                if (Process is not { } process) return;
                try { process.Cancel(); }
                catch { if (process.ActiveProcesses != 0) throw; }
            }
        }
        internal void Complete(Exception? failure = null)
        {
            if (failure is null) completion.TrySetResult();
            else completion.TrySetException(failure);
        }
        private static int Remaining(ref long started, int budget)
        {
            var start = Volatile.Read(ref started);
            if (start == 0)
            {
                var now = Stopwatch.GetTimestamp();
                start = Interlocked.CompareExchange(ref started, now, 0);
                if (start == 0) start = now;
            }
            return Math.Max(0, budget - checked((int)Math.Min(int.MaxValue, Stopwatch.GetElapsedTime(start).TotalMilliseconds)));
        }
        internal int RemainingTerminationWait() => Remaining(ref terminationWaitStarted, TerminationWaitMilliseconds);
        internal async Task JoinReadersAsync()
        {
            var readers = Task.WhenAll(StdoutReader ?? Task.CompletedTask, StderrReader ?? Task.CompletedTask);
            try
            {
                await readers.WaitAsync(TimeSpan.FromMilliseconds(Remaining(ref readerWaitStarted, ReaderWaitMilliseconds))).ConfigureAwait(false);
            }
            catch
            {
                FailOutputReaders();
                DisposePipes();
                // Closing the pipe unblocks failed/stalled I/O. Completion is
                // still required, within the SAME reader budget, before cleanup.
                await readers.WaitAsync(TimeSpan.FromMilliseconds(Remaining(ref readerWaitStarted, ReaderWaitMilliseconds))).ConfigureAwait(false);
            }
        }
        internal void MarkTimedOut() => Interlocked.Exchange(ref timedOut, 1);
        internal void MarkTerminal() => Interlocked.Exchange(ref terminal, 1);

        internal void DisposeLocalClientHandles()
        {
            if (Interlocked.Exchange(ref localClientHandlesDisposed, 1) != 0) return;
            var failures = new List<Exception>();
            try { stdoutPipe.DisposeLocalCopyOfClientHandle(); }
            catch (Exception exception) { failures.Add(exception); }
            try { stderrPipe.DisposeLocalCopyOfClientHandle(); }
            catch (Exception exception) { failures.Add(exception); }
            if (failures.Count != 0)
                throw new IOException("SERVICE_PIPE_CLIENT_DISPOSE_FAILED", new AggregateException(failures));
        }

        internal void StartOutputReaders()
        {
            StdoutReader = Task.Run(() => DrainAsync(stdoutPipe, Stdout, true));
            StderrReader = Task.Run(() => DrainAsync(stderrPipe, Stderr, false));
        }

        private async Task DrainAsync(Stream stream, BoundedOutput output, bool stdout)
        {
            var buffer = new byte[8192];
            try
            {
                while (true)
                {
#if NATIVE_CONTAINMENT_TESTS
                    if (FailOutputReadsForTest) throw new IOException("INJECTED_OUTPUT_READ_FAILURE");
#endif
                    var count = await stream.ReadAsync(buffer.AsMemory()).ConfigureAwait(false);
                    lock (outputGate)
                    {
                        if (count == 0)
                        {
                            if (stdout) stdoutComplete = true; else stderrComplete = true;
                            PersistOutput();
                            return;
                        }
                        if (output.Append(buffer.AsSpan(0, count))) PersistOutput();
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or ObjectDisposedException)
            {
                FailOutputReaders();
            }
        }

        internal void DisposePipes()
        {
            var failures = new List<Exception>();
            try { stdoutPipe.Dispose(); }
            catch (Exception exception) { failures.Add(exception); }
            try { stderrPipe.Dispose(); }
            catch (Exception exception) { failures.Add(exception); }
            if (failures.Count != 0)
                throw new IOException("SERVICE_PIPE_DISPOSE_FAILED", new AggregateException(failures));
        }

        internal void DisposeProcessAndPipes()
        {
            lock (nativeGate)
            {
                Process?.Dispose();
                Process = null;
            }
            DisposePipes();
        }
    }

    private sealed class BoundedOutput(int maximumBytes)
    {
        private readonly object gate = new();
        private readonly MemoryStream buffer = new(Math.Clamp(maximumBytes, 0, ServiceOutputStore.MaximumStreamBytes));
        private bool truncated;

        internal bool Truncated { get { lock (gate) return truncated; } }

        internal bool Append(ReadOnlySpan<byte> value)
        {
            lock (gate)
            {
                var wasTruncated = truncated;
                var remaining = Math.Max(0, Math.Min(maximumBytes, ServiceOutputStore.MaximumStreamBytes) - checked((int)buffer.Length));
                var accepted = Math.Min(remaining, value.Length);
                if (accepted > 0) buffer.Write(value[..accepted]);
                if (accepted < value.Length) truncated = true;
                return accepted > 0 || truncated != wasTruncated;
            }
        }

        internal byte[] Snapshot()
        {
            lock (gate) return buffer.ToArray();
        }
    }
}
