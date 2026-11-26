#if NATIVE_CONTAINMENT_TESTS
using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// Experimental cross-process boundary, exclusively for disposable fixtures.
// WindowsStoreIO holds an OS byte-range lock, not a process-local Monitor.
// Every participating writer holds the same lock for its entire operation.
// Deliberately serialized (not shared-reader optimized). This does not fence
// an unmodified legacy runtime or constitute production machine authority.
[SupportedOSPlatform("windows")]
internal sealed class MaintenanceBoundaryFixture : IDisposable
{
    private readonly WindowsStoreIO io;
    private readonly string root;
    private bool disposed;
    private bool admitted;
    private bool inWriter;
    private bool inRecovery;
    private readonly object instanceGate = new();
    private CoordinatedProtectedWitness? legacyPins;
    private MaintenanceRecord? owned;
    internal bool FailAfterRecoveryReadbackForTest { get; set; }
    internal bool FailBeforeRecoveryReceiptForTest { get; set; }
    internal string? FailAfterStageForTest { get; set; }
    private void AfterStageFixture(string name)
    {
        if (FailAfterStageForTest == name) throw new IOException("RECOVERY_FIXTURE_STAGED_" + name);
    }

    private sealed record MaintenanceRecord(string Scope, string Epoch, string State,
        string Authority, ProcessOwner Owner, string? ReceiptDigest = null, string PreviousDigest = "none")
    {
        internal byte[] Encode()
        {
            if (!Guid.TryParseExact(Epoch, "D", out var id) || id == Guid.Empty
                || State is not ("open" or "fenced") || !Wire.Digest(Authority)
                || !Wire.Digest(Scope) || Owner.Pid <= 0
                || (PreviousDigest != "none" && !Wire.Digest(PreviousDigest))
                || (ReceiptDigest is not null && (State != "open" || !Wire.Digest(ReceiptDigest)))
                || !ulong.TryParse(Owner.CreationTime, out _) || !Path.IsPathFullyQualified(Owner.Executable))
                throw new Refusal("MAINTENANCE_FIXTURE_RECORD_INVALID");
            return Wire.Encode(new JsonObject {
                ["schema"] = 1, ["scope"] = Scope, ["epoch"] = Epoch, ["state"] = State,
                ["authority"] = Authority, ["pid"] = Owner.Pid, ["creation"] = Owner.CreationTime,
                ["image"] = Owner.Executable, ["receipt"] = ReceiptDigest, ["previous"] = PreviousDigest,
            });
        }
        internal string Digest => WindowsStoreIO.Hash(Encode());
        internal static MaintenanceRecord Decode(byte[] bytes)
        {
            var obj = Wire.Object(bytes);
            Wire.Fields(obj, "schema", "scope", "epoch", "state", "authority", "pid", "creation", "image", "receipt", "previous");
            if (Wire.Integer(obj, "schema") != 1) throw new Refusal("MAINTENANCE_FIXTURE_RECORD_INVALID");
            var result = new MaintenanceRecord(Wire.Text(obj, "scope"), Wire.Text(obj, "epoch"),
                Wire.Text(obj, "state"), Wire.Text(obj, "authority"),
                new(checked((int)Wire.Integer(obj, "pid")), Wire.Text(obj, "creation"), Wire.Text(obj, "image")),
                obj["receipt"] is null ? null : Wire.Text(obj, "receipt"), Wire.Text(obj, "previous"));
            if (!bytes.AsSpan().SequenceEqual(result.Encode())) throw new Refusal("MAINTENANCE_FIXTURE_RECORD_INVALID");
            return result;
        }
    }

    internal static string ScopeRoot(string path)
    {
        var full = WindowsStoreIO.ValidatePath(path);
        const string prefix = "lnwjud-maintenance-fixture-";
        var name = Path.GetFileName(full);
        var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        static bool NamedFixture(string name, string prefix) => name.StartsWith(prefix, StringComparison.Ordinal)
            && Guid.TryParseExact(name[prefix.Length..], "N", out var id) && id != Guid.Empty;
        var parent = Path.GetDirectoryName(full);
        var standalone = String.Equals(parent, temp, StringComparison.OrdinalIgnoreCase) && NamedFixture(name, prefix);
        var integrated = parent is not null && name == "maintenance"
            && String.Equals(Path.GetDirectoryName(parent), temp, StringComparison.OrdinalIgnoreCase)
            && NamedFixture(Path.GetFileName(parent), "lnwjud-orphan-fixture-");
        if (!standalone && !integrated) throw new Refusal("MAINTENANCE_FIXTURE_SCOPE_INVALID");
        return full;
    }

    private MaintenanceBoundaryFixture(string path)
    {
        root = ScopeRoot(path);
        // Missing authority must never silently create an open gate.
        if (!Directory.Exists(root)) throw new Refusal("MAINTENANCE_FIXTURE_ROOT_MISSING");
        if (!File.Exists(Path.Combine(root, "owner.lock"))) throw new Refusal("MAINTENANCE_FIXTURE_LOCK_MISSING");
        io = new WindowsStoreIO(root);
    }

    private string Scope => WindowsStoreIO.Hash(System.Text.Encoding.UTF8.GetBytes(root.ToUpperInvariant()));
    internal static void Initialize(string path)
    {
        var root = ScopeRoot(path);
        // Only a fresh, unique test root may be initialized.
        if (Directory.Exists(root) || File.Exists(root)) throw new Refusal("MAINTENANCE_FIXTURE_ALREADY_EXISTS");
        using (var created = new WindowsStoreIO(root)) { }
        using var gate = new MaintenanceBoundaryFixture(root);
        if (gate.io.Read("journal.json") is not null || gate.io.Read("journal.pending.json") is not null)
            throw new Refusal("MAINTENANCE_FIXTURE_ALREADY_EXISTS");
        // Only these synthetic authority files may be protected by the legacy
        // probe. No real ledger, profile or external path can be selected.
        File.WriteAllText(Path.Combine(root, "legacy-native.json"), "fixture native authority");
        File.WriteAllText(Path.Combine(root, "legacy-profile.json"), "fixture profile authority");
        using var pins = gate.PinLegacy();
        gate.Publish(new(gate.Scope, Guid.NewGuid().ToString("D"), "open", pins.Digest(),
            WindowsStoreIO.CurrentOwner()), null);
    }

    private MaintenanceRecord Read()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (io.Read("journal.pending.json") is not null) throw new Refusal("MAINTENANCE_FIXTURE_PENDING");
        var record = io.Read("journal.json") ?? throw new Refusal("MAINTENANCE_FIXTURE_RECORD_MISSING");
        var result = MaintenanceRecord.Decode(record.Bytes);
        if (result.Scope != Scope) throw new Refusal("MAINTENANCE_FIXTURE_SCOPE_CHANGED");
        return result;
    }

    private void Publish(MaintenanceRecord next, MaintenanceRecord? before)
    {
        if (next.PreviousDigest != (before?.Digest ?? "none"))
            throw new Refusal("RECOVERY_PENDING_PREDECESSOR_CHANGED");
        io.Stage(next.Encode());
        AfterStageFixture("fence");
        io.PublishStage(before?.Digest ?? "none");
        if (Read() != next) throw new Refusal("MAINTENANCE_FIXTURE_READBACK_FAILED");
    }

    private CoordinatedProtectedWitness PinLegacy() =>
        new(root, ["legacy-native.json", "legacy-profile.json"]);

    internal static MaintenanceBoundaryFixture Admit(string path)
    {
        var gate = new MaintenanceBoundaryFixture(path);
        try
        {
            gate.RequireOpenAdmission();
            gate.admitted = true;
            return gate;
        }
        catch { gate.Dispose(); throw; }
    }

    private void RequireOpenAdmission()
    {
        var current = Read();
        if (current.State != "open") throw new Refusal("MAINTENANCE_FIXTURE_FENCED");
        if (io.Read("transaction.pending.json") is not null) throw new Refusal("RECOVERY_RECEIPT_PENDING");
        var file = io.Read("transaction.json");
        if (current.ReceiptDigest is null)
        {
            if (file is not null) throw new Refusal("RECOVERY_RECEIPT_OPEN_UNVERIFIED");
            return;
        }
        if (file is null || file.Digest != current.ReceiptDigest)
            throw new Refusal("RECOVERY_RECEIPT_OPEN_UNVERIFIED");
        var receipt = RecoveryReceiptFixture.Decode(file.Bytes);
        if (receipt.Scope != Scope || receipt.FenceEpoch != current.Epoch || receipt.ReleasedWitness is null)
            throw new Refusal("RECOVERY_RECEIPT_OPEN_UNVERIFIED");
    }

    // Both the admission check and the work execute with the OS lock held.
    internal void RunWriter(Action work)
    {
        lock (instanceGate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (inWriter || !admitted || Read().State != "open") throw new Refusal("MAINTENANCE_FIXTURE_NOT_ADMITTED");
            RequireOpenAdmission();
            inWriter = true;
            try { work(); }
            finally { inWriter = false; }
        }
    }

    internal static MaintenanceBoundaryFixture Fence(string path, bool failAfterStage = false)
    {
        var gate = new MaintenanceBoundaryFixture(path);
        try
        {
            var before = gate.Read();
            if (before.State != "open") throw new Refusal("MAINTENANCE_FIXTURE_FENCED");
            // One integrated fixture transaction per root. Preserve its
            // receipt rather than silently repurpose an old authority.
            if (gate.io.Read("transaction.json") is not null || gate.io.Read("transaction.pending.json") is not null)
                throw new Refusal("RECOVERY_RECEIPT_HISTORY_PRESENT");
            gate.legacyPins = gate.PinLegacy(); // refuses an existing uncooperative write handle
            var owner = WindowsStoreIO.CurrentOwner();
            var next = new MaintenanceRecord(gate.Scope, Guid.NewGuid().ToString("D"), "fenced",
                gate.legacyPins.Digest(), owner, PreviousDigest: before.Digest);
            gate.FailAfterStageForTest = failAfterStage ? "fence" : null;
            gate.Publish(next, before);
            gate.owned = next;
            return gate;
        }
        catch { gate.Dispose(); throw; }
    }

    internal string FenceDigest
    {
        get { lock (instanceGate) { RequireOwned(); return owned!.Digest; } }
    }

    private void RequireOwned()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (owned is null || legacyPins is null || Read() != owned
            || legacyPins.Digest() != owned.Authority || owned.Owner != WindowsStoreIO.CurrentOwner())
            throw new Refusal("MAINTENANCE_FIXTURE_OWNER_UNVERIFIED");
    }

    // Reopen only the exact durable fence, with the preceding process proved
    // gone and fresh protected file identity/bytes. No timeout-based takeover.
    internal static MaintenanceBoundaryFixture Resume(string path, string expectedDigest, bool failAfterStage = false)
    {
        var gate = new MaintenanceBoundaryFixture(path);
        try
        {
            var before = gate.Read();
            if (before.State != "fenced" || before.Digest != expectedDigest)
                throw new Refusal("MAINTENANCE_FIXTURE_FENCE_MISMATCH");
            if (WindowsStoreIO.Observe(before.Owner) != "gone")
                throw new Refusal("MAINTENANCE_FIXTURE_PREVIOUS_OWNER_UNVERIFIED");
            gate.legacyPins = gate.PinLegacy();
            if (gate.legacyPins.Digest() != before.Authority)
                throw new Refusal("MAINTENANCE_FIXTURE_LEGACY_CHANGED");
            var next = before with { Owner = WindowsStoreIO.CurrentOwner(), PreviousDigest = before.Digest };
            gate.FailAfterStageForTest = failAfterStage ? "fence" : null;
            gate.Publish(next, before);
            gate.owned = next;
            return gate;
        }
        catch { gate.Dispose(); throw; }
    }

    // An integrated recovery owns the lock from consent through durable
    // readback. The exact fixture root is independently checked by the engine.
    // Neither reentrant disposal nor early completion is allowed.
    internal NativeAtomicFixtureResult RunRecoveryFixture(string digest, ServiceAttemptIdentity expected,
        OrphanImportAction action, NativeMaintenanceAuthority authority,
        ServiceImportTransactionRuntime runtime, Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token)
    {
        lock (instanceGate)
        {
            RequireOwned();
            if (inRecovery || owned!.Digest != digest || Path.GetFileName(root) != "maintenance")
                throw new Refusal("MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
            // Exercise the same OS lifetime primitive as the new service.
            // Fixture marker policy is simulated; no production authority is acquired.
            using var lifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null);
            inRecovery = true;
            try
            {
                var result = authority.ReviewAndApplyFixture(runtime, token, this, digest);
                RequireOwned();
                if (result.Identity != expected || result.Action != action
                    || result.BootWitnessRecorded != (action == OrphanImportAction.RecordBootWitness)
                    || result.NativeHoldReleased == result.BootWitnessRecorded)
                    throw new Refusal("MAINTENANCE_FIXTURE_RECOVERY_RECEIPT_INVALID");
                // A witness alone keeps admissions closed. Only the exact
                // successful abort readback permits opening this fixture.
                if (result.NativeHoldReleased)
                {
                    if (FailBeforeRecoveryReceiptForTest)
                        throw new IOException("INTEGRATED_FIXTURE_AFTER_RELEASE_BEFORE_RECEIPT");
                    FinishReleasedFixture(expected, token, allowInterruptedOpen: true);
                }
                return result;
            }
            finally { inRecovery = false; }
        }
    }

    private RecoveryReceiptFixture? ReadRecoveryReceiptFixture()
    {
        if (io.Read("transaction.pending.json") is not null)
            throw new Refusal("RECOVERY_RECEIPT_PENDING");
        var file = io.Read("transaction.json");
        if (file is null) return null;
        var receipt = RecoveryReceiptFixture.Decode(file.Bytes);
        if (receipt.Scope != Scope || receipt.FenceEpoch != owned!.Epoch)
            throw new Refusal("RECOVERY_RECEIPT_FENCE_MISMATCH");
        return receipt;
    }

    private void SaveRecoveryReceiptFixture(RecoveryReceiptFixture next, RecoveryReceiptFixture? previous)
    {
        io.Stage("transaction.pending.json", next.Encode());
        AfterStageFixture(previous is null ? "intent" : "receipt");
        io.PublishStage("transaction.pending.json", "transaction.json", previous?.Digest ?? "none");
        if (ReadRecoveryReceiptFixture() != next) throw new Refusal("RECOVERY_RECEIPT_READBACK_FAILED");
    }

    internal void PrepareRecoveryIntentFixture(string fixtureRoot, string digest, OrphanImportEvidence approved,
        string expectedPostDigest)
    {
        lock (instanceGate)
        {
            RequireRecoveryFixture(fixtureRoot, digest);
            var existing = ReadRecoveryReceiptFixture();
            if (existing is not null)
            {
                // Fresh exact approval may continue an intent published
                // before any native mutation, or finish an already durable
                // tombstone. Never replace the original intent.
                if (existing.ReleasedWitness is not null || existing.Identity != approved.Identity
                    || existing.OwnerSid != approved.OwnerSid || existing.ExpectedPostDigest != expectedPostDigest
                    || (approved.Action != OrphanImportAction.FinishAbortedHold
                        && (approved.Action != existing.Action || approved.NativeDigest != existing.EvidenceDigest)))
                    throw new Refusal("RECOVERY_RECEIPT_INTENT_CONFLICT");
                return;
            }
            var next = new RecoveryReceiptFixture(Scope, owned!.Epoch, approved.Identity, approved.OwnerSid,
                approved.Action, approved.NativeDigest, expectedPostDigest, null);
            SaveRecoveryReceiptFixture(next, null);
        }
    }

    internal string RecoveryReceiptDigestFixture
    {
        get {
            lock (instanceGate) {
                RequireOwned();
                return (ReadRecoveryReceiptFixture() ?? throw new Refusal("RECOVERY_RECEIPT_MISSING")).Digest;
            }
        }
    }

    private void FinishReleasedFixture(ServiceAttemptIdentity expected,
        Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token, bool allowInterruptedOpen)
    {
        RequireOwned();
        var record = ReadRecoveryReceiptFixture() ?? throw new Refusal("RECOVERY_RECEIPT_MISSING");
        if (record.Identity != expected) throw new Refusal("RECOVERY_RECEIPT_ATTEMPT_MISMATCH");
        var store = Path.Combine(Path.GetDirectoryName(root)!, "native");
        var witness = RecoveryReceiptFixture.ObserveReleased(store, record, token);
        if (record.ReleasedWitness is null)
        {
            var next = record with { ReleasedWitness = witness };
            SaveRecoveryReceiptFixture(next, record);
            record = next;
        }
        if (allowInterruptedOpen && FailAfterRecoveryReadbackForTest)
            throw new IOException("INTEGRATED_FIXTURE_AFTER_RELEASE_BEFORE_OPEN");
        // Re-pin and validate the actual native files through publication of
        // the open journal. No native mutation or abort is called here.
        _ = RecoveryReceiptFixture.ObserveReleased(store, record, token, () =>
        {
            RequireOwned();
            if (ReadRecoveryReceiptFixture() != record) throw new Refusal("RECOVERY_RECEIPT_CHANGED");
            Publish(owned! with { State = "open", ReceiptDigest = record.Digest, PreviousDigest = owned!.Digest }, owned);
            owned = null;
        });
    }

    // Explicit continuation of the exact, previously authorized fixture
    // intent. The OS owner lock and durable fence are still required.
    // There is no automatic open, and no call back into the abort engine.
    internal void ReconcileReleasedFixture(string exactFenceDigest, string exactReceiptDigest,
        ServiceAttemptIdentity expected, Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token)
    {
        lock (instanceGate)
        {
            RequireOwned();
            if (inRecovery || Path.GetFileName(root) != "maintenance" || owned!.Digest != exactFenceDigest)
                throw new Refusal("MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
            var record = ReadRecoveryReceiptFixture() ?? throw new Refusal("RECOVERY_RECEIPT_MISSING");
            if (record.Digest != exactReceiptDigest) throw new Refusal("RECOVERY_RECEIPT_DIGEST_MISMATCH");
            using var lifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null);
            inRecovery = true;
            try { FinishReleasedFixture(expected, token, allowInterruptedOpen: false); }
            finally { inRecovery = false; }
        }
    }

    // Exact explicit reconciliation. Never calls the native mutation engine.
    // Pending initial intent is only published; native hold remains intact.
    internal void ReconcilePendingFixture(string exactFenceDigest, string exactPendingDigest,
        ServiceAttemptIdentity expected, Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token)
    {
        lock (instanceGate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (inRecovery || Path.GetFileName(root) != "maintenance" || owned is null
                || owned.Digest != exactFenceDigest || owned.Owner != WindowsStoreIO.CurrentOwner()
                || legacyPins is null || legacyPins.Digest() != owned.Authority)
                throw new Refusal("MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
            var published = io.Read("journal.json");
            if (published is null || MaintenanceRecord.Decode(published.Bytes) != owned)
                throw new Refusal("RECOVERY_PENDING_PREDECESSOR_CHANGED");
            using var lifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null);
            ReconcilePendingCore(owned, exactPendingDigest, expected, token);
        }
    }

    private void ReconcilePendingCore(MaintenanceRecord before, string exactPendingDigest,
        ServiceAttemptIdentity expected, Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token)
    {
        var txPending = io.Read("transaction.pending.json");
        var fencePending = io.Read("journal.pending.json");
        if ((txPending is null) == (fencePending is null))
            throw new Refusal("RECOVERY_PENDING_AMBIGUOUS");
        var pending = txPending ?? fencePending!;
        if (pending.Digest != exactPendingDigest) throw new Refusal("RECOVERY_PENDING_DIGEST_MISMATCH");
        var store = Path.Combine(Path.GetDirectoryName(root)!, "native");
        var previous = io.Read("transaction.json");
        var record = previous is null ? null : RecoveryReceiptFixture.Decode(previous.Bytes);
        void Exact(RecoveryReceiptFixture receipt)
        {
            if (receipt.Scope != Scope || receipt.FenceEpoch != before.Epoch || receipt.Identity != expected)
                throw new Refusal("RECOVERY_PENDING_SUCCESSOR_INVALID");
        }
        if (record is not null) Exact(record);
        void PublishExact(string pendingName, string targetName, string predecessor)
        {
            if (io.Read(pendingName)?.Digest != exactPendingDigest
                || io.Read("journal.json")?.Digest != before.Digest)
                throw new Refusal("RECOVERY_PENDING_PREDECESSOR_CHANGED");
            io.PublishStage(pendingName, targetName, predecessor);
            if (io.Read(targetName)?.Digest != exactPendingDigest || io.Read(pendingName) is not null)
                throw new Refusal("RECOVERY_PENDING_READBACK_FAILED");
        }
        if (txPending is not null)
        {
            var next = RecoveryReceiptFixture.Decode(txPending.Bytes);
            Exact(next);
            if (record is null)
            {
                RecoveryReceiptFixture.ObservePendingIntent(store, next, token, () =>
                    PublishExact("transaction.pending.json", "transaction.json", "none"));
            }
            else
            {
                if (record.ReleasedWitness is not null || next.ReleasedWitness is null
                    || next != record with { ReleasedWitness = next.ReleasedWitness })
                    throw new Refusal("RECOVERY_PENDING_SUCCESSOR_INVALID");
                _ = RecoveryReceiptFixture.ObserveReleased(store, next, token, () =>
                    PublishExact("transaction.pending.json", "transaction.json", record.Digest));
            }
            return; // Receipt/intent publication never opens admission.
        }
        if (record?.ReleasedWitness is null
            || MaintenanceRecord.Decode(fencePending!.Bytes) != before with { State = "open", ReceiptDigest = record.Digest, PreviousDigest = before.Digest })
            throw new Refusal("RECOVERY_PENDING_SUCCESSOR_INVALID");
        _ = RecoveryReceiptFixture.ObserveReleased(store, record, token, () =>
        {
            if (io.Read("transaction.json")?.Digest != record.Digest)
                throw new Refusal("RECOVERY_PENDING_PREDECESSOR_CHANGED");
            PublishExact("journal.pending.json", "journal.json", before.Digest);
            owned = null;
        });
    }

    // A dead owner cannot leave a staged open journal permanently stranded.
    // Only the exact same fenced predecessor and validated successor may be
    // published. Never transfer ownership or replay native work implicitly.
    internal static void ReconcileExitedOwnerPendingFixture(string path, string exactFenceDigest,
        string exactPendingDigest, ServiceAttemptIdentity expected, Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token)
    {
        using var gate = new MaintenanceBoundaryFixture(path);
        var current = gate.io.Read("journal.json") ?? throw new Refusal("MAINTENANCE_FIXTURE_RECORD_MISSING");
        var before = MaintenanceRecord.Decode(current.Bytes);
        if (Path.GetFileName(gate.root) != "maintenance" || before.Scope != gate.Scope || before.State != "fenced"
            || before.Digest != exactFenceDigest)
            throw new Refusal("MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
        if (WindowsStoreIO.Observe(before.Owner) != "gone")
            throw new Refusal("MAINTENANCE_FIXTURE_PREVIOUS_OWNER_UNVERIFIED");
        gate.legacyPins = gate.PinLegacy();
        if (gate.legacyPins.Digest() != before.Authority)
            throw new Refusal("MAINTENANCE_FIXTURE_LEGACY_CHANGED");
        using var lifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(gate.root, () => null);
        gate.ReconcilePendingCore(before, exactPendingDigest, expected, token);
    }

    // Interrupted creation/owner transfer publishes only a CLOSED fence.
    // The pending owner's identity must be proved gone before publication.
    // A later Resume must independently acquire the new durable fence.
    internal static string ReconcileClosedFenceFixture(string path, string exactPreviousDigest, string exactPendingDigest)
    {
        using var gate = new MaintenanceBoundaryFixture(path);
        var current = gate.io.Read("journal.json") ?? throw new Refusal("MAINTENANCE_FIXTURE_RECORD_MISSING");
        var pending = gate.io.Read("journal.pending.json") ?? throw new Refusal("RECOVERY_PENDING_AMBIGUOUS");
        if (current.Digest != exactPreviousDigest || pending.Digest != exactPendingDigest)
            throw new Refusal("RECOVERY_PENDING_DIGEST_MISMATCH");
        var before = MaintenanceRecord.Decode(current.Bytes);
        var next = MaintenanceRecord.Decode(pending.Bytes);
        if (before.Scope != gate.Scope || next.Scope != gate.Scope || next.State != "fenced"
            || next.PreviousDigest != before.Digest || next.ReceiptDigest is not null
            || gate.io.Read("transaction.pending.json") is not null)
            throw new Refusal("RECOVERY_PENDING_SUCCESSOR_INVALID");
        if (before.State == "open")
        {
            if (before.ReceiptDigest is not null || next.Epoch == before.Epoch
                || gate.io.Read("transaction.json") is not null)
                throw new Refusal("RECOVERY_PENDING_SUCCESSOR_INVALID");
        }
        else
        {
            if (next != before with { Owner = next.Owner, PreviousDigest = before.Digest }
                || WindowsStoreIO.Observe(before.Owner) != "gone")
                throw new Refusal("RECOVERY_PENDING_SUCCESSOR_INVALID");
        }
        if (WindowsStoreIO.Observe(next.Owner) != "gone")
            throw new Refusal("MAINTENANCE_FIXTURE_PREVIOUS_OWNER_UNVERIFIED");
        gate.legacyPins = gate.PinLegacy();
        if (gate.legacyPins.Digest() != next.Authority)
            throw new Refusal("MAINTENANCE_FIXTURE_LEGACY_CHANGED");
        if (gate.io.Read("journal.pending.json")?.Digest != exactPendingDigest)
            throw new Refusal("RECOVERY_PENDING_DIGEST_MISMATCH");
        gate.io.PublishStage(exactPreviousDigest);
        if (gate.Read() != next) throw new Refusal("RECOVERY_PENDING_READBACK_FAILED");
        return next.Digest;
    }

    internal void RequireRecoveryFixture(string fixtureRoot, string digest)
    {
        lock (instanceGate)
        {
            RequireOwned();
            if (!inRecovery || owned!.Digest != digest
                || !String.Equals(root, ScopeRoot(Path.Combine(fixtureRoot, "maintenance")), StringComparison.OrdinalIgnoreCase))
                throw new Refusal("MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
        }
    }

    // Fixture completion only. A real adapter must verify authorized durable
    // recovery and whole-machine isolation before any production reopening.
    internal void CompleteFixture(string exactDigest)
    {
        lock (instanceGate)
        {
            RequireOwned();
            if (inRecovery || Path.GetFileName(root) == "maintenance" || owned!.Digest != exactDigest)
                throw new Refusal("MAINTENANCE_FIXTURE_FENCE_MISMATCH");
            Publish(owned with { State = "open", PreviousDigest = owned.Digest }, owned);
            owned = null;
            // Lock and pins survive until disposal; no check/act window.
        }
    }

    public void Dispose()
    {
        lock (instanceGate)
        {
            if (disposed) return;
            if (inWriter || inRecovery) throw new Refusal("MAINTENANCE_FIXTURE_WRITER_ACTIVE");
            disposed = true;
            legacyPins?.Dispose();
            io.Dispose();
            // Never automatically open a durable fence.
        }
    }
}
#endif
