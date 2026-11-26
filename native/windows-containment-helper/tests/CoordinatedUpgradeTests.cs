using System.Security.Cryptography;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

internal static class CoordinatedUpgradeTests
{
    private static int assertions;
    private static void Check(bool value, string message)
    {
        assertions++;
        if (!value) throw new Exception(message);
    }
    private static void Refused(Action action, string reason)
    {
        try { action(); }
        catch (Refusal error) when (error.Reason == reason) { assertions++; return; }
        throw new Exception("Expected refusal " + reason);
    }
    private static string Hash(string text) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    private static string FileHash(string filename) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(filename))).ToLowerInvariant();

    private static void TestMaintenance(string root)
    {
        var held = false;
        var unreadable = false;
        bool Marker() => unreadable ? throw new UnauthorizedAccessException() : held;
        using var startup = UpdateStartupGate.Isolated(root, root, () => false, Marker);
        startup.RequireMaintenanceOpen();
        Check(startup.InspectMaintenance() is null, "No fixture marker");
        held = true;
        Check(startup.Inspect().Reason == "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE", "Marker precedes ordinary inspection");
        try { startup.RequireMaintenanceOpen(); throw new Exception("Expected maintenance refusal"); }
        catch (IOException error) when (error.Message == "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE") { assertions++; }
        unreadable = true;
        Check(startup.Inspect().Reason == "UPDATE_TRANSACTION_COORDINATED_INSPECTION_UNAVAILABLE", "Unreadable marker holds");
        try { startup.RequireMaintenanceOpen(); throw new Exception("Expected inspection refusal"); }
        catch (IOException error) when (error.Message == "UPDATE_TRANSACTION_COORDINATED_INSPECTION_UNAVAILABLE") { assertions++; }

        var evidence = Path.Combine(root, "protected-witness");
        using (var fixture = new WindowsStoreIO(evidence)) { }
        var ledger = Path.Combine(evidence, "attempts.json");
        var transaction = Path.Combine(evidence, "import.json");
        File.WriteAllText(ledger, "fixture ledger");
        File.WriteAllText(transaction, "fixture import");
        string digest;
        using (var pin = new CoordinatedProtectedWitness(evidence, ["attempts.json", "import.json"]))
        {
            digest = pin.Digest();
            Check(Wire.Digest(digest) && digest == pin.Digest(), "Stable protected file identity and bytes");
            try { File.WriteAllText(ledger, "changed"); throw new Exception("Expected sharing refusal"); }
            catch (IOException) { assertions++; }
            try { File.Move(transaction, transaction + ".moved"); throw new Exception("Expected rename refusal"); }
            catch (IOException) { assertions++; }
            Check(digest == pin.Digest(), "Pin preserves bytes across rejected writes");
        }
        using (var pin = new CoordinatedProtectedWitness(evidence, ["import.json", "attempts.json"]))
            Check(pin.Digest() == digest, "Canonical witness order");
        Refused(() => { using var pin = new CoordinatedProtectedWitness(evidence, ["../attempts.json"]); }, "COORDINATED_WITNESS_INVALID");
        Refused(() => { using var pin = new CoordinatedProtectedWitness(evidence, ["attempts.json", "ATTEMPTS.JSON"]); }, "COORDINATED_WITNESS_INVALID");
        File.WriteAllText(ledger, "different ledger");
        using (var pin = new CoordinatedProtectedWitness(evidence, ["attempts.json", "import.json"]))
            Check(pin.Digest() != digest, "Changed evidence digest");
        File.WriteAllText(ledger, "fixture ledger");
        File.Move(transaction, transaction + ".original");
        File.WriteAllText(transaction, "fixture import");
        using (var pin = new CoordinatedProtectedWitness(evidence, ["attempts.json", "import.json"]))
            Check(pin.Digest() != digest, "Byte-identical replacement is a different file identity");
    }

    private static async Task TestMaintenanceRpc(string root)
    {
        var pipeName = "lnwjud-coordinated-fixture-" + Guid.NewGuid().ToString("N");
        var marker = 1;
        var protectedRoot = Path.Combine(root, "startup-rpc");
        using (var fixture = new WindowsStoreIO(protectedRoot)) { }
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ledger = new ServiceAttemptLedger();
        var server = WindowsContainmentService.RunPipeServerAsync(pipeName, ledger, stopping.Token,
            useCurrentUserTestLauncher: true,
            startup: UpdateStartupGate.Isolated(protectedRoot, protectedRoot, () => false, () =>
                Volatile.Read(ref marker) == 2 ? throw new IOException("fixture unavailable") : Volatile.Read(ref marker) == 1));
        try
        {
            async Task<System.Text.Json.JsonDocument> Rpc(string command)
            {
                using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", pipeName, System.IO.Pipes.PipeDirection.InOut,
                    System.IO.Pipes.PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Impersonation);
                await pipe.ConnectAsync(5000, stopping.Token);
                var bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { protocol = 3, command });
                await pipe.WriteAsync(BitConverter.GetBytes(bytes.Length), stopping.Token);
                await pipe.WriteAsync(bytes, stopping.Token);
                var size = new byte[4];
                await pipe.ReadExactlyAsync(size, stopping.Token);
                var length = BitConverter.ToInt32(size);
                if (length is < 2 or > 65536) throw new Exception("Invalid fixture RPC frame");
                var reply = new byte[length];
                await pipe.ReadExactlyAsync(reply, stopping.Token);
                return System.Text.Json.JsonDocument.Parse(reply);
            }
            using (var response = await Rpc("update_startup"))
            {
                Check(response.RootElement.GetProperty("ok").GetBoolean() &&
                    response.RootElement.GetProperty("result").GetProperty("reason").GetString() == "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE",
                    "RPC startup reports hold");
                try
                {
                    WindowsContainmentServiceInstaller.RequireReplacementStartupReceipt(response.RootElement);
                    throw new Exception("Held startup accepted as replacement success");
                }
                catch (IOException error) when (error.Message == "SERVICE_INSTALL_REPLACEMENT_READINESS_UNVERIFIED") { assertions++; }
            }
            Volatile.Write(ref marker, 0);
            using (var response = await Rpc("update_startup"))
            {
                Check(response.RootElement.GetProperty("error").ValueKind == System.Text.Json.JsonValueKind.Null,
                    "Actual wire response includes explicit null error");
                WindowsContainmentServiceInstaller.RequireReplacementStartupReceipt(response.RootElement);
                Check(true, "Installer accepts actual authenticated fixture wire startup receipt");
            }
            Volatile.Write(ref marker, 1);
            foreach (var command in new[] { "prepare", "run", "control", "update_opaque", "update_launch", "maintenance_remove" })
            {
                using var response = await Rpc(command);
                Check(!response.RootElement.GetProperty("ok").GetBoolean() &&
                    response.RootElement.GetProperty("error").GetString() == "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE",
                    "RPC denied before dispatch: " + command);
            }
            Volatile.Write(ref marker, 2);
            using (var response = await Rpc("prepare"))
                Check(!response.RootElement.GetProperty("ok").GetBoolean() &&
                    response.RootElement.GetProperty("error").GetString() == "UPDATE_TRANSACTION_COORDINATED_INSPECTION_UNAVAILABLE",
                    "RPC unreadable marker fails closed");
        }
        finally
        {
            stopping.Cancel();
            try { await server.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
        }
    }

    private static void TestPackageWitnessSize(string root)
    {
        var package = Path.Combine(root, "package-size");
        using (var fixture = new WindowsStoreIO(package)) { }
        var helper = Path.Combine(package, "lnwjud-containment.exe");
        var manifest = Path.Combine(package, "manifest.json");
        var pin = Path.Combine(package, "lnwjud-containment-pin.node");
        void Size(string path, long length)
        {
            using var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
            file.SetLength(length);
        }
        const long mib = 1024L * 1024;
        Size(helper, 35318578); // observed historical candidate helper size
        File.WriteAllText(manifest, "{}");
        File.WriteAllText(pin, "fixture pin");
        string digest;
        using (var witness = CoordinatedProtectedWitness.ForNativePackage(package))
        {
            digest = witness.Digest();
            Check(Wire.Digest(digest) && witness.Digest() == digest, "Actual-sized package witness stable");
        }
        Refused(() => { using var witness = new CoordinatedProtectedWitness(package, ["lnwjud-containment.exe"]); _ = witness.Digest(); },
            "COORDINATED_WITNESS_SIZE");
        using (var file = new FileStream(helper, FileMode.Open, FileAccess.Write, FileShare.None)) file.WriteByte(1);
        using (var witness = CoordinatedProtectedWitness.ForNativePackage(package))
            Check(witness.Digest() != digest, "Package content change still detected");
        Size(helper, 128 * mib);
        using (var witness = CoordinatedProtectedWitness.ForNativePackage(package))
            Check(Wire.Digest(witness.Digest()), "Exact helper limit accepted");
        Size(helper, 128 * mib + 1);
        Refused(() => { using var witness = CoordinatedProtectedWitness.ForNativePackage(package); _ = witness.Digest(); },
            "COORDINATED_WITNESS_SIZE");
        Size(helper, 0);
        Refused(() => { using var witness = CoordinatedProtectedWitness.ForNativePackage(package); _ = witness.Digest(); },
            "COORDINATED_WITNESS_SIZE");
        Size(helper, 1);
        Size(manifest, 64 * 1024 + 1);
        Refused(() => { using var witness = CoordinatedProtectedWitness.ForNativePackage(package); _ = witness.Digest(); },
            "COORDINATED_WITNESS_SIZE");
        Size(manifest, 64 * 1024);
        Size(pin, 32 * mib + 1);
        Refused(() => { using var witness = CoordinatedProtectedWitness.ForNativePackage(package); _ = witness.Digest(); },
            "COORDINATED_WITNESS_SIZE");
        Size(pin, 32 * mib);
        using (var witness = CoordinatedProtectedWitness.ForNativePackage(package))
            Check(Wire.Digest(witness.Digest()), "Exact manifest and pin bounds accepted");
    }

    private static void TestLegacyWitness(string root)
    {
        var store = Path.Combine(root, "native-authority");
        using (var fixture = new WindowsStoreIO(store)) { }
        var imports = Directory.CreateDirectory(Path.Combine(store, "imports")).FullName;
        var workspace = Directory.CreateDirectory(Path.Combine(root, "legacy-workspace")).FullName;
        var home = Directory.CreateDirectory(Path.Combine(root, "legacy-home")).FullName;
        var stage = Path.Combine(root, ".lnwjud-import-stage-" + Guid.NewGuid().ToString("D"));
        Directory.CreateDirectory(Path.Combine(workspace, "repo"));
        File.WriteAllText(Path.Combine(workspace, "repo", "existing.txt"), "preserve destination");
        using var caller = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sid = caller.User!.Value;
        var identity = new ServiceAttemptIdentity(Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), Guid.NewGuid().ToString(),
            1, Hash("request"), "fixture-client", "fixture-session", "fixture-workspace");
        var request = new ServiceAttemptRequest(identity, sid, ServiceAttemptLedger.GlobalReservationKey, Hash("operation"), Shared: true);
        var ledgerFile = Path.Combine(store, "attempts.json");
        var ledger = new ServiceAttemptLedger(new ServiceAttemptLedgerPersistence(ledgerFile), imports);
        ledger.Prepare(request);
        ledger.TryCommitDispatch(identity, sid, request.OperationDigest);
        ledger.MarkRunning(identity, sid, Environment.ProcessId);
        var args = new ServiceImportArguments(workspace, "repo", stage, new string('a', 40), home);
        var runtime = new ServiceImportTransactionRuntime(ledger, imports);
        var json = System.Text.Json.JsonSerializer.SerializeToElement(args, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
        });
        runtime.Control("prepare_import", identity, sid, json, caller.AccessToken);
        File.WriteAllText(Path.Combine(stage, "stage.txt"), "preserve stage");
        ledger.RecordTerminal(identity, sid, ServiceProcessOutcome.Completed, 1, 0);
        // Reproduce historical V2 lack of validation evidence without
        // weakening the production parser or the boot proof requirement.
        var historical = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(ledgerFile))!.AsObject();
        historical["schemaVersion"] = 2;
        historical["attempts"]!.AsArray()[0]!["request"]!.AsObject().Remove("importValidationPending");
        File.WriteAllText(ledgerFile, historical.ToJsonString());
        var transaction = ServiceImportTransactionRuntime.RecordFilename(imports, identity);
        var beforeLedger = FileHash(ledgerFile);
        var beforeImport = FileHash(transaction);
        var profile = Path.Combine(root, "legacy-profile");
        using (var fixture = new WindowsStoreIO(profile)) { }
        File.WriteAllText(Path.Combine(profile, "owner.json"), "fixture owner evidence");
        string authority;
        using (var witness = new CoordinatedLegacyImportWitness(store, identity, args, caller.AccessToken))
        using (var owner = new CoordinatedProtectedWitness(profile, ["owner.json"]))
        using (var journal = new CoordinatedUpgradeStore(Path.Combine(root, "legacy-journal")))
        {
            Check(witness.SchemaVersion == 2 && witness.Identity == identity, "Exact legacy owner and V2 binding");
            authority = CoordinatedUpgradeStore.PreservedAuthority(witness, owner);
            var plan = new CoordinatedPlan(Guid.NewGuid().ToString(), Hash("old helper"), Hash("new helper"), Hash("old desktop"), Hash("new desktop"), authority);
            var host = new CoordinatedObservation(plan.OldHelper, plan.OldDesktop, authority, true, false, false, false, false);
            var initial = journal.Begin(plan, host);
            var intent = journal.AdvanceWithWitness(initial.Digest, host with { AuthorityDigest = Hash("untrusted caller digest") }, witness, owner);
            Check(intent.Phase == CoordinatedPhase.FenceIntent, "Journal derives evidence from pinned files");
            Refused(() => journal.AdvanceWithWitness(intent.Digest, host with { Fenced = true, Quiesced = false }, witness, owner),
                "COORDINATED_OBSERVATION_UNVERIFIED");
        }
        Refused(() => { using var witness = new CoordinatedLegacyImportWitness(store, identity with { OwnerClientId = "foreign-client" }, args, caller.AccessToken); },
            "COORDINATED_OWNER_UNVERIFIED");
        Refused(() => { using var witness = new CoordinatedLegacyImportWitness(store, identity, args with { Commit = new string('b', 40) }, caller.AccessToken); },
            "COORDINATED_NATIVE_IMPORT_UNVERIFIED");
        using (var witness = new CoordinatedLegacyImportWitness(store, identity, args, caller.AccessToken))
        using (var owner = new CoordinatedProtectedWitness(profile, ["owner.json"]))
            Check(CoordinatedUpgradeStore.PreservedAuthority(witness, owner) == authority, "Fresh witness matches");
        File.WriteAllText(Path.Combine(profile, "owner.json"), "changed profile");
        using (var witness = new CoordinatedLegacyImportWitness(store, identity, args, caller.AccessToken))
        using (var owner = new CoordinatedProtectedWitness(profile, ["owner.json"]))
        using (var journal = new CoordinatedUpgradeStore(Path.Combine(root, "legacy-journal")))
        {
            var intent = journal.Read()!;
            var host = new CoordinatedObservation(intent.Plan.OldHelper, intent.Plan.OldDesktop, authority, true, true, true, false, false);
            Refused(() => journal.AdvanceWithWitness(intent.Digest, host, witness, owner), "COORDINATED_OBSERVATION_UNVERIFIED");
        }
        Directory.Move(stage, stage + "-original");
        Directory.CreateDirectory(stage);
        Refused(() => { using var witness = new CoordinatedLegacyImportWitness(store, identity, args, caller.AccessToken); },
            "COORDINATED_IMPORT_DIRECTORY_CHANGED");
        Check(FileHash(ledgerFile) == beforeLedger && FileHash(transaction) == beforeImport, "No recovery or ledger write");
        Check(File.ReadAllText(Path.Combine(stage + "-original", "stage.txt")) == "preserve stage"
            && File.ReadAllText(Path.Combine(workspace, "repo", "existing.txt")) == "preserve destination", "Directories preserved");
    }

    private static void TestLegacyIsolationContract(string root)
    {
        var image = Path.Combine(root, "legacy.exe");
        void Validate(string actual, uint start, uint state, uint pid, bool isolated, bool quiesced, string account = "LocalSystem")
            => WindowsContainmentServiceInstaller.RequireCoordinatedLegacyIsolation(image, actual, start, 0x10, account, state, pid, isolated, quiesced);
        void Denied(Action action, string reason)
        {
            try { action(); }
            catch (IOException error) when (error.Message == reason) { assertions++; return; }
            throw new Exception("Expected isolation refusal " + reason);
        }
        Validate(image, 4, 1, 0, true, true);
        assertions++;
        Denied(() => Validate(image, 4, 1, 0, false, true), "SERVICE_INSTALL_COORDINATED_LEGACY_ISOLATION_UNVERIFIED");
        Denied(() => Validate(image, 4, 1, 0, true, false), "SERVICE_INSTALL_COORDINATED_LEGACY_ISOLATION_UNVERIFIED");
        Denied(() => Validate(image, 2, 1, 0, true, true), "SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
        Denied(() => Validate(image, 4, 4, 42, true, true), "SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
        Denied(() => Validate(image, 4, 1, 42, true, true), "SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
        Denied(() => Validate(image + ".other", 4, 1, 0, true, true), "SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
        Denied(() => Validate(image, 4, 1, 0, true, true, "LocalService"), "SERVICE_INSTALL_REPLACEMENT_CONFIG_UNVERIFIED");
    }

    internal static void Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "lnwjud-coordinated-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var profile = Path.Combine(root, "profile");
            Directory.CreateDirectory(profile);
            var witnesses = new[] { "ledger", "import", "owner", "workspace", "stage", "destination", "tunnel", "sqlite" }
                .Select(name => Path.Combine(profile, name)).ToArray();
            foreach (var file in witnesses) File.WriteAllText(file, "fixture:" + Path.GetFileName(file));
            string Authority() => Hash(String.Join("|", witnesses.Select(FileHash)));
            var native = Path.Combine(root, "native-selection");
            var desktop = Path.Combine(root, "desktop-selection");
            File.WriteAllText(native, "legacy native");
            File.WriteAllText(desktop, "legacy desktop");
            var plan = new CoordinatedPlan(Guid.NewGuid().ToString("D"), FileHash(native), Hash("candidate native"),
                FileHash(desktop), Hash("candidate desktop"), Authority());
            var fenced = false;
            var healthy = false;
            CoordinatedObservation Observe() => new(FileHash(native), FileHash(desktop), Authority(), true, fenced, fenced, healthy, healthy);
            var state = Path.Combine(root, "state");
            var crash = false;
            using (var store = new CoordinatedUpgradeStore(state, point =>
            {
                if (crash && point == "staged") throw new IOException("fixture interruption");
            }))
            {
                Check(!store.MayAdmit(Observe()), "Missing journal must not admit");
                Refused(() => store.Begin(plan with { CandidateHelper = plan.OldHelper }, Observe()), "COORDINATED_PLAN_INVALID");
                Refused(() => store.Begin(plan, Observe() with { Authenticated = false }), "COORDINATED_OBSERVATION_UNVERIFIED");
                var current = store.Begin(plan, Observe());
                Check(current.Phase == CoordinatedPhase.Prepared, "Prepared");
                Refused(() => store.Begin(plan, Observe()), "COORDINATED_ALREADY_STARTED");
                Refused(() => store.Advance(new string('0', 64), Observe()), "COORDINATED_CAS_CONFLICT");
                crash = true;
                try { store.Advance(current.Digest, Observe()); throw new Exception("Expected staged interruption"); }
                catch (IOException error) when (error.Message == "fixture interruption") { assertions++; }
                Refused(() => store.Read(), "COORDINATED_PUBLICATION_PENDING");
                Check(!store.MayAdmit(Observe()), "Pending journal must not admit");
            }
            using (var store = new CoordinatedUpgradeStore(state))
            {
                var current = store.RecoverPublication();
                Check(current.Phase == CoordinatedPhase.FenceIntent, "Reopened journal recovers staged intent");
                Refused(() => store.Advance(current.Digest, Observe()), "COORDINATED_OBSERVATION_UNVERIFIED");
                fenced = true;
                Refused(() => store.Advance(current.Digest, Observe() with { Quiesced = false }), "COORDINATED_OBSERVATION_UNVERIFIED");
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.Fenced, "Fence observed");
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.NativeIntent, "Native intent durable before action");
                Refused(() => store.Advance(current.Digest, Observe()), "COORDINATED_OBSERVATION_UNVERIFIED");
                File.WriteAllText(native, "candidate native");
                Check(!store.MayAdmit(Observe()), "Mixed pair must not admit");
            }
            using (var store = new CoordinatedUpgradeStore(state))
            {
                var current = store.RecoverPublication();
                Check(current.Phase == CoordinatedPhase.NativeIntent, "Crash after external effect retains intent");
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.NativeSelected, "Readback without repeating external effect");
                Refused(() => store.Advance(current.Digest, Observe() with { Helper = plan.OldHelper }), "COORDINATED_OBSERVATION_UNVERIFIED");
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.DesktopIntent, "Desktop intent durable");
                File.WriteAllText(desktop, "candidate desktop");
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.DesktopSelected, "Desktop readback");
                Refused(() => store.Advance(current.Digest, Observe()), "COORDINATED_OBSERVATION_UNVERIFIED");
                healthy = true;
                var owner = witnesses[2];
                var original = File.ReadAllBytes(owner);
                File.WriteAllText(owner, "foreign owner");
                Refused(() => store.Advance(current.Digest, Observe()), "COORDINATED_OBSERVATION_UNVERIFIED");
                File.WriteAllBytes(owner, original);
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.Verified, "Matching package and preserved authority");
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.OpenIntent, "Open intent durable");
                fenced = false;
                Refused(() => store.Advance(current.Digest, Observe()), "COORDINATED_OBSERVATION_UNVERIFIED");
                Check(!store.MayAdmit(Observe()), "Early fence opening not admitted by journal");
                fenced = true;
                current = store.Advance(current.Digest, Observe());
                Check(current.Phase == CoordinatedPhase.Completed, "Completion durable under fence");
                Check(!store.MayAdmit(Observe()), "Completed but fenced");
                fenced = false;
                Check(store.MayAdmit(Observe()), "Completed healthy pair");
                Check(!store.MayAdmit(Observe() with { Helper = plan.OldHelper }), "Old native never readmitted");
                Check(!store.MayAdmit(Observe() with { AuthorityDigest = Hash("different") }), "Changed authority refused");
                Check(!store.MayAdmit(Observe() with { Authenticated = false }), "Untrusted readback refused");
                Refused(() => store.Advance(current.Digest, Observe()), "COORDINATED_ALREADY_COMPLETE");
                Check(Authority() == plan.AuthorityDigest, "Preserved fixture evidence");
            }
            using (var store = new CoordinatedUpgradeStore(state))
            {
                Check(store.MayAdmit(Observe()), "Completed state survives reopen");
            }
            TestMaintenance(root);
            TestMaintenanceRpc(root).GetAwaiter().GetResult();
            TestPackageWitnessSize(root);
            TestLegacyWitness(root);
            TestLegacyIsolationContract(root);
            Console.WriteLine($"PASS coordinated upgrade journal, intents, forward-only reconciliation and fixture admission ({assertions} assertions)");
        }
        finally
        {
            if (!Path.GetFileName(root).StartsWith("lnwjud-coordinated-fixture-", StringComparison.Ordinal))
                throw new Exception("Unsafe fixture cleanup");
            Directory.Delete(root, true);
        }
    }
}
