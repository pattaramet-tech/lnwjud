using System.Diagnostics;
using System.Runtime.Versioning;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

[SupportedOSPlatform("windows")]
internal static class MaintenanceBoundaryTests
{
    private static int assertions;
    private static void Check(bool ok, string message)
    {
        assertions++;
        if (!ok) throw new Exception(message);
    }

    private static void Refused(Action action, string reason)
    {
        try { action(); }
        catch (Refusal e) when (e.Reason == reason) { assertions++; return; }
        throw new Exception("Expected " + reason);
    }

    // Only the native test executable can enter these subprocess modes.
    internal static int Child(string[] args)
    {
        if (args.Length != 3) return 80;
        var root = MaintenanceBoundaryFixture.ScopeRoot(args[2]);
        try
        {
            switch (args[1])
            {
                case "production-lifetime-probe":
                    try
                    {
                        using var lifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null);
                        Console.WriteLine("LIFETIME_ADMITTED");
                        return 0;
                    }
                    catch (IOException error) { Console.WriteLine(error.Message); return 77; }
                case "fence-stage-exit":
                    try { using var fence = MaintenanceBoundaryFixture.Fence(root, failAfterStage: true); }
                    catch (IOException error) when (error.Message == "RECOVERY_FIXTURE_STAGED_fence")
                    { Console.WriteLine("FENCE_STAGED"); return 0; }
                    return 80;
                case "resume-stage-exit":
                    try
                    {
                        var predecessor = WindowsStoreIO.Hash(File.ReadAllBytes(Path.Combine(root, "journal.json")));
                        using var fence = MaintenanceBoundaryFixture.Resume(root, predecessor, failAfterStage: true);
                    }
                    catch (IOException error) when (error.Message == "RECOVERY_FIXTURE_STAGED_fence")
                    { Console.WriteLine("RESUME_STAGED"); return 0; }
                    return 80;
                case "writer":
                    using (var writer = MaintenanceBoundaryFixture.Admit(root))
                    {
                        writer.RunWriter(() => {
                            Console.WriteLine("WRITER_HELD"); Console.Out.Flush();
                            if (Console.ReadLine() != "exit") throw new Exception("Unexpected fixture input");
                        });
                    }
                    return 0;
                case "probe":
                    using (var writer = MaintenanceBoundaryFixture.Admit(root))
                        writer.RunWriter(() => Console.WriteLine("ADMITTED"));
                    return 0;
                case "pending-fence-child":
                    OrphanImportAuthorizationTests.PendingFenceChild(root);
                    return 80;
                case "released-receipt-child":
                    OrphanImportAuthorizationTests.ReleasedReceiptChild(root);
                    return 80;
                case "fence-probe":
                    using (var candidate = MaintenanceBoundaryFixture.Fence(root))
                        Console.WriteLine("FENCE=" + candidate.FenceDigest);
                    return 0;
                case "fence-crash":
                    // Exit without Dispose to model loss of the owner process.
                    var fenced = MaintenanceBoundaryFixture.Fence(root);
                    Console.WriteLine("FENCE=" + fenced.FenceDigest); Console.Out.Flush();
                    Environment.Exit(0);
                    return 0;
                case "legacy-probe":
                    foreach (var name in new[] { "legacy-native.json", "legacy-profile.json" })
                    {
                        try
                        {
                            using var write = new FileStream(Path.Combine(root, name), FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                            Console.WriteLine("LEGACY_OPENED=" + name);
                        }
                        catch (IOException e) when ((e.HResult & 0xffff) == 32)
                        { Console.WriteLine("LEGACY_DENIED=" + name); }
                    }
                    return 0;
                case "legacy-hold":
                    using (var write = new FileStream(Path.Combine(root, "legacy-profile.json"), FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                    {
                        Console.WriteLine("LEGACY_HELD"); Console.Out.Flush();
                        if (Console.ReadLine() != "exit") throw new Exception("Unexpected fixture input");
                    }
                    return 0;
                default: return 80;
            }
        }
        catch (Refusal e) { Console.WriteLine(e.Reason); return 77; }
    }

    private static Process Start(string mode, string root)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        start.ArgumentList.Add("maintenance-boundary-child");
        start.ArgumentList.Add(mode);
        start.ArgumentList.Add(root);
        return Process.Start(start) ?? throw new Exception("Fixture child unavailable");
    }

    private static string Line(Process child)
        => child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult()
            ?? throw new Exception("Fixture child closed output");

    private static void Exit(Process child, int code)
    {
        if (!child.WaitForExit(10_000)) throw new Exception("Fixture child deadline");
        Check(child.ExitCode == code, "Unexpected child exit: " + child.ExitCode + " " + child.StandardError.ReadToEnd());
    }

    internal static string Probe(string mode, string root, int code)
    {
        using var child = Start(mode, root);
        try
        {
            var output = child.StandardOutput.ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
            Exit(child, code);
            return output.Trim();
        }
        finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(5000); } }
    }

    private static void Hold(string mode, string root, string expected, Action whileHeld)
    {
        using var child = Start(mode, root);
        try
        {
            Check(Line(child) == expected, "Child ready");
            whileHeld();
            child.StandardInput.WriteLine("exit");
            child.StandardInput.Flush();
            Exit(child, 0);
        }
        finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(5000); } }
    }

    private static string Fresh() => Path.Combine(Path.GetTempPath(), "lnwjud-maintenance-fixture-" + Guid.NewGuid().ToString("N"));
    private static void Cleanup(string root)
    {
        if (Directory.Exists(MaintenanceBoundaryFixture.ScopeRoot(root))) Directory.Delete(root, true);
    }

    private static void IoRefused(Action action, string reason)
    {
        try { action(); }
        catch (IOException error) when (error.Message == reason) { assertions++; return; }
        throw new Exception("Expected IO refusal " + reason);
    }

    private static void TestProductionLifetime()
    {
        var root = Fresh();
        try
        {
            MaintenanceBoundaryFixture.Initialize(root);
            var lockPath = Path.Combine(root, "maintenance-lifetime.lock");
            IoRefused(() => ProductionMaintenanceBoundary.EnterLifetimeFixture(root,
                () => new("held", "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE")),
                "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE");
            Check(!File.Exists(lockPath), "Held marker prevents even lock provisioning");
            UpdateStartupDisposition held = new("held", "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE");
            IoRefused(() => ProductionMaintenanceBoundary.EnterReadOnlyInspectionFixture(root, () => held),
                "SERVICE_ENDPOINT_IMAGE_UNAVAILABLE");
            Check(!File.Exists(lockPath), "Read-only recovery inspection never provisions missing lock");
            IoRefused(() => ProductionMaintenanceBoundary.EnterReadOnlyInspectionFixture(root, () => null),
                "SERVICE_MAINTENANCE_MARKER_UNVERIFIED");
            IoRefused(() => ProductionMaintenanceBoundary.EnterReadOnlyInspectionFixture(root,
                () => new("held", "UPDATE_TRANSACTION_COORDINATED_INSPECTION_UNAVAILABLE")),
                "SERVICE_MAINTENANCE_MARKER_UNVERIFIED");
            int reads = 0;
            IoRefused(() => ProductionMaintenanceBoundary.EnterLifetimeFixture(root,
                () => ++reads == 1 ? null : new("held", "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE")),
                "UPDATE_TRANSACTION_COORDINATED_MAINTENANCE");
            Check(File.Exists(lockPath) && new FileInfo(lockPath).Length == 0, "Second marker check fails closed");
            using (var lifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null))
            {
                Check(Probe("production-lifetime-probe", root, 77) == "SERVICE_MAINTENANCE_LIFETIME_BUSY",
                    "Production lifetime primitive excludes an independent process");
                IoRefused(() => ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null),
                    "SERVICE_MAINTENANCE_LIFETIME_BUSY");
            }
            Check(Probe("production-lifetime-probe", root, 0) == "LIFETIME_ADMITTED", "Only released lifetime permits next process");
            UpdateStartupDisposition? marker = held;
            using (var lifetime = ProductionMaintenanceBoundary.EnterReadOnlyInspectionFixture(root, () => marker))
            {
                lifetime.RequireHeldLease();
                Check(Probe("production-lifetime-probe", root, 77) == "SERVICE_MAINTENANCE_LIFETIME_BUSY",
                    "Read-only recovery inspection excludes cooperating service");
                marker = null;
                IoRefused(lifetime.RequireHeldLease, "SERVICE_MAINTENANCE_MARKER_UNVERIFIED");
            }
            marker = held;
            using (var lifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null))
            {
                IoRefused(lifetime.RequireHeldLease, "SERVICE_MAINTENANCE_LOCK_UNVERIFIED");
                IoRefused(() => ProductionMaintenanceBoundary.EnterReadOnlyInspectionFixture(root, () => marker),
                    "SERVICE_MAINTENANCE_LIFETIME_BUSY");
            }
            File.WriteAllText(lockPath, "unexpected authority");
            IoRefused(() => ProductionMaintenanceBoundary.EnterLifetimeFixture(root, () => null),
                "SERVICE_MAINTENANCE_LOCK_UNVERIFIED");
            Check(File.ReadAllText(lockPath) == "unexpected authority", "Invalid lock never truncated");
        }
        finally { Cleanup(root); }
    }

    private static void TestClosedPending()
    {
        var root = Fresh();
        try
        {
            MaintenanceBoundaryFixture.Initialize(root);
            var journal = Path.Combine(root, "journal.json");
            var pending = Path.Combine(root, "journal.pending.json");
            Check(Probe("fence-stage-exit", root, 0) == "FENCE_STAGED", "Initial fence interrupted after staging");
            Check(Probe("probe", root, 77) == "MAINTENANCE_FIXTURE_PENDING", "Pending creation closes admission");
            var old = WindowsStoreIO.Hash(File.ReadAllBytes(journal));
            var bytes = File.ReadAllBytes(pending);
            var digest = WindowsStoreIO.Hash(bytes);
            var invalid = System.Text.Json.Nodes.JsonNode.Parse(bytes)!.AsObject();
            invalid["previous"] = new string('a', 64);
            var bad = Wire.Encode(invalid);
            File.WriteAllBytes(pending, bad);
            Refused(() => MaintenanceBoundaryFixture.ReconcileClosedFenceFixture(root, old, WindowsStoreIO.Hash(bad)),
                "RECOVERY_PENDING_SUCCESSOR_INVALID");
            Check(File.ReadAllBytes(pending).SequenceEqual(bad), "Invalid predecessor retained");
            File.WriteAllBytes(pending, bytes);
            Check(MaintenanceBoundaryFixture.ReconcileClosedFenceFixture(root, old, digest) == digest
                && !File.Exists(pending), "Exact creation reconciles to closed fence only");
            Check(Probe("probe", root, 77) == "MAINTENANCE_FIXTURE_FENCED", "Reconciled fence remains closed");
            Check(Probe("resume-stage-exit", root, 0) == "RESUME_STAGED", "Owner transfer interrupted after staging");
            var next = WindowsStoreIO.Hash(File.ReadAllBytes(pending));
            Check(MaintenanceBoundaryFixture.ReconcileClosedFenceFixture(root, digest, next) == next,
                "Exact dead-owner transfer reconciles");
            Check(Probe("probe", root, 77) == "MAINTENANCE_FIXTURE_FENCED", "Transfer does not open admission");
            using (var resumed = MaintenanceBoundaryFixture.Resume(root, next))
            {
                Refused(() => resumed.CompleteFixture(next), "MAINTENANCE_FIXTURE_FENCE_MISMATCH");
                resumed.CompleteFixture(resumed.FenceDigest);
            }
            Check(Probe("probe", root, 0) == "ADMITTED", "Fresh owner and explicit completion required");
        }
        finally { Cleanup(root); }
    }

    internal static void Run()
    {
        TestProductionLifetime();
        TestClosedPending();
        var root = Fresh();
        try
        {
            Refused(() => MaintenanceBoundaryFixture.Admit(root), "MAINTENANCE_FIXTURE_ROOT_MISSING");
            Refused(() => MaintenanceBoundaryFixture.Admit(Path.GetTempPath()), "MAINTENANCE_FIXTURE_SCOPE_INVALID");
            MaintenanceBoundaryFixture.Initialize(root);
            Refused(() => MaintenanceBoundaryFixture.Initialize(root), "MAINTENANCE_FIXTURE_ALREADY_EXISTS");
            var journal = Path.Combine(root, "journal.json");
            var original = File.ReadAllBytes(journal);
            Hold("writer", root, "WRITER_HELD", () => {
                Refused(() => MaintenanceBoundaryFixture.Fence(root), "OWNER_BUSY");
                Check(Probe("probe", root, 77) == "OWNER_BUSY", "Independent process excludes concurrent writer");
                Check(File.ReadAllBytes(journal).SequenceEqual(original), "Busy fence never writes journal");
            });
            using (var writer = MaintenanceBoundaryFixture.Admit(root))
            {
                writer.RunWriter(() => {
                    Refused(writer.Dispose, "MAINTENANCE_FIXTURE_WRITER_ACTIVE");
                    Refused(() => writer.RunWriter(() => { }), "MAINTENANCE_FIXTURE_NOT_ADMITTED");
                    Check(Probe("probe", root, 77) == "OWNER_BUSY", "No early release through reentrant callback");
                });
            }
            Hold("legacy-hold", root, "LEGACY_HELD", () => {
                try { using var fence = MaintenanceBoundaryFixture.Fence(root); throw new Exception("Legacy writer admitted"); }
                catch (IOException) { assertions++; }
                Check(File.ReadAllBytes(journal).SequenceEqual(original), "Existing legacy write handle prevents fence");
            });
            using (var fence = MaintenanceBoundaryFixture.Fence(root))
            {
                Check(Probe("probe", root, 77) == "OWNER_BUSY", "Cross-process fence denies admission");
                Check(Probe("fence-probe", root, 77) == "OWNER_BUSY", "Second maintenance process cannot take authority");
                var legacy = Probe("legacy-probe", root, 0);
                Check(legacy.Contains("LEGACY_DENIED=legacy-native.json") && legacy.Contains("LEGACY_DENIED=legacy-profile.json")
                    && !legacy.Contains("LEGACY_OPENED"), "OS share denial blocks uncooperative fixture writes");
                Refused(() => fence.CompleteFixture(new string('a', 64)), "MAINTENANCE_FIXTURE_FENCE_MISMATCH");
                fence.CompleteFixture(fence.FenceDigest);
                Check(Probe("probe", root, 77) == "OWNER_BUSY", "Completed state cannot admit before lease disposal");
            }
            Check(Probe("probe", root, 0) == "ADMITTED", "Explicit completion and disposal reopen fixture");

            var crash = Probe("fence-crash", root, 0);
            Check(crash.StartsWith("FENCE="), "Abrupt owner exit returned durable fence digest");
            var digest = crash["FENCE=".Length..];
            Check(Probe("probe", root, 77) == "MAINTENANCE_FIXTURE_FENCED", "OS unlock after exit does not open durable fence");
            Check(Probe("fence-probe", root, 77) == "MAINTENANCE_FIXTURE_FENCED", "New fence cannot overwrite crashed owner's durable record");
            Refused(() => MaintenanceBoundaryFixture.Resume(root, new string('f', 64)), "MAINTENANCE_FIXTURE_FENCE_MISMATCH");
            using (var recovered = MaintenanceBoundaryFixture.Resume(root, digest))
            {
                Check(recovered.FenceDigest != digest, "Recovered ownership changes exact digest");
                Refused(() => recovered.CompleteFixture(digest), "MAINTENANCE_FIXTURE_FENCE_MISMATCH");
                Check(Probe("probe", root, 77) == "OWNER_BUSY", "Recovery owner holds kernel lock");
                recovered.CompleteFixture(recovered.FenceDigest);
            }
            Check(Probe("probe", root, 0) == "ADMITTED", "Exact recovered fence opens only after completion");

            // A live previous owner is not eligible for takeover even if its
            // local lease was disposed. Use a distinct root for each fault.
            var live = Fresh();
            try
            {
                MaintenanceBoundaryFixture.Initialize(live);
                string liveDigest;
                using (var fence = MaintenanceBoundaryFixture.Fence(live)) liveDigest = fence.FenceDigest;
                Refused(() => MaintenanceBoundaryFixture.Resume(live, liveDigest), "MAINTENANCE_FIXTURE_PREVIOUS_OWNER_UNVERIFIED");
                Check(Probe("probe", live, 77) == "MAINTENANCE_FIXTURE_FENCED", "Disposal alone retains fence");
            }
            finally { Cleanup(live); }

            var changed = Fresh();
            try
            {
                MaintenanceBoundaryFixture.Initialize(changed);
                var oldDigest = Probe("fence-crash", changed, 0)["FENCE=".Length..];
                File.WriteAllText(Path.Combine(changed, "legacy-profile.json"), "changed after crash");
                var before = File.ReadAllBytes(Path.Combine(changed, "journal.json"));
                Refused(() => MaintenanceBoundaryFixture.Resume(changed, oldDigest), "MAINTENANCE_FIXTURE_LEGACY_CHANGED");
                Check(File.ReadAllBytes(Path.Combine(changed, "journal.json")).SequenceEqual(before), "Changed legacy evidence preserves durable fence");
            }
            finally { Cleanup(changed); }

            var pending = Fresh();
            try
            {
                MaintenanceBoundaryFixture.Initialize(pending);
                using (var io = new WindowsStoreIO(pending)) io.Stage(io.Read("journal.json")!.Bytes);
                Refused(() => MaintenanceBoundaryFixture.Admit(pending), "MAINTENANCE_FIXTURE_PENDING");
                Refused(() => MaintenanceBoundaryFixture.Fence(pending), "MAINTENANCE_FIXTURE_PENDING");
                Check(File.Exists(Path.Combine(pending, "journal.pending.json")), "Unresolved publication is retained");
            }
            finally { Cleanup(pending); }

            var foreign = Fresh();
            try
            {
                MaintenanceBoundaryFixture.Initialize(foreign);
                var foreignJournal = Path.Combine(foreign, "journal.json");
                File.WriteAllBytes(foreignJournal, File.ReadAllBytes(journal));
                Refused(() => MaintenanceBoundaryFixture.Admit(foreign), "MAINTENANCE_FIXTURE_SCOPE_CHANGED");
                Refused(() => MaintenanceBoundaryFixture.Fence(foreign), "MAINTENANCE_FIXTURE_SCOPE_CHANGED");
                Check(File.ReadAllBytes(foreignJournal).SequenceEqual(File.ReadAllBytes(journal)), "Foreign record never rewritten");
                File.WriteAllText(foreignJournal, "{}");
                var malformed = File.ReadAllBytes(foreignJournal);
                // The wire parser may reject the malformed fields with its
                // own refusal. An invalid journal is never an open gate.
                try { using var lease = MaintenanceBoundaryFixture.Admit(foreign); throw new Exception("Corrupt journal admitted"); }
                catch (Refusal) { assertions++; }
                Check(File.ReadAllBytes(foreignJournal).SequenceEqual(malformed), "Corrupt journal retained");
            }
            finally { Cleanup(foreign); }

            var missing = Fresh();
            try
            {
                MaintenanceBoundaryFixture.Initialize(missing);
                File.Delete(Path.Combine(missing, "journal.json"));
                Refused(() => MaintenanceBoundaryFixture.Admit(missing), "MAINTENANCE_FIXTURE_RECORD_MISSING");
                File.Delete(Path.Combine(missing, "owner.lock"));
                Refused(() => MaintenanceBoundaryFixture.Admit(missing), "MAINTENANCE_FIXTURE_LOCK_MISSING");
                Check(!File.Exists(Path.Combine(missing, "owner.lock")), "No silent lock recreation on admission");
            }
            finally { Cleanup(missing); }
            Console.WriteLine($"PASS cross-process maintenance boundary, sticky fence, legacy file isolation ({assertions} assertions)");
        }
        finally { Cleanup(root); }
    }
}
