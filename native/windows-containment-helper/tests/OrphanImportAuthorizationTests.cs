using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

internal static class OrphanImportAuthorizationTests
{
    private static int assertions;
    private static string Hash(string value) => WindowsStoreIO.Hash(System.Text.Encoding.UTF8.GetBytes(value));
    private static string FileHash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    private static void Check(bool result, string message)
    {
        if (!result) throw new Exception(message);
        assertions++;
    }

    private static void Refused(Action action, string reason)
    {
        try { action(); }
        catch (Refusal error) when (error.Reason == reason) { assertions++; return; }
        throw new Exception("Expected refusal " + reason);
    }

    private static void TestApproval(OrphanImportEvidence evidence)
    {
        var unconfirmed = new OrphanImportApprovalSession(evidence);
        Refused(() => unconfirmed.ConsumeForContractTest(unconfirmed.Challenge, evidence), "ORPHAN_APPROVAL_REFUSED");
        Refused(() => unconfirmed.ConfirmFromTrustedLocalUi(unconfirmed.Challenge, evidence), "ORPHAN_APPROVAL_REFUSED");
        var approved = new OrphanImportApprovalSession(evidence);
        approved.ConfirmFromTrustedLocalUi(approved.Challenge, evidence);
        approved.ConsumeForContractTest(approved.Challenge, evidence);
        Check(true, "Single approved consumption");
        Refused(() => approved.ConsumeForContractTest(approved.Challenge, evidence), "ORPHAN_APPROVAL_REFUSED");
        var fresh = new OrphanImportApprovalSession(evidence);
        Check(fresh.Challenge != approved.Challenge, "Nonce changes on new session");
        Refused(() => fresh.ConfirmFromTrustedLocalUi(approved.Challenge, evidence), "ORPHAN_APPROVAL_REFUSED");

        foreach (var changed in new[] {
            evidence with { Identity = evidence.Identity with { OwnerClientId = "different-client" } },
            evidence with { Identity = evidence.Identity with { OwnerSessionId = "different-session" } },
            evidence with { Identity = evidence.Identity with { WorkspaceId = "different-workspace" } },
            evidence with { Identity = evidence.Identity with { RequestDigest = Hash("different request") } },
            evidence with { Identity = evidence.Identity with { Generation = 2 } },
            evidence with { OwnerSid = "S-1-5-21-999" },
            evidence with { OperatorSecurityDigest = Hash("different token") },
            evidence with { WindowsSession = evidence.WindowsSession + 1 },
            evidence with { NativeDigest = Hash("different authority") },
            evidence with { BootId = Guid.NewGuid().ToString("D") },
            evidence with { Action = OrphanImportAction.AbortPreparedImport },
            evidence with { SchemaVersion = evidence.SchemaVersion + 1 },
        })
        {
            var session = new OrphanImportApprovalSession(evidence);
            Refused(() => session.ConfirmFromTrustedLocalUi(session.Challenge, changed), "ORPHAN_APPROVAL_REFUSED");
            var after = new OrphanImportApprovalSession(evidence);
            after.ConfirmFromTrustedLocalUi(after.Challenge, evidence);
            Refused(() => after.ConsumeForContractTest(after.Challenge, changed), "ORPHAN_APPROVAL_REFUSED");
            Refused(() => after.ConsumeForContractTest(after.Challenge, evidence), "ORPHAN_APPROVAL_REFUSED");
        }

        var expired = new OrphanImportApprovalSession(evidence);
        expired.ElapsedForTest = () => TimeSpan.FromMinutes(2);
        Refused(() => expired.ConfirmFromTrustedLocalUi(expired.Challenge, evidence), "ORPHAN_APPROVAL_REFUSED");
        var expiresAfterConsent = new OrphanImportApprovalSession(evidence);
        expiresAfterConsent.ConfirmFromTrustedLocalUi(expiresAfterConsent.Challenge, evidence);
        expiresAfterConsent.ElapsedForTest = () => TimeSpan.FromMinutes(2);
        Refused(() => expiresAfterConsent.ConsumeForContractTest(expiresAfterConsent.Challenge, evidence), "ORPHAN_APPROVAL_REFUSED");

        var parallel = new OrphanImportApprovalSession(evidence);
        parallel.ConfirmFromTrustedLocalUi(parallel.Challenge, evidence);
        int successes = 0, refusals = 0;
        Parallel.For(0, 16, _ =>
        {
            try { parallel.ConsumeForContractTest(parallel.Challenge, evidence); Interlocked.Increment(ref successes); }
            catch (Refusal error) when (error.Reason == "ORPHAN_APPROVAL_REFUSED") { Interlocked.Increment(ref refusals); }
        });
        Check(successes == 1 && refusals == 15, "Exactly one concurrent consumer");
    }

    private static async Task TestRpcRefusal(ServiceAttemptLedger ledger, ServiceAttemptIdentity identity,
        ServiceImportArguments args, string root, string command = "control",
        string expectedError = "SERVICE_IMPORT_LEGACY_AUTHORIZATION_UNAVAILABLE")
    {
        var pipeName = "lnwjud-orphan-fixture-" + Guid.NewGuid().ToString("N");
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var server = WindowsContainmentService.RunPipeServerAsync(pipeName, ledger, stopping.Token,
            useCurrentUserTestLauncher: true, startup: UpdateStartupGate.Isolated(root, root, () => false));
        try
        {
            using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", pipeName, System.IO.Pipes.PipeDirection.InOut,
                System.IO.Pipes.PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
            await pipe.ConnectAsync(5000, stopping.Token);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                protocol = 3, command, identity, controlCommand = "abort_import",
                controlRequest = args with { RecoverLegacy = true },
            }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            await pipe.WriteAsync(BitConverter.GetBytes(bytes.Length), stopping.Token);
            await pipe.WriteAsync(bytes, stopping.Token);
            var size = new byte[4];
            await pipe.ReadExactlyAsync(size, stopping.Token);
            var length = BitConverter.ToInt32(size);
            if (length is < 2 or > 65536) throw new Exception("Invalid fixture RPC frame");
            var reply = new byte[length];
            await pipe.ReadExactlyAsync(reply, stopping.Token);
            using var response = JsonDocument.Parse(reply);
            Check(!response.RootElement.GetProperty("ok").GetBoolean()
                && response.RootElement.GetProperty("error").GetString() == expectedError,
                "Unauthorized maintenance denied on actual RPC dispatch path: " + command);
        }
        finally
        {
            stopping.Cancel();
            try { await server.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
        }
    }

    private static void TestBroker(string store, ServiceAttemptIdentity identity,
        Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token, string ledgerPath)
    {
        var complete = new OrphanFixtureScope(Hash("fixture inventory"), true, true, true, true, true, true);
        var scope = complete;
        bool pinsChecked = false;
        OrphanApprovalBrokerFixture NewBroker() => new(callback =>
            OrphanImportPreflight.InspectFixture(store, identity, token, true, evidence =>
            {
                // Real protected file witness is held while the broker consumes
                // approval. No native effect is executed by this callback.
                try { using var stream = File.Open(ledgerPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); }
                catch (IOException) { pinsChecked = true; }
                callback(evidence, scope);
            }));
        var broker = NewBroker();
        foreach (var incomplete in new[] {
            complete with { Complete = false }, complete with { ManifestAbsent = false },
            complete with { WorkerSpecAbsent = false }, complete with { RuntimeMarkerAbsent = false },
            complete with { WorkspaceAbsent = false }, complete with { InventoryDigest = "unknown" },
        })
        {
            scope = incomplete;
            Refused(() => broker.Begin(), "ORPHAN_PROFILE_AUTHORITY_UNVERIFIED");
        }
        scope = complete with { LocalConsentChannelVerified = false };
        Refused(() => broker.Begin(), "ORPHAN_LOCAL_CONSENT_UNVERIFIED");
        scope = complete;
        var first = broker.Begin();
        Refused(() => broker.Begin(), "ORPHAN_APPROVAL_IN_FLIGHT");
        broker.Confirm(first);
        var newEpoch = NewBroker();
        Refused(() => newEpoch.ConsumeReadOnly(first), "ORPHAN_APPROVAL_REFUSED");
        var other = newEpoch.Begin();
        Refused(() => newEpoch.Confirm(first), "ORPHAN_APPROVAL_REFUSED");
        Check(first != other, "Different broker epochs do not share grants");
        scope = complete with { InventoryDigest = Hash("changed inventory") };
        Refused(() => broker.ConsumeReadOnly(first), "ORPHAN_PROFILE_AUTHORITY_CHANGED");
        scope = complete;
        Refused(() => broker.ConsumeReadOnly(first), "ORPHAN_APPROVAL_REFUSED");
        var second = broker.Begin();
        broker.Confirm(second);
        broker.ConsumeReadOnly(second);
        Refused(() => broker.ConsumeReadOnly(second), "ORPHAN_APPROVAL_REFUSED");
        Check(pinsChecked, "Read-only approval decision kept protected file pinned");
    }

    private sealed class FixtureConsent(Func<NativeMaintenanceProposal, NativeMaintenanceConsentReply> reply)
        : INativeMaintenanceLocalConsent
    {
        public NativeMaintenanceConsentReply Request(NativeMaintenanceProposal proposal) => reply(proposal);
    }

    private static void TestNativeOnlyAuthority(OrphanImportEvidence evidence, Func<OrphanImportEvidence> inspect)
    {
        var logon = "fixture-logon";
        var current = evidence;
        Func<(OrphanImportEvidence, string)> read = () => (inspect(), logon);
        NativeMaintenanceConsentReply Approve(NativeMaintenanceProposal p)
            => new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly);
        NativeMaintenanceAuthority Make(Func<NativeMaintenanceProposal, NativeMaintenanceConsentReply> reply,
            Func<(OrphanImportEvidence, string)>? source = null, OrphanImportAction? action = null,
            ServiceAttemptIdentity? expected = null)
            => NativeMaintenanceAuthority.ForFixture(expected ?? evidence.Identity, action ?? evidence.Action,
                source ?? read, new FixtureConsent(reply));

        // No application inventory is supplied. The exact protected native
        // record is displayed and independently reread, never reconstructed.
        string? challenge = null;
        var approved = Make(p =>
        {
            Check(p.Scope == NativeMaintenanceAuthority.Scope && p.Evidence == evidence
                && p.Evidence.Arguments.Commit == evidence.Arguments.Commit
                && p.Evidence.Arguments.Destination == evidence.Arguments.Destination
                && p.OperatorLogon == logon, "Exact native-only consent proposal");
            challenge = p.Challenge;
            return Approve(p);
        });
        var result = approved.Review();
        Check(result.Identity == evidence.Identity && result.Action == evidence.Action
            && result.OwnerSid == evidence.OwnerSid && result.NativeDigest == evidence.NativeDigest
            && !result.ApplicationStateVerified && !result.MutationPerformed,
            "Native-only review does not claim application authority or mutation");
        Refused(() => approved.Review(), "NATIVE_MAINTENANCE_REPLAY_REFUSED");
        Refused(() => Make(p => new(challenge!, NativeMaintenanceDecision.ApproveNativeOnly)).Review(),
            "NATIVE_MAINTENANCE_CONSENT_REFUSED");
        var denied = Make(p => new(p.Challenge, NativeMaintenanceDecision.Deny));
        Refused(() => denied.Review(), "NATIVE_MAINTENANCE_CONSENT_REFUSED");
        Refused(() => denied.Review(), "NATIVE_MAINTENANCE_REPLAY_REFUSED");
        Refused(() => Make(p => new(p.Challenge, (NativeMaintenanceDecision)99)).Review(),
            "NATIVE_MAINTENANCE_CONSENT_REFUSED");
        Refused(() => Make(Approve, action: OrphanImportAction.AbortPreparedImport).Review(),
            "NATIVE_MAINTENANCE_EXACT_SCOPE_REQUIRED");
        Refused(() => Make(Approve, expected: evidence.Identity with { OwnerSessionId = "new-session" }).Review(),
            "NATIVE_MAINTENANCE_EXACT_SCOPE_REQUIRED");
        var expired = Make(Approve);
        expired.ElapsedForTest = () => TimeSpan.FromMinutes(2);
        Refused(() => expired.Review(), "NATIVE_MAINTENANCE_CONSENT_EXPIRED");
        Refused(() => expired.Review(), "NATIVE_MAINTENANCE_REPLAY_REFUSED");

        foreach (var changed in new[] {
            evidence with { OwnerSid = "S-1-5-21-999" },
            evidence with { WindowsSession = evidence.WindowsSession + 1 },
            evidence with { OperatorSecurityDigest = Hash("new token") },
            evidence with { NativeDigest = Hash("new ledger") },
            evidence with { BootId = Guid.NewGuid().ToString("D") },
            evidence with { Arguments = evidence.Arguments with { Destination = "other" } },
            evidence with { Arguments = evidence.Arguments with { Commit = new string('b', 40) } },
        })
        {
            current = evidence;
            var stale = Make(p => { current = changed; return Approve(p); }, () => (current, logon));
            Refused(() => stale.Review(), "NATIVE_MAINTENANCE_EVIDENCE_CHANGED");
            Refused(() => stale.Review(), "NATIVE_MAINTENANCE_REPLAY_REFUSED");
        }
        var changedLogon = Make(p => { logon = "other-logon"; return Approve(p); });
        Refused(() => changedLogon.Review(), "NATIVE_MAINTENANCE_EVIDENCE_CHANGED");
        logon = "fixture-logon";
        var broken = Make(_ => throw new IOException("fixture consent failed"));
        try { broken.Review(); throw new Exception("Expected adapter failure"); }
        catch (IOException error) when (error.Message == "fixture consent failed") { assertions++; }
        Refused(() => broken.Review(), "NATIVE_MAINTENANCE_REPLAY_REFUSED");

        NativeMaintenanceAuthority? reentrant = null;
        reentrant = Make(p =>
        {
            Refused(() => reentrant!.Review(), "NATIVE_MAINTENANCE_REPLAY_REFUSED");
            return Approve(p);
        });
        Check(!reentrant.Review().MutationPerformed, "Reentrant consent cannot create a second review");
        var parallel = Make(Approve);
        int successes = 0, refusals = 0;
        Parallel.For(0, 16, _ =>
        {
            try { parallel.Review(); Interlocked.Increment(ref successes); }
            catch (Refusal error) when (error.Reason == "NATIVE_MAINTENANCE_REPLAY_REFUSED") { Interlocked.Increment(ref refusals); }
        });
        Check(successes == 1 && refusals == 15, "Concurrent native-only review is single use");
    }

    private static void TestLocalUtility(string store, OrphanImportEvidence evidence,
        WindowsIdentity user, Func<OrphanImportEvidence> inspect)
    {
        var id = evidence.Identity;
        var command = new[] { "native-maintenance-review", id.AttemptId, id.RequestDigest, "record-boot-witness" };
        var target = LocalMaintenanceTarget.Parse(command);
        Check(target.AttemptId == id.AttemptId && target.Action == evidence.Action, "Strict exact action command");
        Refused(() => LocalMaintenanceTarget.Parse(command.Concat(["--yes"]).ToArray()), "LOCAL_MAINTENANCE_TARGET_INVALID");
        Refused(() => LocalMaintenanceTarget.Parse(command[..3]), "LOCAL_MAINTENANCE_TARGET_INVALID");
        Refused(() => LocalMaintenanceTarget.Parse(["native-maintenance-review", "any", id.RequestDigest, command[3]]),
            "LOCAL_MAINTENANCE_TARGET_INVALID");
        Refused(() => LocalMaintenanceTarget.Parse([command[0], command[1], "bad-digest", command[3]]),
            "LOCAL_MAINTENANCE_TARGET_INVALID");
        Refused(() => LocalMaintenanceTarget.Parse([command[0], command[1], command[2], "0"]),
            "LOCAL_MAINTENANCE_ACTION_INVALID");
        Refused(() => LocalMaintenanceUtility.ResolveFixture(store, target, user, false),
            "NATIVE_MAINTENANCE_ELEVATION_REQUIRED");
        Refused(() => LocalMaintenanceUtility.ResolveFixture(store, target with { RequestDigest = Hash("other request") }, user, true),
            "LOCAL_MAINTENANCE_OWNER_UNVERIFIED");
        Refused(() => LocalMaintenanceUtility.ResolveFixture(store, target with {
            AttemptId = "repository-import-" + Guid.NewGuid().ToString("D")
        }, user, true), "LOCAL_MAINTENANCE_OWNER_UNVERIFIED");
        Check(LocalMaintenanceUtility.ResolveFixture(store, target, user, true) == id,
            "Protected ledger resolves complete original identity");

        var pages = new List<string>();
        var desktopChecks = 0;
        var dialog = LocalMaintenanceDialog.DialogFixture(() => desktopChecks++, page =>
        {
            pages.Add(page);
            return 6;
        });
        NativeMaintenanceAuthority Authority(INativeMaintenanceLocalConsent consent,
            Func<OrphanImportEvidence>? read = null, OrphanImportAction? action = null)
            => NativeMaintenanceAuthority.ForFixture(id, action ?? evidence.Action,
                () => ((read ?? inspect)(), "fixture-logon"), consent);
        var reviewed = Authority(dialog).Review();
        Check(!reviewed.MutationPerformed && !reviewed.ApplicationStateVerified && reviewed.Identity == id,
            "UI confirmation only produces read-only review");
        Check(pages.Count == 4 && desktopChecks == 8 && pages.All(page =>
            page.Contains("READ-ONLY REVIEW", StringComparison.Ordinal)), "All four pages checked before and after display");
        var all = String.Join("\n", pages);
        foreach (var value in new[] { id.AttemptId, id.RequestDigest, id.OwnerClientId, id.OwnerSessionId,
            id.WorkspaceId, evidence.OwnerSid, evidence.NativeDigest, evidence.BootId,
            evidence.Arguments.WorkspaceRoot, evidence.Arguments.Destination, evidence.Arguments.StagePath!,
            evidence.Arguments.Commit, evidence.Arguments.PrivateHome! })
            Check(all.Contains(JsonSerializer.Serialize(value), StringComparison.Ordinal), "Exact display value");
        Check(all.Contains("NOT authorization to abort", StringComparison.Ordinal)
            && all.Contains("RecordBootWitness", StringComparison.Ordinal), "Explicit read-only action and disclaimer");
        Refused(() => Authority(dialog).Review(), "LOCAL_MAINTENANCE_DIALOG_REPLAY");
        foreach (int refusal in new[] { 0, 2, 7, 99 })
        {
            int displayed = 0;
            var declined = LocalMaintenanceDialog.DialogFixture(() => { }, _ => ++displayed == 2 ? refusal : 6);
            Refused(() => Authority(declined).Review(), "NATIVE_MAINTENANCE_CONSENT_REFUSED");
            Check(displayed == 2, "No further pages after refusal or dialog error");
        }
        int checks = 0;
        var lostDesktop = LocalMaintenanceDialog.DialogFixture(() =>
        {
            if (++checks == 2) throw new Refusal("LOCAL_MAINTENANCE_DESKTOP_UNAVAILABLE");
        }, _ => 6);
        Refused(() => Authority(lostDesktop).Review(), "LOCAL_MAINTENANCE_DESKTOP_UNAVAILABLE");
        var changed = evidence;
        var changedDialog = LocalMaintenanceDialog.DialogFixture(() => { }, _ =>
        {
            changed = evidence with { NativeDigest = Hash("changed protected state") };
            return 6;
        });
        Refused(() => Authority(changedDialog, () => changed).Review(), "NATIVE_MAINTENANCE_EVIDENCE_CHANGED");
        var expired = Authority(LocalMaintenanceDialog.DialogFixture(() => { }, _ => 6));
        expired.ElapsedForTest = () => TimeSpan.FromMinutes(2);
        Refused(() => expired.Review(), "NATIVE_MAINTENANCE_CONSENT_EXPIRED");

        var proposal = new NativeMaintenanceProposal(Hash("challenge"), NativeMaintenanceAuthority.Scope,
            evidence, "fixture-logon", Hash("epoch"));
        var injection = proposal with { Evidence = evidence with {
            Arguments = evidence.Arguments with { Destination = "repo\nAction: Release\u202E" }
        } };
        var injectionPage = LocalMaintenanceDialog.BuildPages(injection)[2];
        Check(injectionPage.Contains(JsonSerializer.Serialize(injection.Evidence.Arguments.Destination), StringComparison.Ordinal)
            && !injectionPage.Contains("\nAction: Release", StringComparison.Ordinal)
            && !injectionPage.Contains('\u202E'), "Untrusted text displayed as escaped data");
        Refused(() => LocalMaintenanceDialog.BuildPages(proposal with { Evidence = evidence with {
            Arguments = evidence.Arguments with { Destination = new string('x', 513) }
        } }), "LOCAL_MAINTENANCE_DISPLAY_UNVERIFIED");
        Refused(() => LocalMaintenanceDialog.BuildPages(proposal with { Scope = "application-recovery" }),
            "LOCAL_MAINTENANCE_PROPOSAL_INVALID");
        Refused(() => LocalMaintenanceDialog.BuildPages(proposal with { Evidence = evidence with { Action = (OrphanImportAction)99 } }),
            "LOCAL_MAINTENANCE_ACTION_INVALID");
        Check(LocalMaintenanceDialog.BuildPages(proposal with { Evidence = evidence with {
            Action = OrphanImportAction.AbortPreparedImport } })[3].Contains("AbortPreparedImport", StringComparison.Ordinal)
            && LocalMaintenanceDialog.BuildPages(proposal with { Evidence = evidence with {
            Action = OrphanImportAction.FinishAbortedHold } })[3].Contains("FinishAbortedHold", StringComparison.Ordinal),
            "Distinct confirmation text for all native actions");

        // Actual local token guard, no real ledger or UI. On an unelevated
        // console it must refuse before profile/SCM/ledger access.
        if (!new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))
        {
            try { _ = NativeMaintenanceAuthority.RequireLocalOperator(user); throw new Exception("Nonadmin accepted"); }
            catch (Refusal error) when (error.Reason is "NATIVE_MAINTENANCE_ELEVATION_REQUIRED"
                or "NATIVE_MAINTENANCE_LOCAL_CONSOLE_REQUIRED") { assertions++; }
            Console.WriteLine("PASS actual unelevated local operator refused");
        }
        else Console.WriteLine("SKIP actual unelevated token probe: fixture runner elevated");
    }

    private static void IoRefused(Action action, string reason)
    {
        try { action(); }
        catch (IOException error) when (error.Message == reason) { assertions++; return; }
        throw new Exception("Expected IO refusal " + reason);
    }

    private static void TestAtomicRecovery(bool crash, bool integrated = false, bool afterReleaseFailure = false,
        bool beforeReceiptFailure = false, string? exitFixtureRoot = null, string? pendingFault = null)
    {
        var root = exitFixtureRoot ?? Path.Combine(Path.GetTempPath(), "lnwjud-orphan-fixture-" + Guid.NewGuid().ToString("N"));
        if (exitFixtureRoot is not null && (Directory.Exists(root) || File.Exists(root)
            || Path.GetDirectoryName(MaintenanceBoundaryFixture.ScopeRoot(Path.Combine(root, "maintenance"))) != root))
            throw new Exception("Unsafe subprocess recovery fixture root");
        Directory.CreateDirectory(root);
        try
        {
            var store = Path.Combine(root, "native");
            using (var protectedRoot = new WindowsStoreIO(store)) { }
            var imports = Directory.CreateDirectory(Path.Combine(store, "imports")).FullName;
            var workspace = Directory.CreateDirectory(Path.Combine(root, "workspace")).FullName;
            var home = Directory.CreateDirectory(Path.Combine(root, "home")).FullName;
            var stage = Path.Combine(root, ".lnwjud-import-stage-" + Guid.NewGuid().ToString("D"));
            var destination = Directory.CreateDirectory(Path.Combine(workspace, "repo")).FullName;
            File.WriteAllText(Path.Combine(destination, "existing.txt"), "preserved destination");
            using var user = WindowsIdentity.GetCurrent();
            var token = user.AccessToken;
            var sid = user.User!.Value;
            var taskId = "repository-import-" + Guid.NewGuid().ToString("D");
            var id = new ServiceAttemptIdentity(taskId, taskId, taskId, 1, Hash("atomic request"), "fixture-client", "fixture-session", "fixture-workspace");
            var request = new ServiceAttemptRequest(id, sid, ServiceAttemptLedger.GlobalReservationKey, Hash("atomic operation"), Shared: true);
            var ledgerPath = Path.Combine(store, "attempts.json");
            var ledger = new ServiceAttemptLedger(new ServiceAttemptLedgerPersistence(ledgerPath), imports);
            ledger.Prepare(request);
            ledger.TryCommitDispatch(id, sid, request.OperationDigest);
            ledger.MarkRunning(id, sid, Environment.ProcessId);
            var runtime = new ServiceImportTransactionRuntime(ledger, imports);
            var args = new ServiceImportArguments(workspace, "repo", stage, new string('c', 40), home);
            runtime.Control("prepare_import", id, sid, JsonSerializer.SerializeToElement(args,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }), token);
            File.WriteAllText(Path.Combine(stage, "stage.txt"), "preserved stage");
            ledger.RecordTerminal(id, sid, ServiceProcessOutcome.Completed, 1, 0);
            var old = JsonNode.Parse(File.ReadAllText(ledgerPath))!.AsObject();
            old["schemaVersion"] = 2;
            old["attempts"]!.AsArray()[0]!["request"]!.AsObject().Remove("importValidationPending");
            File.WriteAllText(ledgerPath, old.ToJsonString());
            void Reopen()
            {
                ledger = new ServiceAttemptLedger(new ServiceAttemptLedgerPersistence(ledgerPath), imports);
                runtime = new ServiceImportTransactionRuntime(ledger, imports);
            }
            Reopen();
            var recordPath = ServiceImportTransactionRuntime.RecordFilename(imports, id);
            var ledgerBefore = File.ReadAllText(ledgerPath);
            var recordBefore = File.ReadAllText(recordPath);
            OrphanImportEvidence Inspect() => OrphanImportPreflight.InspectFixture(store, id, token, true);
            NativeMaintenanceAuthority Make(OrphanImportAction action,
                Func<NativeMaintenanceProposal, NativeMaintenanceConsentReply>? answer = null,
                Func<(OrphanImportEvidence, string)>? inspect = null)
                => NativeMaintenanceAuthority.ForFixture(id, action, inspect ?? (() => (Inspect(), "atomic-fixture-logon")),
                    new FixtureConsent(answer ?? (p => new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly))));
            NativeAtomicFixtureResult Apply(NativeMaintenanceAuthority authority) => authority.ReviewAndApplyFixture(runtime, token);
            PersistedServiceAttempt ReadAttempt() => new ServiceAttemptLedgerPersistence(ledgerPath).Load().Single(row => row.Request.Identity == id);
            ServiceImportRecord ReadTransaction() => ServiceImportTransactionRuntime.ReadRecord(recordPath, id, sid)!;
            bool Unchanged() => File.ReadAllText(ledgerPath) == ledgerBefore && File.ReadAllText(recordPath) == recordBefore;

            if (integrated)
            {
                var boundaryRoot = Path.Combine(root, "maintenance");
                MaintenanceBoundaryFixture.Initialize(boundaryRoot);
                using var fence = MaintenanceBoundaryFixture.Fence(boundaryRoot);
                var fenceDigest = fence.FenceDigest;
                var journal = Path.Combine(boundaryRoot, "journal.json");
                var fencedBytes = File.ReadAllBytes(journal);
                var channel = QualifiedRecoveryConsentFixture.Capture(token, Guid.NewGuid().ToString("D"));
                NativeAtomicFixtureResult Qualified(OrphanImportAction action, Func<NativeMaintenanceProposal, string?> answer,
                    Func<RecoveryChannelFixture>? observe = null, string? digest = null, string? alternateRoot = null,
                    Func<TimeSpan>? elapsed = null)
                    => NativeRecoveryAdapter.ExecuteRecoveryFixture(alternateRoot ?? root, id, action, token,
                        fence, digest ?? fenceDigest, runtime,
                        new QualifiedRecoveryConsentFixture(observe ?? (() => channel), answer), elapsed);
                NativeAtomicFixtureResult Execute(OrphanImportAction action,
                    Func<NativeMaintenanceProposal, NativeMaintenanceConsentReply> answer,
                    string? digest = null, string? alternateRoot = null, Func<TimeSpan>? elapsed = null)
                    => Qualified(action, p =>
                    {
                        var reply = answer(p);
                        return reply.Decision == NativeMaintenanceDecision.ApproveFixtureRecovery && reply.Challenge == p.Challenge
                            ? QualifiedRecoveryConsentFixture.ExactText(p) : null;
                    }, digest: digest, alternateRoot: alternateRoot, elapsed: elapsed);
                NativeMaintenanceConsentReply Approve(NativeMaintenanceProposal p)
                    => new(p.Challenge, NativeMaintenanceDecision.ApproveFixtureRecovery);
                bool StillFenced() => File.ReadAllBytes(journal).SequenceEqual(fencedBytes)
                    && fence.FenceDigest == fenceDigest;
                using (var competingLifetime = ProductionMaintenanceBoundary.EnterLifetimeFixture(boundaryRoot, () => null))
                    IoRefused(() => Execute(OrphanImportAction.RecordBootWitness,
                        _ => throw new Exception("Consent prompted during competing lifetime")),
                        "SERVICE_MAINTENANCE_LIFETIME_BUSY");
                Check(Unchanged() && StillFenced(), "Live service lifetime prevents recovery before consent");
                Refused(() => fence.CompleteFixture(fenceDigest), "MAINTENANCE_FIXTURE_FENCE_MISMATCH");
                IoRefused(() => Apply(Make(OrphanImportAction.RecordBootWitness)), "ATOMIC_FIXTURE_BOUNDARY_MISSING");
                Refused(() => Execute(OrphanImportAction.RecordBootWitness,
                    p => LocalMaintenanceDialog.DialogFixture(() => { },
                        _ => throw new Exception("Read-only dialog displayed for mutation")).Request(p)),
                    "LOCAL_MAINTENANCE_PROPOSAL_INVALID");
                Refused(() => Make(OrphanImportAction.RecordBootWitness, Approve).Review(), "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                Refused(() => Execute(OrphanImportAction.RecordBootWitness, Approve, digest: Hash("wrong fence")),
                    "MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
                Refused(() => Execute(OrphanImportAction.RecordBootWitness, Approve,
                    alternateRoot: Path.Combine(Path.GetTempPath(), "lnwjud-orphan-fixture-" + Guid.NewGuid().ToString("N"))),
                    "MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
                Refused(() => Execute(OrphanImportAction.RecordBootWitness,
                    p => new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly)),
                    "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                Refused(() => Execute(OrphanImportAction.RecordBootWitness,
                    p => new(p.Challenge, NativeMaintenanceDecision.Deny)),
                    "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                Refused(() => Execute(OrphanImportAction.RecordBootWitness, Approve, elapsed: () => TimeSpan.FromMinutes(2)),
                    "NATIVE_MAINTENANCE_CONSENT_EXPIRED");
                Check(Unchanged() && StillFenced(), "Wrong fence, foreign root, read-only approval, denial and timeout preserve native records and fence");
                foreach (var bad in new[] {
                    channel with { Local = false }, channel with { Elevated = false },
                    channel with { SecureInteraction = false }, channel with { OwnerSid = "S-1-5-21-999" },
                    channel with { Session = 0 }, channel with { Session = channel.Session + 1 },
                    channel with { SecurityDigest = Hash("other token") }, channel with { Logon = "other-logon" },
                    channel with { ChannelId = "invalid" }
                })
                    Refused(() => Qualified(OrphanImportAction.RecordBootWitness,
                        _ => throw new Exception("Unverified channel prompted"), () => bad),
                        "RECOVERY_FIXTURE_CHANNEL_UNVERIFIED");
                foreach (var substitute in new Func<NativeMaintenanceProposal, string?>[] {
                    _ => "yes",
                    p => QualifiedRecoveryConsentFixture.ExactText(p) + " ",
                    p => QualifiedRecoveryConsentFixture.ExactText(p with { FenceDigest = Hash("wrong fence") }),
                    p => QualifiedRecoveryConsentFixture.ExactText(p with { Evidence = p.Evidence with { Action = OrphanImportAction.AbortPreparedImport } }),
                    p => QualifiedRecoveryConsentFixture.ExactText(p with { Challenge = Hash("old challenge") }),
                    p => QualifiedRecoveryConsentFixture.ExactText(p with { Evidence = p.Evidence with { NativeDigest = Hash("other evidence") } }),
                    p => QualifiedRecoveryConsentFixture.ExactText(p with { Evidence = p.Evidence with {
                        Identity = p.Evidence.Identity with { AttemptId = "repository-import-" + Guid.NewGuid().ToString("D") } } })
                })
                    Refused(() => Qualified(OrphanImportAction.RecordBootWitness, substitute),
                        "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                var observedCount = 0;
                Refused(() => Qualified(OrphanImportAction.RecordBootWitness, QualifiedRecoveryConsentFixture.ExactText,
                    () => ++observedCount == 1 ? channel : channel with { ChannelId = Guid.NewGuid().ToString("D") }),
                    "RECOVERY_FIXTURE_CHANNEL_CHANGED");
                observedCount = 0;
                Refused(() => Qualified(OrphanImportAction.RecordBootWitness, QualifiedRecoveryConsentFixture.ExactText,
                    () => ++observedCount <= 2 ? channel : channel with { SecureInteraction = false }),
                    "RECOVERY_FIXTURE_CHANNEL_UNVERIFIED");
                var single = new QualifiedRecoveryConsentFixture(() => channel, _ => null);
                Refused(() => NativeRecoveryAdapter.ExecuteRecoveryFixture(root, id, OrphanImportAction.RecordBootWitness,
                    token, fence, fenceDigest, runtime, single), "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                Refused(() => NativeRecoveryAdapter.ExecuteRecoveryFixture(root, id, OrphanImportAction.RecordBootWitness,
                    token, fence, fenceDigest, runtime, single), "RECOVERY_FIXTURE_CHANNEL_REPLAY");
                Check(Unchanged() && StillFenced(), "Channel and exact confirmation refusals preserve native authority");
                string? firstChallenge = null;
                var bootOnly = Execute(OrphanImportAction.RecordBootWitness, p =>
                {
                    Check(p.Scope == "native-import-fixture-recovery-v1" && p.Evidence.Identity == id
                        && p.Evidence.Action == OrphanImportAction.RecordBootWitness && p.FenceDigest == fenceDigest,
                        "Distinct fixture mutation consent scope and exact fence");
                    firstChallenge = p.Challenge;
                    Refused(() => fence.Dispose(), "MAINTENANCE_FIXTURE_WRITER_ACTIVE");
                    Refused(() => fence.CompleteFixture(fenceDigest), "MAINTENANCE_FIXTURE_FENCE_MISMATCH");
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "OWNER_BUSY",
                        "Independent writer excluded during consent");
                    Check(MaintenanceBoundaryTests.Probe("production-lifetime-probe", boundaryRoot, 77)
                        == "SERVICE_MAINTENANCE_LIFETIME_BUSY", "Independent service lifetime excluded during consent");
                    return Approve(p);
                });
                Check(bootOnly.BootWitnessRecorded && !bootOnly.NativeHoldReleased && ReadAttempt().ReservationHeld
                    && StillFenced(), "Witness-only result cannot reopen admission");
                Refused(() => Execute(OrphanImportAction.AbortPreparedImport, Approve), "ORPHAN_NEW_BOOT_REQUIRED");

                // Simulated historical boot, not a reboot of the host.
                var historicalFixture = JsonNode.Parse(File.ReadAllText(ledgerPath))!.AsObject();
                historicalFixture["attempts"]!.AsArray()[0]!["request"]!["legacyImportObservedBoot"] = Guid.NewGuid().ToString("D");
                File.WriteAllText(ledgerPath, historicalFixture.ToJsonString());
                Reopen();
                Refused(() => Execute(OrphanImportAction.AbortPreparedImport,
                    p => new(firstChallenge!, NativeMaintenanceDecision.ApproveFixtureRecovery)),
                    "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                var preAbortLedger = File.ReadAllText(ledgerPath);
                if (pendingFault is not null)
                {
                    var preAbortRecord = File.ReadAllBytes(recordPath);
                    fence.FailAfterStageForTest = pendingFault;
                    try { IoRefused(() => Execute(OrphanImportAction.AbortPreparedImport, Approve),
                        "RECOVERY_FIXTURE_STAGED_" + pendingFault); }
                    finally { fence.FailAfterStageForTest = null; }
                    var pendingPath = Path.Combine(boundaryRoot, pendingFault == "fence" ? "journal.pending.json" : "transaction.pending.json");
                    var targetPath = Path.Combine(boundaryRoot, pendingFault == "fence" ? "journal.json" : "transaction.json");
                    var pendingBytes = File.ReadAllBytes(pendingPath);
                    var pendingDigest = WindowsStoreIO.Hash(pendingBytes);
                    var targetBefore = File.Exists(targetPath) ? File.ReadAllBytes(targetPath) : null;
                    var nativeLedger = File.ReadAllBytes(ledgerPath);
                    var nativeRecord = File.ReadAllBytes(recordPath);
                    if (exitFixtureRoot is not null)
                    {
                        Console.WriteLine("PENDING_FIXTURE=" + fenceDigest + ":" + pendingDigest);
                        Console.Out.Flush();
                        Environment.Exit(0);
                    }
                    Check(ReadAttempt().ReservationHeld == (pendingFault == "intent"), "Stage interruption has expected native hold");
                    if (pendingFault == "intent")
                        Check(File.ReadAllText(ledgerPath) == preAbortLedger && nativeRecord.SequenceEqual(preAbortRecord),
                            "Intent staging precedes all abort mutations");
                    Refused(() => fence.ReconcilePendingFixture(fenceDigest, Hash("wrong pending"), id, token),
                        "RECOVERY_PENDING_DIGEST_MISMATCH");
                    Refused(() => fence.ReconcilePendingFixture(fenceDigest, pendingDigest, id with { OwnerSessionId = "foreign" }, token),
                        "RECOVERY_PENDING_SUCCESSOR_INVALID");
                    // A validly encoded but wrong successor must not publish.
                    byte[] altered;
                    if (pendingFault == "fence")
                    {
                        var json = JsonNode.Parse(pendingBytes)!.AsObject();
                        json["receipt"] = Hash("other receipt");
                        altered = Wire.Encode(json);
                    }
                    else
                    {
                        var receipt = RecoveryReceiptFixture.Decode(pendingBytes);
                        altered = (receipt with { ExpectedPostDigest = Hash("other expected state") }).Encode();
                    }
                    File.WriteAllBytes(pendingPath, altered);
                    Refused(() => fence.ReconcilePendingFixture(fenceDigest, WindowsStoreIO.Hash(altered), id, token),
                        pendingFault == "intent" ? "RECOVERY_PENDING_INTENT_UNVERIFIED" : "RECOVERY_PENDING_SUCCESSOR_INVALID");
                    Check(File.ReadAllBytes(pendingPath).SequenceEqual(altered), "Rejected pending evidence retained");
                    File.WriteAllBytes(pendingPath, pendingBytes);
                    Check(targetBefore is null ? !File.Exists(targetPath) : File.ReadAllBytes(targetPath).SequenceEqual(targetBefore),
                        "Invalid successor never overwrites published predecessor");
                    if (pendingFault != "intent")
                    {
                        var changed = JsonNode.Parse(nativeRecord)!.AsObject();
                        changed["arguments"]!["commit"] = new string('f', 40);
                        File.WriteAllText(recordPath, changed.ToJsonString());
                        Refused(() => fence.ReconcilePendingFixture(fenceDigest, pendingDigest, id, token),
                            "RECOVERY_RECEIPT_POST_STATE_UNVERIFIED");
                        File.WriteAllBytes(recordPath, nativeRecord);
                    }
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "OWNER_BUSY",
                        "Writer excluded during pending publication");
                    ServiceImportTransactionRuntime.Fault = _ => throw new Exception("Pending reconciliation invoked native Abort");
                    try
                    {
                        fence.ReconcilePendingFixture(fenceDigest, pendingDigest, id, token);
                        Check(!File.Exists(pendingPath) && File.ReadAllBytes(targetPath).SequenceEqual(pendingBytes),
                            "Exact staged successor published and read back");
                        if (pendingFault == "receipt")
                            fence.ReconcileReleasedFixture(fenceDigest, pendingDigest, id, token);
                    }
                    finally { ServiceImportTransactionRuntime.Fault = null; }
                    Check(File.ReadAllBytes(ledgerPath).SequenceEqual(nativeLedger) && File.ReadAllBytes(recordPath).SequenceEqual(nativeRecord),
                        "Pending reconciliation does not change native state");
                    if (pendingFault == "intent")
                    {
                        // Recovered intent was published before native mutation.
                        // A new exact consent can perform the first abort, not a replay.
                        Refused(() => Execute(OrphanImportAction.AbortPreparedImport,
                            p => new(p.Challenge, NativeMaintenanceDecision.Deny)), "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                        Check(ReadAttempt().ReservationHeld && File.ReadAllBytes(ledgerPath).SequenceEqual(nativeLedger),
                            "Recovered intent alone cannot authorize abort");
                        var result = Execute(OrphanImportAction.AbortPreparedImport, Approve);
                        Check(result.NativeHoldReleased && !ReadAttempt().ReservationHeld, "Fresh consent executes first abort after recovered intent");
                    }
                    fence.Dispose();
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 0) == "ADMITTED",
                        "Only verified released receipt and open journal permit writer");
                    Console.WriteLine("PASS exact pending " + pendingFault + " publication");
                    return;
                }
                ServiceImportTransactionRuntime.Fault = point =>
                {
                    if (point == "after_abort_record")
                    {
                        Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "OWNER_BUSY",
                            "Independent writer excluded at actual tombstone write");
                        Check(MaintenanceBoundaryTests.Probe("production-lifetime-probe", boundaryRoot, 77)
                            == "SERVICE_MAINTENANCE_LIFETIME_BUSY", "Independent service lifetime excluded at tombstone write");
                        if (crash) throw new IOException("INTEGRATED_FIXTURE_CRASH");
                    }
                };
                NativeAtomicFixtureResult? integratedResult = null;
                try
                {
                    fence.FailAfterRecoveryReadbackForTest = afterReleaseFailure;
                    fence.FailBeforeRecoveryReceiptForTest = beforeReceiptFailure;
                    if (beforeReceiptFailure) IoRefused(() => Execute(OrphanImportAction.AbortPreparedImport, Approve),
                        "INTEGRATED_FIXTURE_AFTER_RELEASE_BEFORE_RECEIPT");
                    else if (afterReleaseFailure) IoRefused(() => Execute(OrphanImportAction.AbortPreparedImport, Approve),
                        "INTEGRATED_FIXTURE_AFTER_RELEASE_BEFORE_OPEN");
                    else if (crash) IoRefused(() => Execute(OrphanImportAction.AbortPreparedImport, Approve), "INTEGRATED_FIXTURE_CRASH");
                    else integratedResult = Execute(OrphanImportAction.AbortPreparedImport, Approve);
                }
                finally { ServiceImportTransactionRuntime.Fault = null; fence.FailAfterRecoveryReadbackForTest = false;
                    fence.FailBeforeRecoveryReceiptForTest = false; }
                if (afterReleaseFailure || beforeReceiptFailure)
                {
                    Check(!ReadAttempt().ReservationHeld && !ReadAttempt().Request.HoldForImport
                        && ReadTransaction().Phase == ServiceImportPhase.Aborted && StillFenced(),
                        "Failure after verified native release leaves durable fence closed");
                    // A released tombstone is outside the held-import preflight
                    // contract. No retry or ordinary completion may reopen.
                    try { _ = Inspect(); throw new Exception("Released import accepted as held"); }
                    catch (Refusal) { assertions++; }
                    Refused(() => fence.CompleteFixture(fenceDigest), "MAINTENANCE_FIXTURE_FENCE_MISMATCH");
                    var receiptPath = Path.Combine(boundaryRoot, "transaction.json");
                    var receipt = RecoveryReceiptFixture.Decode(File.ReadAllBytes(receiptPath));
                    Check(receipt.Identity == id && receipt.OwnerSid == sid
                        && (receipt.ReleasedWitness is null) == beforeReceiptFailure,
                        "Durable intent survives before receipt; receipt survives before open");
                    var exactReceipt = fence.RecoveryReceiptDigestFixture;
                    var releasedLedger = File.ReadAllBytes(ledgerPath);
                    var releasedRecord = File.ReadAllBytes(recordPath);
                    if (exitFixtureRoot is not null)
                    {
                        Console.WriteLine("RELEASED_FIXTURE=" + fenceDigest + ":" + exactReceipt);
                        Console.Out.Flush();
                        // Real process termination without disposing the
                        // owned fence, after the injected release failure.
                        Environment.Exit(0);
                    }
                    Refused(() => fence.ReconcileReleasedFixture(fenceDigest, Hash("wrong receipt"), id, token),
                        "RECOVERY_RECEIPT_DIGEST_MISMATCH");
                    Refused(() => fence.ReconcileReleasedFixture(fenceDigest, exactReceipt,
                        id with { OwnerSessionId = "other-session" }, token), "RECOVERY_RECEIPT_ATTEMPT_MISMATCH");
                    Check(StillFenced(), "Wrong receipt and attempt cannot reopen");
                    var changedLedger = JsonNode.Parse(releasedLedger)!.AsObject();
                    changedLedger["attempts"]!.AsArray()[0]!["request"]!["cancellationRequested"] = true;
                    File.WriteAllText(ledgerPath, changedLedger.ToJsonString());
                    Refused(() => fence.ReconcileReleasedFixture(fenceDigest, exactReceipt, id, token),
                        "RECOVERY_RECEIPT_POST_STATE_UNVERIFIED");
                    File.WriteAllBytes(ledgerPath, releasedLedger);
                    Check(StillFenced(), "Changed semantic ledger cannot reopen");
                    var changedImport = JsonNode.Parse(releasedRecord)!.AsObject();
                    changedImport["arguments"]!["commit"] = new string('e', 40);
                    File.WriteAllText(recordPath, changedImport.ToJsonString());
                    Refused(() => fence.ReconcileReleasedFixture(fenceDigest, exactReceipt, id, token),
                        "RECOVERY_RECEIPT_POST_STATE_UNVERIFIED");
                    File.WriteAllBytes(recordPath, releasedRecord);
                    Check(StillFenced(), "Changed semantic tombstone cannot reopen");
                    // A directory replacement is not a valid released witness.
                    Directory.Move(destination, destination + "-original");
                    Directory.CreateDirectory(destination);
                    Refused(() => fence.ReconcileReleasedFixture(fenceDigest, exactReceipt, id, token),
                        "RECOVERY_RECEIPT_DIRECTORY_CHANGED");
                    Directory.Delete(destination);
                    Directory.Move(destination + "-original", destination);
                    Check(StillFenced(), "Changed destination leaves fence closed");
                    ServiceImportTransactionRuntime.Fault = _ => throw new Exception("Reconciliation attempted Abort again");
                    try { fence.ReconcileReleasedFixture(fenceDigest, exactReceipt, id, token); }
                    finally { ServiceImportTransactionRuntime.Fault = null; }
                    var finalReceipt = RecoveryReceiptFixture.Decode(File.ReadAllBytes(receiptPath));
                    Check(finalReceipt.ReleasedWitness is not null && finalReceipt.ExpectedPostDigest == receipt.ExpectedPostDigest
                        && finalReceipt.Identity == id && File.ReadAllBytes(ledgerPath).SequenceEqual(releasedLedger)
                        && File.ReadAllBytes(recordPath).SequenceEqual(releasedRecord),
                        "Reconciliation creates or verifies receipt without changing native files");
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "OWNER_BUSY",
                        "Writer still excluded until lock disposal");
                    fence.Dispose();
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 0) == "ADMITTED",
                        "Verified exact reconciliation opens admission");
                    var receiptBytes = File.ReadAllBytes(receiptPath);
                    File.Move(receiptPath, receiptPath + ".saved");
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "RECOVERY_RECEIPT_OPEN_UNVERIFIED",
                        "Open journal without exact receipt denies admission");
                    File.Move(receiptPath + ".saved", receiptPath);
                    File.WriteAllText(receiptPath, "{}");
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "RECOVERY_RECEIPT_OPEN_UNVERIFIED",
                        "Changed receipt denies admission despite open journal");
                    File.WriteAllBytes(receiptPath, receiptBytes);
                    Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 0) == "ADMITTED",
                        "Exact restored test receipt allows admission");
                    Check(File.ReadAllText(Path.Combine(destination, "existing.txt")) == "preserved destination"
                        && File.ReadAllText(Path.Combine(stage, "stage.txt")) == "preserved stage", "Post-release failure preserves directories");
                    Console.WriteLine("PASS integrated recovery adapter fixture " + (beforeReceiptFailure ? "intent-only reconciliation" : "receipt reconciliation"));
                    return;
                }
                if (crash)
                {
                    Check(ReadTransaction().Phase == ServiceImportPhase.Aborted && ReadAttempt().ReservationHeld
                        && StillFenced() && File.ReadAllText(ledgerPath) != preAbortLedger, "Crash leaves durable tombstone, verified boot and sticky fence");
                    Reopen();
                    Refused(() => Execute(OrphanImportAction.AbortPreparedImport, Approve), "NATIVE_MAINTENANCE_EXACT_SCOPE_REQUIRED");
                    Check(StillFenced() && ReadAttempt().ReservationHeld, "Stale action after crash cannot reopen admission");
                    integratedResult = Execute(OrphanImportAction.FinishAbortedHold, Approve);
                }
                Check(integratedResult is { NativeHoldReleased: true, BootWitnessRecorded: false }
                    && integratedResult.Identity == id && !ReadAttempt().ReservationHeld && !ReadAttempt().Request.HoldForImport
                    && ReadAttempt().Request.AuthenticatedCallerSid == sid
                    && ReadTransaction().Phase == ServiceImportPhase.Aborted && ReadTransaction().Arguments == args,
                    "Integrated exact durable abort readback");
                Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "OWNER_BUSY",
                    "Even completed fixture cannot admit until lock disposal");
                Check(File.ReadAllText(Path.Combine(destination, "existing.txt")) == "preserved destination"
                    && File.ReadAllText(Path.Combine(stage, "stage.txt")) == "preserved stage", "Integrated directory preservation");
                fence.Dispose();
                Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 0) == "ADMITTED",
                    "Verified release and disposal reopen only the fixture");
                Console.WriteLine("PASS integrated recovery adapter fixture " + (crash ? "crash resume" : "direct abort"));
                return;
            }

            if (crash)
            {
                var denied = Make(OrphanImportAction.RecordBootWitness, p => new(p.Challenge, NativeMaintenanceDecision.Deny));
                Refused(() => Apply(denied), "NATIVE_MAINTENANCE_CONSENT_REFUSED");
                Check(Unchanged(), "Denied consent preserves both stores");
                var expired = Make(OrphanImportAction.RecordBootWitness);
                expired.ElapsedForTest = () => TimeSpan.FromMinutes(2);
                Refused(() => Apply(expired), "NATIVE_MAINTENANCE_CONSENT_EXPIRED");
                Check(Unchanged(), "Expired consent preserves both stores");

                Directory.Move(destination, destination + "-original");
                IoRefused(() => Apply(Make(OrphanImportAction.RecordBootWitness)), "ATOMIC_FIXTURE_DESTINATION_ABSENT");
                Check(Unchanged(), "Unpinnable destination refused");
                Directory.Move(destination + "-original", destination);

                var staleLedger = Make(OrphanImportAction.RecordBootWitness, p =>
                {
                    var changed = JsonNode.Parse(ledgerBefore)!.AsObject();
                    changed["attempts"]!.AsArray()[0]!["request"]!["cancellationRequested"] = true;
                    File.WriteAllText(ledgerPath, changed.ToJsonString());
                    return new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly);
                });
                IoRefused(() => Apply(staleLedger), "ATOMIC_FIXTURE_LEDGER_CHANGED");
                Check(File.ReadAllText(ledgerPath) != ledgerBefore && File.ReadAllText(recordPath) == recordBefore,
                    "Stale in-memory ledger never overwrites changed disk");
                File.WriteAllText(ledgerPath, ledgerBefore);
                Reopen();

                var staleRecord = Make(OrphanImportAction.RecordBootWitness, p =>
                {
                    var changed = JsonNode.Parse(recordBefore)!.AsObject();
                    changed["arguments"]!["commit"] = new string('d', 40);
                    File.WriteAllText(recordPath, changed.ToJsonString());
                    return new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly);
                });
                IoRefused(() => Apply(staleRecord), "ATOMIC_FIXTURE_ARGUMENTS_CHANGED");
                Check(File.ReadAllText(ledgerPath) == ledgerBefore && File.ReadAllText(recordPath) != recordBefore,
                    "Changed transaction not overwritten");
                File.WriteAllText(recordPath, recordBefore);

                var staleEvidence = Inspect();
                var changedAfterConsent = Make(OrphanImportAction.RecordBootWitness, p =>
                {
                    var changed = JsonNode.Parse(recordBefore)!.AsObject();
                    // Same parsed fields but different protected bytes.
                    File.WriteAllText(recordPath, changed.ToJsonString() + " ");
                    return new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly);
                }, () => (staleEvidence, "atomic-fixture-logon"));
                IoRefused(() => Apply(changedAfterConsent), "ATOMIC_FIXTURE_EVIDENCE_CHANGED");
                Check(File.ReadAllText(ledgerPath) == ledgerBefore, "Independent native reread rejects stale adapter proof");
                File.WriteAllText(recordPath, recordBefore);

                var swappedDestination = Make(OrphanImportAction.RecordBootWitness, p =>
                {
                    Directory.Move(destination, destination + "-original");
                    Directory.CreateDirectory(destination);
                    return new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly);
                });
                Refused(() => Apply(swappedDestination), "NATIVE_MAINTENANCE_EVIDENCE_CHANGED");
                Check(Unchanged(), "Destination identity change after consent cannot write ledger");
                Directory.Delete(destination);
                Directory.Move(destination + "-original", destination);
            }

            // Observe actual lock exclusion in a single fixture service:
            // a second ledger operation cannot enter during final consent
            // revalidation. It runs only after the boot-witness commit.
            Task<ServiceAttemptObservation>? competing = null;
            using var started = new ManualResetEventSlim();
            int inspections = 0;
            var witness = Make(OrphanImportAction.RecordBootWitness, inspect: () =>
            {
                var e = Inspect();
                if (++inspections == 2)
                {
                    competing = Task.Run(() => { started.Set(); return ledger.Inspect(id, sid); });
                    Check(started.Wait(TimeSpan.FromSeconds(3)) && !competing.Wait(TimeSpan.FromMilliseconds(150)),
                        "Ledger gate excludes concurrent observation during final check");
                }
                return (e, "atomic-fixture-logon");
            });
            var first = Apply(witness);
            Check(first.BootWitnessRecorded && !first.NativeHoldReleased && first.Identity == id, "Witness-only action");
            Check(competing!.Wait(TimeSpan.FromSeconds(3)) && competing.Result.ReservationHeld,
                "Competing operation observes completed witness and retained hold");
            var observed = ReadAttempt();
            Check(observed.Request.LegacyImportObservedBoot == firstBoot() && observed.Request.LegacyImportVerifiedBoot is null
                && observed.ReservationHeld && observed.Request.HoldForImport && ReadTransaction().Phase == ServiceImportPhase.Prepared,
                "Durable first witness, no abort");
            string firstBoot() => NativeBootIdentity.Read();
            Refused(() => Apply(witness), "NATIVE_MAINTENANCE_REPLAY_REFUSED");
            Refused(() => Apply(Make(OrphanImportAction.AbortPreparedImport)), "ORPHAN_NEW_BOOT_REQUIRED");

            // Model the earlier boot on disposable disk only; actual current
            // kernel boot and missing attempt Job are read by the engine.
            var historical = JsonNode.Parse(File.ReadAllText(ledgerPath))!.AsObject();
            historical["attempts"]!.AsArray()[0]!["request"]!["legacyImportObservedBoot"] = Guid.NewGuid().ToString("D");
            File.WriteAllText(ledgerPath, historical.ToJsonString());
            Reopen();
            var abort = Make(OrphanImportAction.AbortPreparedImport);
            NativeAtomicFixtureResult final;
            if (crash)
            {
                ServiceImportTransactionRuntime.Fault = point =>
                {
                    if (point == "after_abort_record") throw new IOException("ATOMIC_FIXTURE_CRASH_AFTER_TOMBSTONE");
                };
                try { IoRefused(() => Apply(abort), "ATOMIC_FIXTURE_CRASH_AFTER_TOMBSTONE"); }
                finally { ServiceImportTransactionRuntime.Fault = null; }
                Check(ReadTransaction().Phase == ServiceImportPhase.Aborted && ReadAttempt().ReservationHeld
                    && ReadAttempt().Request.HoldForImport && ServiceAttemptLedger.HasLegacyBootProof(ReadAttempt().Request),
                    "Actual durable tombstone persists before ledger release");
                Refused(() => Apply(abort), "NATIVE_MAINTENANCE_REPLAY_REFUSED");
                Reopen();
                var finish = Make(OrphanImportAction.FinishAbortedHold);
                final = Apply(finish);
                Refused(() => Apply(finish), "NATIVE_MAINTENANCE_REPLAY_REFUSED");
            }
            else
            {
                // Independent approvals are both issued while the exact
                // prepared state exists. Only one may commit under the same
                // runtime/ledger locks; the other must observe changed state.
                using var barrier = new Barrier(2);
                NativeMaintenanceConsentReply RaceConsent(NativeMaintenanceProposal p)
                {
                    if (!barrier.SignalAndWait(TimeSpan.FromSeconds(5)))
                        throw new Exception("Fixture concurrent consent deadline");
                    return new(p.Challenge, NativeMaintenanceDecision.ApproveNativeOnly);
                }
                NativeAtomicFixtureResult? Race()
                {
                    try { return Apply(Make(OrphanImportAction.AbortPreparedImport, RaceConsent)); }
                    catch (Refusal error) when (error.Reason == "ORPHAN_ABORT_HISTORY_UNVERIFIED")
                    {
                        return null;
                    }
                }
                var raceA = Task.Run(Race);
                var raceB = Task.Run(Race);
                Check(Task.WaitAll([raceA, raceB], TimeSpan.FromSeconds(10)), "Concurrent approvals finish within deadline");
                Check((raceA.Result is null) != (raceB.Result is null), "Exactly one independently approved abort commits");
                final = (raceA.Result ?? raceB.Result)!;
            }
            var saved = ReadAttempt();
            Check(final.NativeHoldReleased && !final.BootWitnessRecorded && final.Identity == id
                && saved.Request.Identity == id && saved.Request.AuthenticatedCallerSid == sid
                && !saved.ReservationHeld && !saved.Request.HoldForImport
                && saved.Request.PublicationCommitted == false && saved.Request.ImportValidationPending is null
                && saved.Request.LegacyImportVerifiedBoot == firstBoot(), "Exact verified release readback");
            Check(ReadTransaction().Phase == ServiceImportPhase.Aborted && ReadTransaction().Arguments == args
                && File.ReadAllText(Path.Combine(destination, "existing.txt")) == "preserved destination"
                && File.ReadAllText(Path.Combine(stage, "stage.txt")) == "preserved stage", "No directory or repository mutation");
            Check(!ledger.Inspect(id, sid).ReservationHeld, "Live fixture ledger agrees with persisted release");
            Console.WriteLine("PASS atomic native maintenance fixture " + (crash ? "crash recovery" : "direct abort"));
        }
        finally
        {
            ServiceImportTransactionRuntime.Fault = null;
            if (!Path.GetFileName(root).StartsWith("lnwjud-orphan-fixture-", StringComparison.Ordinal))
                throw new Exception("Unsafe fixture cleanup");
            Directory.Delete(root, true);
        }
    }

    internal static void ReleasedReceiptChild(string boundaryRoot)
    {
        var root = Path.GetDirectoryName(MaintenanceBoundaryFixture.ScopeRoot(boundaryRoot))!;
        TestAtomicRecovery(false, integrated: true, beforeReceiptFailure: true, exitFixtureRoot: root);
        throw new Exception("Expected fixture owner exit");
    }

    internal static void PendingFenceChild(string boundaryRoot)
    {
        var root = Path.GetDirectoryName(MaintenanceBoundaryFixture.ScopeRoot(boundaryRoot))!;
        TestAtomicRecovery(false, integrated: true, exitFixtureRoot: root, pendingFault: "fence");
        throw new Exception("Expected fixture owner exit");
    }

    private static void TestPendingFenceOwnerExit()
    {
        var root = Path.Combine(Path.GetTempPath(), "lnwjud-orphan-fixture-" + Guid.NewGuid().ToString("N"));
        var boundaryRoot = Path.Combine(root, "maintenance");
        try
        {
            var output = MaintenanceBoundaryTests.Probe("pending-fence-child", boundaryRoot, 0);
            var line = output.Split('\n').Select(x => x.Trim()).Single(x => x.StartsWith("PENDING_FIXTURE=", StringComparison.Ordinal));
            var parts = line["PENDING_FIXTURE=".Length..].Split(':');
            Check(parts.Length == 2 && Wire.Digest(parts[0]) && Wire.Digest(parts[1]), "Exact exited-owner pending fence proof");
            Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "MAINTENANCE_FIXTURE_PENDING",
                "Exited owner pending journal still blocks writers");
            var receipt = RecoveryReceiptFixture.Decode(File.ReadAllBytes(Path.Combine(boundaryRoot, "transaction.json")));
            var store = Path.Combine(root, "native");
            var ledger = Path.Combine(store, "attempts.json");
            var record = ServiceImportTransactionRuntime.RecordFilename(Path.Combine(store, "imports"), receipt.Identity);
            var ledgerBytes = File.ReadAllBytes(ledger);
            var recordBytes = File.ReadAllBytes(record);
            using var user = WindowsIdentity.GetCurrent();
            Refused(() => MaintenanceBoundaryFixture.ReconcileExitedOwnerPendingFixture(boundaryRoot,
                Hash("wrong fence"), parts[1], receipt.Identity, user.AccessToken), "MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
            MaintenanceBoundaryFixture.ReconcileExitedOwnerPendingFixture(boundaryRoot, parts[0], parts[1], receipt.Identity, user.AccessToken);
            Check(!File.Exists(Path.Combine(boundaryRoot, "journal.pending.json"))
                && File.ReadAllBytes(ledger).SequenceEqual(ledgerBytes)
                && File.ReadAllBytes(record).SequenceEqual(recordBytes), "New process publishes pending fence without native mutation");
            Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 0) == "ADMITTED", "Exact pending open survives owner exit");
            Refused(() => MaintenanceBoundaryFixture.ReconcileExitedOwnerPendingFixture(boundaryRoot,
                parts[0], parts[1], receipt.Identity, user.AccessToken), "MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
            Console.WriteLine("PASS pending fence publication after actual owner process exit");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static void TestReleasedOwnerExit()
    {
        var root = Path.Combine(Path.GetTempPath(), "lnwjud-orphan-fixture-" + Guid.NewGuid().ToString("N"));
        var boundaryRoot = Path.Combine(root, "maintenance");
        try
        {
            var output = MaintenanceBoundaryTests.Probe("released-receipt-child", boundaryRoot, 0);
            var line = output.Split('\n').Select(x => x.Trim()).Single(x => x.StartsWith("RELEASED_FIXTURE=", StringComparison.Ordinal));
            var parts = line["RELEASED_FIXTURE=".Length..].Split(':');
            Check(parts.Length == 2 && Wire.Digest(parts[0]) && Wire.Digest(parts[1]), "Exited owner exact fence and intent");
            Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 77) == "MAINTENANCE_FIXTURE_FENCED",
                "Real owner exit retains post-release fence");
            var receiptPath = Path.Combine(boundaryRoot, "transaction.json");
            var receipt = RecoveryReceiptFixture.Decode(File.ReadAllBytes(receiptPath));
            Check(receipt.ReleasedWitness is null && receipt.Digest == parts[1], "Intent survives owner process exit");
            var store = Path.Combine(root, "native");
            var ledgerPath = Path.Combine(store, "attempts.json");
            var recordPath = ServiceImportTransactionRuntime.RecordFilename(Path.Combine(store, "imports"), receipt.Identity);
            var ledgerBytes = File.ReadAllBytes(ledgerPath);
            var recordBytes = File.ReadAllBytes(recordPath);
            using var user = WindowsIdentity.GetCurrent();
            using (var resumed = MaintenanceBoundaryFixture.Resume(boundaryRoot, parts[0]))
            {
                Check(resumed.FenceDigest != parts[0] && resumed.RecoveryReceiptDigestFixture == parts[1],
                    "New owner changes fence digest but preserves exact epoch intent");
                Refused(() => resumed.ReconcileReleasedFixture(parts[0], parts[1], receipt.Identity, user.AccessToken),
                    "MAINTENANCE_FIXTURE_RECOVERY_SCOPE");
                resumed.ReconcileReleasedFixture(resumed.FenceDigest, parts[1], receipt.Identity, user.AccessToken);
                Check(File.ReadAllBytes(ledgerPath).SequenceEqual(ledgerBytes)
                    && File.ReadAllBytes(recordPath).SequenceEqual(recordBytes), "New owner only reconciles fence, not native files");
            }
            Check(MaintenanceBoundaryTests.Probe("probe", boundaryRoot, 0) == "ADMITTED",
                "Post-release reconciliation after real owner exit");
            Console.WriteLine("PASS integrated recovery receipt after actual owner process exit");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    internal static void Run()
    {
        TestAtomicRecovery(false);
        TestAtomicRecovery(true);
        TestAtomicRecovery(false, integrated: true);
        TestAtomicRecovery(true, integrated: true);
        TestAtomicRecovery(false, integrated: true, afterReleaseFailure: true);
        TestAtomicRecovery(false, integrated: true, beforeReceiptFailure: true);
        TestReleasedOwnerExit();
        TestAtomicRecovery(false, integrated: true, pendingFault: "intent");
        TestAtomicRecovery(false, integrated: true, pendingFault: "receipt");
        TestAtomicRecovery(false, integrated: true, pendingFault: "fence");
        TestPendingFenceOwnerExit();
        var root = Path.Combine(Path.GetTempPath(), "lnwjud-orphan-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var store = Path.Combine(root, "native");
            using (var protectedRoot = new WindowsStoreIO(store)) { }
            var imports = Directory.CreateDirectory(Path.Combine(store, "imports")).FullName;
            var workspace = Directory.CreateDirectory(Path.Combine(root, "workspace")).FullName;
            var home = Directory.CreateDirectory(Path.Combine(root, "home")).FullName;
            var stage = Path.Combine(root, ".lnwjud-import-stage-" + Guid.NewGuid().ToString("D"));
            Directory.CreateDirectory(Path.Combine(workspace, "repo"));
            File.WriteAllText(Path.Combine(workspace, "repo", "existing.txt"), "preserved");
            using var user = WindowsIdentity.GetCurrent();
            var taskId = "repository-import-" + Guid.NewGuid().ToString("D");
            var identity = new ServiceAttemptIdentity(taskId, taskId, taskId, 1, Hash("request"), "fixture-client", "fixture-session", "fixture-workspace");
            var sid = user.User!.Value;
            var request = new ServiceAttemptRequest(identity, sid, ServiceAttemptLedger.GlobalReservationKey, Hash("operation"), Shared: true);
            var ledgerPath = Path.Combine(store, "attempts.json");
            var ledger = new ServiceAttemptLedger(new ServiceAttemptLedgerPersistence(ledgerPath), imports);
            ledger.Prepare(request);
            ledger.TryCommitDispatch(identity, sid, request.OperationDigest);
            ledger.MarkRunning(identity, sid, Environment.ProcessId);
            var runtime = new ServiceImportTransactionRuntime(ledger, imports);
            var args = new ServiceImportArguments(workspace, "repo", stage, new string('a', 40), home);
            runtime.Control("prepare_import", identity, sid, JsonSerializer.SerializeToElement(args,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }), user.AccessToken);
            File.WriteAllText(Path.Combine(stage, "stage.txt"), "preserved");
            ledger.RecordTerminal(identity, sid, ServiceProcessOutcome.Completed, 1, 0);
            OrphanImportEvidence Inspect(ServiceAttemptIdentity? expected = null, bool admin = true)
                => OrphanImportPreflight.InspectFixture(store, expected ?? identity, user.AccessToken, admin);
            Refused(() => Inspect(admin: false), "ORPHAN_ADMIN_REQUIRED");
            Refused(() => Inspect(identity with { Generation = 2 }), "ORPHAN_ATTEMPT_INVALID");
            Refused(() => Inspect(), "ORPHAN_LEGACY_ONLY");
            var historical = JsonNode.Parse(File.ReadAllText(ledgerPath))!.AsObject();
            historical["schemaVersion"] = 2;
            historical["attempts"]!.AsArray()[0]!["request"]!.AsObject().Remove("importValidationPending");
            var original = historical.ToJsonString();
            File.WriteAllText(ledgerPath, original);
            var importPath = ServiceImportTransactionRuntime.RecordFilename(imports, identity);
            var beforeLedger = FileHash(ledgerPath);
            var beforeImport = FileHash(importPath);
            var evidence = Inspect();
            Check(evidence.Identity == identity && evidence.OwnerSid == sid && evidence.SchemaVersion == 2, "Exact protected owner binding");
            Check(evidence.Action == OrphanImportAction.RecordBootWitness && evidence == Inspect(), "Stable read-only V2 proof");
            Refused(() => Inspect(identity with { OwnerClientId = "foreign" }), "ORPHAN_OWNER_UNVERIFIED");
            Refused(() => Inspect(identity with { OwnerSessionId = "foreign" }), "ORPHAN_OWNER_UNVERIFIED");
            Refused(() => Inspect(identity with { WorkspaceId = "foreign" }), "ORPHAN_OWNER_UNVERIFIED");
            Refused(() => Inspect(identity with { RequestDigest = Hash("foreign") }), "ORPHAN_OWNER_UNVERIFIED");
            TestApproval(evidence);
            TestBroker(store, identity, user.AccessToken, ledgerPath);
            TestNativeOnlyAuthority(evidence, () => Inspect());
            TestLocalUtility(store, evidence, user, () => Inspect());
            var reopened = new ServiceAttemptLedger(new ServiceAttemptLedgerPersistence(ledgerPath), imports);
            TestRpcRefusal(reopened, identity, args, root).GetAwaiter().GetResult();
            TestRpcRefusal(reopened, identity, args, root, "native_maintenance_review", "SERVICE_COMMAND_UNSUPPORTED").GetAwaiter().GetResult();
            TestRpcRefusal(reopened, identity, args, root, "native_maintenance_recover", "SERVICE_COMMAND_UNSUPPORTED").GetAwaiter().GetResult();
            TestRpcRefusal(reopened, identity, args, root, "native-maintenance-review", "SERVICE_COMMAND_UNSUPPORTED").GetAwaiter().GetResult();
            Check(reopened.Inspect(identity, sid).ReservationHeld, "RPC refusal retained original hold");
            Check(FileHash(ledgerPath) == beforeLedger && FileHash(importPath) == beforeImport, "Preflight and grant contract do not write native authority");

            void Change(Action<JsonObject, JsonObject> edit)
            {
                var document = JsonNode.Parse(original)!.AsObject();
                var row = document["attempts"]!.AsArray()[0]!.AsObject();
                edit(document, row);
                File.WriteAllText(ledgerPath, document.ToJsonString());
            }
            Change((_, row) => row["request"]!["authenticatedCallerSid"] = "S-1-5-21-999");
            Refused(() => Inspect(), "ORPHAN_OWNER_UNVERIFIED");
            Refused(() => LocalMaintenanceUtility.ResolveFixture(store,
                new LocalMaintenanceTarget(identity.AttemptId, identity.RequestDigest, OrphanImportAction.RecordBootWitness),
                user, true), "LOCAL_MAINTENANCE_OWNER_UNVERIFIED");
            Change((_, row) => row["request"]!["publicationCommitted"] = true);
            Refused(() => Inspect(), "COORDINATED_NATIVE_HOLD_UNVERIFIED");
            Change((_, row) => row["request"]!["publicationCommitted"] = null);
            Refused(() => Inspect(), "COORDINATED_NATIVE_HOLD_UNVERIFIED");
            Change((document, row) =>
            {
                document["schemaVersion"] = 3;
                row["request"]!["legacyImportObservedBoot"] = evidence.BootId;
            });
            Refused(() => Inspect(), "ORPHAN_NEW_BOOT_REQUIRED");
            // Simulated historical witness in fixture only, not an actual reboot.
            Change((document, row) =>
            {
                document["schemaVersion"] = 3;
                row["request"]!["legacyImportObservedBoot"] = Guid.NewGuid().ToString("D");
            });
            var next = Inspect();
            Check(next.Action == OrphanImportAction.AbortPreparedImport && next.NativeDigest != evidence.NativeDigest, "Different recorded boot changes action and evidence");
            var oldGrant = new OrphanImportApprovalSession(evidence);
            oldGrant.ConfirmFromTrustedLocalUi(oldGrant.Challenge, evidence);
            Refused(() => oldGrant.ConsumeForContractTest(oldGrant.Challenge, next), "ORPHAN_APPROVAL_REFUSED");
            // Synthetic persisted post-crash tombstone: no actual abort runs.
            var preparedRecord = File.ReadAllText(importPath);
            var tombstone = JsonNode.Parse(preparedRecord)!.AsObject();
            tombstone["version"] = 2;
            tombstone["phase"] = (int)ServiceImportPhase.Aborted;
            using (var anchor = new RepositoryImportAnchor(workspace, "repo", false))
                tombstone["abortDestinationIdentity"] = anchor.PinAbortDestinationIdentityOrMissing();
            tombstone["abortDestinationMissing"] = false;
            File.WriteAllText(importPath, tombstone.ToJsonString());
            Refused(() => Inspect(), "ORPHAN_ABORT_HOLD_UNVERIFIED");
            Change((document, row) =>
            {
                document["schemaVersion"] = 3;
                row["request"]!["legacyImportObservedBoot"] = Guid.NewGuid().ToString("D");
                row["request"]!["legacyImportVerifiedBoot"] = evidence.BootId;
            });
            var crashed = Inspect();
            Check(crashed.Action == OrphanImportAction.FinishAbortedHold, "Durable aborted-held proof selects a distinct action");
            var stale = new OrphanImportApprovalSession(next);
            stale.ConfirmFromTrustedLocalUi(stale.Challenge, next);
            Refused(() => stale.ConsumeForContractTest(stale.Challenge, crashed), "ORPHAN_APPROVAL_REFUSED");
            Directory.Move(Path.Combine(workspace, "repo"), Path.Combine(workspace, "repo-original"));
            Directory.CreateDirectory(Path.Combine(workspace, "repo"));
            Refused(() => Inspect(), "ORPHAN_ABORT_DIRECTORY_CHANGED");
            Directory.Delete(Path.Combine(workspace, "repo"));
            Directory.Move(Path.Combine(workspace, "repo-original"), Path.Combine(workspace, "repo"));
            File.WriteAllText(importPath, preparedRecord);
            File.WriteAllText(ledgerPath, original);
            Directory.Move(stage, stage + "-original");
            Directory.CreateDirectory(stage);
            Refused(() => Inspect(), "COORDINATED_IMPORT_DIRECTORY_CHANGED");
            Check(FileHash(ledgerPath) == beforeLedger && FileHash(importPath) == beforeImport, "No native hold release");
            Check(File.ReadAllText(Path.Combine(workspace, "repo", "existing.txt")) == "preserved"
                && File.ReadAllText(Path.Combine(stage + "-original", "stage.txt")) == "preserved", "Preserved directories");
            Console.WriteLine($"PASS orphan import native preflight and one-time approval contract ({assertions} assertions)");
        }
        finally
        {
            if (!Path.GetFileName(root).StartsWith("lnwjud-orphan-fixture-", StringComparison.Ordinal))
                throw new Exception("Unsafe fixture cleanup");
            Directory.Delete(root, true);
        }
    }
}
