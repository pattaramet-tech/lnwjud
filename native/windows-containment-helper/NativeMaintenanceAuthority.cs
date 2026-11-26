using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// Native-only review contract. An affirmative review is NOT a recovery grant,
// an application task receipt, a writer lease, or evidence of profile absence.
// Local read-only CLI uses this contract. No mutating CLI, RPC, renderer IPC,
// or grant transport is registered.
internal sealed record NativeMaintenanceProposal(string Challenge, string Scope,
    OrphanImportEvidence Evidence, string OperatorLogon, string AuthorityEpoch, string? FenceDigest = null);
internal enum NativeMaintenanceDecision { Deny, ApproveNativeOnly
#if NATIVE_CONTAINMENT_TESTS
    , ApproveFixtureRecovery
#endif
}
internal sealed record NativeMaintenanceConsentReply(string Challenge, NativeMaintenanceDecision Decision);

// Reserved for a trusted composition root, not a caller-supplied MCP adapter.
// The future UI must display the immutable proposal and solicit a fresh
// human decision. The interface alone is NOT proof of physical human presence.
internal interface INativeMaintenanceLocalConsent
{
    NativeMaintenanceConsentReply Request(NativeMaintenanceProposal proposal);
}

// This is a diagnostic result, with no bearer token or conversion to an
// executable capability. Future mutation needs a separate atomic boundary.
internal sealed record NativeMaintenanceReview(string Scope, ServiceAttemptIdentity Identity,
    OrphanImportAction Action, string NativeDigest, string BootId, string OwnerSid,
    bool ApplicationStateVerified, bool MutationPerformed, bool CooperativeBoundaryVerified = false);

#if NATIVE_CONTAINMENT_TESTS
internal sealed record NativeAtomicFixtureResult(ServiceAttemptIdentity Identity, OrphanImportAction Action,
    bool BootWitnessRecorded, bool NativeHoldReleased);
#endif

[SupportedOSPlatform("windows")]
internal sealed class NativeMaintenanceAuthority
{
    internal const string Scope = "native-import-only-v1";
    private readonly Func<(OrphanImportEvidence Evidence, string Logon)> inspect;
    private readonly INativeMaintenanceLocalConsent consent;
    private readonly ServiceAttemptIdentity expected;
    private readonly OrphanImportAction action;
    private readonly string epoch = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
    private int used;

    private NativeMaintenanceAuthority(ServiceAttemptIdentity expected, OrphanImportAction action,
        Func<(OrphanImportEvidence Evidence, string Logon)> inspect, INativeMaintenanceLocalConsent consent)
    {
        this.expected = expected;
        this.action = action;
        this.inspect = inspect;
        this.consent = consent;
    }

    // The read-only utility is the production composition root. It is
    // deliberately local-process-only, not a server-side pipe impersonation.
    // The Windows dialog is not a secure-desktop human-presence proof.
    internal static NativeMaintenanceAuthority ForLocalOperator(ServiceAttemptIdentity expected,
        OrphanImportAction action)
        => new(expected, action, () =>
        {
            // Revalidate the actual desktop at both evidence inspections,
            // not merely while the dialog is visible.
            LocalMaintenanceDialog.RequireInteractiveDesktop();
            return InspectLocalOperator(expected);
        }, LocalMaintenanceDialog.Create());

#if NATIVE_CONTAINMENT_TESTS
    internal static NativeMaintenanceAuthority ForFixture(ServiceAttemptIdentity expected,
        OrphanImportAction action, Func<(OrphanImportEvidence Evidence, string Logon)> inspect,
        INativeMaintenanceLocalConsent consent)
        => new(expected, action, inspect, consent);
    internal Func<TimeSpan>? ElapsedForTest { get; set; }
#endif

    // Verify the real local process token before any protected store lookup.
    internal static (uint Session, string Logon) RequireLocalOperator(WindowsIdentity identity)
    {
        using var impersonated = WindowsIdentity.GetCurrent(ifImpersonating: true);
        if (impersonated is not null) throw new Refusal("NATIVE_MAINTENANCE_IMPERSONATION_REFUSED");
        using var current = WindowsIdentity.GetCurrent();
        if (identity.User?.Value is null || identity.User.Value != current.User?.Value
            || AuthenticatedPipeCaller.SecurityFingerprint(identity.AccessToken)
                != AuthenticatedPipeCaller.SecurityFingerprint(current.AccessToken)
            || ReadAuthenticationId(identity.AccessToken) != ReadAuthenticationId(current.AccessToken))
            throw new Refusal("NATIVE_MAINTENANCE_OPERATOR_CHANGED");
        var token = identity.AccessToken;
        var session = AuthenticatedPipeCaller.ReadSessionId(token.DangerousGetHandle());
        if (session == 0 || session == UInt32.MaxValue || session != WTSGetActiveConsoleSessionId())
            throw new Refusal("NATIVE_MAINTENANCE_LOCAL_CONSOLE_REQUIRED");
        if (!GetTokenElevation(token, 20, out var elevated, sizeof(uint), out var size)
            || size != sizeof(uint) || elevated != 1
            || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new Refusal("NATIVE_MAINTENANCE_ELEVATION_REQUIRED");
        return (session, ReadAuthenticationId(token));
    }

    private static (OrphanImportEvidence Evidence, string Logon) InspectLocalOperator(ServiceAttemptIdentity expected)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var token = identity.AccessToken;
        var (session, logon) = RequireLocalOperator(identity);
        var evidence = OrphanImportPreflight.Inspect(expected, token);
        if (evidence.WindowsSession != session || session != WTSGetActiveConsoleSessionId()
            || evidence.OwnerSid != identity.User?.Value || logon != ReadAuthenticationId(token))
            throw new Refusal("NATIVE_MAINTENANCE_OPERATOR_CHANGED");
        return (evidence, logon);
    }

    private void RequireExact((OrphanImportEvidence Evidence, string Logon) observed)
    {
        var e = observed.Evidence;
        if (e.Identity != expected || e.Action != action || !Enum.IsDefined(action)
            || String.IsNullOrWhiteSpace(e.OwnerSid) || e.WindowsSession == 0
            || !Wire.Digest(e.NativeDigest) || !Wire.Digest(e.OperatorSecurityDigest)
            || !Guid.TryParseExact(e.BootId, "D", out var boot) || boot == Guid.Empty
            || e.SchemaVersion is not (2 or 3) || String.IsNullOrWhiteSpace(observed.Logon))
            throw new Refusal("NATIVE_MAINTENANCE_EXACT_SCOPE_REQUIRED");
    }

    internal NativeMaintenanceReview Review() => ReviewCore();

#if NATIVE_CONTAINMENT_TESTS
    // The approval is retained inside this invocation, not returned as a
    // bearer grant. Only the disposable fixture runtime can execute it.
    internal NativeAtomicFixtureResult ReviewAndApplyFixture(ServiceImportTransactionRuntime runtime,
        Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token,
        MaintenanceBoundaryFixture? boundary = null, string? fenceDigest = null)
    {
        NativeAtomicFixtureResult? applied = null;
        _ = ReviewCore((approved, verify) =>
        {
            NativeMaintenanceReview? reviewed = null;
            applied = runtime.ApplyApprovedMaintenanceFixture(approved, token, () => reviewed = verify(), boundary, fenceDigest);
            return reviewed ?? throw new Refusal("ATOMIC_FIXTURE_REVIEW_MISSING");
        }, fenceDigest);
        return applied ?? throw new Refusal("ATOMIC_FIXTURE_RESULT_MISSING");
    }
#endif

    private NativeMaintenanceReview ReviewCore(
#if NATIVE_CONTAINMENT_TESTS
        Func<OrphanImportEvidence, Func<NativeMaintenanceReview>, NativeMaintenanceReview>? fixtureComplete = null,
        string? fixtureFenceDigest = null
#endif
        )
    {
        // One call for the lifetime of this authority instance, even if the
        // adapter denies, throws, reenters, or a subsequent check fails.
        if (Interlocked.Exchange(ref used, 1) != 0)
            throw new Refusal("NATIVE_MAINTENANCE_REPLAY_REFUSED");
        var first = inspect();
        RequireExact(first);
        var e = first.Evidence;
        var id = e.Identity;
        var args = e.Arguments;
        var purpose = Scope;
        var decision = NativeMaintenanceDecision.ApproveNativeOnly;
        string? fence = null;
#if NATIVE_CONTAINMENT_TESTS
        if (fixtureFenceDigest is not null)
        {
            if (fixtureComplete is null || !Wire.Digest(fixtureFenceDigest))
                throw new Refusal("NATIVE_MAINTENANCE_FIXTURE_FENCE_INVALID");
            purpose = "native-import-fixture-recovery-v1";
            decision = NativeMaintenanceDecision.ApproveFixtureRecovery;
            fence = fixtureFenceDigest;
        }
#endif
        var challenge = WindowsStoreIO.Hash(Wire.Encode(new JsonObject
        {
            ["purpose"] = purpose, ["epoch"] = epoch, ["fence"] = fence,
            ["nonce"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(),
            ["task"] = id.TaskId, ["attempt"] = id.AttemptId, ["reservation"] = id.ReservationId,
            ["generation"] = id.Generation, ["request"] = id.RequestDigest,
            ["client"] = id.OwnerClientId, ["session"] = id.OwnerSessionId, ["workspace"] = id.WorkspaceId,
            ["ownerSid"] = e.OwnerSid, ["security"] = e.OperatorSecurityDigest,
            ["windowsSession"] = e.WindowsSession, ["logon"] = first.Logon,
            ["boot"] = e.BootId, ["nativeDigest"] = e.NativeDigest, ["schema"] = e.SchemaVersion,
            ["action"] = e.Action.ToString(), ["workspaceRoot"] = args.WorkspaceRoot,
            ["destination"] = args.Destination, ["stage"] = args.StagePath, ["commit"] = args.Commit,
            ["privateHome"] = args.PrivateHome,
        }));
        var issued = Stopwatch.GetTimestamp();
        var proposal = new NativeMaintenanceProposal(challenge, purpose, e, first.Logon, epoch, fence);
        var reply = consent.Request(proposal);
        if (reply is null || reply.Decision != decision || reply.Challenge != challenge)
            throw new Refusal("NATIVE_MAINTENANCE_CONSENT_REFUSED");
        NativeMaintenanceReview Verify()
        {
            var fresh = inspect();
            RequireExact(fresh);
#if NATIVE_CONTAINMENT_TESTS
            var elapsed = ElapsedForTest?.Invoke() ?? Stopwatch.GetElapsedTime(issued);
#else
            var elapsed = Stopwatch.GetElapsedTime(issued);
#endif
            if (elapsed < TimeSpan.Zero || elapsed >= TimeSpan.FromMinutes(2))
                throw new Refusal("NATIVE_MAINTENANCE_CONSENT_EXPIRED");
            if (fresh != first) throw new Refusal("NATIVE_MAINTENANCE_EVIDENCE_CHANGED");
            return new(Scope, id, e.Action, e.NativeDigest, e.BootId, e.OwnerSid, false, false);
        }
#if NATIVE_CONTAINMENT_TESTS
        if (fixtureComplete is not null) return fixtureComplete(e, Verify);
#endif
        return Verify();
    }

    // TOKEN_STATISTICS.AuthenticationId is the LUID of the logon session,
    // not a caller-provided Windows session label. Read exactly the fixed
    // native structure; do not export it through any external API.
    internal static string ReadAuthenticationId(Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token)
    {
        var size = (uint)Marshal.SizeOf<TokenStatistics>();
        if (!GetTokenStatistics(token, 10, out var data, size, out var read) || read != size)
            throw new Refusal("NATIVE_MAINTENANCE_LOGON_UNVERIFIED");
        return data.AuthenticationId.High.ToString("X8") + ":" + data.AuthenticationId.Low.ToString("X8");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { internal uint Low; internal int High; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TokenStatistics
    {
        internal Luid TokenId, AuthenticationId;
        internal long ExpirationTime;
        internal int TokenType, ImpersonationLevel;
        internal uint DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount;
        internal Luid ModifiedId;
    }
    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenElevation(Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token,
        int type, out uint data, uint size, out uint returned);
    [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenStatistics(Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token,
        int type, out TokenStatistics data, uint size, out uint returned);
}
