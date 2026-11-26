#if NATIVE_CONTAINMENT_TESTS
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// Test-only simulation of a qualified local interaction channel. The flags
// are NOT evidence of a human, elevation or a real secure desktop.
internal sealed record RecoveryChannelFixture(string ChannelId, bool Local, bool Elevated,
    bool SecureInteraction, string OwnerSid, uint Session, string SecurityDigest, string Logon);

[SupportedOSPlatform("windows")]
internal sealed class QualifiedRecoveryConsentFixture : INativeMaintenanceLocalConsent
{
    private readonly Func<RecoveryChannelFixture> observe;
    private readonly Func<NativeMaintenanceProposal, string?> confirm;
    private int used;
    private RecoveryChannelFixture? acceptedChannel;
    private NativeMaintenanceProposal? acceptedProposal;

    internal QualifiedRecoveryConsentFixture(Func<RecoveryChannelFixture> observe,
        Func<NativeMaintenanceProposal, string?> confirm)
        => (this.observe, this.confirm) = (observe, confirm);

    // The security identity is real; only the interaction attributes above
    // are simulated. Never used against the installed authority.
    internal static RecoveryChannelFixture Capture(SafeAccessTokenHandle token, string channelId)
    {
        using var user = new WindowsIdentity(token.DangerousGetHandle());
        return new(channelId, true, true, true, user.User!.Value,
            AuthenticatedPipeCaller.ReadSessionId(token.DangerousGetHandle()),
            WindowsStoreIO.Hash(System.Text.Encoding.UTF8.GetBytes(AuthenticatedPipeCaller.SecurityFingerprint(token))),
            NativeMaintenanceAuthority.ReadAuthenticationId(token));
    }

    private static void RequireChannel(RecoveryChannelFixture c, NativeMaintenanceProposal p)
    {
        if (!Guid.TryParseExact(c.ChannelId, "D", out var channel) || channel == Guid.Empty
            || !c.Local || !c.Elevated || !c.SecureInteraction || c.OwnerSid != p.Evidence.OwnerSid
            || c.Session == 0 || c.Session != p.Evidence.WindowsSession
            || c.SecurityDigest != p.Evidence.OperatorSecurityDigest || c.Logon != p.OperatorLogon)
            throw new Refusal("RECOVERY_FIXTURE_CHANNEL_UNVERIFIED");
    }

    internal static string ExactText(NativeMaintenanceProposal p)
    {
        if (p.Scope != "native-import-fixture-recovery-v1" || p.FenceDigest is null
            || !Wire.Digest(p.FenceDigest) || !Wire.Digest(p.Challenge)
            || !Wire.Digest(p.Evidence.NativeDigest) || !Wire.Digest(p.AuthorityEpoch)
            || !Enum.IsDefined(p.Evidence.Action))
            throw new Refusal("RECOVERY_FIXTURE_PROPOSAL_INVALID");
        return "CONFIRM FIXTURE ONLY " + p.Evidence.Action + " " + p.Evidence.Identity.AttemptId
            + " " + p.FenceDigest + " " + p.Evidence.NativeDigest + " " + p.Challenge;
    }

    internal void Revalidate(OrphanImportEvidence evidence, string logon, string fence)
    {
        if (acceptedProposal is null) return; // initial evidence inspection
        var p = acceptedProposal;
        if (p.Evidence != evidence || p.OperatorLogon != logon || p.FenceDigest != fence)
            throw new Refusal("RECOVERY_FIXTURE_PROPOSAL_CHANGED");
        var fresh = observe();
        RequireChannel(fresh, p);
        if (fresh != acceptedChannel) throw new Refusal("RECOVERY_FIXTURE_CHANNEL_CHANGED");
    }

    public NativeMaintenanceConsentReply Request(NativeMaintenanceProposal p)
    {
        if (Interlocked.Exchange(ref used, 1) != 0)
            throw new Refusal("RECOVERY_FIXTURE_CHANNEL_REPLAY");
        var expected = ExactText(p);
        var before = observe();
        RequireChannel(before, p);
        var input = confirm(p);
        var after = observe();
        RequireChannel(after, p);
        if (before != after) throw new Refusal("RECOVERY_FIXTURE_CHANNEL_CHANGED");
        if (!String.Equals(input, expected, StringComparison.Ordinal))
            return new(p.Challenge, NativeMaintenanceDecision.Deny);
        acceptedChannel = after;
        acceptedProposal = p;
        return new(p.Challenge, NativeMaintenanceDecision.ApproveFixtureRecovery);
    }
}
#endif
