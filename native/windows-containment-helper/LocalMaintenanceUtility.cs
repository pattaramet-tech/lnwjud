using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// Explicit local read-only command. No supplied paths, owner rebind, grant,
// application RPC, SCM operation, or mutating recovery is available.
internal sealed record LocalMaintenanceTarget(string AttemptId, string RequestDigest, OrphanImportAction Action)
{
    internal static LocalMaintenanceTarget Parse(string[] args)
    {
        const string prefix = "repository-import-";
        if (args.Length != 4 || args[0] != "native-maintenance-review"
            || !args[1].StartsWith(prefix, StringComparison.Ordinal)
            || !Guid.TryParseExact(args[1][prefix.Length..], "D", out var id) || id == Guid.Empty
            || args[1] != prefix + id.ToString("D") || !Wire.Digest(args[2]))
            throw new Refusal("LOCAL_MAINTENANCE_TARGET_INVALID");
        var action = args[3] switch
        {
            "record-boot-witness" => OrphanImportAction.RecordBootWitness,
            "abort-prepared-import" => OrphanImportAction.AbortPreparedImport,
            "finish-aborted-hold" => OrphanImportAction.FinishAbortedHold,
            _ => throw new Refusal("LOCAL_MAINTENANCE_ACTION_INVALID"),
        };
        return new(args[1], args[2], action);
    }
}

[SupportedOSPlatform("windows")]
internal static class LocalMaintenanceUtility
{
    internal static NativeMaintenanceReview RunReadOnly(string[] args)
    {
        var target = LocalMaintenanceTarget.Parse(args);
        using var user = WindowsIdentity.GetCurrent();
        _ = NativeMaintenanceAuthority.RequireLocalOperator(user);
        LocalMaintenanceDialog.RequireInteractiveDesktop();
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "lnwjud-containment");
        var expected = Resolve(root, target, user.User!.Value);
        return NativeRecoveryAdapter.ReviewLocal(expected, target.Action);
    }

    private static ServiceAttemptIdentity Resolve(string root, LocalMaintenanceTarget target, string sid)
    {
        using var pin = new CoordinatedProtectedWitness(root, ["attempts.json"]);
        var before = pin.Digest();
        var records = new ServiceAttemptLedgerPersistence(Path.Combine(root, "attempts.json")).Load();
        var matches = records.Where(row => row.Request.Identity.AttemptId == target.AttemptId).ToArray();
        if (matches.Length != 1) throw new Refusal("LOCAL_MAINTENANCE_OWNER_UNVERIFIED");
        var record = matches[0];
        ServiceAttemptLedger.ValidateStored(record);
        var identity = record.Request.Identity;
        if (record.Request.AuthenticatedCallerSid != sid || identity.RequestDigest != target.RequestDigest
            || identity.TaskId != target.AttemptId || identity.ReservationId != target.AttemptId
            || identity.Generation != 1 || before != pin.Digest())
            throw new Refusal("LOCAL_MAINTENANCE_OWNER_UNVERIFIED");
        return identity;
    }

#if NATIVE_CONTAINMENT_TESTS
    internal static ServiceAttemptIdentity ResolveFixture(string root, LocalMaintenanceTarget target,
        System.Security.Principal.WindowsIdentity user, bool elevated)
    {
        if (!elevated) throw new Refusal("NATIVE_MAINTENANCE_ELEVATION_REQUIRED");
        return Resolve(root, target, user.User!.Value);
    }
#endif
}

// Windows-native local consent, never exposed to renderer IPC or MCP. Default
// No on every screen. Desktop checks are not cryptographic human-presence
// proof; privileged same-desktop automation is outside this read-only contract.
[SupportedOSPlatform("windows")]
internal sealed class LocalMaintenanceDialog : INativeMaintenanceLocalConsent
{
    private const string Caption = "lnwjud - READ-ONLY native maintenance review";
    private readonly Action requireDesktop;
    private readonly Func<string, int> show;
    private int used;

    private LocalMaintenanceDialog(Action requireDesktop, Func<string, int> show)
    {
        this.requireDesktop = requireDesktop;
        this.show = show;
    }

    internal static LocalMaintenanceDialog Create()
        => new(RequireInteractiveDesktop, text => MessageBoxW(0, text, Caption,
            0x00000004u /* YESNO */ | 0x00000030u /* WARNING */ | 0x00000100u /* DEFBUTTON2 */));

#if NATIVE_CONTAINMENT_TESTS
    internal static LocalMaintenanceDialog DialogFixture(Action requireDesktop, Func<string, int> show)
        => new(requireDesktop, show);
#endif

    private static string Display(string? value)
    {
        if (value is null || value.Length is < 1 or > 512)
            throw new Refusal("LOCAL_MAINTENANCE_DISPLAY_UNVERIFIED");
        // Quote and escape every non-ASCII code unit, including line breaks,
        // bidi controls and quotes. Never allow path/owner text to spoof labels.
        var escaped = JsonSerializer.Serialize(value);
        if (escaped.Length > 1024) throw new Refusal("LOCAL_MAINTENANCE_DISPLAY_UNVERIFIED");
        return escaped;
    }

    internal static string[] BuildPages(NativeMaintenanceProposal proposal)
    {
        if (proposal.Scope != NativeMaintenanceAuthority.Scope || proposal.FenceDigest is not null || !Wire.Digest(proposal.Challenge)
            || !Wire.Digest(proposal.AuthorityEpoch)) throw new Refusal("LOCAL_MAINTENANCE_PROPOSAL_INVALID");
        var e = proposal.Evidence;
        var id = e.Identity;
        var a = e.Arguments;
        var action = e.Action switch
        {
            OrphanImportAction.RecordBootWitness => "RecordBootWitness (future action: record boot proof only)",
            OrphanImportAction.AbortPreparedImport => "AbortPreparedImport (future action: abort prepared import)",
            OrphanImportAction.FinishAbortedHold => "FinishAbortedHold (future action: finish a persisted abort)",
            _ => throw new Refusal("LOCAL_MAINTENANCE_ACTION_INVALID"),
        };
        const string header = "READ-ONLY REVIEW. No reservation will be released. No files will be changed.\n";
        var pages = new[]
        {
            header + "1/4 - Exact target\n\nAction: " + action
                + "\nTask / attempt / reservation: " + Display(id.AttemptId)
                + "\nGeneration: " + id.Generation.ToString(CultureInfo.InvariantCulture)
                + "\nRequest digest: " + Display(id.RequestDigest)
                + "\nOriginal owner SID: " + Display(e.OwnerSid)
                + "\n\nYes: continue review. No: cancel.",
            header + "2/4 - Original binding\n\nAttempt: " + Display(id.AttemptId)
                + "\nClient: " + Display(id.OwnerClientId) + "\nOriginal session: " + Display(id.OwnerSessionId)
                + "\nWorkspace: " + Display(id.WorkspaceId)
                + "\nWindows session: " + e.WindowsSession.ToString(CultureInfo.InvariantCulture)
                + "\nOperator logon: " + Display(proposal.OperatorLogon)
                + "\nOperator security digest: " + Display(e.OperatorSecurityDigest)
                + "\n\nYes: continue review. No: cancel.",
            header + "3/4 - Protected import record\n\nWorkspace root: " + Display(a.WorkspaceRoot)
                + "\nDestination: " + Display(a.Destination) + "\nStage: " + Display(a.StagePath)
                + "\nCommit: " + Display(a.Commit) + "\nPrivate home: " + Display(a.PrivateHome)
                + "\n\nPaths are quoted with JSON escaping.\nYes: continue review. No: cancel.",
            header + "4/4 - Confirm exact review\n\nAction: " + action
                + "\nAttempt: " + Display(id.AttemptId)
                + "\nBoot: " + Display(e.BootId)
                + "\nLedger schema: " + e.SchemaVersion.ToString(CultureInfo.InvariantCulture)
                + "\nNative evidence digest: " + Display(e.NativeDigest)
                + "\nChallenge: " + Display(proposal.Challenge)
                + "\n\nApplication state is NOT verified. This is NOT authorization to abort, "
                + "release a hold, or write a file. Approval expires in two minutes."
                + "\n\nYes: confirm this read-only review. No: cancel.",
        };
        if (id.TaskId != id.AttemptId || id.ReservationId != id.AttemptId
            || pages.Any(page => page.Length > 1800))
            throw new Refusal("LOCAL_MAINTENANCE_DISPLAY_UNVERIFIED");
        return pages;
    }

    public NativeMaintenanceConsentReply Request(NativeMaintenanceProposal proposal)
    {
        if (Interlocked.Exchange(ref used, 1) != 0) throw new Refusal("LOCAL_MAINTENANCE_DIALOG_REPLAY");
        foreach (var page in BuildPages(proposal))
        {
            requireDesktop();
            var answer = show(page);
            requireDesktop();
            if (answer != 6 /* IDYES */) return new(proposal.Challenge, NativeMaintenanceDecision.Deny);
        }
        return new(proposal.Challenge, NativeMaintenanceDecision.ApproveNativeOnly);
    }

    internal static void RequireInteractiveDesktop()
    {
        using var user = WindowsIdentity.GetCurrent();
        _ = NativeMaintenanceAuthority.RequireLocalOperator(user);
        var station = GetProcessWindowStation();
        var thread = GetThreadDesktop(GetCurrentThreadId());
        if (station == 0 || thread == 0 || Name(station) != "WinSta0" || Name(thread) != "Default")
            throw new Refusal("LOCAL_MAINTENANCE_DESKTOP_UNAVAILABLE");
        var input = OpenInputDesktop(0, false, 0x0001 /* DESKTOP_READOBJECTS */);
        if (input == 0) throw new Refusal("LOCAL_MAINTENANCE_DESKTOP_UNAVAILABLE");
        try
        {
            if (Name(input) != "Default") throw new Refusal("LOCAL_MAINTENANCE_DESKTOP_UNAVAILABLE");
        }
        finally { _ = CloseDesktop(input); }
    }

    private static string Name(nint handle)
    {
        var result = new StringBuilder(128);
        if (!GetUserObjectInformationW(handle, 2 /* UOI_NAME */, result, 256, out var needed)
            || needed is < 2 or > 256)
            throw new Refusal("LOCAL_MAINTENANCE_DESKTOP_UNAVAILABLE");
        return result.ToString();
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int MessageBoxW(nint window, string text, string caption, uint type);
    [DllImport("user32.dll")] private static extern nint GetProcessWindowStation();
    [DllImport("user32.dll")] private static extern nint GetThreadDesktop(uint id);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint OpenInputDesktop(uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(nint desktop);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformationW(nint handle, int index, StringBuilder value,
        uint length, out uint needed);
}
