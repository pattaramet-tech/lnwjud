using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// This is the coordinated upgrade protocol, not an SCM or launcher adapter.
// Evidence must be supplied by a trusted, independently authenticated adapter.
// No live entry point may use this until the machine-wide fence is qualified.
internal enum CoordinatedPhase
{
    Prepared, FenceIntent, Fenced, NativeIntent, NativeSelected,
    DesktopIntent, DesktopSelected, Verified, OpenIntent, Completed
}

internal sealed record CoordinatedPlan(string TransactionId, string OldHelper, string CandidateHelper,
    string OldDesktop, string CandidateDesktop, string AuthorityDigest)
{
    internal void Validate()
    {
        if (!Guid.TryParseExact(TransactionId, "D", out var id) || id == Guid.Empty
            || new[] { OldHelper, CandidateHelper, OldDesktop, CandidateDesktop, AuthorityDigest }.Any(x => !Wire.Digest(x) || x.All(c => c == '0'))
            || OldHelper == CandidateHelper || OldDesktop == CandidateDesktop)
            throw new Refusal("COORDINATED_PLAN_INVALID");
    }
}

// AuthorityDigest binds the protected ledger, transaction, original owner,
// workspace/profile identity and preserved directory witnesses. It is not a
// substitute for independently verifying those inputs in the host adapter.
internal sealed record CoordinatedObservation(string Helper, string Desktop, string AuthorityDigest,
    bool Authenticated, bool Fenced, bool Quiesced, bool EndpointVerified, bool DesktopVerified);

internal sealed record CoordinatedJournal(CoordinatedPlan Plan, CoordinatedPhase Phase, string PreviousDigest)
{
    internal byte[] Encode()
    {
        Plan.Validate();
        if (!Enum.IsDefined(Phase) || (Phase == CoordinatedPhase.Prepared ? PreviousDigest != "none" : !Wire.Digest(PreviousDigest)))
            throw new Refusal("COORDINATED_JOURNAL_INVALID");
        return Wire.Encode(new JsonObject
        {
            ["schema"] = 1, ["transactionId"] = Plan.TransactionId,
            ["oldHelper"] = Plan.OldHelper, ["candidateHelper"] = Plan.CandidateHelper,
            ["oldDesktop"] = Plan.OldDesktop, ["candidateDesktop"] = Plan.CandidateDesktop,
            ["authorityDigest"] = Plan.AuthorityDigest, ["phase"] = Phase.ToString(),
            ["previousDigest"] = PreviousDigest,
        });
    }

    internal string Digest => WindowsStoreIO.Hash(Encode());

    internal static CoordinatedJournal Decode(byte[] bytes)
    {
        var obj = Wire.Object(bytes);
        Wire.Fields(obj, "schema", "transactionId", "oldHelper", "candidateHelper", "oldDesktop",
            "candidateDesktop", "authorityDigest", "phase", "previousDigest");
        if (Wire.Integer(obj, "schema") != 1 || !Enum.TryParse<CoordinatedPhase>(Wire.Text(obj, "phase"), out var phase)
            || phase.ToString() != Wire.Text(obj, "phase")) throw new Refusal("COORDINATED_JOURNAL_INVALID");
        var result = new CoordinatedJournal(new(Wire.Text(obj, "transactionId"), Wire.Text(obj, "oldHelper"),
            Wire.Text(obj, "candidateHelper"), Wire.Text(obj, "oldDesktop"), Wire.Text(obj, "candidateDesktop"),
            Wire.Text(obj, "authorityDigest")), phase, Wire.Text(obj, "previousDigest"));
        if (!bytes.AsSpan().SequenceEqual(result.Encode())) throw new Refusal("COORDINATED_JOURNAL_INVALID");
        return result;
    }
}

[SupportedOSPlatform("windows")]
internal sealed class CoordinatedUpgradeStore : IDisposable
{
    private readonly WindowsStoreIO io;
    private readonly Action<string>? boundary;
    internal CoordinatedUpgradeStore(string dedicatedStateRoot, Action<string>? boundary = null)
    {
        // Dedicated root only: never share a managed updater journal directory.
        io = new WindowsStoreIO(dedicatedStateRoot);
        this.boundary = boundary;
    }
    internal CoordinatedJournal? Read()
    {
        if (io.Read("journal.pending.json") is not null) throw new Refusal("COORDINATED_PUBLICATION_PENDING");
        return Published();
    }
    private CoordinatedJournal? Published() => io.Read("journal.json") is { } file ? CoordinatedJournal.Decode(file.Bytes) : null;

    internal CoordinatedJournal Begin(CoordinatedPlan plan, CoordinatedObservation observed)
    {
        plan.Validate();
        if (Read() is not null) throw new Refusal("COORDINATED_ALREADY_STARTED");
        Require(plan, observed, candidateHelper: false, candidateDesktop: false);
        if (observed.Fenced) throw new Refusal("COORDINATED_FOREIGN_FENCE");
        return Publish(new(plan, CoordinatedPhase.Prepared, "none"), null);
    }

    // Bind actual native and profile file witnesses to the journal. The
    // external adapter must hold them for the duration of this publication and
    // acquire fresh witnesses for the next observation. These are not a proof
    // of exclusive machine-wide access or of MCP client authorization.
    internal static string PreservedAuthority(CoordinatedLegacyImportWitness native, CoordinatedProtectedWitness profile)
        => WindowsStoreIO.Hash(Wire.Encode(new JsonObject
        {
            ["native"] = native.Digest(), ["profile"] = profile.Digest(),
        }));

    internal CoordinatedJournal AdvanceWithWitness(string expectedDigest, CoordinatedObservation host,
        CoordinatedLegacyImportWitness native, CoordinatedProtectedWitness profile)
        => Advance(expectedDigest, host with { AuthorityDigest = PreservedAuthority(native, profile) });

    // The caller may perform an external action only after its matching intent
    // has been returned durably. Advance never invokes an external mutation.
    // Recovery reads the observed outcome; an unresolved intent stays held.
    internal CoordinatedJournal Advance(string expectedDigest, CoordinatedObservation observed)
    {
        var current = Read() ?? throw new Refusal("COORDINATED_JOURNAL_MISSING");
        if (current.Digest != expectedDigest) throw new Refusal("COORDINATED_CAS_CONFLICT");
        var p = current.Plan;
        switch (current.Phase)
        {
            case CoordinatedPhase.Prepared:
                Require(p, observed, false, false);
                if (observed.Fenced) throw new Refusal("COORDINATED_FOREIGN_FENCE");
                break;
            case CoordinatedPhase.FenceIntent:
            case CoordinatedPhase.Fenced:
                Require(p, observed, false, false, fenced: true);
                break;
            case CoordinatedPhase.NativeIntent:
            case CoordinatedPhase.NativeSelected:
                Require(p, observed, true, false, fenced: true);
                break;
            case CoordinatedPhase.DesktopIntent:
                Require(p, observed, true, true, fenced: true);
                break;
            case CoordinatedPhase.DesktopSelected:
            case CoordinatedPhase.Verified:
            case CoordinatedPhase.OpenIntent:
                // Complete durably while the fence is still held. Only then
                // may an adapter open admissions; a crash cannot open early.
                Require(p, observed, true, true, fenced: true, healthy: true);
                break;
            default: throw new Refusal("COORDINATED_ALREADY_COMPLETE");
        }
        return Publish(new(p, (CoordinatedPhase)((int)current.Phase + 1), current.Digest), current);
    }

    private static void Require(CoordinatedPlan plan, CoordinatedObservation value, bool candidateHelper,
        bool candidateDesktop, bool fenced = false, bool healthy = false)
    {
        if (!value.Authenticated || value.AuthorityDigest != plan.AuthorityDigest
            || value.Helper != (candidateHelper ? plan.CandidateHelper : plan.OldHelper)
            || value.Desktop != (candidateDesktop ? plan.CandidateDesktop : plan.OldDesktop)
            || (fenced && (!value.Fenced || !value.Quiesced))
            || (healthy && (!value.EndpointVerified || !value.DesktopVerified)))
            throw new Refusal("COORDINATED_OBSERVATION_UNVERIFIED");
    }

    private CoordinatedJournal Publish(CoordinatedJournal next, CoordinatedJournal? current)
    {
        ValidateSuccessor(next, current);
        io.Stage(next.Encode());
        boundary?.Invoke("staged");
        io.PublishStage(current?.Digest ?? "none");
        boundary?.Invoke("published");
        return Read() is { } observed && observed == next ? observed : throw new Refusal("COORDINATED_READBACK_UNVERIFIED");
    }

    // Finishes only a journal publication, never repeats a service/desktop action.
    internal CoordinatedJournal RecoverPublication()
    {
        var current = Published();
        var pending = io.Read("journal.pending.json");
        if (pending is null) return current ?? throw new Refusal("COORDINATED_JOURNAL_MISSING");
        var next = CoordinatedJournal.Decode(pending.Bytes);
        ValidateSuccessor(next, current);
        io.PublishStage(current?.Digest ?? "none");
        return Read() is { } observed && observed == next ? observed : throw new Refusal("COORDINATED_READBACK_UNVERIFIED");
    }

    private static void ValidateSuccessor(CoordinatedJournal next, CoordinatedJournal? current)
    {
        _ = next.Encode();
        if (current is null ? next.Phase != CoordinatedPhase.Prepared || next.PreviousDigest != "none"
            : current.Phase == CoordinatedPhase.Completed || next.Plan != current.Plan
                || (int)next.Phase != (int)current.Phase + 1 || next.PreviousDigest != current.Digest)
            throw new Refusal("COORDINATED_SUCCESSOR_INVALID");
    }

    // Advisory for a *new* adapter only; old installed runtimes do not consult
    // this journal. Missing, unreadable or pending evidence never admits a writer.
    internal bool MayAdmit(CoordinatedObservation observed)
    {
        try
        {
            var current = Read();
            if (current is null || current.Phase != CoordinatedPhase.Completed || observed.Fenced) return false;
            Require(current.Plan, observed, true, true, healthy: true);
            return true;
        }
        catch { return false; }
    }

    public void Dispose() => io.Dispose();
}
