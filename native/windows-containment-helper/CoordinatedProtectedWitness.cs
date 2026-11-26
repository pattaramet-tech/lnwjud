using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Lnwjud.UpdateWorker;

namespace Lnwjud.Containment;

// Read-only protected evidence primitive for the future host adapter.
// Does not accept a caller assertion of authentication or change any authority.
// The caller must independently select the trusted machine root and exact
// ledger/transaction filenames, and verify semantic owner/attempt bindings.
[SupportedOSPlatform("windows")]
internal sealed class CoordinatedProtectedWitness : IDisposable
{
    private readonly List<SafeFileHandle> directories = [];
    private readonly List<(string Relative, FileStream Stream)> files = [];
    private readonly string root;
    private bool disposed;
    private readonly bool nativePackage;
    private const long DefaultMaximumBytes = 32L * 1024 * 1024;
    private const long HelperMaximumBytes = 128L * 1024 * 1024;
    private const long ManifestMaximumBytes = 64L * 1024;

    internal static CoordinatedProtectedWitness ForNativePackage(string protectedRoot)
        => new(protectedRoot, ["lnwjud-containment.exe", "manifest.json", "lnwjud-containment-pin.node"], nativePackage: true);

    internal CoordinatedProtectedWitness(string protectedRoot, IReadOnlyList<string> relativeFiles)
        : this(protectedRoot, relativeFiles, nativePackage: false) { }

    private CoordinatedProtectedWitness(string protectedRoot, IReadOnlyList<string> relativeFiles, bool nativePackage)
    {
        this.nativePackage = nativePackage;
        root = WindowsStoreIO.ValidatePath(protectedRoot);
        if (relativeFiles.Count is < 1 or > 128) throw new Refusal("COORDINATED_WITNESS_INVALID");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            // Keep each ancestor open without delete sharing. The final
            // protected root and every descendant also require trusted ACLs.
            var volume = Path.GetPathRoot(root)!;
            var current = volume;
            directories.Add(ServiceEndpointIdentity.PinKnownFolder(current));
            foreach (var part in root[volume.Length..].Split(Path.DirectorySeparatorChar))
            {
                current = Path.Combine(current, part);
                directories.Add(String.Equals(current, root, StringComparison.OrdinalIgnoreCase)
                    ? ServiceEndpointIdentity.OpenProtected(current, true) : ServiceEndpointIdentity.PinKnownFolder(current));
            }
            foreach (var name in relativeFiles.OrderBy(x => x, StringComparer.Ordinal))
            {
                var parts = name.Split('/');
                if (name.Length > 200 || !seen.Add(name) || parts.Any(part => !Wire.Identifier(part) || part is "." or ".." || part.EndsWith('.')))
                    throw new Refusal("COORDINATED_WITNESS_INVALID");
                current = root;
                foreach (var part in parts.Take(parts.Length - 1))
                {
                    current = Path.Combine(current, part);
                    directories.Add(ServiceEndpointIdentity.OpenProtected(current, true));
                }
                var stream = new FileStream(ServiceEndpointIdentity.OpenProtected(Path.Combine(current, parts[^1]), false), FileAccess.Read);
                files.Add((name, stream));
                ValidateFile(stream.SafeFileHandle);
            }
        }
        catch { Dispose(); throw; }
    }

    internal string Digest()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var records = new JsonArray();
        foreach (var (relative, stream) in files)
        {
            var before = ValidateFile(stream.SafeFileHandle);
            // Only the fixed package witness may use the larger helper limit.
            // Ledger, profile, and pin witnesses retain the original bound.
            var maximum = nativePackage ? relative switch
            {
                "lnwjud-containment.exe" => HelperMaximumBytes,
                "manifest.json" => ManifestMaximumBytes,
                _ => DefaultMaximumBytes,
            } : DefaultMaximumBytes;
            if (before.Length < 1 || before.Length > maximum) throw new Refusal("COORDINATED_WITNESS_SIZE");
            stream.Position = 0;
            var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            var after = ValidateFile(stream.SafeFileHandle);
            if (before != after || stream.Position != before.Length) throw new Refusal("COORDINATED_WITNESS_CHANGED");
            records.Add(new JsonObject
            {
                ["path"] = relative, ["identity"] = before.Identity,
                ["size"] = Wire.Decimal((ulong)before.Length), ["sha256"] = hash,
            });
        }
        return WindowsStoreIO.Hash(Wire.Encode(new JsonObject
        {
            ["root"] = root, ["rootIdentity"] = Identity(directories[RootIndex()]), ["files"] = records,
        }));
    }

    private int RootIndex() => root[Path.GetPathRoot(root)!.Length..].Split(Path.DirectorySeparatorChar).Length;

    private static (string Identity, long Length) ValidateFile(SafeFileHandle handle)
    {
        if (!GetStandard(handle, 1, out var info, (uint)Marshal.SizeOf<StandardInfo>())
            || info.Directory != 0 || info.DeletePending != 0 || info.Links != 1)
            throw new Refusal("COORDINATED_WITNESS_FILE_UNSAFE");
        return (Identity(handle), info.Length);
    }

    private static string Identity(SafeFileHandle handle)
    {
        if (!GetIdentity(handle, 18, out var info, (uint)Marshal.SizeOf<FileId>()))
            throw new Refusal("COORDINATED_WITNESS_IDENTITY_UNAVAILABLE");
        return info.Volume.ToString("X16") + "-" + Convert.ToHexString(BitConverter.GetBytes(info.Low))
            + Convert.ToHexString(BitConverter.GetBytes(info.High));
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        foreach (var file in files) file.Stream.Dispose();
        foreach (var directory in directories) directory.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StandardInfo { internal long Allocation, Length; internal uint Links; internal byte DeletePending, Directory; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileId { internal ulong Volume, Low, High; }
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetStandard(SafeFileHandle handle, int kind, out StandardInfo info, uint size);
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetIdentity(SafeFileHandle handle, int kind, out FileId info, uint size);
}
