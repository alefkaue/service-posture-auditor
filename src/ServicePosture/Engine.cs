using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ServicePosture;

public sealed record ServiceSnapshot
{
    public string Name { get; init; } = "";
    public string PathName { get; init; } = "";
    public string StartName { get; init; } = "";
    public string StartMode { get; init; } = "";
    public bool? BinaryWritableByUsers { get; init; }
    public string[] WritableCandidatePaths { get; init; } = [];
    public string Evidence { get; init; } = "Operator-supplied service inventory";
}
public sealed record Finding(string Rule, string Priority, string Observation, string Recommendation);
public sealed record ServiceResult(string Name, string Account, string Startup, string? Executable,
    string Confidence, IReadOnlyList<string> AmbiguousCandidates, IReadOnlyList<Finding> Findings, string Evidence);
public sealed record AuditReport(int SchemaVersion, string Scope, string InputSha256,
    IReadOnlyList<ServiceResult> Services);

public static class Engine
{
    public static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
    static readonly Regex Absolute = new(@"^(?:[a-zA-Z]:\\|\\\\[^\\]+\\[^\\]+\\)", RegexOptions.CultureInvariant);
    static readonly Regex Executable = new(@"^(.+?\.exe)(?:\s|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static AuditReport Load(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > 5_000_000) throw new InvalidDataException("Inventory exceeds 5 MB");
        var data = new byte[checked((int)stream.Length)];
        stream.ReadExactly(data);
        var services = JsonSerializer.Deserialize<ServiceSnapshot[]>(data, JsonOptions)
                       ?? throw new InvalidDataException("Expected an array of services");
        if (services.Length is 0 or > 10000) throw new InvalidDataException("Expected 1..10000 services");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in services)
            if (service is null || string.IsNullOrWhiteSpace(service.Name) || service.PathName is null
                || service.StartName is null || service.StartMode is null || service.Evidence is null || !names.Add(service.Name))
                throw new InvalidDataException("Missing or duplicate service name");
        return new(1, "Offline snapshot review; no services started, permissions changed or exploitation performed.",
            Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(), services.Select(Assess).ToArray());
    }

    public static ServiceResult Assess(ServiceSnapshot service)
    {
        var findings = new List<Finding>();
        var raw = service.PathName?.Trim() ?? "";
        string? executable = null;
        bool quoted = raw.StartsWith('"');
        if (raw.Contains('%') || raw.Length == 0)
            findings.Add(new("PATH_UNRESOLVED", "review", "Missing path or environment variables require source-machine resolution.", "Collect the expanded executable path from the owning machine; do not expand using the analyst's environment."));
        else if (quoted)
        {
            int end = raw.IndexOf('"', 1);
            if (end > 1) executable = raw[1..end];
        }
        else
        {
            var match = Executable.Match(raw);
            if (match.Success) executable = match.Groups[1].Value;
        }
        if (executable is not null && !Absolute.IsMatch(executable)) executable = null;
        if (executable is null && !findings.Any(f => f.Rule == "PATH_UNRESOLVED"))
            findings.Add(new("PATH_UNRESOLVED", "review", "Executable could not be resolved conservatively.", "Review the original command line; scripts, drivers and relative paths are outside this parser's supported model."));
        var candidates = new List<string>();
        if (executable is not null && !quoted)
        {
            for (int i = 0; i < executable.Length; i++)
                if (executable[i] == ' ') candidates.Add(executable[..i] + ".exe");
        }
        bool system = service.StartName.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase)
            || service.StartName.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase);
        bool disabled = service.StartMode.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
        if (candidates.Count > 0)
        {
            var supplied = service.WritableCandidatePaths ?? [];
            bool writableCandidate = candidates.Any(c => supplied.Contains(c, StringComparer.OrdinalIgnoreCase));
            findings.Add(new("UNQUOTED_EXECUTABLE_PATH", writableCandidate && system && !disabled ? "high" : "medium",
                writableCandidate ? "Unquoted spaced path with operator-supplied write evidence for an actual ambiguous candidate." : "Unquoted spaced executable path; candidate existence and write access remain unverified.",
                "Quote only the executable, preserve arguments, validate ACLs and test changes through normal change management. This observation is not proof of privilege escalation."));
        }
        if (service.BinaryWritableByUsers is true)
            findings.Add(new("REPORTED_BINARY_WRITE", disabled ? "medium" : "high", "Snapshot reports unprivileged write access to the service binary.", "Validate the effective ACL and inheritance on the source machine. Remove unintended write permission after testing; do not replace the binary."));
        if (string.IsNullOrWhiteSpace(service.StartName))
            findings.Add(new("ACCOUNT_UNKNOWN", "review", "Service account was not collected.", "Collect StartName before making a privilege-impact claim."));
        return new(service.Name, service.StartName, service.StartMode, executable,
            executable is null ? "inconclusive_path" : "snapshot_only", candidates, findings, service.Evidence);
    }

    static string Cell(string value) => value.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ").Replace("<", "&lt;").Replace(">", "&gt;");
    public static string Markdown(AuditReport report)
    {
        var b = new StringBuilder("# Windows service posture\n\n" + report.Scope + "\n\nInput SHA-256: `" + report.InputSha256 + "`\n\n");
        b.AppendLine("| Service | Account | Startup | Findings |\n|---|---|---|---|");
        foreach (var s in report.Services) b.AppendLine($"| {Cell(s.Name)} | {Cell(s.Account)} | {Cell(s.Startup)} | {s.Findings.Count} |");
        foreach (var s in report.Services)
        {
            b.AppendLine("\n## " + Cell(s.Name));
            b.AppendLine("\nEvidence: " + Cell(s.Evidence));
            foreach (var f in s.Findings) b.AppendLine($"- **{f.Priority} / {f.Rule}:** {Cell(f.Observation)} {Cell(f.Recommendation)}");
        }
        return b.ToString();
    }
}
