using ServicePosture;
using System.Text.Json;
var tests = new List<(string, Action)>();
void Test(string name, Action body) => tests.Add((name, body));
void Check(bool condition) { if (!condition) throw new Exception("assertion failed"); }
ServiceSnapshot Sample(string path) => new() { Name = "SyntheticService", PathName = path, StartName = "LocalSystem", StartMode = "Auto" };
Test("quoted executable with arguments is not unquoted", () => Check(!Engine.Assess(Sample("\"C:\\Program Files\\Lab\\svc.exe\" --demo")).Findings.Any()));
Test("spaces in arguments alone are not a path finding", () => Check(!Engine.Assess(Sample("C:\\Lab\\svc.exe --name value with spaces")).Findings.Any()));
Test("unquoted candidates are modeled", () => Check(Engine.Assess(Sample(@"C:\Program Files\Vendor App\svc.exe")).AmbiguousCandidates.SequenceEqual(new[] { @"C:\Program.exe", @"C:\Program Files\Vendor.exe" })));
Test("unverified unquoted path is medium", () => Check(Engine.Assess(Sample(@"C:\Program Files\svc.exe")).Findings.Single().Priority == "medium"));
Test("matching candidate evidence raises priority", () => Check(Engine.Assess(Sample(@"C:\Program Files\svc.exe") with { WritableCandidatePaths = [@"c:\program.exe"] }).Findings.Single().Priority == "high"));
Test("unrelated writable path is ignored", () => Check(Engine.Assess(Sample(@"C:\Program Files\svc.exe") with { WritableCandidatePaths = [@"D:\Other.exe"] }).Findings.Single().Priority == "medium"));
Test("disabled service priority remains bounded", () => Check(Engine.Assess(Sample(@"C:\Program Files\svc.exe") with { StartMode = "Disabled", WritableCandidatePaths = [@"C:\Program.exe"] }).Findings.Single().Priority == "medium"));
Test("environment paths remain unresolved", () => Check(Engine.Assess(Sample(@"%ProgramFiles%\Lab\svc.exe")).Executable is null));
Test("relative command remains unresolved", () => Check(Engine.Assess(Sample(@"Lab\svc.exe")).Executable is null));
Test("unterminated quote remains unresolved", () => Check(Engine.Assess(Sample("\"C:\\Lab\\svc.exe")).Executable is null));
Test("UNC executable supported", () => Check(Engine.Assess(Sample(@"\\host.example\share\svc.exe")).Executable is not null));
Test("reported binary write is explicit evidence", () => Check(Engine.Assess(Sample(@"C:\Lab\svc.exe") with { BinaryWritableByUsers = true }).Findings.Single().Rule == "REPORTED_BINARY_WRITE"));
Test("unknown account not silently privileged", () => Check(Engine.Assess(Sample(@"C:\Lab\svc.exe") with { StartName = "" }).Findings.Single().Rule == "ACCOUNT_UNKNOWN"));
string temp = Path.Combine(Path.GetTempPath(), "service-posture-tests-" + Guid.NewGuid()); Directory.CreateDirectory(temp);
try
{
    Test("duplicate identities rejected", () => { string p = Path.Combine(temp, "duplicate.json"); File.WriteAllText(p, JsonSerializer.Serialize(new[] { Sample(@"C:\a.exe"), Sample(@"C:\b.exe") })); try { Engine.Load(p); throw new Exception("accepted duplicate"); } catch (InvalidDataException) { } });
    Test("CLI writes reports and high-risk exit code", () => { string p = Path.Combine(temp, "valid.json"); File.WriteAllText(p, JsonSerializer.Serialize(new[] { Sample(@"C:\a.exe") with { BinaryWritableByUsers = true } })); Check(ServicePosture.Program.Main([p, Path.Combine(temp, "out"), "--fail-on-high"]) == 1); Check(File.Exists(Path.Combine(temp, "out/services.md"))); });
    Test("malformed JSON has explicit failure", () => { string p = Path.Combine(temp, "bad.json"); File.WriteAllText(p, "{"); Check(ServicePosture.Program.Main([p, Path.Combine(temp, "bad-out")]) == 2); });
    int failed = 0;
    foreach (var (name, body) in tests) { try { body(); Console.WriteLine("PASS " + name); } catch (Exception e) { failed++; Console.WriteLine("FAIL " + name + ": " + e.Message); } }
    Console.WriteLine($"{tests.Count - failed}/{tests.Count} passed"); return failed == 0 ? 0 : 1;
}
finally { Directory.Delete(temp, true); }
