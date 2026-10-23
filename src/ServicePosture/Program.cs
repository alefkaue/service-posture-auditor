using System.Text.Json;
namespace ServicePosture;
public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--help")
        { Console.WriteLine("ServicePosture INVENTORY.json OUTPUT_DIRECTORY [--fail-on-high]\nOffline assessment; no service execution or configuration changes."); return 0; }
        if (args.Length is < 2 or > 3 || args.Length == 3 && args[2] != "--fail-on-high") return 2;
        try
        {
            var report = Engine.Load(args[0]); Directory.CreateDirectory(args[1]);
            File.WriteAllText(Path.Combine(args[1], "services.json"), JsonSerializer.Serialize(report, Engine.JsonOptions));
            File.WriteAllText(Path.Combine(args[1], "services.md"), Engine.Markdown(report));
            Console.WriteLine($"Services: {report.Services.Count}; findings for review: {report.Services.Sum(s => s.Findings.Count)}");
            return args.Length == 3 && report.Services.Any(s => s.Findings.Any(f => f.Priority == "high")) ? 1 : 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or OverflowException)
        { Console.Error.WriteLine("Input/report error: " + ex.Message); return 2; }
    }
}
