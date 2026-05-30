using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;

public class AgentDemo
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("=== VulcansTrace Security Agent Demo ===\n");

        var scanners = new IScanner[]
        {
            new FirewallScanner(),
            new PortScanner(),
            new ServiceScanner(),
            new NetworkScanner(),
            new FilePermissionScanner()
        };

        var rules = new IRule[]
        {
            new FirewallActiveRule(),
            new FirewallDefaultDropRule(),
            new FirewallSshExposureRule(),
            new FirewallStateTrackingRule(),
            new FirewallIcmpRule(),
            new DefaultRouteRule(),
            new SuspiciousConnectionsRule(),
            new NetworkInterfaceUpRule(),
            new LoopbackExposureRule(),
            new TelnetServiceRule(),
            new FtpServiceRule(),
            new SshServiceRule(),
            new LegacyRservicesRule(),
            new UnnecessaryServicesRule(),
            new SshNonDefaultPortRule(),
            new WideOpenServicesRule(),
            new DatabasePortExposureRule(),
            new HighPortListeningRule(),
            new ShadowPermissionRule(),
            new PasswdPermissionRule(),
            new SshHostKeyPermissionRule(),
            new RootSshDirectoryPermissionRule(),
            new CronDirectoryWorldWritableRule(),
            new CrontabPermissionRule(),
            new UserSshDirectoryPermissionRule()
        };

        var agent = new SecurityAgent(
            scanners,
            rules,
            new ExplanationProvider()
        );

        var queries = new[]
        {
            "check firewall",
            "what ports are open",
            "is SSH secure",
            "scan network",
            "full security audit"
        };

        foreach (var query in queries)
        {
            Console.WriteLine($"> {query}");
            var result = await agent.AskAsync(query, rawLog: null, CancellationToken.None);
            Console.WriteLine($"  Intent: {result.Intent}");
            Console.WriteLine($"  Findings: {result.AgentFindings?.Count ?? 0}");
            if (result.AgentFindings?.Count > 0)
            {
                foreach (var f in result.AgentFindings.Take(3))
                {
                    Console.WriteLine($"    • [{f.Severity}] {f.Details}");
                }
                if (result.AgentFindings.Count > 3)
                    Console.WriteLine($"    ... and {result.AgentFindings.Count - 3} more");
            }
            Console.WriteLine($"  Summary: {result.Summary?.Substring(0, Math.Min(120, result.Summary?.Length ?? 0))}...");
            Console.WriteLine();
        }

        Console.WriteLine("=== Demo Complete ===");
    }
}
