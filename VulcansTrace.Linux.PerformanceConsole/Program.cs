using System.Text;
using System.Text.Json;
using VulcansTrace.Linux.Performance;

namespace VulcansTrace.Linux.PerformanceConsole;

/// <summary>
/// Console application for running performance benchmarks and profiling.
/// </summary>
public class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("profile", StringComparison.OrdinalIgnoreCase))
        {
            // Run profiling mode
            return await RunProfiling();
        }
        else
        {
            // Run benchmarking mode
            return await RunBenchmark(args);
        }
    }

    private static async Task<int> RunBenchmark(string[] args)
    {
        Console.WriteLine("VulcansTrace Linux Edition - Performance Benchmark Tool");
        Console.WriteLine("=====================================================");
        Console.WriteLine();

        var benchmark = new PerformanceBenchmark();

        // Default test sizes if no arguments provided
        var sizes = args.Length > 1
            ? args.Skip(1).Select(int.Parse).ToArray()
            : new[] { 100, 500, 1000, 5000 };

        Console.WriteLine($"Running benchmarks for log sizes: {string.Join(", ", sizes)} lines");
        Console.WriteLine();

        var results = benchmark.RunBenchmark(sizes);

        DisplayBenchmarkResults(results);

        // Optionally save detailed results to JSON
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        var jsonResult = JsonSerializer.Serialize(results, jsonOptions);

        var fileName = $"benchmark_results_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
        await File.WriteAllTextAsync(fileName, jsonResult);
        Console.WriteLine($"Detailed results saved to: {fileName}");

        return 0;
    }

    private static async Task<int> RunProfiling()
    {
        Console.WriteLine("VulcansTrace Linux Edition - Performance Profiler");
        Console.WriteLine("=================================================");
        Console.WriteLine();

        var profiler = new PerformanceProfiler();

        // Generate a sample log for profiling
        var sampleLog = GenerateSampleLog(500);

        Console.WriteLine("Running performance profile on sample log...");
        Console.WriteLine();

        var profile = await profiler.ProfileAnalysisAsync(sampleLog);

        DisplayProfile(profile);

        // Save detailed results to JSON
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        var jsonResult = JsonSerializer.Serialize(profile, jsonOptions);

        var fileName = $"profile_results_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";
        await File.WriteAllTextAsync(fileName, jsonResult);
        Console.WriteLine($"Detailed profile saved to: {fileName}");

        return 0;
    }

    private static void DisplayBenchmarkResults(BenchmarkResult results)
    {
        Console.WriteLine("Performance Benchmark Results");
        Console.WriteLine("============================");
        Console.WriteLine();

        // Table header
        Console.WriteLine("{0,-10} {1,-12} {2,-12} {3,-15} {4,-12} {5,-15}",
            "Log Size", "Parsed", "Time (ms)", "Rate (lines/s)", "Findings", "Memory Δ (KB)");
        Console.WriteLine(new string('-', 90));

        // Table rows
        foreach (var run in results.Runs)
        {
            Console.WriteLine("{0,-10} {1,-12} {2,-12} {3,-15:F2} {4,-12} {5,-15}",
                run.LogSize,
                run.ParsedLines,
                run.ElapsedMs,
                run.ProcessingRate,
                run.FindingsCount,
                run.MemoryDeltaKB);
        }

        Console.WriteLine(new string('-', 90));
        Console.WriteLine("{0,-10} {1,-12} {2,-12} {3,-15:F2}",
            "Average", "", results.OverallAverageTime, results.AverageProcessingRate);
        Console.WriteLine();
    }

    private static void DisplayProfile(ProfileResult profile)
    {
        Console.WriteLine("Performance Profile Results");
        Console.WriteLine("===========================");
        Console.WriteLine();

        Console.WriteLine($"Normalization Time: {profile.NormalizationTimeMs} ms");
        Console.WriteLine($"Analysis Time: {profile.AnalysisTimeMs} ms");
        Console.WriteLine($"Total Events Processed: {profile.NormalizedEvents}");
        Console.WriteLine($"Total Findings: {profile.FindingsCount}");
        Console.WriteLine();

        Console.WriteLine("Detector Performance:");
        Console.WriteLine("=====================");

        // Group by category
        var byCategory = profile.DetectorProfiles
            .GroupBy(p => p.Category)
            .OrderBy(g => g.Key);

        foreach (var categoryGroup in byCategory)
        {
            Console.WriteLine($"\n{categoryGroup.Key} Detectors:");
            Console.WriteLine("{0,-30} {1,-15} {2,-10}", "Detector", "Time (ms)", "Findings");
            Console.WriteLine(new string('-', 57));

            foreach (var detector in categoryGroup.OrderBy(d => d.ExecutionTimeMs, Comparer<long>.Create((x, y) => y.CompareTo(x))))
            {
                Console.WriteLine("{0,-30} {1,-15} {2,-10}",
                    detector.Name.Replace("Detector", ""),
                    detector.ExecutionTimeMs,
                    detector.FindingsCount);
            }
        }

        Console.WriteLine();
    }

    private static string GenerateSampleLog(int lineCount)
    {
        var sb = new StringBuilder();
        var startTime = DateTime.UtcNow;

        for (int i = 0; i < lineCount; i++)
        {
            var timestamp = startTime.AddSeconds(i);
            var sourceIp = $"192.168.1.{(i % 254) + 2}";
            var destIp = $"10.0.0.{(i % 254) + 2}";
            var port = 80 + (i % 1000);

            sb.AppendLine($"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={sourceIp} DST={destIp} PROTO=TCP SPT={50000 + (i % 10000)} DPT={port} LEN=60");
        }

        return sb.ToString();
    }
}