namespace VulcansTrace.Linux.Agent.Scanners;

using System.Text.Json;

/// <summary>
/// Scans for running containers via docker or crictl, detects privileged modes,
/// latest tags, exposed Docker socket, and containerd namespace defaults.
/// </summary>
public sealed class ContainerScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Container";

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var runtimeInfo = new ContainerRuntimeInfo
        {
            DockerSocketExposed = File.Exists("/var/run/docker.sock")
        };

        // Persist socket detection immediately so an exception later doesn't lose it
        builder.SetContainerRuntime(runtimeInfo);

        // Docker path
        var (dockerPsOutput, dockerPsError, dockerPsOk) = await RunCommandAsync(
            "docker", new[] { "ps", "--format", "{{.Names}}|{{.Image}}" }, cancellationToken);

        var dockerPsStatus = DataSourceCapability.FromCommandResult(dockerPsOk, dockerPsOutput, dockerPsError);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "docker ps",
            Status = dockerPsStatus,
            Detail = dockerPsError
        });

        if (dockerPsOk && !string.IsNullOrWhiteSpace(dockerPsOutput))
        {
            runtimeInfo = runtimeInfo with { DockerAvailable = true };
            var dockerContainers = ParseDockerPs(dockerPsOutput);

            // Inspect containers for deep config
            var names = dockerContainers.Keys.ToList();
            if (names.Count > 0)
            {
                var inspectArgs = new List<string> { "inspect" };
                inspectArgs.AddRange(names);
                var (inspectOutput, inspectError, inspectOk) = await RunCommandAsync(
                    "docker", inspectArgs.ToArray(), cancellationToken);

                var inspectStatus = DataSourceCapability.FromCommandResult(inspectOk, inspectOutput, inspectError);
                builder.AddCapability(new DataSourceCapability
                {
                    SourceName = "docker inspect",
                    Status = inspectStatus,
                    Detail = inspectError
                });

                if (inspectOk && !string.IsNullOrWhiteSpace(inspectOutput))
                {
                    var inspected = ParseDockerInspectJson(inspectOutput, builder);
                    foreach (var (name, container) in dockerContainers)
                    {
                        if (inspected.TryGetValue(name, out var inspectedContainer))
                        {
                            builder.AddContainer(container with
                            {
                                IsPrivileged = inspectedContainer.IsPrivileged,
                                HasHostPid = inspectedContainer.HasHostPid,
                                HasHostNetwork = inspectedContainer.HasHostNetwork,
                                HasDockerSocketMount = inspectedContainer.HasDockerSocketMount,
                                KnownBadBaseLayers = MergeDistinct(
                                    container.KnownBadBaseLayers,
                                    inspectedContainer.KnownBadBaseLayers)
                            });
                        }
                        else
                        {
                            builder.AddContainer(container);
                        }
                    }
                }
                else
                {
                    foreach (var container in dockerContainers.Values)
                        builder.AddContainer(container);
                }
            }
        }

        if (!runtimeInfo.DockerAvailable || (dockerPsOk && string.IsNullOrWhiteSpace(dockerPsOutput)))
        {
            // Fallback: crictl when docker is unavailable OR when docker ps returned empty
            var (crictlOutput, crictlError, crictlOk) = await RunCommandAsync(
                "crictl", new[] { "ps", "-o", "json" }, cancellationToken);

            var crictlStatus = DataSourceCapability.FromCommandResult(crictlOk, crictlOutput, crictlError);
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "crictl",
                Status = crictlStatus,
                Detail = crictlError
            });

            if (crictlOk && !string.IsNullOrWhiteSpace(crictlOutput))
            {
                runtimeInfo = runtimeInfo with { ContainerdAvailable = true };
                var crictlContainers = ParseCrictlPsJson(crictlOutput, builder);
                foreach (var c in crictlContainers)
                    builder.AddContainer(c);
            }
        }

        // Containerd namespaces
        var (ctrOutput, ctrError, ctrOk) = await RunCommandAsync(
            "ctr", new[] { "namespace", "ls" }, cancellationToken);

        var ctrStatus = DataSourceCapability.FromCommandResult(ctrOk, ctrOutput, ctrError);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "ctr namespace",
            Status = ctrStatus,
            Detail = ctrError
        });

        if (ctrOk && !string.IsNullOrWhiteSpace(ctrOutput))
        {
            runtimeInfo = runtimeInfo with { ContainerdAvailable = true };
            if (HasDefaultNamespaceOnly(ctrOutput))
            {
                builder.AddWarning("Containerd default namespace is in use without explicit isolation.");
            }
        }

        builder.SetContainerRuntime(runtimeInfo);

        // Docker socket capability
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "docker.sock",
            Status = runtimeInfo.DockerSocketExposed ? CapabilityStatus.Available : CapabilityStatus.Unavailable
        });
    }

    internal static Dictionary<string, ContainerInfo> ParseDockerPs(string output)
    {
        var result = new Dictionary<string, ContainerInfo>();
        var lines = output.Split('\n');
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var parts = line.Split('|');
            if (parts.Length < 2)
                continue;

            var name = parts[0].Trim();
            var imageFull = parts[1].Trim();
            var (image, tag) = SplitImageAndTag(imageFull);

            result[name] = new ContainerInfo
            {
                Name = name,
                Image = image,
                Tag = tag,
                KnownBadBaseLayers = DetectKnownBadBaseLayers(imageFull),
                Runtime = "docker"
            };
        }

        return result;
    }

    internal static Dictionary<string, ContainerInfo> ParseDockerInspectJson(string json, ScanDataBuilder? builder = null)
    {
        var result = new Dictionary<string, ContainerInfo>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
                return result;

            foreach (var element in doc.RootElement.EnumerateArray())
            {
                try
                {
                    var name = element.GetProperty("Name").GetString()?.TrimStart('/') ?? "";
                    var config = element.GetProperty("HostConfig");
                    var privileged = config.TryGetProperty("Privileged", out var privProp) && privProp.GetBoolean();
                    var pidMode = config.TryGetProperty("PidMode", out var pidProp) ? pidProp.GetString() : "";
                    var networkMode = config.TryGetProperty("NetworkMode", out var netProp) ? netProp.GetString() : "";
                    var baseHints = new List<string>();

                    if (element.TryGetProperty("Config", out var configProp) && configProp.ValueKind == JsonValueKind.Object)
                    {
                        if (configProp.TryGetProperty("Image", out var imageProp))
                            baseHints.Add(imageProp.GetString() ?? string.Empty);

                        if (configProp.TryGetProperty("Labels", out var labelsProp) && labelsProp.ValueKind == JsonValueKind.Object)
                        {
                            foreach (var label in labelsProp.EnumerateObject())
                            {
                                if (IsBaseImageLabel(label.Name))
                                    baseHints.Add(label.Value.GetString() ?? string.Empty);
                            }
                        }
                    }

                    var hasDockerSocketMount = false;
                    if (element.TryGetProperty("Mounts", out var mountsProp) && mountsProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var mount in mountsProp.EnumerateArray())
                        {
                            var source = mount.TryGetProperty("Source", out var srcProp) ? srcProp.GetString() : "";
                            if (source == "/var/run/docker.sock" || source == "/run/docker.sock")
                            {
                                hasDockerSocketMount = true;
                                break;
                            }
                        }
                    }

                    result[name] = new ContainerInfo
                    {
                        Name = name,
                        IsPrivileged = privileged,
                        HasHostPid = !string.IsNullOrEmpty(pidMode) && pidMode.Equals("host", StringComparison.OrdinalIgnoreCase),
                        HasHostNetwork = !string.IsNullOrEmpty(networkMode) && networkMode.Equals("host", StringComparison.OrdinalIgnoreCase),
                        HasDockerSocketMount = hasDockerSocketMount,
                        KnownBadBaseLayers = DetectKnownBadBaseLayers(baseHints),
                        Runtime = "docker"
                    };
                }
                catch (Exception ex)
                {
                    builder?.AddWarning($"Container scanner skipped malformed docker inspect entry: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            builder?.AddWarning($"Container scanner failed to parse docker inspect JSON: {ex.Message}");
        }

        return result;
    }

    internal static List<ContainerInfo> ParseCrictlPsJson(string json, ScanDataBuilder? builder = null)
    {
        var result = new List<ContainerInfo>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("containers", out var containersProp))
                return result;

            foreach (var container in containersProp.EnumerateArray())
            {
                try
                {
                    var metadata = container.GetProperty("metadata");
                    var name = metadata.GetProperty("name").GetString() ?? "";
                    var image = container.GetProperty("image").GetProperty("image").GetString() ?? "";
                    var (imageName, tag) = SplitImageAndTag(image);

                    result.Add(new ContainerInfo
                    {
                        Name = name,
                        Image = imageName,
                        Tag = tag,
                        KnownBadBaseLayers = DetectKnownBadBaseLayers(image),
                        Runtime = "containerd"
                    });
                }
                catch (Exception ex)
                {
                    builder?.AddWarning($"Container scanner skipped malformed crictl entry: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            builder?.AddWarning($"Container scanner failed to parse crictl JSON: {ex.Message}");
        }

        return result;
    }

    internal static bool HasDefaultNamespaceOnly(string output)
    {
        var lines = output.Split('\n');
        var namespaces = new List<string>();
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("NAME", StringComparison.OrdinalIgnoreCase))
                continue;

            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 1)
                namespaces.Add(parts[0]);
        }

        return namespaces.Count == 1 && namespaces[0].Equals("default", StringComparison.OrdinalIgnoreCase);
    }

    internal static IReadOnlyList<string> DetectKnownBadBaseLayers(params string?[] imageReferences) =>
        DetectKnownBadBaseLayers((IEnumerable<string?>)imageReferences);

    private static IReadOnlyList<string> DetectKnownBadBaseLayers(IEnumerable<string?> imageReferences)
    {
        var findings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var reference in imageReferences)
        {
            if (string.IsNullOrWhiteSpace(reference))
                continue;

            var normalized = reference.Trim().ToLowerInvariant();
            foreach (var signature in KnownBadBaseImageSignatures)
            {
                if (normalized.Contains(signature.Pattern, StringComparison.OrdinalIgnoreCase))
                    findings.Add(signature.Description);
            }
        }

        return findings.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IReadOnlyList<string> MergeDistinct(IReadOnlyList<string> first, IReadOnlyList<string> second) =>
        first.Concat(second).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();

    private static bool IsBaseImageLabel(string labelName) =>
        labelName.Equals("org.opencontainers.image.base.name", StringComparison.OrdinalIgnoreCase)
            || labelName.Equals("org.label-schema.build-base-image", StringComparison.OrdinalIgnoreCase)
            || labelName.Equals("image.base.name", StringComparison.OrdinalIgnoreCase)
            || labelName.Equals("base.image", StringComparison.OrdinalIgnoreCase);

    private static (string Image, string Tag) SplitImageAndTag(string imageFull)
    {
        if (string.IsNullOrWhiteSpace(imageFull))
            return (string.Empty, string.Empty);

        var tagIndex = imageFull.LastIndexOf(':');
        var atIndex = imageFull.LastIndexOf('@');

        // Digest reference (image@sha256:...)
        if (atIndex > 0)
            return (imageFull[..atIndex], imageFull[(atIndex + 1)..]);

        // Tag reference (image:tag)
        if (tagIndex > 0 && !imageFull[(tagIndex + 1)..].Contains('/'))
            return (imageFull[..tagIndex], imageFull[(tagIndex + 1)..]);

        return (imageFull, "latest");
    }

    private static readonly (string Pattern, string Description)[] KnownBadBaseImageSignatures =
    {
        ("ubuntu:12.04", "ubuntu:12.04 EOL base image"),
        ("ubuntu:14.04", "ubuntu:14.04 EOL base image"),
        ("ubuntu:16.04", "ubuntu:16.04 EOL base image"),
        ("debian:jessie", "debian:jessie EOL base image"),
        ("debian:stretch", "debian:stretch EOL base image"),
        ("centos:6", "centos:6 EOL base image"),
        ("centos:7", "centos:7 EOL base image"),
        ("alpine:3.12", "alpine:3.12 EOL base image"),
        ("alpine:3.13", "alpine:3.13 EOL base image"),
        ("alpine:3.14", "alpine:3.14 EOL base image"),
        ("oraclelinux:6", "oraclelinux:6 EOL base image"),
        ("oraclelinux:7", "oraclelinux:7 EOL base image")
    };

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
