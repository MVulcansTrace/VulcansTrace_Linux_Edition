namespace VulcansTrace.Linux.Agent.Scanners;

using System.Text.Json;

/// <summary>
/// Scans Kubernetes pods and security contexts via kubectl when ~/.kube/config exists.
/// Detects Pod Security Standard violations through the kubectl context configured by the user.
/// </summary>
public sealed class KubernetesScanner : IScanner
{
    /// <inheritdoc />
    public string Name => "Kubernetes";

    private static string GetKubeConfigPath()
    {
        var envPath = Environment.GetEnvironmentVariable("KUBECONFIG");
        if (!string.IsNullOrWhiteSpace(envPath))
            return envPath;

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".kube", "config");
    }

    /// <inheritdoc />
    public async Task ScanAsync(ScanDataBuilder builder, CancellationToken cancellationToken)
    {
        var kubeConfigPath = GetKubeConfigPath();
        if (!File.Exists(kubeConfigPath))
        {
            builder.AddCapability(new DataSourceCapability
            {
                SourceName = "kubectl",
                Status = CapabilityStatus.Unavailable,
                Detail = $"{kubeConfigPath} not found"
            });
            return;
        }

        var (output, error, ok) = await RunCommandAsync(
            "kubectl", new[] { "get", "pods", "--all-namespaces", "-o", "json" }, cancellationToken);

        var status = DataSourceCapability.FromCommandResult(ok, output, error);
        builder.AddCapability(new DataSourceCapability
        {
            SourceName = "kubectl",
            Status = status,
            Detail = error
        });

        if (!ok || string.IsNullOrWhiteSpace(output))
        {
            builder.AddWarning($"Kubernetes scan skipped: kubectl failed. {error}");
            return;
        }

        ParseKubectlGetPodsJson(output, builder);
    }

    internal static void ParseKubectlGetPodsJson(string json, ScanDataBuilder builder)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("items", out var itemsProp))
                return;

            foreach (var item in itemsProp.EnumerateArray())
            {
                try
                {
                    ParsePod(item, builder);
                }
                catch (Exception ex)
                {
                    builder.AddWarning($"Kubernetes scanner skipped malformed pod: {ex.Message}");
                }
            }
        }
        catch
        {
            // Ignore malformed JSON
        }
    }

    private static void ParsePod(JsonElement item, ScanDataBuilder builder)
    {
        var metadata = item.GetProperty("metadata");
        var ns = metadata.GetProperty("namespace").GetString() ?? "default";
        var name = metadata.GetProperty("name").GetString() ?? "";

        var spec = item.GetProperty("spec");
        var hostNetwork = spec.TryGetProperty("hostNetwork", out var hnProp) && hnProp.GetBoolean();
        var hostPid = spec.TryGetProperty("hostPID", out var hpProp) && hpProp.GetBoolean();
        var hostIpc = spec.TryGetProperty("hostIPC", out var hiProp) && hiProp.GetBoolean();

        // Pod-level securityContext
        var podSecurityContext = spec.TryGetProperty("securityContext", out var podScProp)
            ? podScProp
            : new JsonElement();

        var containers = new List<K8sContainerInfo>();
        var violations = new List<string>();

        // Parse containers + init containers
        ParseContainers(spec, "containers", containers, violations, hostNetwork, hostPid, podSecurityContext);
        ParseContainers(spec, "initContainers", containers, violations, hostNetwork, hostPid, podSecurityContext);

        if (hostNetwork)
            violations.Add($"Pod '{name}' uses hostNetwork");
        if (hostPid)
            violations.Add($"Pod '{name}' uses hostPID");
        if (hostIpc)
            violations.Add($"Pod '{name}' uses hostIPC");

        builder.AddKubernetesPod(new KubernetesPodInfo
        {
            Namespace = ns,
            Name = name,
            HostNetwork = hostNetwork,
            HostPid = hostPid,
            HostIpc = hostIpc,
            Containers = containers,
            Violations = violations
        });
    }

    private static void ParseContainers(
        JsonElement spec,
        string propertyName,
        List<K8sContainerInfo> containers,
        List<string> violations,
        bool podHostNetwork,
        bool podHostPid,
        JsonElement podSecurityContext)
    {
        if (!spec.TryGetProperty(propertyName, out var containersProp))
            return;

        // Extract pod-level settings that containers inherit
        var podRunAsUser = GetOptionalInt64(podSecurityContext, "runAsUser");
        var podRunAsNonRoot = GetOptionalBoolean(podSecurityContext, "runAsNonRoot");
        var podSeccompProfile = GetOptionalString(podSecurityContext, "seccompProfile", "type");

        foreach (var container in containersProp.EnumerateArray())
        {
            var cName = container.GetProperty("name").GetString() ?? "";
            var image = container.GetProperty("image").GetString() ?? "";

            var securityContext = container.TryGetProperty("securityContext", out var scProp)
                ? scProp
                : new JsonElement();

            // Merge container and pod-level security contexts
            // Container-level overrides pod-level
            var privileged = GetOptionalBoolean(securityContext, "privileged") ?? false;

            var allowPrivilegeEscalation = true;
            if (securityContext.ValueKind == JsonValueKind.Object
                && securityContext.TryGetProperty("allowPrivilegeEscalation", out var apeProp))
            {
                allowPrivilegeEscalation = apeProp.GetBoolean();
            }

            var readOnlyRootFilesystem = false;
            if (securityContext.ValueKind == JsonValueKind.Object
                && securityContext.TryGetProperty("readOnlyRootFilesystem", out var rofsProp))
            {
                readOnlyRootFilesystem = rofsProp.GetBoolean();
            }

            // runAsUser: container overrides pod
            var containerRunAsUser = GetOptionalInt64(securityContext, "runAsUser");
            var effectiveRunAsUser = containerRunAsUser ?? podRunAsUser;

            // runAsNonRoot: container overrides pod
            var containerRunAsNonRoot = GetOptionalBoolean(securityContext, "runAsNonRoot");
            var effectiveRunAsNonRoot = containerRunAsNonRoot ?? podRunAsNonRoot;

            // Determine if container runs as root
            var runAsRoot = effectiveRunAsUser == 0;
            // If runAsNonRoot is explicitly true, it's not root
            if (effectiveRunAsNonRoot == true)
                runAsRoot = false;
            // If no explicit runAsUser and runAsNonRoot is false or absent, we conservatively flag it
            // (the pod/container hasn't explicitly opted out of root)
            if (!effectiveRunAsUser.HasValue && effectiveRunAsNonRoot != true)
                runAsRoot = true;

            var dropAllCapabilities = false;
            if (securityContext.ValueKind == JsonValueKind.Object
                && securityContext.TryGetProperty("capabilities", out var capProp)
                && capProp.ValueKind == JsonValueKind.Object
                && capProp.TryGetProperty("drop", out var dropProp)
                && dropProp.ValueKind == JsonValueKind.Array)
            {
                var drops = dropProp.EnumerateArray().Select(e => e.GetString()).ToList();
                dropAllCapabilities = drops.Any(d => d != null && d.Equals("ALL", StringComparison.OrdinalIgnoreCase));
            }

            // seccompProfile: container overrides pod
            var containerSeccomp = GetOptionalString(securityContext, "seccompProfile", "type");
            var effectiveSeccomp = !string.IsNullOrEmpty(containerSeccomp) ? containerSeccomp : podSeccompProfile;

            var cInfo = new K8sContainerInfo
            {
                Name = cName,
                Image = image,
                Privileged = privileged,
                AllowPrivilegeEscalation = allowPrivilegeEscalation,
                ReadOnlyRootFilesystem = readOnlyRootFilesystem,
                RunAsRoot = runAsRoot,
                DropAllCapabilities = dropAllCapabilities,
                SeccompProfile = effectiveSeccomp ?? ""
            };

            containers.Add(cInfo);

            // Per-container violations
            if (privileged)
                violations.Add($"Container '{cName}' is privileged");
            if (cInfo.RunAsRoot)
                violations.Add($"Container '{cName}' may run as root");
            if (allowPrivilegeEscalation)
                violations.Add($"Container '{cName}' allows privilege escalation");
            if (!readOnlyRootFilesystem)
                violations.Add($"Container '{cName}' has writable root filesystem");
            if (!dropAllCapabilities)
                violations.Add($"Container '{cName}' does not drop ALL capabilities");
            if (string.IsNullOrEmpty(effectiveSeccomp))
                violations.Add($"Container '{cName}' has no seccomp profile");
            else if (effectiveSeccomp.Equals("Unconfined", StringComparison.OrdinalIgnoreCase))
                violations.Add($"Container '{cName}' uses unconfined seccomp profile");
        }
    }

    private static long? GetOptionalInt64(JsonElement element, string propertyName)
    {
        if (element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var prop)
            && prop.ValueKind == JsonValueKind.Number)
        {
            return prop.GetInt64();
        }
        return null;
    }

    private static bool? GetOptionalBoolean(JsonElement element, string propertyName)
    {
        if (element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var prop)
            && (prop.ValueKind == JsonValueKind.True || prop.ValueKind == JsonValueKind.False))
        {
            return prop.GetBoolean();
        }
        return null;
    }

    private static string? GetOptionalString(JsonElement element, string objectProperty, string typeProperty)
    {
        if (element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(objectProperty, out var objProp)
            && objProp.ValueKind == JsonValueKind.Object
            && objProp.TryGetProperty(typeProperty, out var typeProp))
        {
            return typeProp.GetString();
        }
        return null;
    }

    private static async Task<(string? Stdout, string? Stderr, bool Success)> RunCommandAsync(
        string fileName, string[] args, CancellationToken ct)
    {
        return await ScannerCommandRunner.RunAsync(fileName, args, ct);
    }
}
