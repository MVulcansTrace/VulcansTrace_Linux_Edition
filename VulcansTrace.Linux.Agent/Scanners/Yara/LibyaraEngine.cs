using System.Reflection;
using System.Runtime.InteropServices;

namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Thin P/Invoke wrapper around the native libyara library.
/// Only the minimal C API surface needed for file scanning is imported.
/// </summary>
internal sealed class LibyaraEngine : IYaraEngine
{
    private const string Libyara = "libyara";

    private const int ErrorSuccess = 0;
    private const int CallbackMsgRuleMatching = 1;
    private const int CallbackContinue = 0;

    private const int ScanFlagsFastMode = 1;
    private const int ScanFlagsReportRulesMatching = 4;

    private static readonly object InitLock = new();
    private static bool _initialized;

    private IntPtr _compiler;
    private IntPtr _rules;

    static LibyaraEngine()
    {
        NativeLibrary.SetDllImportResolver(
            typeof(LibyaraEngine).Assembly,
            DllImportResolver);
    }

    private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!libraryName.Equals(Libyara, StringComparison.Ordinal))
            return IntPtr.Zero;

        if (NativeLibrary.TryLoad("libyara.so.10", out var handle))
            return handle;

        if (NativeLibrary.TryLoad("libyara.so", out handle))
            return handle;

        return IntPtr.Zero;
    }

    public bool IsAvailable
    {
        get
        {
            try
            {
                InitializeOnce();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public IReadOnlyList<string> CompileRules(string rulesText, string? @namespace = null)
    {
        ArgumentNullException.ThrowIfNull(rulesText);

        var errors = new List<string>();

        EnsureInitialized();
        ReleaseCompilerAndRules();

        var result = yr_compiler_create(out _compiler);
        if (result != ErrorSuccess)
        {
            errors.Add($"yr_compiler_create failed with error {result}");
            return errors;
        }

        var errorCount = yr_compiler_add_string(_compiler, rulesText, @namespace ?? "default");
        if (errorCount > 0)
        {
            var buffer = Marshal.AllocHGlobal(512);
            try
            {
                yr_compiler_get_error_message(_compiler, buffer, 512);
                var message = Marshal.PtrToStringUTF8(buffer) ?? $"unknown compile error ({errorCount} error(s))";
                errors.Add(message);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            ReleaseCompilerAndRules();
            return errors;
        }

        result = yr_compiler_get_rules(_compiler, out _rules);
        if (result != ErrorSuccess)
        {
            errors.Add($"yr_compiler_get_rules failed with error {result}");
            ReleaseCompilerAndRules();
            return errors;
        }

        return errors;
    }

    public IReadOnlyList<YaraMatchDetail> ScanFile(string path, int timeoutSeconds = 30, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        EnsureInitialized();

        if (_rules == IntPtr.Zero)
            throw new InvalidOperationException("No compiled rules are available. Call CompileRules first.");

        cancellationToken.ThrowIfCancellationRequested();

        var matches = new List<YaraMatchDetail>();
        var handle = GCHandle.Alloc(matches);
        try
        {
            var callback = new YaraScanCallback(OnScanMessage);
            var result = yr_rules_scan_file(_rules, path, ScanFlagsFastMode | ScanFlagsReportRulesMatching, callback, GCHandle.ToIntPtr(handle), timeoutSeconds);

            cancellationToken.ThrowIfCancellationRequested();

            if (result != ErrorSuccess)
            {
                throw new InvalidOperationException($"yr_rules_scan_file failed with error {result} for '{path}'");
            }
        }
        finally
        {
            handle.Free();
        }

        return matches;
    }

    public void Dispose()
    {
        ReleaseCompilerAndRules();
    }

    private static void EnsureInitialized()
    {
        InitializeOnce();
    }

    private static void InitializeOnce()
    {
        if (_initialized)
            return;

        lock (InitLock)
        {
            if (_initialized)
                return;

            var result = yr_initialize();
            if (result != ErrorSuccess)
                throw new InvalidOperationException($"yr_initialize failed with error {result}");

            _initialized = true;
        }
    }

    private void ReleaseCompilerAndRules()
    {
        if (_compiler != IntPtr.Zero)
        {
            yr_compiler_destroy(_compiler);
            _compiler = IntPtr.Zero;
        }

        if (_rules != IntPtr.Zero)
        {
            yr_rules_destroy(_rules);
            _rules = IntPtr.Zero;
        }
    }

    private static int OnScanMessage(IntPtr context, int message, IntPtr messageData, IntPtr userData)
    {
        if (message != CallbackMsgRuleMatching || messageData == IntPtr.Zero)
            return CallbackContinue;

        var rule = Marshal.PtrToStructure<YrRule>(messageData);
        var ruleName = Marshal.PtrToStringUTF8(rule.Identifier) ?? "unknown";

        var matches = (List<YaraMatchDetail>)GCHandle.FromIntPtr(userData).Target!;
        lock (matches)
        {
            matches.Add(new YaraMatchDetail { RuleIdentifier = ruleName });
        }

        return CallbackContinue;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct YrRule
    {
        public int Flags;
        public int NumAtoms;
        public uint RequiredStrings;
        public uint Unused;
        public IntPtr Identifier;
        public IntPtr Tags;
        public IntPtr Metas;
        public IntPtr Strings;
        public IntPtr Ns;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int YaraScanCallback(IntPtr context, int message, IntPtr messageData, IntPtr userData);

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern int yr_initialize();

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern int yr_finalize();

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern int yr_compiler_create(out IntPtr compiler);

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern void yr_compiler_destroy(IntPtr compiler);

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern int yr_compiler_add_string(IntPtr compiler, string rulesString, string? namespace_);

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr yr_compiler_get_error_message(IntPtr compiler, IntPtr buffer, int bufferSize);

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern int yr_compiler_get_rules(IntPtr compiler, out IntPtr rules);

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern int yr_rules_destroy(IntPtr rules);

    [DllImport(Libyara, CallingConvention = CallingConvention.Cdecl)]
    private static extern int yr_rules_scan_file(
        IntPtr rules,
        string filename,
        int flags,
        YaraScanCallback callback,
        IntPtr userData,
        int timeout);
}
