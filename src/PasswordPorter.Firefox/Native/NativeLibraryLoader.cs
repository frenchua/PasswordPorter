using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PasswordPorter.Firefox.Native;

/// <summary>
/// Loads a native library from an explicit path and resolves exports, on both .NET Framework
/// (Windows only) and modern .NET (any OS).
/// </summary>
internal static class NativeLibraryLoader
{
    const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;
    const int ERROR_BAD_EXE_FORMAT = 193;

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibraryExW(string lpLibFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    /// <summary>Loads the library. Its dependencies are looked up next to it.</summary>
    public static IntPtr Load(string path)
    {
        if (IsWindows)
        {
            // LOAD_WITH_ALTERED_SEARCH_PATH makes Windows resolve nss3.dll's own dependencies
            // (mozglue.dll, the VC runtime...) from the Firefox directory.
            var handle = LoadLibraryExW(path, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (handle != IntPtr.Zero)
                return handle;

            var error = Marshal.GetLastWin32Error();
            if (error == ERROR_BAD_EXE_FORMAT)
                throw new BadImageFormatException(
                    $"'{path}' does not match this process's architecture ({(Environment.Is64BitProcess ? "64" : "32")}-bit). " +
                    "Run a build of this tool that matches your Firefox installation.");
            throw new DllNotFoundException($"Could not load '{path}': {new Win32Exception(error).Message}");
        }

#if NET
        try
        {
            return NativeLibrary.Load(path);
        }
        catch (Exception e) when (e is DllNotFoundException || e is BadImageFormatException)
        {
            throw new DllNotFoundException($"Could not load '{path}': {e.Message}", e);
        }
#else
        throw new PlatformNotSupportedException("The .NET Framework build only supports Windows. Use the modern .NET build on other platforms.");
#endif
    }

    public static IntPtr GetExport(IntPtr library, string name)
    {
        IntPtr address;
        if (IsWindows)
            address = GetProcAddress(library, name);
        else
        {
#if NET
            NativeLibrary.TryGetExport(library, name, out address);
#else
            address = IntPtr.Zero;
#endif
        }

        if (address == IntPtr.Zero)
            throw new EntryPointNotFoundException($"The NSS library does not export '{name}'.");
        return address;
    }

    public static T GetFunction<T>(IntPtr library, string name) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(GetExport(library, name));

    public static T? TryGetFunction<T>(IntPtr library, string name) where T : Delegate
    {
        try { return GetFunction<T>(library, name); }
        catch (EntryPointNotFoundException) { return null; }
    }
}
