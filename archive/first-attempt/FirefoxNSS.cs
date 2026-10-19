using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// Native C functions from Firefox's libNSS

// from <nss/seccommon.h>
public enum SECItemType {
    siBuffer = 0,
    siClearDataBuffer = 1,
    siCipherDataBuffer = 2,
    siDERCertBuffer = 3,
    siEncodedCertBuffer = 4,
    siDERNameBuffer = 5,
    siEncodedNameBuffer = 6,
    siAsciiNameString = 7,
    siAsciiString = 8,
    siDEROID = 9,
    siUnsignedInteger = 10,
    siUTCTime = 11,
    siGeneralizedTime = 12,
    siVisibleString = 13,
    siUTF8String = 14,
    siBMPString = 15
}

// from <nss/seccommon.h>
public unsafe struct SECItem
{
    public SECItemType type;
    public char *data;

}

/// <summary>
/// Native C functions from Firefox's libnss
/// </summary>
static partial class FireFoxNSS {

    // constant used in attributes; runtime resolution will redirect this to a discovered full path when possible
    private const string LibName = "nss3";

    // the discovered full path (if any) to the nss library on disk
    static readonly string discoveredLibPath;

    static FireFoxNSS()
    {
        var candidates = new List<string>();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrEmpty(pf))
                candidates.Add(Path.Combine(pf, "Mozilla Firefox", "nss3.dll"));

            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (!string.IsNullOrEmpty(pf86))
                candidates.Add(Path.Combine(pf86, "Mozilla Firefox", "nss3.dll"));

            // possible local installs
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!string.IsNullOrEmpty(local))
                candidates.Add(Path.Combine(local, "Mozilla Firefox", "nss3.dll"));
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            candidates.Add("/Applications/Firefox.app/Contents/MacOS/libnss3.dylib");
            candidates.Add("/usr/local/lib/libnss3.dylib");
            candidates.Add("/opt/homebrew/opt/nss/lib/libnss3.dylib");
            candidates.Add("/usr/lib/libnss3.dylib");
        }
        else // Linux / other Unix
        {
            candidates.Add("/usr/lib/x86_64-linux-gnu/libnss3.so");
            candidates.Add("/usr/lib64/libnss3.so");
            candidates.Add("/usr/lib/libnss3.so");
            candidates.Add("/usr/lib/firefox/libnss3.so");
            candidates.Add("/usr/lib/mozilla/libnss3.so");
            candidates.Add("/snap/firefox/current/usr/lib/x86_64-linux-gnu/libnss3.so");
        }

        string found = null;
        foreach (var c in candidates)
        {
            if (string.IsNullOrEmpty(c))
                continue;
            try
            {
                if (File.Exists(c))
                {
                    found = c;
                    break;
                }
            }
            catch { }
        }

        discoveredLibPath = found;

        // If we discovered an explicit path, ensure the runtime will bind DllImports for LibName to that path.
        if (!string.IsNullOrEmpty(discoveredLibPath))
        {
#if NETFRAMEWORK
            // On .NET Framework, register the module with the OS loader so DllImport("nss3") resolves to this module.
            // LoadLibrary will add the module to the process and subsequent DllImport resolution will find it.
            try
            {
                LoadLibrary(discoveredLibPath);
            }
            catch { }
#else
            // On modern .NET, use the NativeLibrary resolver to map the constant LibName to our discovered path.
            try
            {
                NativeLibrary.SetDllImportResolver(typeof(FireFoxNSS).Assembly, (name, asm, path) =>
                {
                    if (!string.Equals(name, LibName, StringComparison.Ordinal))
                        return IntPtr.Zero;

                    if (!string.IsNullOrEmpty(discoveredLibPath) && NativeLibrary.TryLoad(discoveredLibPath, out var handle))
                        return handle;

                    // fallback to default resolution
                    if (NativeLibrary.TryLoad(name, out var fallback))
                        return fallback;

                    return IntPtr.Zero;
                });
            }
            catch { }
#endif
        }
    }

#if NETFRAMEWORK
    [System.Runtime.InteropServices.DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibrary(string lpFileName);
#endif


#if NET7_0_OR_GREATER
    [LibraryImport(LibName, StringMarshalling = StringMarshalling.Utf8)]
#else
    [DllImport(LibName, CharSet = CharSet.Unicode)]
#endif
    public static partial SECItem NSS_Init(string str);

#if NET7_0_OR_GREATER
     [LibraryImport(LibName)]
#else
    [DllImport(LibName)]
#endif
     public static partial IntPtr PK11_GetInternalKeySlot();

#if NET7_0_OR_GREATER
     [LibraryImport(LibName)]
#else
    [DllImport(LibName)]
#endif
     public static partial void PK11_FreeSlot(IntPtr slot);
}