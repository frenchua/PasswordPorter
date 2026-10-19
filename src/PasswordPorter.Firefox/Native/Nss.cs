using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using PasswordPorter.Providers;

namespace PasswordPorter.Firefox.Native;

/// <summary>SECItem from nss/seccomon.h.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SecItem
{
    public int Type;      // SECItemType; 0 = siBuffer
    public IntPtr Data;   // unsigned char*
    public uint Len;
}

internal sealed class NssException : Exception
{
    public NssException(string function, int errorCode)
        : base($"{function} failed: {NssLibrary.DescribeError(errorCode)}")
    {
        ErrorCode = errorCode;
    }

    public int ErrorCode { get; }
}

/// <summary>
/// The subset of Firefox's NSS library needed to decrypt (and, for tests, encrypt) saved logins.
/// One instance per library path for the life of the process: NSS does not support being unloaded.
/// </summary>
internal sealed class NssLibrary
{
    const int SECSuccess = 0;
    public const int SEC_ERROR_BAD_PASSWORD = -8177;

    // All NSS entry points use the C calling convention.
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int NSS_Init_Fn(IntPtr configDir);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int NSS_Shutdown_Fn();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate IntPtr PK11_GetInternalKeySlot_Fn();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void PK11_FreeSlot_Fn(IntPtr slot);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PK11_NeedLogin_Fn(IntPtr slot);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PK11_NeedUserInit_Fn(IntPtr slot);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PK11_CheckUserPassword_Fn(IntPtr slot, IntPtr password);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PK11_InitPin_Fn(IntPtr slot, IntPtr ssoPassword, IntPtr userPassword);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PK11SDR_Decrypt_Fn(ref SecItem data, ref SecItem result, IntPtr cx);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PK11SDR_Encrypt_Fn(ref SecItem keyId, ref SecItem data, ref SecItem result, IntPtr cx);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PK11SDR_EncryptWithMechanism_Fn(IntPtr slot, ref SecItem keyId, UIntPtr mechanism, ref SecItem data, ref SecItem result, IntPtr cx);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void SECITEM_ZfreeItem_Fn(ref SecItem item, int freeIt);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int PORT_GetError_Fn();

    readonly NSS_Init_Fn nssInit;
    readonly NSS_Init_Fn nssInitReadWrite;
    readonly NSS_Shutdown_Fn nssShutdown;
    readonly PK11_GetInternalKeySlot_Fn getInternalKeySlot;
    readonly PK11_FreeSlot_Fn freeSlot;
    readonly PK11_NeedLogin_Fn needLogin;
    readonly PK11_NeedUserInit_Fn needUserInit;
    readonly PK11_CheckUserPassword_Fn checkUserPassword;
    readonly PK11_InitPin_Fn initPin;
    readonly PK11SDR_Decrypt_Fn sdrDecrypt;
    // Encryption is only used to build test profiles; Firefox's own NSS build exports only one of these.
    readonly PK11SDR_Encrypt_Fn? sdrEncrypt;
    readonly PK11SDR_EncryptWithMechanism_Fn? sdrEncryptWithMechanism;
    const uint CKM_AES_CBC = 0x00001082;
    readonly SECITEM_ZfreeItem_Fn zfreeItem;
    readonly PORT_GetError_Fn getError;

    static readonly Dictionary<string, NssLibrary> Loaded = new Dictionary<string, NssLibrary>(StringComparer.OrdinalIgnoreCase);
    static readonly object Gate = new object();
    bool sessionOpen;

    NssLibrary(string path)
    {
        Path = path;
        var h = NativeLibraryLoader.Load(path);
        nssInit = NativeLibraryLoader.GetFunction<NSS_Init_Fn>(h, "NSS_Init");
        nssInitReadWrite = NativeLibraryLoader.GetFunction<NSS_Init_Fn>(h, "NSS_InitReadWrite");
        nssShutdown = NativeLibraryLoader.GetFunction<NSS_Shutdown_Fn>(h, "NSS_Shutdown");
        getInternalKeySlot = NativeLibraryLoader.GetFunction<PK11_GetInternalKeySlot_Fn>(h, "PK11_GetInternalKeySlot");
        freeSlot = NativeLibraryLoader.GetFunction<PK11_FreeSlot_Fn>(h, "PK11_FreeSlot");
        needLogin = NativeLibraryLoader.GetFunction<PK11_NeedLogin_Fn>(h, "PK11_NeedLogin");
        needUserInit = NativeLibraryLoader.GetFunction<PK11_NeedUserInit_Fn>(h, "PK11_NeedUserInit");
        checkUserPassword = NativeLibraryLoader.GetFunction<PK11_CheckUserPassword_Fn>(h, "PK11_CheckUserPassword");
        initPin = NativeLibraryLoader.GetFunction<PK11_InitPin_Fn>(h, "PK11_InitPin");
        sdrDecrypt = NativeLibraryLoader.GetFunction<PK11SDR_Decrypt_Fn>(h, "PK11SDR_Decrypt");
        sdrEncrypt = NativeLibraryLoader.TryGetFunction<PK11SDR_Encrypt_Fn>(h, "PK11SDR_Encrypt");
        sdrEncryptWithMechanism = NativeLibraryLoader.TryGetFunction<PK11SDR_EncryptWithMechanism_Fn>(h, "PK11SDR_EncryptWithMechanism");
        zfreeItem = NativeLibraryLoader.GetFunction<SECITEM_ZfreeItem_Fn>(h, "SECITEM_ZfreeItem");
        getError = NativeLibraryLoader.GetFunction<PORT_GetError_Fn>(h, "PORT_GetError");
    }

    public string Path { get; }

    public static NssLibrary Load(string libraryPath)
    {
        lock (Gate)
        {
            if (!Loaded.TryGetValue(libraryPath, out var lib))
            {
                lib = new NssLibrary(libraryPath);
                Loaded[libraryPath] = lib;
            }
            return lib;
        }
    }

    /// <summary>
    /// Initialises NSS against a profile directory. NSS is process-global, so only one session
    /// can be open at a time; dispose it before opening another.
    /// </summary>
    public NssSession OpenSession(string profileDirectory, bool readWrite = false)
    {
        lock (Gate)
        {
            if (sessionOpen)
                throw new InvalidOperationException("An NSS session is already open in this process.");

            using (var dir = Utf8String.Create("sql:" + profileDirectory))
            {
                var status = readWrite ? nssInitReadWrite(dir.Pointer) : nssInit(dir.Pointer);
                if (status != SECSuccess)
                    throw new NssException("NSS_Init", getError());
            }

            var slot = getInternalKeySlot();
            if (slot == IntPtr.Zero)
            {
                var error = getError();
                nssShutdown();
                throw new NssException("PK11_GetInternalKeySlot", error);
            }

            sessionOpen = true;
            return new NssSession(this, slot);
        }
    }

    internal void CloseSession(IntPtr slot)
    {
        lock (Gate)
        {
            freeSlot(slot);
            nssShutdown();
            sessionOpen = false;
        }
    }

    internal bool NeedLogin(IntPtr slot) => needLogin(slot) != 0;

    internal bool NeedUserInit(IntPtr slot) => needUserInit(slot) != 0;

    internal bool CheckUserPassword(IntPtr slot, string password)
    {
        using var pw = Utf8String.Create(password);
        if (checkUserPassword(slot, pw.Pointer) == SECSuccess)
            return true;
        var error = getError();
        if (error == SEC_ERROR_BAD_PASSWORD)
            return false;
        throw new NssException("PK11_CheckUserPassword", error);
    }

    internal void InitPin(IntPtr slot, string password)
    {
        using var sso = Utf8String.Create("");
        using var pw = Utf8String.Create(password);
        if (initPin(slot, sso.Pointer, pw.Pointer) != SECSuccess)
            throw new NssException("PK11_InitPin", getError());
    }

    internal byte[] Decrypt(byte[] cipherText) => Transform(IntPtr.Zero, cipherText, encrypt: false);

    internal byte[] Encrypt(IntPtr slot, byte[] plainText) => Transform(slot, plainText, encrypt: true);

    byte[] Transform(IntPtr slot, byte[] input, bool encrypt)
    {
        var buffer = Marshal.AllocHGlobal(Math.Max(1, input.Length));
        try
        {
            Marshal.Copy(input, 0, buffer, input.Length);
            var inItem = new SecItem { Type = 0, Data = buffer, Len = (uint)input.Length };
            var outItem = new SecItem();
            int status;
            if (encrypt)
            {
                var keyId = new SecItem(); // empty key id = the default SDR key (created on demand)
                if (sdrEncryptWithMechanism != null)
                    status = sdrEncryptWithMechanism(slot, ref keyId, new UIntPtr(CKM_AES_CBC), ref inItem, ref outItem, IntPtr.Zero);
                else if (sdrEncrypt != null)
                    status = sdrEncrypt(ref keyId, ref inItem, ref outItem, IntPtr.Zero);
                else
                    throw new NotSupportedException("This NSS library exports no SDR encryption function.");
            }
            else
            {
                status = sdrDecrypt(ref inItem, ref outItem, IntPtr.Zero);
            }

            if (status != SECSuccess)
                throw new NssException(encrypt ? "PK11SDR_Encrypt" : "PK11SDR_Decrypt", getError());

            try
            {
                var result = new byte[outItem.Len];
                Marshal.Copy(outItem.Data, result, 0, result.Length);
                return result;
            }
            finally
            {
                zfreeItem(ref outItem, 0);
            }
        }
        finally
        {
            // Zero our unmanaged copy of the input (it is plaintext when encrypting).
            Marshal.Copy(new byte[input.Length], 0, buffer, input.Length);
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static string DescribeError(int code)
    {
        switch (code)
        {
            case -8190: return "SEC_ERROR_BAD_DATA (the encrypted data is corrupt)";
            case -8187: return "SEC_ERROR_INVALID_ARGS";
            case -8177: return "SEC_ERROR_BAD_PASSWORD (wrong primary password)";
            case -8174: return "SEC_ERROR_BAD_DATABASE (key4.db missing or unreadable)";
            case -8015: return "SEC_ERROR_NOT_INITIALIZED";
            case -8152: return "SEC_ERROR_NO_KEY (the key for this data is not in key4.db)";
            default: return "NSS error " + code;
        }
    }

    /// <summary>A NUL-terminated UTF-8 copy of a string in unmanaged memory, zeroed on dispose.</summary>
    readonly struct Utf8String : IDisposable
    {
        readonly int length;

        Utf8String(IntPtr pointer, int length)
        {
            Pointer = pointer;
            this.length = length;
        }

        public IntPtr Pointer { get; }

        public static Utf8String Create(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            var p = Marshal.AllocHGlobal(bytes.Length + 1);
            Marshal.Copy(bytes, 0, p, bytes.Length);
            Marshal.WriteByte(p, bytes.Length, 0);
            Array.Clear(bytes, 0, bytes.Length);
            return new Utf8String(p, bytes.Length + 1);
        }

        public void Dispose()
        {
            Marshal.Copy(new byte[length], 0, Pointer, length);
            Marshal.FreeHGlobal(Pointer);
        }
    }
}

/// <summary>An initialised NSS database for one profile. Dispose to shut NSS down.</summary>
internal sealed class NssSession : IDisposable
{
    readonly NssLibrary library;
    IntPtr slot;

    internal NssSession(NssLibrary library, IntPtr slot)
    {
        this.library = library;
        this.slot = slot;
    }

    /// <summary>True when the profile is protected by a primary password that has not been entered yet.</summary>
    public bool NeedsPassword => library.NeedLogin(Slot);

    public bool TryUnlock(string password) => library.CheckUserPassword(Slot, password);

    /// <summary>For brand new databases (tests): sets the primary password, "" for none.</summary>
    public void Initialize(string password)
    {
        if (library.NeedUserInit(Slot))
            library.InitPin(Slot, password);
    }

    public string DecryptString(string base64)
    {
        var plain = library.Decrypt(Convert.FromBase64String(base64));
        try { return Encoding.UTF8.GetString(plain); }
        finally { Array.Clear(plain, 0, plain.Length); }
    }

    public string EncryptString(string value) =>
        Convert.ToBase64String(library.Encrypt(Slot, Encoding.UTF8.GetBytes(value)));

    IntPtr Slot => slot != IntPtr.Zero ? slot : throw new ObjectDisposedException(nameof(NssSession));

    public void Dispose()
    {
        if (slot == IntPtr.Zero)
            return;
        library.CloseSession(slot);
        slot = IntPtr.Zero;
    }
}

/// <summary>Finds the NSS shared library that belongs to an installed Firefox.</summary>
internal static class NssLocator
{
    public static string LibraryFileName =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "nss3.dll"
        : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "libnss3.dylib"
        : "libnss3.so";

    /// <summary>Returns the full path of the NSS library, or throws with the locations that were tried.</summary>
    public static string Find(string? explicitDirectory)
    {
        if (!string.IsNullOrEmpty(explicitDirectory))
        {
            var candidate = File.Exists(explicitDirectory) ? explicitDirectory! : System.IO.Path.Combine(explicitDirectory!, LibraryFileName);
            if (!File.Exists(candidate))
                throw new ProviderException($"'{LibraryFileName}' was not found in '{explicitDirectory}'.");
            return System.IO.Path.GetFullPath(candidate);
        }

        var tried = new List<string>();
        foreach (var dir in CandidateDirectories())
        {
            if (string.IsNullOrEmpty(dir))
                continue;
            var candidate = System.IO.Path.Combine(dir, LibraryFileName);
            if (tried.Contains(candidate))
                continue;
            tried.Add(candidate);
            if (File.Exists(candidate))
                return candidate;
        }

        throw new ProviderException(
            "Could not find Firefox's NSS library. Pass nss-dir=<Firefox install folder>. Looked in:" +
            Environment.NewLine + "  " + string.Join(Environment.NewLine + "  ", tried));
    }

    static IEnumerable<string?> CandidateDirectories()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            foreach (var dir in RegistryInstallDirectories())
                yield return dir;

            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetEnvironmentVariable("ProgramW6432"),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };
            foreach (var root in roots)
            {
                if (string.IsNullOrEmpty(root))
                    continue;
                foreach (var name in new[] { "Mozilla Firefox", "Firefox Developer Edition", "Firefox Nightly", "Mozilla Firefox ESR" })
                    yield return System.IO.Path.Combine(root, name);
            }
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            yield return "/Applications/Firefox.app/Contents/MacOS";
            yield return "/Applications/Firefox Developer Edition.app/Contents/MacOS";
            yield return "/Applications/Firefox Nightly.app/Contents/MacOS";
            yield return "/opt/homebrew/opt/nss/lib";
            yield return "/usr/local/opt/nss/lib";
        }
        else
        {
            yield return "/usr/lib/firefox";
            yield return "/usr/lib64/firefox";
            yield return "/opt/firefox";
            yield return "/usr/lib/x86_64-linux-gnu";
            yield return "/usr/lib/aarch64-linux-gnu";
            yield return "/usr/lib64";
            yield return "/usr/lib";
            yield return "/snap/firefox/current/usr/lib/firefox";
        }
    }

    static IEnumerable<string> RegistryInstallDirectories()
    {
        var result = new List<string>();
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return result;
        try
        {
            foreach (var hive in new[] { Microsoft.Win32.Registry.LocalMachine, Microsoft.Win32.Registry.CurrentUser })
            {
                using var products = hive.OpenSubKey(@"SOFTWARE\Mozilla\Mozilla Firefox");
                if (products == null)
                    continue;
                foreach (var version in products.GetSubKeyNames())
                {
                    using var main = products.OpenSubKey(version + @"\Main");
                    if (main?.GetValue("Install Directory") is string dir)
                        result.Add(dir);
                }
            }
        }
        catch (Exception e) when (e is System.Security.SecurityException || e is UnauthorizedAccessException || e is IOException)
        {
            // Registry not readable; fall back to the well-known folders.
        }
        return result;
    }

}
