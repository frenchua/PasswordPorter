using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace PasswordPorter.Firefox.Native;

/// <summary>SECItem from nss/seccomon.h.</summary>
internal unsafe struct SecItem
{
    public int Type;    // SECItemType; 0 = siBuffer
    public byte* Data;
    public uint Len;
}

internal sealed class NssException(string function, int errorCode)
    : Exception($"{function} failed: {NssLibrary.DescribeError(errorCode)}")
{
    public int ErrorCode { get; } = errorCode;
}

/// <summary>
/// The subset of Firefox's NSS library needed to decrypt (and, for tests, encrypt) saved logins,
/// bound at runtime from an explicit path. One instance per library for the life of the process:
/// NSS does not support being unloaded.
/// </summary>
internal sealed unsafe class NssLibrary
{
    const int SECSuccess = 0;
    const int SEC_ERROR_BAD_PASSWORD = -8177;
    const nuint CKM_AES_CBC = 0x00001082;

    // All NSS entry points use the C calling convention.
    readonly delegate* unmanaged[Cdecl]<byte*, int> nssInit;
    readonly delegate* unmanaged[Cdecl]<byte*, int> nssInitReadWrite;
    readonly delegate* unmanaged[Cdecl]<int> nssShutdown;
    readonly delegate* unmanaged[Cdecl]<nint> getInternalKeySlot;
    readonly delegate* unmanaged[Cdecl]<nint, void> freeSlot;
    readonly delegate* unmanaged[Cdecl]<nint, int> needLogin;
    readonly delegate* unmanaged[Cdecl]<nint, int> needUserInit;
    readonly delegate* unmanaged[Cdecl]<nint, byte*, int> checkUserPassword;
    readonly delegate* unmanaged[Cdecl]<nint, byte*, byte*, int> initPin;
    readonly delegate* unmanaged[Cdecl]<SecItem*, SecItem*, void*, int> sdrDecrypt;
    readonly delegate* unmanaged[Cdecl]<SecItem*, int, void> zfreeItem;
    readonly delegate* unmanaged[Cdecl]<int> getError;

    // Encryption is only used to build test profiles. Firefox's own NSS build exports only the
    // mechanism variant; system NSS builds export both.
    readonly delegate* unmanaged[Cdecl]<SecItem*, SecItem*, SecItem*, void*, int> sdrEncrypt;
    readonly delegate* unmanaged[Cdecl]<nint, SecItem*, nuint, SecItem*, SecItem*, void*, int> sdrEncryptWithMechanism;

    static readonly Dictionary<string, NssLibrary> Loaded = new(StringComparer.OrdinalIgnoreCase);
    static readonly Lock Gate = new();
    bool sessionOpen;

    NssLibrary(string path)
    {
        nint h;
        try
        {
            // An absolute path makes Windows resolve nss3.dll's own dependencies (mozglue.dll...) next to it.
            h = NativeLibrary.Load(path);
        }
        catch (BadImageFormatException e)
        {
            throw new BadImageFormatException(
                $"'{path}' does not match this process's architecture ({RuntimeInformation.ProcessArchitecture}). " +
                "Run a build of this tool that matches your Firefox installation.", e);
        }

        nssInit = (delegate* unmanaged[Cdecl]<byte*, int>)Export(h, "NSS_Init");
        nssInitReadWrite = (delegate* unmanaged[Cdecl]<byte*, int>)Export(h, "NSS_InitReadWrite");
        nssShutdown = (delegate* unmanaged[Cdecl]<int>)Export(h, "NSS_Shutdown");
        getInternalKeySlot = (delegate* unmanaged[Cdecl]<nint>)Export(h, "PK11_GetInternalKeySlot");
        freeSlot = (delegate* unmanaged[Cdecl]<nint, void>)Export(h, "PK11_FreeSlot");
        needLogin = (delegate* unmanaged[Cdecl]<nint, int>)Export(h, "PK11_NeedLogin");
        needUserInit = (delegate* unmanaged[Cdecl]<nint, int>)Export(h, "PK11_NeedUserInit");
        checkUserPassword = (delegate* unmanaged[Cdecl]<nint, byte*, int>)Export(h, "PK11_CheckUserPassword");
        initPin = (delegate* unmanaged[Cdecl]<nint, byte*, byte*, int>)Export(h, "PK11_InitPin");
        sdrDecrypt = (delegate* unmanaged[Cdecl]<SecItem*, SecItem*, void*, int>)Export(h, "PK11SDR_Decrypt");
        zfreeItem = (delegate* unmanaged[Cdecl]<SecItem*, int, void>)Export(h, "SECITEM_ZfreeItem");
        getError = (delegate* unmanaged[Cdecl]<int>)Export(h, "PORT_GetError");

        NativeLibrary.TryGetExport(h, "PK11SDR_Encrypt", out var encrypt);
        NativeLibrary.TryGetExport(h, "PK11SDR_EncryptWithMechanism", out var encryptWithMechanism);
        sdrEncrypt = (delegate* unmanaged[Cdecl]<SecItem*, SecItem*, SecItem*, void*, int>)encrypt;
        sdrEncryptWithMechanism = (delegate* unmanaged[Cdecl]<nint, SecItem*, nuint, SecItem*, SecItem*, void*, int>)encryptWithMechanism;
    }

    static nint Export(nint library, string name) =>
        NativeLibrary.TryGetExport(library, name, out var address)
            ? address
            : throw new EntryPointNotFoundException($"The NSS library does not export '{name}'.");

    public static NssLibrary Load(string libraryPath)
    {
        lock (Gate)
        {
            if (!Loaded.TryGetValue(libraryPath, out var lib))
                Loaded[libraryPath] = lib = new NssLibrary(libraryPath);
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

            var dir = Utf8Z("sql:" + profileDirectory);
            int status;
            fixed (byte* p = dir)
                status = readWrite ? nssInitReadWrite(p) : nssInit(p);
            if (status != SECSuccess)
                throw new NssException("NSS_Init", getError());

            var slot = getInternalKeySlot();
            if (slot == 0)
            {
                var error = getError();
                nssShutdown();
                throw new NssException("PK11_GetInternalKeySlot", error);
            }

            sessionOpen = true;
            return new NssSession(this, slot);
        }
    }

    internal void CloseSession(nint slot)
    {
        lock (Gate)
        {
            freeSlot(slot);
            nssShutdown();
            sessionOpen = false;
        }
    }

    internal bool NeedLogin(nint slot) => needLogin(slot) != 0;

    internal bool NeedUserInit(nint slot) => needUserInit(slot) != 0;

    internal bool CheckUserPassword(nint slot, string password)
    {
        var pw = Utf8Z(password);
        try
        {
            int status;
            fixed (byte* p = pw)
                status = checkUserPassword(slot, p);
            if (status == SECSuccess)
                return true;
            var error = getError();
            return error == SEC_ERROR_BAD_PASSWORD ? false : throw new NssException("PK11_CheckUserPassword", error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
        }
    }

    internal void InitPin(nint slot, string password)
    {
        var sso = Utf8Z("");
        var pw = Utf8Z(password);
        try
        {
            int status;
            fixed (byte* s = sso)
            fixed (byte* p = pw)
                status = initPin(slot, s, p);
            if (status != SECSuccess)
                throw new NssException("PK11_InitPin", getError());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
        }
    }

    internal byte[] Decrypt(byte[] cipherText) => Transform(0, cipherText, encrypt: false);

    internal byte[] Encrypt(nint slot, byte[] plainText) => Transform(slot, plainText, encrypt: true);

    byte[] Transform(nint slot, byte[] input, bool encrypt)
    {
        fixed (byte* data = input)
        {
            var inItem = new SecItem { Type = 0, Data = data, Len = (uint)input.Length };
            var outItem = new SecItem();
            var keyId = new SecItem(); // empty key id = the default SDR key (created on demand)

            int status;
            if (!encrypt)
                status = sdrDecrypt(&inItem, &outItem, null);
            else if (sdrEncryptWithMechanism != null)
                status = sdrEncryptWithMechanism(slot, &keyId, CKM_AES_CBC, &inItem, &outItem, null);
            else if (sdrEncrypt != null)
                status = sdrEncrypt(&keyId, &inItem, &outItem, null);
            else
                throw new NotSupportedException("This NSS library exports no SDR encryption function.");

            if (status != SECSuccess)
                throw new NssException(encrypt ? "PK11SDR_Encrypt" : "PK11SDR_Decrypt", getError());

            try
            {
                return new ReadOnlySpan<byte>(outItem.Data, (int)outItem.Len).ToArray();
            }
            finally
            {
                zfreeItem(&outItem, 0);
            }
        }
    }

    /// <summary>NUL-terminated UTF-8 bytes, for passing to C. Callers zero the array when it holds a secret.</summary>
    static byte[] Utf8Z(string value)
    {
        var bytes = new byte[Encoding.UTF8.GetByteCount(value) + 1];
        Encoding.UTF8.GetBytes(value, bytes);
        return bytes;
    }

    public static string DescribeError(int code) => code switch
    {
        -8190 => "SEC_ERROR_BAD_DATA (the encrypted data is corrupt)",
        -8187 => "SEC_ERROR_INVALID_ARGS",
        -8177 => "SEC_ERROR_BAD_PASSWORD (wrong primary password)",
        -8174 => "SEC_ERROR_BAD_DATABASE (key4.db missing or unreadable)",
        -8152 => "SEC_ERROR_NO_KEY (the key for this data is not in key4.db)",
        -8015 => "SEC_ERROR_NOT_INITIALIZED",
        _ => "NSS error " + code,
    };
}

/// <summary>An initialised NSS database for one profile. Dispose to shut NSS down.</summary>
internal sealed class NssSession(NssLibrary library, nint slot) : IDisposable
{
    nint slot = slot;

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
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public string EncryptString(string value) =>
        Convert.ToBase64String(library.Encrypt(Slot, Encoding.UTF8.GetBytes(value)));

    nint Slot => slot != 0 ? slot : throw new ObjectDisposedException(nameof(NssSession));

    public void Dispose()
    {
        if (slot == 0)
            return;
        library.CloseSession(slot);
        slot = 0;
    }
}
