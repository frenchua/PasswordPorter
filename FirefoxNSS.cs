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
    
    const string libnss3 = "/usr/local/lib/libnss3.dylib";

    [LibraryImport(libnss3, StringMarshalling = StringMarshalling.Utf8)]
    public static partial SECItem NSS_Init(string str);

     [LibraryImport(libnss3)]
     public static partial IntPtr PK11_GetInternalKeySlot();

     [LibraryImport(libnss3)]
     public static partial void PK11_FreeSlot(IntPtr slot);
}