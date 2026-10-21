using System.Text;
using PasswordPorter.KeePass.Crypto;
using Xunit;

namespace PasswordPorter.Tests;

/// <summary>Known-answer tests from the RFCs / reference implementations.</summary>
public class CryptoTests
{
    static byte[] Repeat(byte value, int count)
    {
        var b = new byte[count];
        for (int i = 0; i < count; i++) b[i] = value;
        return b;
    }

    [Fact]
    public void Blake2b_Abc() =>
        Assert.Equal(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            Convert.ToHexStringLower(Blake2b.Hash(Encoding.ASCII.GetBytes("abc"), 64)));

    [Fact]
    public void Blake2b_Empty() =>
        Assert.Equal(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            Convert.ToHexStringLower(Blake2b.Hash(new byte[0], 64)));

    // RFC 9106 section 5 test vectors.
    [Theory]
    [InlineData(0, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")]
    [InlineData(1, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")]
    [InlineData(2, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")]
    public void Argon2_Rfc9106(int type, string expected)
    {
        var tag = Argon2.Hash((Argon2Type)type, Repeat(1, 32), Repeat(2, 16), parallelism: 4, memoryKiB: 32, iterations: 3,
            version: 0x13, tagLength: 32, secret: Repeat(3, 8), associatedData: Repeat(4, 12));
        Assert.Equal(expected, Convert.ToHexStringLower(tag));
    }

    [Fact]
    public void ChaCha20_Rfc8439_Section2_4_2()
    {
        var key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte)i;
        var nonce = Convert.FromHexString("000000000000004a00000000");
        var data = Encoding.ASCII.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        new ChaCha20(key, nonce, counter: 1).Transform(data);
        Assert.StartsWith("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b", Convert.ToHexStringLower(data));
    }

    [Fact]
    public void Salsa20_Estream_256bit_Set1_Vector0()
    {
        var key = new byte[32];
        key[0] = 0x80;
        var data = new byte[64];
        new Salsa20(key, new byte[8]).Transform(data);
        Assert.Equal(
            "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117",
            Convert.ToHexStringLower(data));
    }

    [Fact]
    public void StreamCipher_IsContinuousAcrossCalls()
    {
        var key = Repeat(7, 32);
        var nonce = Repeat(9, 12);
        var whole = new byte[200];
        new ChaCha20(key, nonce).Transform(whole);

        var parts = new byte[200];
        var c = new ChaCha20(key, nonce);
        c.Transform(parts, 0, 3);
        c.Transform(parts, 3, 100);
        c.Transform(parts, 103, 97);
        Assert.Equal(whole, parts);
    }
}
