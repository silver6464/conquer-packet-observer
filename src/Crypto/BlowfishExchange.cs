using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using ConquerPoc;

namespace ConquerPoc.Cryptography
{
    public class ServerKeyExchange
    {
        private const string P = "E7A69EBDF105F2A6BBDEAD7E798F76A209AD73FB466431E2E7352ED262F8C558F10BEFEA977DE9E21DCEE9B04D245F300ECCBBA03E72630556D011023F9E857F";
        private const string G = "05";
        private const int PAD_LENGTH = 11;
        private const int JUNK_LENGTH = 12;
        private const string TQSERVER = "TQServer";

        private DHParameters _dhParameters;
        private AsymmetricCipherKeyPair _dhKeyPair;
        private byte[] _clientIV;
        private byte[] _serverIV;

        public byte[] CreateServerKeyPacket()
        {
            _clientIV = new byte[8];
            _serverIV = new byte[8];

            _dhParameters = new DHParameters(new BigInteger(P, 16), new BigInteger(G, 16));

            var generator = new DHKeyPairGenerator();
            generator.Init(new DHKeyGenerationParameters(new SecureRandom(), _dhParameters));
            _dhKeyPair = generator.GenerateKeyPair();

            return GeneratePacket();
        }

        public void HandleClientKeyPacket(string publicKey, ref GameCryptography crypto)
        {
            var agreement = new DHBasicAgreement();
            agreement.Init(_dhKeyPair.Private);
            var otherPublic = new DHPublicKeyParameters(new BigInteger(publicKey, 16), _dhParameters);
            var sharedSecret = agreement.CalculateAgreement(otherPublic).ToByteArrayUnsigned();
            crypto.SetKey(sharedSecret);
            crypto.SetIvs(_clientIV, _serverIV);
        }

        public unsafe byte[] GeneratePacket()
        {
            var pad = new byte[PAD_LENGTH];
            var junk = new byte[JUNK_LENGTH];

            Common.Random.NextBytes(pad);
            Common.Random.NextBytes(junk);

            var publicKey = ((DHPublicKeyParameters)_dhKeyPair.Public).Y.ToString(16).ToUpperInvariant();
            // OpenSSL's BN_bn2hex emits even-length output; pad if BC's ToString(16) dropped a leading zero.
            if ((publicKey.Length & 1) == 1) publicKey = "0" + publicKey;

            var size = 28 + PAD_LENGTH + JUNK_LENGTH + _clientIV.Length + _serverIV.Length + P.Length + G.Length + publicKey.Length + 8;

            var buffer = new byte[size];
            fixed (byte* ptr = buffer, pPad = pad, pJunk = junk, pClientIV = _clientIV, pServerIV = _serverIV)
            {
                var offset = 0;

                MSVCRT.memcpy(ptr + offset, pPad, PAD_LENGTH);
                offset += PAD_LENGTH;

                *((int*)(ptr + offset)) = size - PAD_LENGTH;
                offset += 4;

                *((int*)(ptr + offset)) = JUNK_LENGTH;
                offset += 4;

                MSVCRT.memcpy(ptr + offset, pJunk, JUNK_LENGTH);
                offset += JUNK_LENGTH;

                *((int*)(ptr + offset)) = _clientIV.Length;
                offset += 4;

                MSVCRT.memcpy(ptr + offset, pClientIV, _clientIV.Length);
                offset += _clientIV.Length;

                *((int*)(ptr + offset)) = _serverIV.Length;
                offset += 4;

                MSVCRT.memcpy(ptr + offset, pServerIV, _serverIV.Length);
                offset += _serverIV.Length;

                *((int*)(ptr + offset)) = P.Length;
                offset += 4;

                P.CopyTo(ptr + offset);
                offset += P.Length;

                *((int*)(ptr + offset)) = G.Length;
                offset += 4;

                G.CopyTo(ptr + offset);
                offset += G.Length;

                *((int*)(ptr + offset)) = publicKey.Length;
                offset += 4;

                publicKey.CopyTo(ptr + offset);
                offset += publicKey.Length;

                TQSERVER.CopyTo(ptr + offset);
            }

            return buffer;
        }
    }

    /// <summary>
    /// Client side of the Conquer DH exchange — the proxy uses this to talk to the real server.
    /// Parses the server's key packet, generates our own keypair against the server's P/G,
    /// builds a response in the byte layout the server's parser at Player.CompleteExchange expects,
    /// and derives the shared secret on demand.
    /// </summary>
    public class ClientKeyExchange
    {
        private DHParameters _dhParameters;
        private AsymmetricCipherKeyPair _dhKeyPair;
        public byte[] ClientIV { get; private set; }
        public byte[] ServerIV { get; private set; }
        public string ServerPublicKey { get; private set; }
        public string OurPublicKey { get; private set; }

        /// <summary>
        /// Parse the server's key packet (already decrypted with the initial ENCRYPTION_KEY).
        /// Layout matches ServerKeyExchange.GeneratePacket():
        ///   [0..10] pad(11) [11..14] size(int) [15..18] junk_len(int) [junk]
        ///   [iv_len:int][clientIV(8)] [iv_len:int][serverIV(8)]
        ///   [P_len:int][P(hex)] [G_len:int][G(hex)] [pubkey_len:int][pubkey(hex)] [TQServer(8)]
        /// </summary>
        public unsafe void ParseServerKeyPacket(byte[] buffer)
        {
            string P, G;
            fixed (byte* ptr = buffer)
            {
                int offset = 11; // skip pad
                int size = *((int*)(ptr + offset)); offset += 4;
                int junkLen = *((int*)(ptr + offset)); offset += 4;
                offset += junkLen;
                int clientIvLen = *((int*)(ptr + offset)); offset += 4;
                ClientIV = new byte[clientIvLen];
                for (int i = 0; i < clientIvLen; i++) ClientIV[i] = ptr[offset + i];
                offset += clientIvLen;
                int serverIvLen = *((int*)(ptr + offset)); offset += 4;
                ServerIV = new byte[serverIvLen];
                for (int i = 0; i < serverIvLen; i++) ServerIV[i] = ptr[offset + i];
                offset += serverIvLen;
                int pLen = *((int*)(ptr + offset)); offset += 4;
                var pBytes = new byte[pLen];
                for (int i = 0; i < pLen; i++) pBytes[i] = ptr[offset + i];
                P = System.Text.Encoding.ASCII.GetString(pBytes);
                offset += pLen;
                int gLen = *((int*)(ptr + offset)); offset += 4;
                var gBytes = new byte[gLen];
                for (int i = 0; i < gLen; i++) gBytes[i] = ptr[offset + i];
                G = System.Text.Encoding.ASCII.GetString(gBytes);
                offset += gLen;
                int pubLen = *((int*)(ptr + offset)); offset += 4;
                var pubBytes = new byte[pubLen];
                for (int i = 0; i < pubLen; i++) pubBytes[i] = ptr[offset + i];
                ServerPublicKey = System.Text.Encoding.ASCII.GetString(pubBytes);
            }

            _dhParameters = new DHParameters(new BigInteger(P, 16), new BigInteger(G, 16));
            var generator = new DHKeyPairGenerator();
            generator.Init(new DHKeyGenerationParameters(new SecureRandom(), _dhParameters));
            _dhKeyPair = generator.GenerateKeyPair();
            OurPublicKey = ((DHPublicKeyParameters)_dhKeyPair.Public).Y.ToString(16).ToUpperInvariant();
            if ((OurPublicKey.Length & 1) == 1) OurPublicKey = "0" + OurPublicKey;
        }

        /// <summary>
        /// Build the response packet the server expects (Player.CompleteExchange at Player.cs:1393).
        /// Layout: [0..6] anything(7) [7..10] length(int) [11..14] junk_len(int) [junk]
        ///         [pubkey_len:int][pubkey ascii hex]
        /// We use junk_len=0 to keep it minimal.
        /// </summary>
        public unsafe byte[] BuildClientKeyResponse()
        {
            int pubLen = OurPublicKey.Length;
            // server reads length at offset 7; total minus 8 (standard Conquer header subtract).
            // body bytes after offset 7: 4(length) + 4(junk_len=0) + 0(junk) + 4(pub_len) + pubLen
            int totalSize = 7 + 4 + 4 + 4 + pubLen;
            // Round up to multiple of 8 so Blowfish CFB-64 streaming is byte-aligned-safe (CFB is byte-stream so this is optional but matches client behaviour).
            int padded = totalSize;
            var buffer = new byte[padded];
            fixed (byte* ptr = buffer)
            {
                // Conquer-style header at offset 0-3: size-8 ushort, type ushort. Real client uses MSG_KEY_EXCHANGE (probably 1059) — but the server never reads these bytes for this packet, so values are cosmetic. We'll write something plausible.
                *((ushort*)(ptr + 0)) = (ushort)(padded - 8);
                *((ushort*)(ptr + 2)) = 1059; // MSG_KEY_EXCHANGE-ish; ignored
                // 3 more pad bytes (4..6) left zero
                int offset = 7;
                *((int*)(ptr + offset)) = padded; offset += 4;        // length
                *((int*)(ptr + offset)) = 0; offset += 4;             // junk_len = 0
                *((int*)(ptr + offset)) = pubLen; offset += 4;        // pubkey_len
                OurPublicKey.CopyTo(ptr + offset);
            }
            return buffer;
        }

        /// <summary>
        /// After ParseServerKeyPacket, compute the shared secret with the real server and
        /// initialise the upstream crypto.
        /// </summary>
        public void DeriveSharedKey(GameCryptography crypto)
        {
            var agreement = new DHBasicAgreement();
            agreement.Init(_dhKeyPair.Private);
            var otherPublic = new DHPublicKeyParameters(new BigInteger(ServerPublicKey, 16), _dhParameters);
            var sharedSecret = agreement.CalculateAgreement(otherPublic).ToByteArrayUnsigned();
            crypto.SetKey(sharedSecret);
            crypto.SetIvs(ClientIV, ServerIV);
        }
    }
}
