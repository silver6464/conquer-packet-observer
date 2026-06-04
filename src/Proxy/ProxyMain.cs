using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ConquerPoc;
using ConquerPoc.Cryptography;

namespace ConquerRevObserver
{
    /// <summary>
    /// Observer-only MitM proxy for the Rev Conquer server.
    ///
    /// Setup:
    ///   - Listens on 0.0.0.0:1080 as a minimal SOCKS5 server.
    ///   - Proxifier on the Windows machine running Conquer.exe routes its outbound
    ///     traffic to this proxy via SOCKS5.
    ///   - For each incoming SOCKS5 CONNECT, the destination IP+port the client wants
    ///     to reach (e.g. 139.99.125.223:5817 game, :9959 login) is extracted; we open
    ///     a TCP connection to the REAL destination ourselves and bridge.
    ///   - In the bridge, we run the standard TQ Blowfish handshake (same DR654 key
    ///     and same DH constants as 5065 — confirmed by binary inspection of the Rev
    ///     Conquer.exe) and log every plaintext packet we observe in either direction.
    ///
    /// This is observation-only. No injection, no fabrication, no swallowing. The goal
    /// is to learn how the Rev server's wire protocol differs from 5065.
    /// </summary>
    public static class ProxyMain
    {
        private const int LISTEN_PORT = 1080;
        private const int REV_LOGIN_PORT = 9959;
        private const int REV_GAME_PORT = 5817;

        // Directory the proxy watches for Frida-captured keyfiles. When a session.json
        // appears here, the next 5817 connection switches from MitM-DH mode to
        // observe-only mode (passthrough ciphertext, decrypt locally using the
        // captured BF_KEY schedules).
        public static string KeyfileDir { get; private set; } =
            System.IO.Path.Combine(AppContext.BaseDirectory, "captures", "keys");

        public static void Main(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--keyfile-dir" && i + 1 < args.Length)
                {
                    KeyfileDir = args[++i];
                }
            }
            Directory.CreateDirectory(KeyfileDir);

            var listener = new TcpListener(IPAddress.Any, LISTEN_PORT);
            listener.Start();
            Log("proxy", $"SOCKS5 observer listening on 0.0.0.0:{LISTEN_PORT}");
            Log("proxy", $"Watching keyfile dir: {KeyfileDir}");
            Log("proxy", "Configure Proxifier: Proxy Server type=SOCKS5, host=<this machine's Tailscale IP>, port=1080");
            Log("proxy", "Then a Proxification Rule: match Conquer.exe -> action: that proxy server");

            while (true)
            {
                var client = listener.AcceptTcpClient();
                ThreadPool.QueueUserWorkItem(_ => new Session(client).Run());
            }
        }

        public static void Log(string tag, string msg)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [{tag}] {msg}");
        }
    }

    public sealed class Session
    {
        private readonly TcpClient _client;
        private NetworkStream _cs;          // client (Proxifier) side
        private TcpClient _upstream;        // upstream (real Rev server) side
        private NetworkStream _ss;

        // For game-port (5817) flow:
        private readonly GameCryptography _downstream = new GameCryptography(Common.ENCRYPTION_KEY);
        private readonly GameCryptography _upstreamCrypto = new GameCryptography(Common.ENCRYPTION_KEY);
        private readonly ServerKeyExchange _downstreamDh = new ServerKeyExchange();
        private readonly ClientKeyExchange _upstreamDh = new ClientKeyExchange();

        // For login-port (9959) flow:
        private readonly AuthCryptography _downstreamAuth = new AuthCryptography();
        private readonly AuthCryptography _upstreamAuth = new AuthCryptography();

        private int _destPort;
        private string _destHost;

        // Per-session capture state. Only opened for ports we care about (game/login/anticheat).
        // Raw ciphertext goes to `<sessionDir>/s2c.bin` and `c2s.bin` exactly as it arrived on
        // the socket — pre-decryption, byte-for-byte. Hex log goes to `<sessionDir>/transcript.log`.
        private string _sessionDir;
        private FileStream _s2cBin, _c2sBin;
        private StreamWriter _transcript;
        private readonly object _captureLock = new object();
        private static readonly string CaptureRoot = System.IO.Path.Combine(AppContext.BaseDirectory, "captures");

        public Session(TcpClient client)
        {
            _client = client;
        }

        private void OpenCapture()
        {
            // Only capture the ports we care about — keeps the launcher's noisy
            // background TLS connections out of the capture dir.
            if (!(_destPort == 9528 || _destPort == 5817 || _destPort == 9959))
                return;
            try
            {
                Directory.CreateDirectory(CaptureRoot);
                string sid = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                _sessionDir = System.IO.Path.Combine(CaptureRoot, $"{sid}__{_destHost}_{_destPort}");
                Directory.CreateDirectory(_sessionDir);
                _s2cBin = new FileStream(System.IO.Path.Combine(_sessionDir, "s2c.bin"), FileMode.Create, FileAccess.Write, FileShare.Read);
                _c2sBin = new FileStream(System.IO.Path.Combine(_sessionDir, "c2s.bin"), FileMode.Create, FileAccess.Write, FileShare.Read);
                _transcript = new StreamWriter(System.IO.Path.Combine(_sessionDir, "transcript.log")) { AutoFlush = true };
                _transcript.WriteLine($"# session {sid} dest={_destHost}:{_destPort}");
                ProxyMain.Log("capture", $"opened {_sessionDir}");
            }
            catch (Exception e)
            {
                ProxyMain.Log("capture", $"failed to open capture dir: {e.Message}");
            }
        }

        private void CaptureChunk(byte[] chunk, int n, bool isServerToClient, int chunkIdx)
        {
            if (_sessionDir == null) return;
            lock (_captureLock)
            {
                try
                {
                    var bin = isServerToClient ? _s2cBin : _c2sBin;
                    bin?.Write(chunk, 0, n);
                    bin?.Flush();
                    if (_transcript != null)
                    {
                        string tag = isServerToClient ? "s->c" : "c->s";
                        _transcript.Write($"[{DateTime.Now:HH:mm:ss.fff}] {tag} chunk#{chunkIdx} n={n}\n");
                        for (int i = 0; i < n; i++)
                        {
                            _transcript.Write(chunk[i].ToString("X2"));
                            _transcript.Write((i + 1) % 16 == 0 ? '\n' : ' ');
                        }
                        if (n % 16 != 0) _transcript.Write('\n');
                    }
                }
                catch (Exception e)
                {
                    ProxyMain.Log("capture", $"write error: {e.Message}");
                }
            }
        }

        private void CloseCapture()
        {
            lock (_captureLock)
            {
                try { _s2cBin?.Dispose(); } catch { }
                try { _c2sBin?.Dispose(); } catch { }
                try { _transcript?.Dispose(); } catch { }
                _s2cBin = null; _c2sBin = null; _transcript = null;
            }
        }

        public void Run()
        {
            try
            {
                _cs = _client.GetStream();
                _cs.ReadTimeout = 30000;
                if (!DoSocksHandshake()) return;
                ProxyMain.Log("sess", $"SOCKS5 CONNECT -> {_destHost}:{_destPort}");
                OpenCapture();

                // Open upstream
                _upstream = new TcpClient();
                _upstream.Connect(_destHost, _destPort);
                _ss = _upstream.GetStream();
                ProxyMain.Log("sess", $"upstream connected");

                // SOCKS5 success reply (BIND.ADDR = 0.0.0.0:0 is fine for CONNECT)
                _cs.Write(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);

                // Reset timeouts now that the proxy phase is over.
                _cs.ReadTimeout = Timeout.Infinite;
                _ss.ReadTimeout = Timeout.Infinite;

                // Game port (5817): two modes.
                //   - Keyfile mode: a Frida-captured session.json is in KeyfileDir, OR
                //     will arrive while this connection is alive. We do NOT attempt
                //     MitM-DH. Forward bytes untouched. When the keyfile appears, the
                //     pumps start decrypting locally — they don't re-encrypt because
                //     we're matched 1:1 with the client's cipher state, so the server
                //     never sees a proxy.
                //   - DH mode: legacy path that tries to mediate the handshake itself.
                //     Kept for environments where the schedule isn't being captured.
                // Other ports: raw passthrough.
                if (_destPort == ProxyMainPorts.REV_GAME_PORT)
                    BridgeGameObserveOnly();
                else
                    BridgeRaw();
            }
            catch (Exception e)
            {
                ProxyMain.Log("sess", $"error: {e.Message}");
            }
            finally
            {
                try { _client.Close(); } catch { }
                try { _upstream?.Close(); } catch { }
                CloseCapture();
                ProxyMain.Log("sess", "session closed");
            }
        }

        // Minimal SOCKS5 (no auth, CONNECT only). Returns true if we got a valid CONNECT.
        // RFC 1928. Sets _destHost / _destPort on success.
        private bool DoSocksHandshake()
        {
            var buf = new byte[512];

            // Greeting: [VER=5][NMETHODS][METHODS...]
            int n = _cs.Read(buf, 0, 2);
            if (n < 2 || buf[0] != 0x05) { ProxyMain.Log("socks", "bad greeting"); return false; }
            int nmethods = buf[1];
            _cs.Read(buf, 0, nmethods); // discard method bytes
            // Reply: [VER=5][METHOD=0 (no auth)]
            _cs.Write(new byte[] { 0x05, 0x00 }, 0, 2);

            // Request: [VER=5][CMD][RSV=0][ATYP][ADDR][PORT]
            n = _cs.Read(buf, 0, 4);
            if (n < 4 || buf[0] != 0x05 || buf[1] != 0x01)
            {
                ProxyMain.Log("socks", $"unsupported request: ver={buf[0]} cmd={buf[1]}");
                SocksReplyErr(0x07);
                return false;
            }
            byte atyp = buf[3];
            if (atyp == 0x01) // IPv4
            {
                _cs.Read(buf, 0, 4);
                _destHost = $"{buf[0]}.{buf[1]}.{buf[2]}.{buf[3]}";
            }
            else if (atyp == 0x03) // domain
            {
                _cs.Read(buf, 0, 1);
                int len = buf[0];
                _cs.Read(buf, 0, len);
                _destHost = Encoding.ASCII.GetString(buf, 0, len);
            }
            else if (atyp == 0x04) // IPv6
            {
                _cs.Read(buf, 0, 16);
                var ipv6 = new System.Net.IPAddress(buf.AsSpan(0, 16).ToArray()).ToString();
                _destHost = ipv6;
            }
            else
            {
                ProxyMain.Log("socks", $"unsupported ATYP {atyp}");
                SocksReplyErr(0x08);
                return false;
            }
            _cs.Read(buf, 0, 2);
            _destPort = (buf[0] << 8) | buf[1];
            return true;
        }

        private void SocksReplyErr(byte code)
        {
            try { _cs.Write(new byte[] { 0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10); } catch { }
        }

        // ============================================================
        // Game port (5817), keyfile mode: forward ciphertext untouched, watch
        // for a Frida-captured session.json, and start decrypting locally once
        // it's available. The proxy never re-encrypts in this mode — it's a
        // pure observer that happens to know the same key the client knows.
        //
        // Rev's wire format on 5817 is post-DH from byte 1: the 64-byte game
        // BF_KEY is set up via the login flow on 9959, and 5817 is encrypted
        // with it from the first byte. IV starts at 0 for both directions on
        // each new TCP connection. So the pumps decrypt from byte 0, no
        // cutover math needed.
        // ============================================================
        private GameKeyState _keyState;     // null until keyfile arrives

        private void BridgeGameObserveOnly()
        {
            ProxyMain.Log("game", "observe-only mode: forwarding ciphertext, watching for keyfile");

            Task.Run(() => KeyfileWatcher());

            var sToC = Task.Run(() => ObservePump(_ss, _cs, "s->c", isServerToClient: true));
            var cToS = Task.Run(() => ObservePump(_cs, _ss, "c->s", isServerToClient: false));
            Task.WaitAny(sToC, cToS);
        }

        private void ObservePump(NetworkStream from, NetworkStream to, string tag, bool isServerToClient)
        {
            var buf = new byte[8192];
            int chunkIdx = 0;
            while (true)
            {
                int n;
                try { n = from.Read(buf, 0, buf.Length); }
                catch { return; }
                if (n <= 0) return;

                var chunk = new byte[n];
                Buffer.BlockCopy(buf, 0, chunk, 0, n);

                // Always capture raw ciphertext to disk for offline replay.
                CaptureChunk(chunk, n, isServerToClient, chunkIdx);
                chunkIdx++;

                var state = _keyState;
                if (state != null)
                {
                    var pt = (byte[])chunk.Clone();
                    lock (state)
                    {
                        if (isServerToClient) state.Crypto.DecryptS2c(pt);
                        else                  state.Crypto.DecryptC2s(pt);
                    }
                    WalkPackets(pt, tag);
                }

                try { to.Write(chunk, 0, n); } catch { return; }
            }
        }

        private void KeyfileWatcher()
        {
            // Poll for the first session_*.json we haven't already consumed.
            // Rename to .used after load so subsequent connections don't reuse it.
            while (_keyState == null)
            {
                try
                {
                    if (Directory.Exists(ProxyMain.KeyfileDir))
                    {
                        foreach (var f in Directory.GetFiles(ProxyMain.KeyfileDir, "session_*.json"))
                        {
                            try
                            {
                                var state = GameKeyState.LoadFrom(f);
                                if (state == null) continue;
                                File.Move(f, f + ".used");
                                _keyState = state;
                                ProxyMain.Log("game", $"loaded keyfile {Path.GetFileName(f)}");
                                return;
                            }
                            catch (Exception e)
                            {
                                ProxyMain.Log("game", $"keyfile load failed for {f}: {e.Message}");
                            }
                        }
                    }
                }
                catch { }
                Thread.Sleep(200);
            }
        }

        // ============================================================
        // Game port (5817): same TQ Blowfish/DH dance as 5065 (we confirmed
        // both binaries use DR654dt34trg4UI6 as the pre-DH key).
        // ============================================================
        private void BridgeGame()
        {
            ProxyMain.Log("game", "starting Blowfish DH handshake observation");

            // Step 1: read the server's ServerKeyPacket.
            // Time-bounded with a long window because we observed Rev's server respond slowly
            // (10-25 seconds) when our test IP makes many rapid connections — looks like
            // their DDoS protection / per-IP rate limit. If 60s elapse with no bytes, fall
            // back to raw passthrough so login isn't blocked indefinitely.
            byte[] realServerKeyPkt;
            try
            {
                _ss.ReadTimeout = 60000;
                realServerKeyPkt = ReadOnce(_ss);
                _ss.ReadTimeout = Timeout.Infinite;
            }
            catch (Exception e)
            {
                ProxyMain.Log("game", $"upstream read timed out / failed ({e.GetType().Name}: {e.Message}). Falling back to raw passthrough so client can retry.");
                _ss.ReadTimeout = Timeout.Infinite;
                BridgeRaw();
                return;
            }
            // We've now consumed bytes from _ss. We MUST forward them downstream regardless
            // of what happens below, otherwise the client never gets its hello and login hangs.

            // Keep the original ciphertext so we can forward it after analysis.
            byte[] originalCiphertext = (byte[])realServerKeyPkt.Clone();

            // Capture the raw ciphertext to disk as the FIRST s2c bytes — RawPump would
            // otherwise miss this because ReadOnce already consumed them from _ss.
            CaptureChunk(originalCiphertext, originalCiphertext.Length, isServerToClient: true, chunkIdx: 0);

            // Dump RAW CIPHERTEXT before any decryption attempt. This is what we need for
            // known-plaintext analysis to find their actual pre-DH key.
            {
                var sb = new StringBuilder();
                int dumpLen = Math.Min(originalCiphertext.Length, 512);
                for (int i = 0; i < dumpLen; i++)
                {
                    sb.Append(originalCiphertext[i].ToString("X2"));
                    sb.Append((i + 1) % 16 == 0 ? '\n' : ' ');
                }
                ProxyMain.Log("game", $"server hello RAW CIPHERTEXT ({originalCiphertext.Length} bytes, dumping {dumpLen}):\n{sb}");
            }

            // Decrypt with the static pre-DH key, then dump the plaintext so we can analyze
            // exactly what Rev's hello looks like — even if our 5065 parser would crash on it.
            _upstreamCrypto.Decrypt(realServerKeyPkt);
            {
                var sb = new StringBuilder();
                int dumpLen = Math.Min(realServerKeyPkt.Length, 512);
                for (int i = 0; i < dumpLen; i++)
                {
                    sb.Append(realServerKeyPkt[i].ToString("X2"));
                    sb.Append((i + 1) % 16 == 0 ? '\n' : ' ');
                }
                ProxyMain.Log("game", $"server hello plaintext ({realServerKeyPkt.Length} bytes, dumping {dumpLen}):\n{sb}");
            }

            // Sanity-check the 5065 layout BEFORE calling ParseServerKeyPacket. The parser
            // reads several int32 length fields from fixed offsets and advances 'offset'. If
            // any length is bogus we walk off the end and AccessViolationException terminates
            // the process. Bounds-check here and fall back to raw if shapes don't match.
            bool layoutLooksOk = ValidateKeyPacketLayout(realServerKeyPkt);
            if (!layoutLooksOk)
            {
                ProxyMain.Log("game", "Rev hello does not match 5065 layout — falling back to raw passthrough and forwarding the bytes downstream so client can continue.");
                // Forward original ciphertext to client unchanged. The client's pre-DH crypto
                // will decrypt it correctly because nothing else has gone over _downstream yet.
                try { _cs.Write(originalCiphertext, 0, originalCiphertext.Length); } catch { }
                BridgeRaw();
                return;
            }

            try
            {
                _upstreamDh.ParseServerKeyPacket(realServerKeyPkt);
                ProxyMain.Log("game", $"ParseServerKeyPacket succeeded — P/G/pubkey extracted");
            }
            catch (Exception e)
            {
                ProxyMain.Log("game", $"ParseServerKeyPacket threw despite bounds check ({e.GetType().Name}: {e.Message}). Falling back to raw.");
                try { _cs.Write(originalCiphertext, 0, originalCiphertext.Length); } catch { }
                BridgeRaw();
                return;
            }

            // Step 2: forward our own ServerKeyPacket downstream to the client
            //         (proxy plays server-role on the client side)
            var ourServerKeyPkt = _downstreamDh.CreateServerKeyPacket();
            var ourServerKeyPktEnc = (byte[])ourServerKeyPkt.Clone();
            _downstream.Encrypt(ourServerKeyPktEnc);
            _cs.Write(ourServerKeyPktEnc, 0, ourServerKeyPktEnc.Length);
            ProxyMain.Log("game", $"sent ServerKeyPacket to client ({ourServerKeyPkt.Length} bytes)");

            // Step 3: read client's DH response (entire chunk, including any pipelined post-DH bytes)
            var clientPubResp = ReadOnce(_cs);
            _downstream.Decrypt(clientPubResp);
            int dhSize;
            unsafe { fixed (byte* p = clientPubResp) dhSize = *((int*)(p + 7)); }
            string clientPubKey = ExtractClientPubKey(clientPubResp);
            ProxyMain.Log("game", $"received client pubkey ({clientPubKey.Length} hex chars), DH packet size={dhSize}, chunk size={clientPubResp.Length}");

            // Complete downstream DH (client side re-key)
            var dsRef = _downstream;
            _downstreamDh.HandleClientKeyPacket(clientPubKey, ref dsRef);
            ProxyMain.Log("game", "downstream DH complete, re-keyed");

            // Stash any leftover plaintext post-DH bytes (client pipelines MSG_CONNECT)
            byte[] leftover = null;
            int leftoverLen = clientPubResp.Length - dhSize;
            if (leftoverLen > 0)
            {
                leftover = new byte[leftoverLen];
                Buffer.BlockCopy(clientPubResp, dhSize, leftover, 0, leftoverLen);
                ProxyMain.Log("game", $"stashed {leftoverLen} leftover bytes (post-DH plaintext)");
            }

            // Step 4: send our own DH response upstream and re-key upstream crypto
            var ourClientResp = _upstreamDh.BuildClientKeyResponse();
            var ourClientRespEnc = (byte[])ourClientResp.Clone();
            _upstreamCrypto.Encrypt(ourClientRespEnc);
            _ss.Write(ourClientRespEnc, 0, ourClientRespEnc.Length);
            _upstreamDh.DeriveSharedKey(_upstreamCrypto);
            ProxyMain.Log("game", "upstream DH complete, re-keyed");

            // Spin both pumps
            if (leftover != null)
            {
                // Forward the leftover plaintext upstream (re-encrypt with new upstream key)
                lock (_upstreamCrypto)
                {
                    _upstreamCrypto.Encrypt(leftover);
                    _ss.Write(leftover, 0, leftover.Length);
                }
                ProxyMain.Log("game", $"forwarded {leftoverLen} stashed leftover bytes to server");
            }

            var sToC = Task.Run((Action)GamePumpServerToClient);
            var cToS = Task.Run((Action)GamePumpClientToServer);
            Task.WaitAny(sToC, cToS);
        }

        private void GamePumpServerToClient()
        {
            var buf = new byte[8192];
            while (true)
            {
                int n = _ss.Read(buf, 0, buf.Length);
                if (n <= 0) return;
                var chunk = new byte[n];
                Buffer.BlockCopy(buf, 0, chunk, 0, n);
                _upstreamCrypto.Decrypt(chunk);
                WalkPackets(chunk, "s->c");
                lock (_downstream)
                {
                    _downstream.Encrypt(chunk);
                    _cs.Write(chunk, 0, chunk.Length);
                }
            }
        }

        private void GamePumpClientToServer()
        {
            var buf = new byte[8192];
            while (true)
            {
                int n = _cs.Read(buf, 0, buf.Length);
                if (n <= 0) return;
                var chunk = new byte[n];
                Buffer.BlockCopy(buf, 0, chunk, 0, n);
                _downstream.Decrypt(chunk);
                WalkPackets(chunk, "c->s");
                lock (_upstreamCrypto)
                {
                    _upstreamCrypto.Encrypt(chunk);
                    _ss.Write(chunk, 0, chunk.Length);
                }
            }
        }

        private unsafe void WalkPackets(byte[] chunk, string dir)
        {
            fixed (byte* basePtr = chunk)
            {
                int offset = 0;
                int safety = 0;
                while (offset + 4 <= chunk.Length && safety++ < 64)
                {
                    ushort size = *((ushort*)(basePtr + offset));
                    ushort type = *((ushort*)(basePtr + offset + 2));
                    int total = size + 8;
                    if (total <= 0 || total > chunk.Length - offset)
                    {
                        ProxyMain.Log("pkt", $"{dir} type={type} total={total} [malformed, stop walking]");
                        return;
                    }
                    // Hex dump the first 32 bytes (or full packet if shorter) for new packet types.
                    int dumpLen = Math.Min(total, 64);
                    var sb = new StringBuilder();
                    for (int i = 0; i < dumpLen; i++)
                        sb.Append(chunk[offset + i].ToString("X2")).Append(' ');
                    ProxyMain.Log("pkt", $"{dir} type={type,4} size={total,4}  {sb}{(total > dumpLen ? "..." : "")}");
                    offset += total;
                }
            }
        }

        // ============================================================
        // Login port (9959): AuthCryptography flow, identical to 5065's
        // login server (Apply with InCounter / OutCounter, no DH).
        // ============================================================
        private void BridgeLogin()
        {
            ProxyMain.Log("login", "starting auth-flow observation");
            var sToC = Task.Run((Action)LoginPumpServerToClient);
            var cToS = Task.Run((Action)LoginPumpClientToServer);
            Task.WaitAny(sToC, cToS);
        }

        private void LoginPumpClientToServer()
        {
            var buf = new byte[4096];
            while (true)
            {
                int n = _cs.Read(buf, 0, buf.Length);
                if (n <= 0) return;
                var chunk = new byte[n];
                Buffer.BlockCopy(buf, 0, chunk, 0, n);
                _downstreamAuth.Decrypt(chunk, chunk, n);
                WalkPackets(chunk, "c->s [login]");
                _upstreamAuth.EncryptInverse(chunk, chunk, n, useOutCounter: true);
                _ss.Write(chunk, 0, n);
            }
        }

        private void LoginPumpServerToClient()
        {
            var buf = new byte[4096];
            while (true)
            {
                int n = _ss.Read(buf, 0, buf.Length);
                if (n <= 0) return;
                var chunk = new byte[n];
                Buffer.BlockCopy(buf, 0, chunk, 0, n);
                _upstreamAuth.EncryptInverse(chunk, chunk, n, useOutCounter: false);
                WalkPackets(chunk, "s->c [login]");
                _downstreamAuth.Encrypt(chunk, chunk, n);
                _cs.Write(chunk, 0, n);
            }
        }

        // Unknown ports: relay raw ciphertext with no decryption.
        // Also: opportunistically decrypt each direction's FIRST chunk with the static
        // ENCRYPTION_KEY (Blowfish CFB-64) and check if the result looks like a TQ
        // handshake packet. If yes, log loudly with the destination IP+port — that's
        // a Conquer-protocol stream hiding under a non-standard port/IP.
        private long _s2cBytes, _c2sBytes;
        private bool _firstS2cChecked, _firstC2sChecked;

        private void BridgeRaw()
        {
            var sToC = Task.Run(() => RawPump(_ss, _cs, "s->c", isServerToClient: true));
            var cToS = Task.Run(() => RawPump(_cs, _ss, "c->s", isServerToClient: false));
            Task.WaitAny(sToC, cToS);
            ProxyMain.Log("sess", $"  totals: c->s={_c2sBytes} s->c={_s2cBytes} bytes (dest={_destHost}:{_destPort})");
        }

        private void RawPump(NetworkStream from, NetworkStream to, string tag, bool isServerToClient)
        {
            // Ports we care deeply about — full hex of every chunk. Specifically the
            // Rev anti-cheat heartbeat (9528) and the canonical TQ game/login ports.
            bool verbose = _destPort == 9528 || _destPort == 5817 || _destPort == 9959
                           || _destHost == "139.99.125.223";

            var buf = new byte[8192];
            bool firstChunkSeen = false;
            int chunkIdx = 0;
            while (true)
            {
                int n = from.Read(buf, 0, buf.Length);
                if (n <= 0) return;
                var chunk = new byte[n];
                Buffer.BlockCopy(buf, 0, chunk, 0, n);

                // Update byte totals
                if (isServerToClient) _s2cBytes += n; else _c2sBytes += n;

                // Disk capture of every raw chunk (pre-decryption) for offline key recovery.
                CaptureChunk(chunk, n, isServerToClient, chunkIdx);

                // Fingerprint check on first chunk in each direction (for any destination,
                // so we catch TQ-shaped traffic hiding under unknown IPs).
                if (!firstChunkSeen)
                {
                    firstChunkSeen = true;
                    TryFingerprintTq(chunk, tag);
                }

                if (verbose)
                {
                    // Cap the dump at 512 bytes per chunk to keep the log usable.
                    int dumpLen = Math.Min(n, 512);
                    var sb = new StringBuilder();
                    for (int i = 0; i < dumpLen; i++)
                    {
                        sb.Append(chunk[i].ToString("X2"));
                        sb.Append((i + 1) % 16 == 0 ? '\n' : ' ');
                    }
                    ProxyMain.Log("hex", $"{tag} [{_destHost}:{_destPort}] chunk#{chunkIdx} n={n}{(n > dumpLen ? " (truncated)" : "")}\n{sb}");
                }
                chunkIdx++;

                to.Write(buf, 0, n);
            }
        }

        private void TryFingerprintTq(byte[] chunk, string tag)
        {
            // Try Blowfish-CFB-64 decrypt with the static ENCRYPTION_KEY (used pre-DH).
            // If the result contains the well-known DH prime P fragment "E7A69EBDF105",
            // this is a TQ Conquer stream.
            try
            {
                var copy = (byte[])chunk.Clone();
                var crypto = new GameCryptography(Common.ENCRYPTION_KEY);
                crypto.Decrypt(copy);
                string decoded = Encoding.ASCII.GetString(copy);
                if (decoded.Contains("E7A69EBDF105") || decoded.Contains("TQServer") || decoded.Contains("TQClient"))
                {
                    ProxyMain.Log("FINGERPRINT", $"!!! TQ HANDSHAKE DETECTED on {tag} ({_destHost}:{_destPort}) — first chunk decrypts to TQ payload !!!");
                    // Hex dump of first 64 bytes for inspection
                    var sb = new StringBuilder();
                    for (int i = 0; i < Math.Min(64, copy.Length); i++)
                        sb.Append(copy[i].ToString("X2")).Append(' ');
                    ProxyMain.Log("FINGERPRINT", $"  decrypted hex: {sb}");
                }
                else
                {
                    // No fingerprint match — could be HTTPS, anti-cheat heartbeat, anything.
                    // Show the first 24 raw bytes so we can eyeball it.
                    var sb = new StringBuilder();
                    for (int i = 0; i < Math.Min(24, chunk.Length); i++)
                        sb.Append(chunk[i].ToString("X2")).Append(' ');
                    ProxyMain.Log("raw", $"  {tag} first {Math.Min(24, chunk.Length)} bytes raw: {sb}");
                }
            }
            catch { /* ignore decode errors */ }
        }

        // Read one chunk off a stream (one TCP recv).
        private static byte[] ReadOnce(NetworkStream s)
        {
            var buf = new byte[8192];
            int n = s.Read(buf, 0, buf.Length);
            if (n <= 0) throw new IOException("stream closed");
            var trimmed = new byte[n];
            Buffer.BlockCopy(buf, 0, trimmed, 0, n);
            return trimmed;
        }

        private static unsafe string ExtractClientPubKey(byte[] buffer)
        {
            fixed (byte* ptr = buffer)
            {
                int junk = *((int*)(ptr + 11));
                int pubLen = *((int*)(ptr + 15 + junk));
                var pubBytes = new byte[pubLen];
                for (int i = 0; i < pubLen; i++) pubBytes[i] = ptr[19 + junk + i];
                return Encoding.ASCII.GetString(pubBytes);
            }
        }

        /// <summary>
        /// Bounds-checked sanity test for the 5065 ServerKeyPacket layout. Returns true if
        /// the lengths and offsets the parser would read all fit inside the buffer with
        /// plausible values. We do NOT call ParseServerKeyPacket if this returns false, to
        /// avoid AccessViolationException (which terminates the process in .NET 8 because
        /// it's a corrupted-state exception that escapes try/catch by default).
        ///
        /// Expected layout (from BlowfishExchange.ParseServerKeyPacket):
        ///   [0..10]  11 bytes of pad
        ///   [11..14] int total_size_minus_11
        ///   [15..18] int junk_length          (typically 12)
        ///   [19..19+J-1] junk bytes
        ///   [19+J..22+J] int client_iv_len    (typically 8)
        ///   [23+J..30+J] client IV
        ///   [31+J..34+J] int server_iv_len    (typically 8)
        ///   [35+J..42+J] server IV
        ///   [43+J..46+J] int P_len            (ASCII hex DH prime, ~128 chars)
        ///   ...
        /// </summary>
        private static bool ValidateKeyPacketLayout(byte[] buf)
        {
            try
            {
                if (buf.Length < 50) return false;
                int junkLen = BitConverter.ToInt32(buf, 15);
                if (junkLen < 0 || junkLen > 256) return false;

                int o = 19 + junkLen;
                if (o + 4 > buf.Length) return false;
                int clientIvLen = BitConverter.ToInt32(buf, o);
                if (clientIvLen != 8) return false; // 5065 always uses 8

                o += 4 + clientIvLen;
                if (o + 4 > buf.Length) return false;
                int serverIvLen = BitConverter.ToInt32(buf, o);
                if (serverIvLen != 8) return false;

                o += 4 + serverIvLen;
                if (o + 4 > buf.Length) return false;
                int pLen = BitConverter.ToInt32(buf, o);
                if (pLen < 64 || pLen > 512) return false; // DH prime ASCII hex

                o += 4 + pLen;
                if (o + 4 > buf.Length) return false;
                int gLen = BitConverter.ToInt32(buf, o);
                if (gLen < 1 || gLen > 8) return false; // generator is usually just "5"

                o += 4 + gLen;
                if (o + 4 > buf.Length) return false;
                int pubLen = BitConverter.ToInt32(buf, o);
                if (pubLen < 64 || pubLen > 512) return false;
                if (o + 4 + pubLen > buf.Length) return false;

                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    internal static class ProxyMainPorts
    {
        public const int REV_GAME_PORT = 5817;
        public const int REV_LOGIN_PORT = 9959;
    }

    // Holds the Frida-captured game-port BF_KEY schedule. Rev's client uses
    // one shared schedule for both directions on 5817 (only IV/num differ),
    // and the first cfb64 call after BF_set_key starts at IV=0. So:
    //   - no cutover offset (decrypt from byte 0 of the 5817 stream)
    //   - no per-direction IV (both directions start at IV=0)
    //   - one P/S array, loaded into both engines
    internal sealed class GameKeyState
    {
        public GameCryptography Crypto;

        public static GameKeyState LoadFrom(string path)
        {
            // session.json shape (v2):
            // {
            //   "version": 2,
            //   "p": [18 hex uint32],
            //   "s": [1024 hex uint32]
            // }
            string text = File.ReadAllText(path);
            uint[] p = ParseUintArray(text, "p", 18);
            uint[] s = ParseUintArray(text, "s", 1024);

            var state = new GameKeyState
            {
                Crypto = new GameCryptography(new byte[] { 0 }), // dummy init, replaced below
            };
            state.Crypto.LoadSchedules(p, s);
            return state;
        }

        private static uint[] ParseUintArray(string body, string key, int expectedLen)
        {
            int k = body.IndexOf("\"" + key + "\"");
            if (k < 0) throw new FormatException("missing " + key);
            int br = body.IndexOf('[', k);
            int en = body.IndexOf(']', br);
            string inner = body.Substring(br + 1, en - br - 1);
            var parts = inner.Split(',');
            if (parts.Length != expectedLen)
                throw new FormatException($"{key}: expected {expectedLen} entries, got {parts.Length}");
            var arr = new uint[expectedLen];
            for (int i = 0; i < expectedLen; i++)
            {
                string raw = parts[i].Trim().Trim('"');
                if (raw.StartsWith("0x") || raw.StartsWith("0X")) raw = raw.Substring(2);
                arr[i] = Convert.ToUInt32(raw, 16);
            }
            return arr;
        }
    }
}
