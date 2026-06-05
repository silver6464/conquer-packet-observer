using System;
using System.IO;
using System.Linq;
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

        /// <summary>
        /// Operating mode for the 5817 game-port bridge.
        ///   - ObserveOnly (default): forward ciphertext byte-for-byte between
        ///     client and server, decrypt a copy locally for logging only.
        ///     Cannot inject packets; cannot break the client/server connection.
        ///   - ActiveMitM: maintain TWO independent cipher pairs (one for the
        ///     server side, one for the client side), decrypt + re-encrypt
        ///     each chunk. Enables injection of fabricated packets to the
        ///     client (Phase 2 fake-visual test) at the cost of being able
        ///     to corrupt the stream if cipher state drifts.
        /// </summary>
        public enum OperatingMode { ObserveOnly, ActiveMitM }

        public static OperatingMode Mode { get; private set; } = OperatingMode.ObserveOnly;

        public static void Main(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--keyfile-dir" && i + 1 < args.Length)
                {
                    KeyfileDir = args[++i];
                }
                else if (args[i] == "--mode" && i + 1 < args.Length)
                {
                    string v = args[++i].ToLowerInvariant();
                    if (v == "observe-only" || v == "observe") Mode = OperatingMode.ObserveOnly;
                    else if (v == "active-mitm" || v == "mitm") Mode = OperatingMode.ActiveMitM;
                    else { Console.Error.WriteLine($"unknown --mode '{v}'; valid: observe-only | active-mitm"); System.Environment.Exit(2); }
                }
            }
            Directory.CreateDirectory(KeyfileDir);

            var listener = new TcpListener(IPAddress.Any, LISTEN_PORT);
            listener.Start();
            Log("proxy", $"SOCKS5 observer listening on 0.0.0.0:{LISTEN_PORT}");
            Log("proxy", $"Watching keyfile dir: {KeyfileDir}");
            Log("proxy", $"Mode: {Mode}");
            if (Mode == OperatingMode.ActiveMitM)
            {
                Log("proxy", "============================================================");
                Log("proxy", " ACTIVE MitM MODE — proxy will RE-ENCRYPT both directions.");
                Log("proxy", " Chat command '@cyclone' will fire a client-only fake visual");
                Log("proxy", " injection test. Use only against operator-authorized servers.");
                Log("proxy", "============================================================");
            }
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

                // Game port (5817): dispatch by operating mode. Other ports
                // (login, etc.) always raw-passthrough.
                if (_destPort == ProxyMainPorts.REV_GAME_PORT)
                {
                    if (ProxyMain.Mode == ProxyMain.OperatingMode.ActiveMitM)
                        BridgeGameActiveMitM();
                    else
                        BridgeGameObserveOnly();
                }
                else
                {
                    BridgeRaw();
                }
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

            // If a direction has stashed pre-key bytes but no fresh chunk has
            // arrived since the keyfile loaded, the drain logic never runs and
            // those bytes sit in the buffer forever. Watch for that and flush
            // the backlog through DrainAndDecrypt as soon as the key is ready.
            Task.Run(() => FlushBacklogsOnce());

            Task.WaitAny(sToC, cToS);
        }

        private void FlushBacklogsOnce()
        {
            // Wait for keyfile to load.
            while (_keyState == null) Thread.Sleep(50);
            // Force-drain whatever's already buffered in each direction by
            // calling DrainAndDecrypt with an empty fresh chunk. The drain
            // sets the `_*Drained` flag, so subsequent ObservePump reads
            // won't re-drain.
            lock (_pendingLock)
            {
                if (_c2sPending.Length > 0 && !_c2sDrained)
                {
                    var pending = _c2sPending.ToArray();
                    _c2sPending.SetLength(0);
                    _c2sDrained = true;
                    ProxyMain.Log("game", $"flushing {pending.Length} stashed c->s bytes after keyfile load");
                    // Release the lock before invoking decode (decode may itself
                    // take the lock).
                    Task.Run(() =>
                    {
                        lock (_keyState)
                        {
                            DecodeC2s(_keyState, pending, Array.Empty<byte>(), "c->s");
                        }
                    });
                }
                if (_s2cPending.Length > 0 && !_s2cDrained)
                {
                    _s2cPending.SetLength(0);
                    _s2cDrained = true;
                    ProxyMain.Log("game", $"discarding stashed s->c bytes (session-start handling)");
                }
            }
        }

        // Pre-keyfile ciphertext buffers. CFB-64 is stateful: the IV evolves
        // byte-by-byte as bytes pass through the cipher, so we MUST decrypt
        // from byte 0 of the connection — we can't start mid-stream with a
        // fresh IV. Until the keyfile arrives we buffer raw ciphertext per
        // direction; once the key is loaded we drain the buffers through the
        // cipher in order, then continue decrypting live bytes.
        private readonly MemoryStream _s2cPending = new MemoryStream();
        private readonly MemoryStream _c2sPending = new MemoryStream();
        private readonly object _pendingLock = new object();

        private bool _loggedFirstC2sRaw, _loggedFirstS2cRaw;

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

                // One-time raw dump per direction for cross-checking with Frida's
                // captured plaintext/ciphertext. The first 64 bytes the proxy
                // forwards on each direction should correspond to the first
                // cfb64 call(s) Frida sees.
                lock (this)
                {
                    if (isServerToClient && !_loggedFirstS2cRaw)
                    {
                        _loggedFirstS2cRaw = true;
                        var sb = new StringBuilder();
                        for (int i = 0; i < Math.Min(64, n); i++) sb.Append(chunk[i].ToString("X2")).Append(' ');
                        ProxyMain.Log("game", $"FIRST s->c raw[:64]: {sb}");
                    }
                    else if (!isServerToClient && !_loggedFirstC2sRaw)
                    {
                        _loggedFirstC2sRaw = true;
                        var sb = new StringBuilder();
                        for (int i = 0; i < Math.Min(64, n); i++) sb.Append(chunk[i].ToString("X2")).Append(' ');
                        ProxyMain.Log("game", $"FIRST c->s raw[:64]: {sb}");
                    }
                }

                // Always capture raw ciphertext to disk for offline replay.
                CaptureChunk(chunk, n, isServerToClient, chunkIdx);
                chunkIdx++;

                var state = _keyState;
                if (state == null)
                {
                    // Key not ready yet — stash for replay once it arrives.
                    lock (_pendingLock)
                    {
                        var pending = isServerToClient ? _s2cPending : _c2sPending;
                        pending.Write(chunk, 0, n);
                    }
                }
                else
                {
                    // Drain any buffered ciphertext for this direction FIRST,
                    // then decrypt this chunk. The drain happens at most once
                    // per direction (after _keyState becomes non-null), but
                    // we guard it with a lock+check anyway since both pumps
                    // race for the key load.
                    DrainAndDecrypt(state, isServerToClient, chunk, tag);
                }

                try { to.Write(chunk, 0, n); } catch { return; }
            }
        }

        // Two-key c->s decoding on 5817 (Frida-verified):
        //   - First c->s bytes the client sends are ONE auth packet (variable
        //     length — ~167 bytes in observed runs) encrypted with the static
        //     DR654 key, NOT the game key. Length comes from the standard
        //     TQ u16-LE header after DR654 decryption.
        //   - Everything after that auth packet (starting with the Connect
        //     packet #1052) uses the 64-byte DH-derived game key with IV=0.
        //   - s->c is single-key: game key from byte 0, IV=0, no DR654 phase.
        // This asymmetry is in the wire protocol, not a bug here.
        private bool _s2cDrained, _c2sDrained;

        // c->s key-transition state.
        private GameCryptography _c2sLoginCipher;   // DR654, lazily created
        private bool _c2sGameKeyActive;             // once true, c->s uses game key

        private void DrainAndDecrypt(GameKeyState state, bool isServerToClient, byte[] freshChunk, string tag)
        {
            bool alreadyDrained = isServerToClient ? _s2cDrained : _c2sDrained;
            byte[] backlog = null;
            if (!alreadyDrained)
            {
                lock (_pendingLock)
                {
                    var pending = isServerToClient ? _s2cPending : _c2sPending;
                    if (pending.Length > 0)
                    {
                        backlog = pending.ToArray();
                        pending.SetLength(0);
                    }
                    if (isServerToClient) _s2cDrained = true;
                    else                  _c2sDrained = true;
                }
            }

            lock (state)
            {
                if (isServerToClient)
                {
                    // Empirically: in some sessions the pre-keyfile s->c bytes
                    // we forwarded DO align with what the client's BF_cfb64
                    // decrypts after the keyfile loads; in others they don't
                    // (the offset is off by an unknown amount, possibly because
                    // of pipelined or server-buffered chunks that aren't 1:1
                    // with what BF_cfb64 sees). Discarding the backlog and
                    // starting fresh on the next live chunk is the more
                    // reliable behavior. We'll lose the first few packets per
                    // session but steady-state is what we care about.
                    if (backlog != null && backlog.Length > 0)
                    {
                        ProxyMain.Log("game", $"discarding {backlog.Length} pre-keyfile s->c bytes (session start lost)");
                    }
                    var pt = (byte[])freshChunk.Clone();
                    state.Crypto.DecryptS2c(pt);
                    WalkPackets(pt, tag);
                }
                else
                {
                    DecodeC2s(state, backlog, freshChunk, tag);
                }
            }
        }

        // Auth packet has no [u16-len][u16-type] header — its body is an opaque
        // login blob, so we can't predict the end from a header read. We detect
        // the boundary by scanning DR654-decrypted bytes for the ASCII trailer
        // "TQClient" (8 bytes), which the client appends to every packet.
        //
        // Strategy: accumulate raw c->s ciphertext into _c2sRawAccum until we
        // can identify the boundary. We do this by maintaining a shadow DR654
        // decryption alongside the raw bytes: every byte we add to the raw
        // accumulator, we also add to a parallel decrypted accumulator. When
        // "TQClient" appears in the decrypted accumulator at position P, the
        // auth packet is the first (P+8) raw bytes; everything after that is
        // game-key ciphertext.
        private static readonly byte[] TQ_CLIENT_TRAILER =
            new byte[] { 0x54, 0x51, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
        private readonly MemoryStream _c2sRawAccum = new MemoryStream();
        private readonly MemoryStream _c2sLoginDecrypted = new MemoryStream();

        private void DecodeC2s(GameKeyState state, byte[] backlog, byte[] freshChunk, string tag)
        {
            // Prefer the Frida-captured DR654 schedule if available; falling
            // back to deriving it from the ASCII key only works if Rev's
            // BF_set_key matches OpenSSL exactly, which we cannot assume.
            if (_c2sLoginCipher == null)
            {
                if (state.LoginCrypto != null)
                {
                    _c2sLoginCipher = state.LoginCrypto;
                    ProxyMain.Log("game", "c->s using Frida-captured DR654 schedule");
                }
                else
                {
                    _c2sLoginCipher = new GameCryptography(Common.ENCRYPTION_KEY);
                    ProxyMain.Log("game", "c->s using self-derived DR654 schedule (no captured login key)");
                }
            }

            if (!_c2sGameKeyActive)
            {
                // Accumulate raw + DR654-decrypted shadow.
                int backlogLen = backlog?.Length ?? 0;
                if (backlogLen > 0)
                {
                    _c2sRawAccum.Write(backlog, 0, backlog.Length);
                    var copy = (byte[])backlog.Clone();
                    _c2sLoginCipher.DecryptC2s(copy);
                    _c2sLoginDecrypted.Write(copy, 0, copy.Length);
                }
                _c2sRawAccum.Write(freshChunk, 0, freshChunk.Length);
                {
                    var copy = (byte[])freshChunk.Clone();
                    _c2sLoginCipher.DecryptC2s(copy);
                    _c2sLoginDecrypted.Write(copy, 0, copy.Length);
                }

                byte[] decrypted = _c2sLoginDecrypted.ToArray();
                int trailerIdx = IndexOf(decrypted, TQ_CLIENT_TRAILER);
                ProxyMain.Log("game",
                    $"c->s DecodeC2s: backlog={backlogLen} fresh={freshChunk.Length} " +
                    $"accum={decrypted.Length} trailerIdx={trailerIdx}");
                if (trailerIdx < 0)
                {
                    // Hex-dump the first 32 decrypted bytes to confirm DR654
                    // is working — should be plaintext-looking, not random.
                    var sb = new StringBuilder();
                    for (int i = 0; i < Math.Min(32, decrypted.Length); i++)
                        sb.Append(decrypted[i].ToString("X2")).Append(' ');
                    ProxyMain.Log("game", $"  decrypted[:32] = {sb}");
                    return;
                }

                int authPacketEnd = trailerIdx + TQ_CLIENT_TRAILER.Length;
                ProxyMain.Log("game", $"c->s auth (DR654) ended at offset {authPacketEnd} (TQClient trailer)");

                // Emit the auth packet for visibility — re-extract from decrypted.
                var authPacket = new byte[authPacketEnd];
                Buffer.BlockCopy(decrypted, 0, authPacket, 0, authPacketEnd);
                WalkPackets(authPacket, tag + " [auth]");

                // Now switch to game key. Decrypt the post-auth RAW bytes (still
                // unmolested in _c2sRawAccum) with the game key. The c->s game
                // engine has not been used yet, so it's at IV=0 — correct for
                // the start of the game-key cipher stream from the client.
                byte[] rawAll = _c2sRawAccum.ToArray();
                int postAuthLen = rawAll.Length - authPacketEnd;
                _c2sGameKeyActive = true;

                if (postAuthLen > 0)
                {
                    var postAuth = new byte[postAuthLen];
                    Buffer.BlockCopy(rawAll, authPacketEnd, postAuth, 0, postAuthLen);
                    state.Crypto.DecryptC2s(postAuth);
                    WalkPackets(postAuth, tag);
                }

                // Free the shadow buffers — we won't need them again.
                _c2sRawAccum.SetLength(0);
                _c2sLoginDecrypted.SetLength(0);
                return;
            }

            // Steady-state: game key.
            byte[] combined;
            if (backlog != null && backlog.Length > 0)
            {
                combined = new byte[backlog.Length + freshChunk.Length];
                Buffer.BlockCopy(backlog, 0, combined, 0, backlog.Length);
                Buffer.BlockCopy(freshChunk, 0, combined, backlog.Length, freshChunk.Length);
            }
            else
            {
                combined = (byte[])freshChunk.Clone();
            }
            state.Crypto.DecryptC2s(combined);
            WalkPackets(combined, tag);
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }

        private void KeyfileWatcher()
        {
            // Poll for the NEWEST session_*.json we haven't consumed yet. Sort
            // by last-write time descending so a stale keyfile from a previous
            // run can't be picked up before the freshly-captured one.
            // Rename to .used after load so subsequent connections don't reuse it.
            // The watcher also only considers files that started life AFTER the
            // proxy session began — anything older is treated as stale.
            var sessionStart = DateTime.UtcNow;
            while (_keyState == null)
            {
                try
                {
                    if (Directory.Exists(ProxyMain.KeyfileDir))
                    {
                        var files = Directory.GetFiles(ProxyMain.KeyfileDir, "session_*.json")
                            .Where(p => File.GetLastWriteTimeUtc(p) >= sessionStart)
                            .OrderByDescending(p => File.GetLastWriteTimeUtc(p))
                            .ToArray();
                        foreach (var f in files)
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
        // Game port (5817), ACTIVE-MITM mode (Phase 2).
        //
        // Unlike observe-only mode, here the proxy maintains TWO independent
        // cipher pairs (one for the server side, one for the client side),
        // each loaded from the same Frida-captured schedules:
        //
        //   _upstreamGameCipher    — encrypts c->s for the server; decrypts s->c from the server
        //   _downstreamGameCipher  — encrypts s->c for the client;  decrypts c->s from the client
        //   _upstreamLoginCipher   — DR654 for c->s auth phase, server side
        //   _downstreamLoginCipher — DR654 for c->s auth phase, client side
        //
        // Every chunk gets:
        //   c->s: decrypt with downstream, walk packets (log + chat-command sniff), re-encrypt with upstream, write to server
        //   s->c: decrypt with upstream,   walk packets (log),                       re-encrypt with downstream, write to client
        //
        // Injection (Phase 2 fake-visual): build a plaintext s->c packet,
        // serialize on the downstream-encrypt lock with the s->c pump, encrypt
        // it with _downstreamGameCipher, write to client. The client's CFB
        // state advances by the injected packet's length — but so does the
        // proxy's downstream-encrypt cipher, so subsequent real server bytes
        // re-encrypted to the client stay aligned with what the client
        // expects. The server never sees the injection.
        // ============================================================
        private GameKeyState _activeKeyState;           // shared schedule source (same as observe-only)
        // True once ActiveFlushBacklogsOnce has finished fast-forwarding the
        // cipher states. Until then, live ActiveMitmPump chunks are buffered
        // (not processed) so they can't run through the cipher engines at
        // the wrong IV state and corrupt alignment.
        private volatile bool _activeFastFwdDone;
        private GameCryptography _upstreamGameCipher;
        private GameCryptography _downstreamGameCipher;
        private GameCryptography _upstreamLoginCipher;
        private GameCryptography _downstreamLoginCipher;
        private readonly object _activeUpstreamLock = new object();
        private readonly object _activeDownstreamLock = new object();

        // c->s key-transition state for active MitM (parallel to observe-only's
        // _c2sGameKeyActive but for both directions of the c->s pipe).
        private bool _activeC2sGameKeyActive;
        private readonly MemoryStream _activeC2sRawAccum = new MemoryStream();
        private readonly MemoryStream _activeC2sShadowDecrypted = new MemoryStream();

        // Pre-keyfile backlog buffers (same idea as observe-only).
        private readonly MemoryStream _activeS2cPending = new MemoryStream();
        private readonly MemoryStream _activeC2sPending = new MemoryStream();
        private readonly object _activePendingLock = new object();

        // Captured player UID, used by injection. Read from MSG_CONNECT (1052)
        // post-auth, which contains the player's UID in body bytes 0..3.
        private uint _activePlayerUid;

        // One-shot guard: only allow one fake-visual injection per @cyclone trigger.
        // Set when an injection fires, cleared when the trigger arrives again.
        private bool _activeCycloneActive;

        private void BridgeGameActiveMitM()
        {
            ProxyMain.Log("game", "active-mitm mode: re-encrypting both directions, watching for keyfile");

            Task.Run(() => KeyfileWatcher());

            var sToC = Task.Run(() => ActiveMitmPump(_ss, _cs, "s->c", isServerToClient: true));
            var cToS = Task.Run(() => ActiveMitmPump(_cs, _ss, "c->s", isServerToClient: false));

            Task.Run(() => ActiveFlushBacklogsOnce());

            Task.WaitAny(sToC, cToS);
        }

        // Once the keyfile arrives, instantiate the four cipher engines and
        // drain any backlog through them. Called from a background task.
        private void ActiveOnKeyfileLoaded()
        {
            if (_activeKeyState != null) return; // already done
            // _keyState is what KeyfileWatcher writes — we share that state.
            var ks = _keyState;
            if (ks == null) return;

            // Re-derive both cipher pairs from the same schedules. ks.Crypto
            // and ks.LoginCrypto each hold ONE pair (used by observe-only for
            // local decryption); we need TWO pairs total for active MitM, so
            // build fresh GameCryptography instances from the raw schedules
            // we have in ks.Crypto / ks.LoginCrypto by re-loading them.
            // Trick: GameKeyState.LoadFrom stored the P/S arrays into Crypto
            // and LoginCrypto via LoadSchedules — but we don't have direct
            // access to the arrays afterward. Re-read the keyfile from disk.
            // (Could be cached, but reloading is simple and runs once.)
            string keyPath = FindLoadedKeyfilePath();
            if (keyPath == null)
            {
                ProxyMain.Log("game", "WARN: keyfile loaded but path lost; injection disabled");
                _activeKeyState = ks; // still set so pumps can decrypt via ks.Crypto
                return;
            }

            try
            {
                var ksUpstream = GameKeyState.LoadFrom(keyPath);
                var ksDownstream = GameKeyState.LoadFrom(keyPath);
                _upstreamGameCipher    = ksUpstream.Crypto;
                _upstreamLoginCipher   = ksUpstream.LoginCrypto;
                _downstreamGameCipher  = ksDownstream.Crypto;
                _downstreamLoginCipher = ksDownstream.LoginCrypto;
                _activeKeyState = ks;
                ProxyMain.Log("game", "active-mitm cipher pairs initialized");
            }
            catch (Exception e)
            {
                ProxyMain.Log("game", $"failed to init active-mitm ciphers: {e.Message}");
            }
        }

        // The KeyfileWatcher renamed the consumed file to .used. Find it.
        private string FindLoadedKeyfilePath()
        {
            try
            {
                var files = Directory.GetFiles(ProxyMain.KeyfileDir, "session_*.json.used");
                if (files.Length == 0) return null;
                Array.Sort(files, (a, b) => File.GetLastWriteTimeUtc(b).CompareTo(File.GetLastWriteTimeUtc(a)));
                return files[0];
            }
            catch { return null; }
        }

        private void ActiveFlushBacklogsOnce()
        {
            while (_keyState == null) Thread.Sleep(50);
            ActiveOnKeyfileLoaded();

            // Drain in a loop: snapshot the pending buffers, fast-forward
            // both ciphers, then check whether the pumps wrote more bytes
            // during the fast-forward. We only mark _activeFastFwdDone once
            // both pending buffers are empty after a drain — that means no
            // more pre-key bytes can land. The pumps stay in "buffer +
            // forward raw" mode until we flip the flag, so the cipher
            // engines aren't touched concurrently.
            byte[] c2sPend = null;
            byte[] s2cPend = null;
            int pass = 0;
            while (true)
            {
                bool empty;
                lock (_activePendingLock)
                {
                    if (_activeC2sPending.Length > 0)
                    {
                        var add = _activeC2sPending.ToArray();
                        _activeC2sPending.SetLength(0);
                        c2sPend = c2sPend == null ? add : Concat(c2sPend, add);
                    }
                    if (_activeS2cPending.Length > 0)
                    {
                        var add = _activeS2cPending.ToArray();
                        _activeS2cPending.SetLength(0);
                        s2cPend = s2cPend == null ? add : Concat(s2cPend, add);
                    }
                    // Inside the lock, mark fast-forward done IF the pending
                    // buffers are empty right now. The pumps check the flag
                    // before writing to pending — combined with this lock,
                    // no new bytes can be added between us setting the flag
                    // and the pumps starting to process bytes live.
                    empty = _activeC2sPending.Length == 0 && _activeS2cPending.Length == 0;
                    if (empty) _activeFastFwdDone = true;
                }
                if (empty) break;
                pass++;
                if (pass > 10)
                {
                    ProxyMain.Log("game", "active: too many fast-fwd passes; bailing");
                    break;
                }
                // Brief sleep to let pumps drain to the buffers; then re-check.
                Thread.Sleep(20);
            }

            // Fast-forward the cipher pairs by running the accumulated
            // pre-keyfile ciphertext through each of the four CFB streams.
            // We discard the output and care only about the resulting IV
            // state. After this, all four of our streams' IVs match the
            // corresponding real party's IV at the same byte position,
            // and we can re-encrypt cleanly from here on.
            // s->c handling: do NOT fast-forward the cipher state. Empirical
            // evidence (observe-only mode decrypts post-keyfile s->c cleanly
            // starting from IV=0) shows that the server's s->c BF_cfb64
            // game-key cipher is at IV=0 right when the keyfile lands.
            // Whatever pre-keyfile s->c bytes the proxy forwarded to the
            // client weren't part of that cipher stream (probably a separate
            // handshake/greeting channel). If we fast-forward our cipher by
            // those non-cipher bytes, our IV diverges from the server's.
            //
            // So we leave the s->c game cipher pair at IV=0 and rely on the
            // assumption that the client's s->c-decrypt is also at IV=0
            // (consistent with observe-only's success). The pre-keyfile s->c
            // bytes already reached the client unmodified.
            if (s2cPend != null && s2cPend.Length > 0)
            {
                ProxyMain.Log("game", $"active: NOT fast-forwarding s->c ({s2cPend.Length} pre-key bytes treated as out-of-cipher-stream)");
            }
            if (c2sPend != null && c2sPend.Length > 0 && _activeKeyState != null)
            {
                // The c->s pre-keyfile buffer almost always straddles the
                // DR654→game-key boundary: the first ~170 bytes are the
                // single DR654-encrypted auth packet ending in "TQClient",
                // everything after is game-key. We must fast-forward the
                // LOGIN cipher state by exactly the auth bytes and the
                // GAME cipher state by exactly the post-auth bytes,
                // otherwise post-keyfile c->s decryption is garbled.
                int authEnd = -1;
                try
                {
                    string keyPath = FindLoadedKeyfilePath();
                    if (keyPath != null)
                    {
                        var freshKs = GameKeyState.LoadFrom(keyPath);
                        var shadow = (byte[])c2sPend.Clone();
                        freshKs.LoginCrypto.DecryptC2s(shadow);
                        int trailerIdx = IndexOf(shadow, TQ_CLIENT_TRAILER_ACTIVE);
                        if (trailerIdx >= 0)
                        {
                            authEnd = trailerIdx + TQ_CLIENT_TRAILER_ACTIVE.Length;
                        }
                    }
                }
                catch (Exception e)
                {
                    ProxyMain.Log("game", $"active: c->s boundary scan failed: {e.Message}");
                }

                if (authEnd < 0)
                {
                    // Auth packet doesn't end in this buffer — entire buffer
                    // is DR654. Fast-forward LOGIN ciphers only.
                    ProxyMain.Log("game", $"active: fast-fwd c->s LOGIN by {c2sPend.Length} bytes (no trailer in buffer)");
                    lock (_activeUpstreamLock)   { var s = (byte[])c2sPend.Clone(); _upstreamLoginCipher.DecryptC2s(s); }
                    lock (_activeDownstreamLock) { var s = (byte[])c2sPend.Clone(); _downstreamLoginCipher.DecryptC2s(s); }
                    _activeC2sRawAccum.Write(c2sPend, 0, c2sPend.Length);
                    // Build the side-shadow for later trailer scan as before.
                    try
                    {
                        string keyPath = FindLoadedKeyfilePath();
                        if (keyPath != null)
                        {
                            var freshKs = GameKeyState.LoadFrom(keyPath);
                            var shadow = (byte[])c2sPend.Clone();
                            freshKs.LoginCrypto.DecryptC2s(shadow);
                            _activeC2sShadowDecrypted.Write(shadow, 0, shadow.Length);
                        }
                    }
                    catch { }
                }
                else
                {
                    // Buffer contains the full auth packet plus some post-auth
                    // bytes. Fast-forward LOGIN by authEnd bytes, GAME by the
                    // remainder, and mark c->s game-key active.
                    int postAuth = c2sPend.Length - authEnd;
                    ProxyMain.Log("game", $"active: c->s auth packet ends at offset {authEnd}; fast-fwd LOGIN by {authEnd}, GAME by {postAuth}");
                    var authPortion = new byte[authEnd];
                    Buffer.BlockCopy(c2sPend, 0, authPortion, 0, authEnd);
                    lock (_activeUpstreamLock)   { var s = (byte[])authPortion.Clone(); _upstreamLoginCipher.DecryptC2s(s); }
                    lock (_activeDownstreamLock) { var s = (byte[])authPortion.Clone(); _downstreamLoginCipher.DecryptC2s(s); }
                    if (postAuth > 0)
                    {
                        var postPortion = new byte[postAuth];
                        Buffer.BlockCopy(c2sPend, authEnd, postPortion, 0, postAuth);
                        lock (_activeUpstreamLock)   { var s = (byte[])postPortion.Clone(); _upstreamGameCipher.DecryptC2s(s); }
                        lock (_activeDownstreamLock) { var s = (byte[])postPortion.Clone(); _downstreamGameCipher.DecryptC2s(s); }
                    }
                    // Skip the login-phase state machine entirely — we've
                    // already crossed the boundary during the fast-forward.
                    _activeC2sGameKeyActive = true;
                    ProxyMain.Log("game", "active: c->s game-key mode active (skipped login-phase state machine)");
                }
            }
        }

        private void ActiveMitmPump(NetworkStream from, NetworkStream to, string tag, bool isServerToClient)
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
                CaptureChunk(chunk, n, isServerToClient, chunkIdx++);

                if (_activeKeyState == null || !_activeFastFwdDone)
                {
                    // Two cases collapsed into one:
                    //   1) Keyfile not loaded yet — buffer + forward raw.
                    //   2) Keyfile loaded but fast-forward not finished —
                    //      buffer + forward raw; we cannot run these bytes
                    //      through our cipher engines yet or alignment
                    //      breaks (the engines are still at IV=0 while the
                    //      real parties are at IV=N).
                    //
                    // In both cases we accumulate the ciphertext bytes so
                    // that fast-forward processes EVERY byte that flowed
                    // before our ciphers are ready, and forward unmodified
                    // bytes so the client/server connection stays alive.
                    lock (_activePendingLock)
                    {
                        var pending = isServerToClient ? _activeS2cPending : _activeC2sPending;
                        pending.Write(chunk, 0, n);
                    }
                    try { to.Write(chunk, 0, n); } catch { return; }
                    continue;
                }

                if (isServerToClient)
                {
                    ActiveProcessS2c(chunk);
                }
                else
                {
                    ActiveProcessC2s(chunk);
                }
            }
        }

        // s->c: decrypt with upstream cipher (which the *server* uses to
        // encrypt outbound), walk packets, re-encrypt with downstream cipher
        // (which the *client* expects), forward to client.
        private void ActiveProcessS2c(byte[] chunk)
        {
            if (_upstreamGameCipher == null || _downstreamGameCipher == null) return;

            // Decrypt copy for logging.
            byte[] plaintext;
            lock (_activeUpstreamLock)
            {
                plaintext = (byte[])chunk.Clone();
                _upstreamGameCipher.DecryptS2c(plaintext);
            }
            WalkPackets(plaintext, "s->c");

            // Re-encrypt the SAME plaintext with the downstream cipher and
            // write to client. EncryptS2c specifically uses the s2c-engine
            // in encrypt direction (the same engine downstream's DecryptS2c
            // is NOT — they're separate per-direction streams).
            lock (_activeDownstreamLock)
            {
                var outbound = (byte[])plaintext.Clone();
                _downstreamGameCipher.EncryptS2c(outbound);
                try { _cs.Write(outbound, 0, outbound.Length); } catch { return; }
            }
        }

        // c->s: decrypt with downstream cipher (which the *client* uses to
        // encrypt outbound), walk packets (and sniff @cyclone trigger),
        // re-encrypt with upstream cipher, forward to server.
        // Handles the DR654 auth handoff identically to DecodeC2s in
        // observe-only mode.
        private void ActiveProcessC2s(byte[] freshChunk)
        {
            if (_downstreamGameCipher == null || _upstreamGameCipher == null) return;
            if (_downstreamLoginCipher == null || _upstreamLoginCipher == null) return;

            // Phase: are we still in DR654 auth territory or have we crossed
            // the TQClient trailer boundary into game-key territory?
            if (!_activeC2sGameKeyActive)
            {
                ActiveC2sLoginPhase(freshChunk);
                return;
            }

            // Steady state: game key both ways.
            byte[] plaintext;
            lock (_activeDownstreamLock)
            {
                plaintext = (byte[])freshChunk.Clone();
                _downstreamGameCipher.DecryptC2s(plaintext);
            }
            // Inspect plaintext for @cyclone trigger before re-encrypting.
            InspectC2sForCommands(plaintext);
            WalkPackets(plaintext, "c->s");

            lock (_activeUpstreamLock)
            {
                var outbound = (byte[])plaintext.Clone();
                // c->s encrypt path on the upstream cipher. CFB encrypt
                // mirrors what the real client did with its own cipher.
                _upstreamGameCipher.EncryptC2s(outbound);
                try { _ss.Write(outbound, 0, outbound.Length); } catch { return; }
            }
        }

        // Auth-phase c->s: decrypt with the DR654 schedule, scan for the
        // "TQClient" trailer (which marks the end of the single DR654-encrypted
        // auth packet), then switch to game-key mode. Same algorithm as
        // observe-only's DecodeC2s, but here we also re-encrypt for upstream.
        private static readonly byte[] TQ_CLIENT_TRAILER_ACTIVE =
            new byte[] { 0x54, 0x51, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74 };

        private void ActiveC2sLoginPhase(byte[] freshChunk)
        {
            // Decrypt the fresh chunk with DR654 (downstream side), accumulate
            // both the raw and decrypted bytes so we can find the trailer.
            _activeC2sRawAccum.Write(freshChunk, 0, freshChunk.Length);
            byte[] copy;
            lock (_activeDownstreamLock)
            {
                copy = (byte[])freshChunk.Clone();
                _downstreamLoginCipher.DecryptC2s(copy);
            }
            _activeC2sShadowDecrypted.Write(copy, 0, copy.Length);

            byte[] decrypted = _activeC2sShadowDecrypted.ToArray();
            int trailerIdx = IndexOf(decrypted, TQ_CLIENT_TRAILER_ACTIVE);
            if (trailerIdx < 0)
            {
                // Still in auth packet; we don't have the boundary yet. We
                // CANNOT forward to the server yet because we haven't
                // re-encrypted under the upstream's DR654. Do it now: take
                // the raw bytes we just received, run them through
                // _upstreamLoginCipher's encrypt path, write to server.
                lock (_activeUpstreamLock)
                {
                    var outbound = (byte[])freshChunk.Clone();
                    _upstreamLoginCipher.EncryptC2s(outbound);
                    try { _ss.Write(outbound, 0, outbound.Length); } catch { return; }
                }
                return;
            }

            int authPacketEnd = trailerIdx + TQ_CLIENT_TRAILER_ACTIVE.Length;
            ProxyMain.Log("game", $"active: c->s auth (DR654) ended at offset {authPacketEnd}");

            // Emit the auth packet for logging.
            var authPlain = new byte[authPacketEnd];
            Buffer.BlockCopy(decrypted, 0, authPlain, 0, authPacketEnd);
            WalkPackets(authPlain, "c->s [auth]");

            // Re-encrypt and forward the auth packet to the upstream server.
            // Some of these bytes may have already been re-encrypted+forwarded
            // in earlier ActiveC2sLoginPhase calls (the "still in auth packet"
            // branch above). We forward only the NEW portion of this chunk
            // up to authPacketEnd (in shadow-buffer coordinates); everything
            // after authPacketEnd is post-auth and gets game-key treatment.
            byte[] rawAll = _activeC2sRawAccum.ToArray();
            // raw bytes that haven't been forwarded yet = the part of this
            // freshChunk that we held back. Since we forwarded each prior
            // chunk fully in the "still in auth" branch, the only bytes
            // unwritten are those in THIS chunk. The boundary inside this
            // chunk = authPacketEnd minus the count of bytes accumulated
            // BEFORE this chunk.
            int priorAccumLen = decrypted.Length - freshChunk.Length;
            int boundaryInChunk = authPacketEnd - priorAccumLen;
            if (boundaryInChunk < 0) boundaryInChunk = 0;
            if (boundaryInChunk > freshChunk.Length) boundaryInChunk = freshChunk.Length;

            // Forward the auth portion of this chunk (still DR654-encrypted
            // for upstream).
            if (boundaryInChunk > 0)
            {
                var authPortion = new byte[boundaryInChunk];
                Buffer.BlockCopy(freshChunk, 0, authPortion, 0, boundaryInChunk);
                lock (_activeUpstreamLock)
                {
                    _upstreamLoginCipher.EncryptC2s(authPortion);
                    try { _ss.Write(authPortion, 0, authPortion.Length); } catch { return; }
                }
            }

            // Switch to game key. Post-auth raw bytes within this chunk get
            // the game-key treatment for both directions.
            _activeC2sGameKeyActive = true;
            int postAuthLen = freshChunk.Length - boundaryInChunk;
            if (postAuthLen > 0)
            {
                var postAuthRaw = new byte[postAuthLen];
                Buffer.BlockCopy(freshChunk, boundaryInChunk, postAuthRaw, 0, postAuthLen);
                // Decrypt with downstream game cipher.
                byte[] postPlain;
                lock (_activeDownstreamLock)
                {
                    postPlain = (byte[])postAuthRaw.Clone();
                    _downstreamGameCipher.DecryptC2s(postPlain);
                }
                InspectC2sForCommands(postPlain);
                WalkPackets(postPlain, "c->s");

                // Re-encrypt with upstream game cipher and forward to server.
                lock (_activeUpstreamLock)
                {
                    var outbound = (byte[])postPlain.Clone();
                    _upstreamGameCipher.EncryptC2s(outbound);
                    try { _ss.Write(outbound, 0, outbound.Length); } catch { return; }
                }
            }

            // Free the shadow buffers — done with the DR654 phase.
            _activeC2sRawAccum.SetLength(0);
            _activeC2sShadowDecrypted.SetLength(0);
        }

        // Walk c->s plaintext looking for things the proxy reacts to:
        //   - MSG_CONNECT (1052): grab the player's UID for use in injection.
        //   - MSG_TALK (1004) with body containing "@cyclone": fire the fake
        //     visual injection. The chat message is NOT modified — it still
        //     reaches the server normally.
        private unsafe void InspectC2sForCommands(byte[] chunk)
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
                    if (total <= 0 || total > chunk.Length - offset) return;
                    if (size == 0 && type == 0) return;

                    if (type == ConquerPoc.Constants.MSG_CONNECT && _activePlayerUid == 0 && total >= 8)
                    {
                        _activePlayerUid = BitConverter.ToUInt32(chunk, offset + 4);
                        ProxyMain.Log("game", $"active: captured player UID={_activePlayerUid} from MSG_CONNECT");
                    }
                    else if (type == ConquerPoc.Constants.MSG_TALK && total > 24)
                    {
                        // Body is at offset+4. After 20 bytes of header fields,
                        // NetStringPacker entries begin: [count:u8][len:u8][bytes]...
                        // Speaker is first, hearer second, target third, message
                        // fourth (usually). Look at message contents for triggers.
                        string msg = ExtractTalkMessage(chunk, offset, total);
                        if (msg != null)
                        {
                            HandleChatCommand(msg);
                        }
                    }

                    offset += total;
                }
            }
        }

        private static string ExtractTalkMessage(byte[] chunk, int packetOff, int total)
        {
            // body at packetOff+4. Skip 20 bytes of fixed fields, then NetStrings.
            int bodyOff = packetOff + 4;
            int nsOff = bodyOff + 20;
            int remaining = total - 24 - 8; // exclude header + fixed + trailer
            if (remaining < 1) return null;
            int count = chunk[nsOff]; nsOff++; remaining--;
            string lastString = null;
            for (int i = 0; i < count && remaining > 0; i++)
            {
                int n = chunk[nsOff]; nsOff++; remaining--;
                if (n > remaining) break;
                lastString = System.Text.Encoding.UTF8.GetString(chunk, nsOff, n);
                nsOff += n; remaining -= n;
            }
            return lastString;
        }

        private void HandleChatCommand(string message)
        {
            if (message == null) return;
            string m = message.Trim();
            if (m.Equals("@cyclone", StringComparison.OrdinalIgnoreCase))
            {
                if (_activePlayerUid == 0)
                {
                    ProxyMain.Log("inject", "@cyclone: player UID not yet known; skipping injection");
                    return;
                }
                if (_activeCycloneActive)
                {
                    ProxyMain.Log("inject", "@cyclone: clearing fake StatusEffects (off)");
                    SendFakeCycloneToClient(false);
                    _activeCycloneActive = false;
                }
                else
                {
                    ProxyMain.Log("inject", "@cyclone: arming fake StatusEffects bit23 (on)");
                    SendFakeCycloneToClient(true);
                    _activeCycloneActive = true;
                }
            }
        }

        /// <summary>
        /// Inject a fabricated MSG_UPDATE(StatusEffects) packet to the client only.
        /// The server never sees this. If the client renders the visual, we've
        /// demonstrated that proxy-level visual spoofing still works on Rev 5517.
        ///
        /// Packet layout. 5065 had MSG_UPDATE=1017 with a 20-byte body
        /// (uid:4 count:4 updateType:4 data:8). Rev 5517 uses type=10017
        /// and the real packets on the wire are 44 bytes total (32-byte
        /// body), so there are 12 extra bytes somewhere — fields the new
        /// build added that we haven't reverse-engineered. We zero-pad the
        /// tail to match the observed on-wire size; if the client validates
        /// the size strictly, our fake at the old 32-byte length would be
        /// rejected silently.
        ///
        ///   [0..1]   size = 36 (packet length minus 8)
        ///   [2..3]   type = 10017
        ///   [4..7]   UID
        ///   [8..11]  count = 1
        ///   [12..15] UpdateType = 26 (StatusEffects in 5065 — value may
        ///                          have moved in 5517; verify against
        ///                          a real Update packet's updateType field)
        ///   [16..23] Data = 64-bit ClientEffect bitmask (bit 23 = Cyclone in 5065)
        ///   [24..35] padding (12 bytes of zeros)
        ///   [36..43] "TQServer" trailer
        ///
        /// Two unknowns remain that could explain the visual not rendering:
        ///   - UpdateType 26 may not be StatusEffects on 5517.
        ///   - Bit 23 may not be Cyclone on 5517.
        /// Cross-check by triggering Cyclone normally and watching the
        /// s->c [Update? #10017] body for the updateType / data values.
        /// </summary>
        private unsafe void SendFakeCycloneToClient(bool enable)
        {
            if (_downstreamGameCipher == null)
            {
                ProxyMain.Log("inject", "WARN: downstream cipher not ready; cannot inject");
                return;
            }
            ulong data = enable ? ConquerPoc.Constants.CLIENT_EFFECT_CYCLONE : 0UL;
            // 44 bytes total: 4 header + 32 body + 8 trailer. Body matches the
            // size we see on real Rev 5517 Update packets on the wire.
            var pkt = new byte[44];
            fixed (byte* ptr = pkt)
            {
                *((ushort*)ptr) = (ushort)(pkt.Length - 8);
                *((ushort*)(ptr + 2)) = ConquerPoc.Constants5517.MSG_UPDATE_LIKE;
                *((uint*)(ptr + 4)) = _activePlayerUid;
                *((uint*)(ptr + 8)) = 1;
                *((uint*)(ptr + 12)) = ConquerPoc.Constants.UPDATE_TYPE_STATUS_EFFECTS;
                *((ulong*)(ptr + 16)) = data;
                // [24..35] already zero (default array init). If 5517 needs
                // specific values here, we'll see the visual still not render
                // and need to dump a real Update for the same updateType
                // value to copy the byte pattern.
            }
            // Trailer (the client validates this; without it, the client
            // closes the TCP connection).
            var seal = System.Text.Encoding.ASCII.GetBytes("TQServer");
            Buffer.BlockCopy(seal, 0, pkt, pkt.Length - 8, 8);

            // Log plaintext (for confirmation it's well-formed).
            var hex = new StringBuilder();
            for (int i = 0; i < pkt.Length; i++) hex.Append(pkt[i].ToString("X2")).Append(' ');
            ProxyMain.Log("inject", $"fake StatusEffects pkt plaintext: {hex}");

            // Encrypt with the downstream cipher's s2c-encrypt engine and
            // write to client. The downstream s2c-encrypt CFB state advances
            // by 32 bytes — those same 32 ciphertext bytes also advance the
            // client's own s2c-decrypt CFB state when it reads them off the
            // socket, so the streams stay in lockstep.
            lock (_activeDownstreamLock)
            {
                _downstreamGameCipher.EncryptS2c(pkt);
                try
                {
                    _cs.Write(pkt, 0, pkt.Length);
                    ProxyMain.Log("inject", $"sent fake UpdatePacket(StatusEffects=0x{data:X16}) to client UID={_activePlayerUid}");
                }
                catch (Exception e)
                {
                    ProxyMain.Log("inject", $"failed to send fake packet: {e.Message}");
                }
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
                    // Heuristic: an all-zero "packet" (size=0, type=0) means we've
                    // walked into a zero-padded region (typical inside a #2685
                    // ACReport body whose tail is nearly-all-zero). Real TQ
                    // packets always have a non-zero type. Stop silently rather
                    // than flooding the log with one entry per 8 zero bytes.
                    if (size == 0 && type == 0)
                    {
                        return;
                    }
                    string formatted = ConquerPoc.Packets.PacketPrinter.Format(chunk, offset, total, type);
                    ProxyMain.Log("pkt", $"{dir} {formatted}");
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

    // Holds the Frida-captured BF_KEY schedules:
    //   - game: post-DH 64-byte derived key, used for s->c entire stream and
    //     for c->s after the auth packet.
    //   - login: 16-byte DR654 schedule, used for the c->s auth packet.
    // We capture LOGIN too rather than computing it from "DR654dt34trg4UI6"
    // ourselves, because Rev's BF_set_key may produce a non-OpenSSL-compatible
    // key schedule. Using the actual schedule the client uses guarantees a
    // match.
    internal sealed class GameKeyState
    {
        public GameCryptography Crypto;       // game schedule (both dirs)
        public GameCryptography LoginCrypto;  // DR654 schedule (c->s auth only)

        public static GameKeyState LoadFrom(string path)
        {
            // session.json v3:
            // {
            //   "version": 3,
            //   "login": { "p": [...], "s": [...] },
            //   "game":  { "p": [...], "s": [...] },
            //   "p": [...], "s": [...]   // back-compat alias for game
            // }
            string text = File.ReadAllText(path);

            string gameSection = ExtractObject(text, "game");
            string loginSection = ExtractObject(text, "login");

            uint[] gameP, gameS;
            if (gameSection != null)
            {
                gameP = ParseUintArray(gameSection, "p", 18);
                gameS = ParseUintArray(gameSection, "s", 1024);
            }
            else
            {
                // v2 fallback
                gameP = ParseUintArray(text, "p", 18);
                gameS = ParseUintArray(text, "s", 1024);
            }

            var state = new GameKeyState
            {
                Crypto = new GameCryptography(new byte[] { 0 }),
            };
            state.Crypto.LoadSchedules(gameP, gameS);

            if (loginSection != null)
            {
                uint[] loginP = ParseUintArray(loginSection, "p", 18);
                uint[] loginS = ParseUintArray(loginSection, "s", 1024);
                state.LoginCrypto = new GameCryptography(new byte[] { 0 });
                state.LoginCrypto.LoadSchedules(loginP, loginS);
            }

            return state;
        }

        // Find {"...": { ... matching } } and return the inner section as a
        // substring. Returns null if missing.
        private static string ExtractObject(string text, string key)
        {
            int k = text.IndexOf("\"" + key + "\"");
            if (k < 0) return null;
            int open = text.IndexOf('{', k);
            if (open < 0) return null;
            int depth = 0;
            for (int i = open; i < text.Length; i++)
            {
                if (text[i] == '{') depth++;
                else if (text[i] == '}')
                {
                    depth--;
                    if (depth == 0) return text.Substring(open + 1, i - open - 1);
                }
            }
            return null;
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
