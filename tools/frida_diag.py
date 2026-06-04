r"""
Diagnostic-only hook. Logs every BF_set_key and BF_cfb64_encrypt call so we
can figure out:
  - how many distinct BF_KEY pointers Rev's Conquer.exe uses
  - which calls correspond to the 9959 login port vs 5817 game port
  - whether the game port re-keys the same BF_KEY that the login port used,
    or a fresh one
  - the *direction* (enc=1 client->server, enc=0 server->client) usage pattern
  - byte volumes between rekeys (the cutover offset for the proxy)

Run alongside the proxy. Trigger one full login -> in-game flow. Read the
output to design the right capture strategy.

Usage (admin cmd, while game is NOT yet running):
    python frida_diag.py watch [--name Conquer.exe]
  then launch via the game's launcher.
"""
import argparse
import sys
import time
import frida

BF_SET_KEY_RVA       = 0x005A07E0 - 0x00400000
BF_CFB64_ENCRYPT_RVA = 0x005A05E0 - 0x00400000

JS = r"""
'use strict';
(function () {

const BF_SET_KEY_RVA       = ptr(""" + hex(BF_SET_KEY_RVA) + r""");
const BF_CFB64_ENCRYPT_RVA = ptr(""" + hex(BF_CFB64_ENCRYPT_RVA) + r""");

let conquer = null;
const tryHook = function () {
    conquer = Process.findModuleByName('Conquer.exe');
    if (!conquer) return false;
    installHooks();
    return true;
};

const installHooks = function () {
    const setKey = conquer.base.add(BF_SET_KEY_RVA);
    const cfb    = conquer.base.add(BF_CFB64_ENCRYPT_RVA);
    console.log('[diag] hooks at set_key=' + setKey + '  cfb=' + cfb);

    // Per-pointer state — we don't gate capture here, we just log.
    // events:
    //   "K"  set_key call: pointer, key-len, first 16 bytes of input key
    //   "E"  cfb64 call:   pointer, length, enc-direction, first 4 bytes of in-buffer (post-decrypt for s2c, pre-encrypt for c2s)
    // Per-pointer running byte total so we can see how much traffic each
    // BF_KEY processes between rekeys.
    const perKey = {};   // ptr -> { setKeyCalls, cfb64Calls, bytesSinceKey }
    const ensure = function (k) {
        if (!perKey[k]) perKey[k] = { setKeyCalls: 0, cfb64Calls: 0, bytesSinceKey: 0 };
        return perKey[k];
    };

    const hex16 = function (p, n) {
        try {
            const v = new Uint8Array(p.readByteArray(n));
            let s = '';
            for (let i = 0; i < v.length; i++) s += ('0' + v[i].toString(16)).slice(-2);
            return s;
        } catch (_e) { return '?'; }
    };

    Interceptor.attach(setKey, {
        onEnter: function (args) {
            this.bfkey_ptr = args[0];
            this.keylen   = args[1].toInt32();
            this.keydata  = args[2];
        },
        onLeave: function (_retval) {
            if (!this.bfkey_ptr || this.bfkey_ptr.isNull()) return;
            const k = this.bfkey_ptr.toString();
            const st = ensure(k);
            st.setKeyCalls++;
            const keyHex = (this.keylen > 0 && this.keylen <= 256 && !this.keydata.isNull())
                ? hex16(this.keydata, Math.min(this.keylen, 16))
                : '?';
            console.log('[K #' + st.setKeyCalls + '] bfkey=' + k +
                        '  keylen=' + this.keylen +
                        '  key[:16]=' + keyHex +
                        '  (bytes_since_last_key=' + st.bytesSinceKey + ', cfb64_calls=' + st.cfb64Calls + ')');
            // Reset per-key counters: from now on we're a new schedule.
            st.cfb64Calls = 0;
            st.bytesSinceKey = 0;
        }
    });

    // Track first cfb64 call per (bfkey, direction). On the first call for
    // a direction, dump the full plaintext and full output ciphertext, plus
    // the IV state. This lets us verify whether the proxy is seeing the
    // same ciphertext on the wire that the client just produced, and whether
    // the IV at first call is really 0.
    const firstSeen = {};  // map "k|enc" -> true

    Interceptor.attach(cfb, {
        onEnter: function (args) {
            const inbuf  = args[0];
            const outbuf = args[1];
            const length = args[2].toInt32();
            const bfkey  = args[3];
            const ivec   = args[4];
            const enc    = args[6].toInt32();
            if (length <= 0 || length > 65536) return;

            const k = bfkey.toString();
            const st = ensure(k);
            st.cfb64Calls++;
            st.bytesSinceKey += length;

            const dir = (enc === 1) ? 'c2s' : 's2c';
            const firstKey = k + '|' + enc;

            if (!firstSeen[firstKey]) {
                firstSeen[firstKey] = true;
                const ivHex = ivec.isNull() ? '?' : hex16(ivec, 8);
                const fullIn = inbuf.isNull() ? '?' : hex16(inbuf, length);
                console.log('[FIRST ' + dir + '] bfkey=' + k +
                            '  len=' + length +
                            '  iv=' + ivHex);
                console.log('  plaintext-in  = ' + fullIn);
                // Save outbuf to dump in onLeave (ciphertext on c2s, plaintext on s2c)
                this.dumpAfter = { dir: dir, outbuf: outbuf, length: length };
                return;
            }

            const shouldLog = st.cfb64Calls <= 20 || (st.cfb64Calls % 50 === 0);
            if (shouldLog) {
                const ivHex = ivec.isNull() ? '?' : hex16(ivec, 8);
                const sample = !inbuf.isNull() ? hex16(inbuf, Math.min(length, 4)) : '?';
                console.log('[E #' + st.cfb64Calls + '] bfkey=' + k +
                            '  ' + dir +
                            '  len=' + length +
                            '  iv=' + ivHex +
                            '  in[:4]=' + sample +
                            '  (total_since_key=' + st.bytesSinceKey + ')');
            }
        },
        onLeave: function (_retval) {
            if (!this.dumpAfter) return;
            const d = this.dumpAfter;
            try {
                const out = hex16(d.outbuf, d.length);
                if (d.dir === 'c2s') {
                    console.log('  ciphertext-out = ' + out);
                } else {
                    console.log('  plaintext-out  = ' + out);
                }
            } catch (e) { console.error('  out dump err: ' + e); }
        }
    });

    console.log('[diag] installed. Trigger a full login -> in-game flow.');
};

if (!tryHook()) {
    let ticks = 0;
    const iv = setInterval(function () {
        ticks++;
        if (tryHook()) clearInterval(iv);
        else if (ticks > 200) { clearInterval(iv); console.error('[!] no Conquer.exe after 2s'); }
    }, 10);
}

})();
"""


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    p_watch = sub.add_parser("watch")
    p_watch.add_argument("--name", default="Conquer.exe")
    p_watch.add_argument("--poll-ms", type=int, default=25)
    p_attach = sub.add_parser("attach")
    p_attach.add_argument("target")
    args = ap.parse_args()

    if args.mode == "watch":
        device = frida.get_local_device()
        target_lower = args.name.lower()
        seen = {p.pid for p in device.enumerate_processes() if target_lower in p.name.lower()}
        print(f"[*] watching for {args.name}. Start the launcher now.")
        target_pid = None
        while target_pid is None:
            for p in device.enumerate_processes():
                if target_lower in p.name.lower() and p.pid not in seen:
                    target_pid = p.pid
                    print(f"[+] {p.name} pid={p.pid}")
                    break
            time.sleep(args.poll_ms / 1000.0)
    else:
        try: target_pid = int(args.target)
        except ValueError: target_pid = args.target

    # Attach with brief retry — the process may not be ready instantly.
    start = time.monotonic()
    session = None
    while session is None:
        try:
            session = frida.attach(target_pid)
        except frida.ProcessNotFoundError:
            if time.monotonic() - start > 5.0:
                print("[!] process disappeared")
                return
            time.sleep(0.01)
        except frida.ProcessNotRespondingError as e:
            print(f"[!] frida injection refused / process died: {e}")
            print("    AC blocked injection. Try a fresh start of Conquer.exe (full process exit + relaunch).")
            return

    script = session.create_script(JS)
    def on_message(msg, _data):
        if msg["type"] == "error":
            print("[js ERROR]", msg["description"])
        elif msg["type"] == "send":
            print("[js]", msg["payload"])
    script.on("message", on_message)
    script.load()
    print("[*] Diagnostic running. Ctrl+C to stop.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try: session.detach()
        except Exception: pass


if __name__ == "__main__":
    main()
