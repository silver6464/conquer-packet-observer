r"""
Capture Rev Conquer's game-port (5817) Blowfish key via Frida.

What we learned from the diag run:
  - Rev's client uses ONE BF_KEY per network connection, not one per direction.
    Both c2s and s2c CFB streams share the same BF_KEY schedule; only the
    IV+num counter differ per direction (and those are caller-maintained).
  - The 5817 game-port BF_KEY is initialized exactly once, with a 64-byte
    key (raw DH-derived bytes). There is NO pre-DH static key on 5817 in
    this build — game traffic is post-DH from byte 1.
  - The first cfb64 call after that set_key uses IV=0x00.....00 in both
    directions, which is the expected behavior since OpenSSL's BF_set_key
    leaves the caller-supplied IV alone.
  - The login port (9959) uses a separate BF_KEY initialized with the
    static "DR654dt34trg4UI6" key. The game-port key is presumably derived
    from a DH-style exchange that completes during login. We don't need
    to understand that exchange — we just snapshot the result.

Capture trigger: the FIRST BF_set_key call with keylen != 16. The static
DR654 key is exactly 16 bytes, so anything else is the game-port key.

Output: session.json with one BF_KEY schedule. Proxy installs IV=0 in both
directions and decrypts from byte 0 of the 5817 stream.

Usage (admin cmd, with Conquer.exe NOT yet running):
    python frida_key_capture.py watch [--out <dir>]
    # then start the launcher, log in once, done.

    # or, attach to a running client (only useful if you started Frida
    # BEFORE the login completed):
    python frida_key_capture.py attach <PID>
"""
import argparse
import json
import os
import sys
import time
import frida

BF_SET_KEY_RVA       = 0x005A07E0 - 0x00400000
BF_CFB64_ENCRYPT_RVA = 0x005A05E0 - 0x00400000  # kept for future diag if needed


JS = r"""
'use strict';
(function () {

const BF_SET_KEY_RVA = ptr(""" + hex(BF_SET_KEY_RVA) + r""");

let conquer = null;
const tryHook = function () {
    conquer = Process.findModuleByName('Conquer.exe');
    if (!conquer) return false;
    installHooks();
    return true;
};

// Capture two schedules:
//   - login (16-byte DR654) for the c->s auth packet phase
//   - game  (64-byte DH-derived) for the post-auth game-key phase
// We need BOTH because Rev's BF_set_key may produce a non-OpenSSL schedule;
// computing DR654's schedule ourselves can be wrong. Capturing the actual
// schedule the client uses sidesteps that whole question.
const haveCaptured = { login: false, game: false };
const captured = { login: null, game: null };
let doneSent = false;

const readSchedule = function (bfkey_ptr) {
    const P = [];
    for (let i = 0; i < 18; i++) {
        P.push(bfkey_ptr.add(i * 4).readU32());
    }
    const S = [];
    for (let i = 0; i < 1024; i++) {
        S.push(bfkey_ptr.add(72 + i * 4).readU32());
    }
    return { P: P, S: S };
};

const installHooks = function () {
    const setKey = conquer.base.add(BF_SET_KEY_RVA);
    console.log('[+] hooking BF_set_key at ' + setKey);

    Interceptor.attach(setKey, {
        onEnter: function (args) {
            this.bfkey_ptr = args[0];
            this.keylen   = args[1].toInt32();
        },
        onLeave: function (_retval) {
            if (doneSent) return;
            if (!this.bfkey_ptr || this.bfkey_ptr.isNull()) return;

            // Multiple BF_set_key calls per session — some are login key
            // re-inits (16-byte DR654), the special one is the game key
            // (64-byte). Capture each kind once.
            const which = (this.keylen === 16) ? 'login' : (this.keylen > 16 ? 'game' : null);
            if (which === null) return;
            if (haveCaptured[which]) return;

            try {
                const sched = readSchedule(this.bfkey_ptr);
                captured[which] = sched;
                haveCaptured[which] = true;
                console.log('[+] captured ' + which + ' BF_KEY  ptr=' + this.bfkey_ptr +
                            '  keylen=' + this.keylen);
                if (haveCaptured.login && haveCaptured.game && !doneSent) {
                    doneSent = true;
                    send({
                        kind: 'done',
                        login: { p: captured.login.P, s: captured.login.S },
                        game:  { p: captured.game.P,  s: captured.game.S  },
                    });
                }
            } catch (e) {
                console.error('  capture error: ' + e);
            }
        }
    });

    console.log('[+] installed. Trigger a login.');
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


def to_hex_array(uints):
    return [f"0x{x & 0xFFFFFFFF:08X}" for x in uints]


def write_keyfile(payload, outdir):
    ts = time.strftime("%Y%m%d_%H%M%S")
    tmp = os.path.join(outdir, f"session_{ts}.json.tmp")
    final = os.path.join(outdir, f"session_{ts}.json")
    # Schema (v3): both DR654 login schedule and DH-derived game schedule.
    # Backwards-compatible top-level p/s = game schedule for older proxy
    # builds that expect a single schedule.
    doc = {
        "version": 3,
        "login": {
            "p": to_hex_array(payload["login"]["p"]),
            "s": to_hex_array(payload["login"]["s"]),
        },
        "game": {
            "p": to_hex_array(payload["game"]["p"]),
            "s": to_hex_array(payload["game"]["s"]),
        },
        "p": to_hex_array(payload["game"]["p"]),
        "s": to_hex_array(payload["game"]["s"]),
    }
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, final)
    print(f"[+] wrote keyfile: {final}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    p_watch = sub.add_parser("watch", help="watch for Conquer.exe; attach on spawn")
    p_watch.add_argument("--name", default="Conquer.exe")
    p_watch.add_argument("--poll-ms", type=int, default=25)
    p_watch.add_argument("--out", default=None)

    p_attach = sub.add_parser("attach")
    p_attach.add_argument("target")
    p_attach.add_argument("--out", default=None)

    args = ap.parse_args()

    if args.out is None:
        here = os.path.dirname(os.path.abspath(__file__))
        args.out = os.path.join(os.path.dirname(here), "bin", "Debug", "net8.0", "captures", "keys")
    os.makedirs(args.out, exist_ok=True)
    print(f"[*] keyfile output dir: {args.out}")

    done = {"flag": False, "payload": None}

    def on_message(msg, _data):
        if msg["type"] == "error":
            print("[js ERROR]", msg["description"])
            return
        if msg["type"] != "send":
            return
        payload = msg["payload"]
        if isinstance(payload, dict) and payload.get("kind") == "done":
            done["payload"] = payload
            done["flag"] = True
        else:
            print("[js]", payload)

    session = None
    if args.mode == "watch":
        device = frida.get_local_device()
        target_lower = args.name.lower()
        seen = {p.pid for p in device.enumerate_processes() if target_lower in p.name.lower()}
        print(f"[*] watching for {args.name}. Start the launcher now.")
        target_pid = None
        try:
            while target_pid is None:
                for p in device.enumerate_processes():
                    if target_lower in p.name.lower() and p.pid not in seen:
                        target_pid = p.pid
                        print(f"[+] {p.name} pid={p.pid}")
                        break
                if target_pid is None:
                    time.sleep(args.poll_ms / 1000.0)
        except KeyboardInterrupt:
            return

        # Brief attach retry — process may not be fully ready in the first ms.
        start = time.monotonic()
        while session is None:
            try:
                session = frida.attach(target_pid)
            except frida.ProcessNotFoundError:
                if time.monotonic() - start > 5.0:
                    print("[!] process disappeared")
                    return
                time.sleep(0.01)
            except frida.ProcessNotRespondingError as e:
                print(f"[!] frida injection blocked: {e}")
                print("    AC refused the inject. Try a fully fresh launch (full process exit + relaunch).")
                return
        script = session.create_script(JS)
        script.on("message", on_message)
        script.load()
    else:
        try: target = int(args.target)
        except ValueError: target = args.target
        session = frida.attach(target)
        script = session.create_script(JS)
        script.on("message", on_message)
        script.load()

    print("[*] capture running. Trigger a login. Ctrl+C to abort.")
    try:
        while not done["flag"]:
            time.sleep(0.05)
        write_keyfile(done["payload"], args.out)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
            print("[*] detached.")
        except Exception:
            pass


if __name__ == "__main__":
    main()
