"""
Frida hooks for OpenSSL Blowfish functions statically linked into Rev's Conquer.exe.

Located by reverse-engineering the binary:

    BF_set_key        VA 0x005A07E0   (found via the unique xref to the Blowfish
                                       P-init constant table at VA 0x006242A8)
    BF_cfb64_encrypt  VA 0x005A05E0   (found via xrefs called immediately after
                                       BF_set_key in the cipher-setup function)

x86 cdecl calling convention. At function entry [esp+0] is the return address;
arg N is at [esp + 4*N].

Signatures:
    void BF_set_key(BF_KEY *key, int len, const unsigned char *data);
    void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length,
                          const BF_KEY *schedule, unsigned char *ivec, int *num, int enc);

Usage (on the Windows box):
    pip install frida-tools
    1) launch Conquer.exe normally
    2) get its PID from Process Hacker or `tasklist`
    3) python frida_bf_setkey_hook.py <PID>
    4) trigger a handshake (connect to game server) and watch the output
"""
import sys
import frida

# Compile-time-resolved offsets (relative to Conquer.exe ImageBase=0x00400000).
BF_SET_KEY_RVA       = 0x005A07E0 - 0x00400000   # = 0x1A07E0
BF_CFB64_ENCRYPT_RVA = 0x005A05E0 - 0x00400000   # = 0x1A05E0
BF_ENCRYPT_RVA       = 0x005AA390 - 0x00400000   # = 0x1AA390

JS = r"""
'use strict';
(function () {

const BF_SET_KEY_RVA       = ptr(""" + hex(BF_SET_KEY_RVA) + r""");
const BF_CFB64_ENCRYPT_RVA = ptr(""" + hex(BF_CFB64_ENCRYPT_RVA) + r""");
const BF_ENCRYPT_RVA       = ptr(""" + hex(BF_ENCRYPT_RVA) + r""");

const hexdump = function (view, prefix) {
    let hex = '';
    let asc = '';
    for (let i = 0; i < view.length; i++) {
        if (i > 0 && i % 16 == 0) {
            console.log(prefix + hex.padEnd(48) + '  ' + asc);
            hex = ''; asc = '';
        }
        hex += ('0' + view[i].toString(16)).slice(-2) + ' ';
        const c = view[i];
        asc += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
    }
    if (hex) console.log(prefix + hex.padEnd(48) + '  ' + asc);
};

const conquer = Process.findModuleByName('Conquer.exe');
if (!conquer) {
    console.error('[!] Could not find Conquer.exe module — is it loaded?');
} else {
    console.log('[+] Conquer.exe base: ' + conquer.base);

    // ===================================================================
    // BF_set_key(BF_KEY *key, int len, const unsigned char *data)
    // ===================================================================
    const setKey = conquer.base.add(BF_SET_KEY_RVA);
    console.log('[+] Hooking BF_set_key at ' + setKey);
    Interceptor.attach(setKey, {
        onEnter: function (args) {
            this.bfkey_ptr = args[0];
            const keylen   = args[1].toInt32();
            const keydata  = args[2];
            console.log('--------------------------------------------------');
            console.log('[BF_set_key] BF_KEY* = ' + this.bfkey_ptr + '  len=' + keylen + '  data*=' + keydata);
            if (keylen > 0 && keylen <= 256 && !keydata.isNull()) {
                try {
                    const view = new Uint8Array(keydata.readByteArray(keylen));
                    hexdump(view, '  key: ');
                } catch (e) { console.error('  key read error: ' + e); }
            }
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                             .map(DebugSymbol.fromAddress);
            console.log('  caller: ' + (bt[0] || '?'));
        },
        onLeave: function (_retval) {
            if (this.bfkey_ptr && !this.bfkey_ptr.isNull()) {
                dumpBfKeyP(this.bfkey_ptr, '[BF_set_key  post-init]');
                // Also dump the FULL 4168-byte schedule for Python replay.
                dumpFullBfKey(this.bfkey_ptr, 'post-set_key');
            }
        }
    });

    // ===================================================================
    // Diagnostic: dump first 8 P-array entries of a BF_KEY. OpenSSL BF_KEY
    // layout is BF_LONG P[18]; BF_LONG S[4][256]; (BF_LONG = uint32_t, host-endian).
    // If P[0] != 0x606d5cbd here, something tampered with the BF_KEY between
    // BF_set_key(DR654) and BF_cfb64_encrypt — possibly SecurePlay re-running
    // its own key schedule, or a runtime patch that replaces the key.
    // ===================================================================
    const dumpBfKeyP = function (bfkey_ptr, label) {
        try {
            let pline = '  ' + label + '  P[0..17] =';
            for (let i = 0; i < 18; i++) {
                pline += ' ' + bfkey_ptr.add(i * 4).readU32().toString(16).padStart(8, '0');
            }
            console.log(pline);
            let sline = '  ' + label + '  S[0][0..3] =';
            for (let i = 0; i < 4; i++) {
                sline += ' ' + bfkey_ptr.add(72 + i * 4).readU32().toString(16).padStart(8, '0');
            }
            console.log(sline);
        } catch (e) { console.error('  P-dump error: ' + e); }
    };

    // Dump the entire BF_KEY struct (4168 bytes: P[18] + S[4][256]) as a hex
    // string. We'll feed this into Python — it gives us the exact cipher state
    // without having to reverse Rev's modified BF_set_key algorithm.
    let dumpedKeys = 0;  // limit how many we dump (don't spam on every TCP packet)
    const dumpFullBfKey = function (bfkey_ptr, tag) {
        if (dumpedKeys >= 4) return;  // first 4 unique BF_KEYs is plenty
        dumpedKeys++;
        try {
            const SIZE = 18 * 4 + 4 * 256 * 4;  // 4168 bytes
            const raw = bfkey_ptr.readByteArray(SIZE);
            const view = new Uint8Array(raw);
            console.log('  [FULL_BFKEY ' + tag + ' addr=' + bfkey_ptr + ' size=' + SIZE + ']');
            // Print as long hex (one line per 64 bytes for readability).
            let hex = '';
            for (let i = 0; i < view.length; i++) {
                hex += ('0' + view[i].toString(16)).slice(-2);
                if ((i + 1) % 64 == 0) { console.log('  HEX ' + hex); hex = ''; }
            }
            if (hex) console.log('  HEX ' + hex);
            console.log('  [END_BFKEY]');
        } catch (e) { console.error('  full-dump error: ' + e); }
    };

    // ===================================================================
    // BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length,
    //                  const BF_KEY *schedule, unsigned char *ivec, int *num,
    //                  int enc)
    // ===================================================================
    // To catch BOTH plaintext-on-entry AND ciphertext-on-exit, we save the
    // out-buffer pointer and length in onEnter, then dump it in onLeave.
    const cfb = conquer.base.add(BF_CFB64_ENCRYPT_RVA);
    console.log('[+] Hooking BF_cfb64_encrypt at ' + cfb);
    Interceptor.attach(cfb, {
        onEnter: function (args) {
            const inbuf  = args[0];
            const outbuf = args[1];
            const length = args[2].toInt32();
            const bfkey  = args[3];
            const ivec   = args[4];
            const numptr = args[5];
            const enc    = args[6].toInt32();
            console.log('--------------------------------------------------');
            console.log('[BF_cfb64] in*=' + inbuf + '  out*=' + outbuf + '  len=' + length +
                        '  key*=' + bfkey + '  ivec*=' + ivec + '  num*=' + numptr + '  enc=' + enc);

            // Dump the BF_KEY's first 8 P-entries — proves whether the schedule
            // is what OpenSSL would compute or something different.
            if (!bfkey.isNull()) {
                dumpBfKeyP(bfkey, '[BF_cfb64    @entry  ]');
            }

            // Save for onLeave so we can dump the OUTPUT after the function runs.
            this.outbuf = outbuf;
            this.length = length;
            this.enc    = enc;

            if (length > 0 && length <= 4096) {
                try {
                    if (!inbuf.isNull()) {
                        const v = new Uint8Array(inbuf.readByteArray(Math.min(length, 256)));
                        hexdump(v, '  in : ');
                    }
                    if (!ivec.isNull()) {
                        const iv = new Uint8Array(ivec.readByteArray(8));
                        hexdump(iv, '  iv : ');
                    }
                    if (!numptr.isNull()) {
                        console.log('  num= ' + numptr.readInt());
                    }
                } catch (e) { console.error('  buf read error: ' + e); }
            }
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                             .map(DebugSymbol.fromAddress);
            console.log('  caller: ' + (bt[0] || '?'));
        },
        onLeave: function (_retval) {
            if (this.length > 0 && this.length <= 4096 && this.outbuf && !this.outbuf.isNull()) {
                try {
                    const v = new Uint8Array(this.outbuf.readByteArray(Math.min(this.length, 256)));
                    hexdump(v, '  out: ');
                } catch (e) { console.error('  out read error: ' + e); }
            }
        }
    });

    // ===================================================================
    // BF_encrypt(BF_LONG *data, const BF_KEY *key)
    //
    // Ground-truth test: hook the raw Feistel function. On entry data[0..7]
    // is (L_in, R_in); on exit data[0..7] is (L_out, R_out). Combined with
    // the BF_KEY pointer (which we already dump separately), this proves
    // exactly what input/output the modified algorithm produces.
    //
    // Heavily rate-limited — this gets called hundreds of times per second
    // during normal cipher operation, so we only log the first 8 calls.
    // ===================================================================
    const bfEnc = conquer.base.add(BF_ENCRYPT_RVA);
    console.log('[+] Hooking BF_encrypt at ' + bfEnc);
    let bfEncCalls = 0;
    Interceptor.attach(bfEnc, {
        onEnter: function (args) {
            if (bfEncCalls >= 8) { this.skip = true; return; }
            bfEncCalls++;
            this.skip = false;
            this.data_ptr = args[0];
            this.key_ptr  = args[1];
            try {
                const buf = new Uint8Array(this.data_ptr.readByteArray(8));
                let hex = '';
                for (let i = 0; i < 8; i++) hex += ('0'+buf[i].toString(16)).slice(-2);
                console.log('[BF_encrypt #' + bfEncCalls + '] data*=' + this.data_ptr + ' key*=' + this.key_ptr + '  in=' + hex);
            } catch (e) { console.error('  bf_enc in error: ' + e); }
        },
        onLeave: function (_retval) {
            if (this.skip) return;
            try {
                const buf = new Uint8Array(this.data_ptr.readByteArray(8));
                let hex = '';
                for (let i = 0; i < 8; i++) hex += ('0'+buf[i].toString(16)).slice(-2);
                console.log('[BF_encrypt #' + bfEncCalls + ']                                                out=' + hex);
            } catch (e) { console.error('  bf_enc out error: ' + e); }
        }
    });

    console.log('[+] Hooks installed. Trigger a Conquer handshake.');
}

})();
"""

def on_message(msg, _data):
    if msg["type"] == "send":
        print("[js]", msg["payload"])
    elif msg["type"] == "error":
        print("[js ERROR]", msg["description"])

def main():
    if len(sys.argv) < 2:
        print("Usage: python frida_bf_setkey_hook.py <PID|process-name>")
        sys.exit(1)
    target = sys.argv[1]
    try:
        target = int(target)
    except ValueError:
        pass  # name, not PID

    session = frida.attach(target)
    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    print("[*] Hook running. Press Ctrl+C to detach.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    session.detach()

if __name__ == "__main__":
    main()
