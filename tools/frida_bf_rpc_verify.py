"""
Sanity check the CFB-64 wrapper against a known (in, out) pair from the latest
Frida session.

Inputs the EXACT 15 ciphertext bytes that Conquer's BF_cfb64_encrypt was
observed decrypting (with key=DR654 BF_KEY, iv=zeros, num=0, enc=0), and
expects the EXACT 12 plaintext bytes Frida printed.

If this passes, our CFB-64 framing is correct — meaning any garbage decryption
of s2c.bin must be due to misaligned input (e.g. the captured bytes don't
start at the stream's offset 0).
"""
import sys
import time
import frida
from frida_bf_rpc_decrypt import JS, DR654_BFKEY, bf_cfb64_decrypt

# Latest Frida session ground truth (from your run of frida_bf_setkey_hook.py
# with the BF_encrypt hook installed):
#
#   [BF_cfb64] in*=0xe905c84  ivec*=0x1ac640  num=0  enc=0
#     in : 3d 55 69 78 5a 33 6f 21 ef 2c d6 0f d2 96 08
#     out: b2 b6 22 c3 f2 85 77 31 c9 01 2d 45 [01 00 00]
#                                              ^^^^^^^^ last 3 bytes are stale
#                                              buffer (length=15, only first
#                                              12 bytes of out were written)
CT_HEX = "3d5569785a336f21ef2cd60fd29608"
PT_EXPECTED_HEX = "b2b622c3f2857731c9012d45"  # first 12 bytes


def main():
    if len(sys.argv) < 2:
        print("Usage: python frida_bf_rpc_verify.py <PID>")
        sys.exit(1)
    pid = int(sys.argv[1])
    session = frida.attach(pid)
    script = session.create_script(JS)

    def on_message(msg, _data):
        if msg["type"] == "send":
            print("[js]", msg["payload"])
        elif msg["type"] == "error":
            print("[js ERROR]", msg["description"])
    script.on("message", on_message)
    script.load()
    time.sleep(0.3)

    print(script.exports_sync.load_bfkey(DR654_BFKEY.hex()))

    def encrypt_block(b: bytes) -> bytes:
        return bytes.fromhex(script.exports_sync.bf_encrypt(b.hex()))

    ct = bytes.fromhex(CT_HEX)
    pt = bf_cfb64_decrypt(ct, encrypt_block)
    print()
    print(f"Ciphertext (15 bytes): {ct.hex()}")
    print(f"Our plaintext:         {pt.hex()}")
    print(f"Expected (12 valid):   {PT_EXPECTED_HEX}")
    print(f"MATCH (first 12 bytes): {pt[:12].hex() == PT_EXPECTED_HEX}")

    session.detach()


if __name__ == "__main__":
    main()
