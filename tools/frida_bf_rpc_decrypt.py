"""
Frida RPC decryptor for Rev's modified Blowfish.

Workflow:
  1. Attach to a running Conquer.exe.
  2. Inside the process, allocate two persistent buffers (data[8] and a 4168-byte
     BF_KEY blob) and bind the real BF_encrypt at VA 0x005AA390 as a NativeFunction.
  3. Export an RPC method `bf_encrypt(data_hex, bfkey_hex) -> out_hex` that writes
     the inputs into the in-process buffers, calls Conquer's BF_encrypt, and
     returns the 8 output bytes.
  4. On the Python side, implement BF_cfb64_decrypt using that RPC as the
     primitive — exactly the algorithm OpenSSL uses, but the block cipher is
     the live Conquer BF_encrypt.
  5. Decrypt a captured s2c.bin and print the plaintext.

Run this on the Windows box where Conquer.exe lives. It must be running with the
Conquer game-port BF_KEY already initialized (so connect to the login screen first).

Usage:
    python frida_bf_rpc_decrypt.py <Conquer.exe PID> <path-to-s2c.bin> [N_bytes_to_decrypt]

If <s2c.bin> is omitted, the script just runs the self-test against the known
Frida-captured (in, out) vectors.
"""
import sys
import time
import frida

BF_ENCRYPT_RVA = 0x005AA390 - 0x00400000  # 0x1AA390

# The captured DR654 BF_KEY (4168 bytes = P[18] + S[4][256]). This is the same
# blob we dumped via Frida earlier, embedded here so Python can preload it into
# the process. It corresponds to the schedule produced by Conquer's modified
# BF_set_key for the key 'DR654dt34trg4UI6'.
BFKEY_HEX = """
ae8e622d1ced73c18b17896b6583434d6c97bb1e9499b85881e23586f5f7a47fec136fec1838c086d28aedea2d2c8ae1d6b8e859a6f972d62cdcad3ba1be51fb
7e576f7ef7ea81e373d52eb44bd29b982f0a8dbb6dc240fe682d59cd7957cf1eb6c3e14e1fce6726e501197e8d02fd0221f27c0b22ba5d9e256458d0d7e1e550
76f516ce0aa818c2e41a581962a5f13ef0443f4d821ffee5b33b99022162b2c4e9e6c8312e6b7ce54bd78853cde396ca1788b37bcb146388eee483b455e2db47
3c2bae926a7e99beeaf40c123171b17ef934d37a2df50ccec0370c65d27ad9d22b152076b777d7359c0f6d9de534c4671278978fa65b28e082c5aa847fe0a3af
abcce4bec245caedb57d785fad9694f740ed777c336fcefd75372bcba2ead153fd9598d55c2726cc06bf8f05dc5a4e5a1ca7c8bd12f3bab42b2126f95f444ab2
d84bbab05db9d47650a21d88beba0273069caf71b1d052c2694356834483277a8a9a5ec694bd71581ec4566d7d0e84a613dce3d65723360676941ceddc8b4e74
1b385a3f35ff1c0aa0b6d0b94b61b3c323e6638b64717e3928b1837ccec7789d2969bf6d660b984bebb98b31219a81794b0203e5983164d5abd1053f55ef668b
17bd4b065de47b1b51f6b3f17641fc13910ae49af568168d530470bb0a1c710f7893310d9094d701fb592cb9d579ce6f868aee1170c0e8984491139cc4cc534d
b25840fc8fe91a3d429d191ace67f8763c1fbb031d3581e9a4b352ba967367ed5dc48f8a13a338ff7adb7d1d98d5a34f0c9ec0851f2376c2a2ca57cf480c9fb7
da0f3c0cba6c84f9bc10c03fa86c2dc1f7ee98b2c60f5c8b29435e9ed71023315bf1de20f656231d3fe590a85027f2584122d3355e66fbd9ad4731ae1a3101b9
8bb1809b7dfd03e749eaff30c7764b51fff4b129fc07c5f4da703d84a75a77284cde28bbc7d6c70ed4fe68fcd494047b5025e513957cc7dae2e8fd2d2ec3cdeb
77c40c5476f80f3f3cbf6af1f5c817fd49e15bd3ac1c5b0f7f7c013166fcd734260c675de221aa028a1e5f1fb38bbea63af0250265a8b3e1006812e187d1c1c2
2bfdbf474e275fc5430fc1494d5bde908e34683ef4f50217e5c45640cf113dfe0854fdfec92f70fe789fef00e37f08f19a145b6113ea79500b6bd96a76d70d71
e905c047ffacc0cbe616c017fd7cee13954c207cbcd5d1d38b3499d49167dce888f555505a6380d38c050cb885fee674417d8ab61d82f859f4944aa5c62d3b4d
c885c88f9e25c40665c41cdf8b3b853c4f4221b1dfe557bd0f850a28d3795a8a161d4240c595cbc1ef686bd9c08bc4e3c2f2451772001350e0161d50210aa24e
80e69a386a8428f60cfb52622f807e493f852866c54eded7df549fd09484336cf947111aff0a0e953a8d8448ec5712b22f2795fff20d59da8f955a875a15272b
ad7a4d2381015c86b59a7bb1550a536aa7cde73ab9630072992df86af89a5d0a8b5f022dd7cf408b9587d1f9dfb57bf6a3721489d47a8c6343490a9860f45524
921c128eefddc5f8f58d604becca38315a8f52ea5a7e6fc7db8f1f21168e68a8daada7e9f16d87ebbe231768a49ecc118e6969052a20451f119349b605207528
1389e81baf4b5ca7a2bb82528c865518281a2ce943cfe9d477e7a4aa24308476a041881058b30b0a5bb4a554b3bbfa15149699bf84134fdce931d3127779edea
d71b2ebf35d5e483490c3ed87b732964f7ace6cdb3cc9c8d65af4542a4194e1e0bac29cc80faf2c5fa54974d3492238cb3d02bc4ac5cc44b0d10708c56a8cda5
9571f482ffa9da705ae72b8d409b772c6638566c87ffb073163d4664ee22fa0c0f79037eefb2acdf8448badcf313cd211b11b5518fdf563a5959ad8877946e58
0260c22f1058a938b0ae1bbc72f3e904e0422d8cd9b3570d4d080f9c806ce5ea26768ffd6f471e1d6a36a9ff910849a3da7e0049c22bd8a1f60edcb4af6d35eb
a83ddd20dc3a9ba47b60f45f749b8b5305222b9d6b299b0188cdc1db6ed6521c7760d61a456c75ff90ac495f2a1a1ecf356c5a94e872e5368b5f751a526852a5
606706f04645e9d7446e45fb473b6a789842269714bbcb951fe45a2d809a9a6c2c0ce8a90ae5ed0cffdbe99a6baefa0786ac5fdd7692c4bd1a2c82642ff19b22
aacd2a065c37ea26bf12d961959f1f75350e98469f7daad1dae4b85f9bc1b7a95f6140a4791c732b6a1843bfe634ab6e1ff51d5bcf2d644f3e46dcb2f75ab0ea
7b7b78cc14242d024a3eaf1ee898c4be052bd6bdc43fb6e96fabed5c5fe386ae35457b8cfc864390f5a892544a23bf2def8a96342cba3b1da4bc29364a8041ef
4435ab8d498516bf4eeaf2a6733dd3722b229e1c4f74c00cf85f465a46021c6c81a6292f22638dc018ad6527bbcb1ad29069df85a12b4efb1aadbb56767d03d1
c59580dc9fdc350e7bfb4632990bf7799dc2e9ca67a6a2c7f102c33ad9c21a72f119311d6cc9d9679b8cc5227b9d9bc7f667e33fae385319a9fea1b2723a64c7
7ed414d186f9be124375ff17ce4cb8d081635c446b1e43fb7488147c3d73f12e153a756a9d25ce0975d876b319ec1f2a0901e8abdc29792a44f98c1db17b2d2f
385542e7160dd3fb7452f5b54444a071be0442304bb87180bb69fda06bdc459592de3f5d62fdb1f35913f9a5b5ac4de5056dee545faf3e850dabe700ba0c7fae
278f0d6ea1d11f2d324e7490dcfcefb0c014eb128e9c3342e98434ce9d0ecb17480ce9035574be9e0e3bd58b85509135c486ae9c0090c7403ce64f0eb281e222
eb0681369870018a1bb7ddb63e914ff5489e4ecd82947baa66ce7e2cf80de22ce6e04d3a57101c50a293b335ba6aa7af53f6eec93dbf95ca77c1f8fbd9ec6754
8a66247f30ca56ba03250025970bbe401c56e3f0c48a0f1cc7c9672c14301a49994b67d701a05124671889d4eb9b25778e179204b1dee0d05ae7c245da96e7ec
a36a41be4930d681a6c1c0d40d320961e0cb81a3c0e14fd2717b0c6fcdc2ae5d6fc5dd9d535610f6736bfdf1f385d76fa343096aee227305c6d3ee64407e8870
ace9ae398f92b702fffe616d61722cd87f38aaa388fcdea8bde3ce3814519e64a38f419941bc2753fb07b4da8e084421325c098e231fc56b75ae3fa22e16b380
a16863a99748f0da8f13c4bcbbf9af6991522139b7d7cdef2a3d3a19eb00205bc88fac00b2550a3f0e318f9a7a6bc1da7cafad0fd54e1d91155d9615eb8a3424
d391821c4e13e77b68cbcc36bbae66e9262de784b50c4286fea6b2f508d834e715789b9e73a297a233957508d95362cda72d7b91b95cc73c94a084428ef66921
cb6b02b4092be94f40f2af5dabe1bc740894d01c7b22be177d5dd02702e09a2e75d39ff06439febcaba853949fc8eefe994721220fac19e9d40f0493ba8d4b26
d4736dbbddc8ffd5ea6f7756443bcd1163c673e2b9791f244ae7efbe0c4beb9a2579a842bb42528167bbb49073871fe8013c850ce84d26c2f136c571605ab478
09957dc6f980a7299e0e1de9e7e6758e3ea614f890dd72228e37743b4a9aaba2cc4de75a07fe6cb786964b9ae3cd516985ff22bd5ebc3c511af0ecfb64c73522
d3e8845a89a5e06b0c09663f059246886b2a71dec6da97a47e13cbacde369a1fe750a75a03e1966fe9655813b1df3201c4a836ce4a30815542373fe906d32818
9dd4c6611ac1dd0767aac44464f52559a84ac65f12f3b673eea2c594dde6d82458bc4be3a3b5bd804f278bf59a188099c35342cbad5e63f15c84fb1f94f1f529
87f9da48b9e269a2d5a8014a34c7102dce97e60dea1145094c05cbf68ef44ced9bce6aba2df4d4d6ace18f79c1713fa75dcb31c409c4367f741424e628178d29
b4522f6fa9ddc6e3a0b46838e2899140cf8f5e11e0cea890c850f732dea23c7907ab133960e8a42d7b152315f7ce49fc7a081d6d013e574ad439b814207ceaf1
e44edbc0b14990c7a7ad17ef3d6733f1c866518421ea52ee058d5612fc9c299038cbd71d96b6f24a0cb66b069f1df7a038bb2b3b5e9169dcd841f327763025b7
500f553e3881548187e9b784bc2f773115ff46901f18f04b33c30a6d85da553245d01e2e96e99e80f45bf3f4cd8e301c739e85cf1399516e83af43d3b83763c0
bb3c287d068552465f84020c6dbf3f3ff5cd0a496d22f51b3bd303dd735eea3b30299e5876e96f5c732897dd125b6cddee9fbf7db0f51ff38c32bcaac6b70812
7b8068b48ca07a6e7dd014e2ca3a1ea90233b45b0a233fddfebdd3cd04809eaa4718f4fa3b60284747b016dac08b427805ed618377496c40fc9ca766ce35c173
09eca7a5987c51cf6d755a34505ac1d45da22b6e1a1ca21b10e2ee87faf3992cb206e8b317077c22b68e06269af3e9cca40ea861c8766a2460791a6a8af05949
8d8a6de679e90dfbab769ab7f37d406fb6b46a02307eb5c9fbeb0168e90ecca027b6afcf6b654cf35e58426d3abe7d6f7c6a354ae23752d2bfdc54589a7950b4
b5089e5a7b5d8ae6ffd5f4708e0ff815ff996176c95fbedffef6e67e6eff5345a7b32cbc070685d3340a41c471b0634350c8e464c98d1cbc513b3fc3246b3520
d9d015e2e624868d75fb0b488b859f267b10ae066e9681aafc2145399360018f01f10fdfcfad6b46b2baf8b05e54884c5028ea0e443e462e6e141be23891529e
e3bd28920bc250dc8dc46ec5e4245e6b137abfc8adfee5de8adcdd56f5501c02de860a783db62cf4d58eab6ea668b0e272612ec2a6d301d153c23bb90abc75da
7d89700027a57a6520f17d60cba7f93a702fb395d964ded0aacb035852502fb11e4f255925a6461e9cc59ff226ad784262872ca0471d119243593e5456fe44e5
3f7930ee67c82543f8facb94cbea7aa6099529d8a9bc72c780d79d70043fdba32530ee661f0a72634b8717f5b36e65d1aa6da05d49c37b75262d30b538b9e24c
cfe63f7a3553f20256fa1f536c76b9f495591303679d4868d57a607c6678bcda3dc45d451d21af3316fd87d462a6a9ff60b1210871feac36e63b59cc5da74007
f978645cdb343e42518142ffb876e991021052df1680ad21cf0641c30bbb39bbabef417a4e8d72cc812a75de5e950ae280cb9ee3de3830cc2641927af5176bb0
a0ffe5bc7c40307f5054ab491b6401e5d2b3a6532e0399d1eb969f5eb13e5c77c7ee7aaedde160b0f335c1193bc8bd708ed65943ce4fadf2130177e9279087cc
c56def8af7e59a74ec6eceb603d4c110bffcc2dcf349b669b8efb235a7892efff6b6a3d2e3328f2e19d34b87ccea9bdcd99c3c32fbccd4c732b410d3f2575d9a
3581e1831b16106eb8f6b6bf0cdafd56f4a6c217699a193f055871d72f62744e7b874d202daacd8d702ef5586d0e800c0effdcc1db4a40e71998839c9ef5aa18
ab2817e54954c5eca11cc1a7db408c8dae1594a53f72c69a8d79bd4980b4bf52df9513761963a80e70ee599b4f4d0a80607975ea8914232db263bba7904f0839
59c1f9b433f6a287b0b83180405626fe08be74ea010afe092cc84f037b03ac8b264629d72aa7284b4f4dd16d62ba1fde9b70931d2be98e2029ff0392c7699ac2
85d76b3104bbb7d4f3e8bdda89d8aa47cb960711a1215775dc71a4a9db4225d36b60d05fb973877801d1883152fd8545167f7c7d551ba03ef5213057f903aec3
b25b0e3ca75f5cf3dbf61e55acf979f2dcdb314ebf134e21a3be0ff658d416a511c334a21f275aed0363ca9574942ec80cd138aaf3dbd21466371199c2f40c6f
bc3755b5afe52f4d72ab45c74669444acec5dfc6b99d6a3e316c4fef765813192d53ab98c8ec4174c1ab27b384be25c7e78b8c58b5d83480e7af3ab53e3c2829
6fa1273547b42c41
""".replace("\n", "").replace(" ", "")
DR654_BFKEY = bytes.fromhex(BFKEY_HEX)
assert len(DR654_BFKEY) == 4168

JS = r"""
'use strict';
(function () {

const BF_ENCRYPT_RVA = ptr(""" + hex(BF_ENCRYPT_RVA) + r""");
const conquer = Process.findModuleByName('Conquer.exe');
if (!conquer) {
    console.error('[!] Conquer.exe not loaded');
} else {
    const target = conquer.base.add(BF_ENCRYPT_RVA);
    console.log('[rpc] BF_encrypt at ' + target);

    // Persistent buffers in the target process (lives until script unloads).
    const dataBuf  = Memory.alloc(8);
    const bfkeyBuf = Memory.alloc(4168);
    console.log('[rpc] dataBuf  = ' + dataBuf);
    console.log('[rpc] bfkeyBuf = ' + bfkeyBuf);

    // Bind BF_encrypt: void BF_encrypt(BF_LONG *data, const BF_KEY *key)
    // Conquer.exe is x86 cdecl.
    const BF_encrypt = new NativeFunction(target, 'void', ['pointer', 'pointer'], 'mscdecl');

    rpc.exports = {
        // Load the BF_KEY blob (4168 bytes hex) into the persistent in-process buffer.
        loadBfkey: function (hex) {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
            }
            bfkeyBuf.writeByteArray(bytes.buffer);
            return 'loaded ' + bytes.length + ' bytes into ' + bfkeyBuf;
        },
        // Encrypt one 8-byte block. Input/output are hex strings.
        bfEncrypt: function (dataHex) {
            const bytes = new Uint8Array(8);
            for (let i = 0; i < 8; i++) {
                bytes[i] = parseInt(dataHex.substr(i * 2, 2), 16);
            }
            dataBuf.writeByteArray(bytes.buffer);
            BF_encrypt(dataBuf, bfkeyBuf);
            const out = new Uint8Array(dataBuf.readByteArray(8));
            let hex = '';
            for (let i = 0; i < 8; i++) hex += ('0' + out[i].toString(16)).slice(-2);
            return hex;
        },
        // Bulk encrypt — encrypt N independent 8-byte blocks in one round-trip.
        // Each block input/output is encoded as 16 hex chars, concatenated.
        bfEncryptBulk: function (concatHex) {
            const n = concatHex.length / 16;
            let outHex = '';
            for (let k = 0; k < n; k++) {
                const slice = concatHex.substr(k * 16, 16);
                const bytes = new Uint8Array(8);
                for (let i = 0; i < 8; i++) {
                    bytes[i] = parseInt(slice.substr(i * 2, 2), 16);
                }
                dataBuf.writeByteArray(bytes.buffer);
                BF_encrypt(dataBuf, bfkeyBuf);
                const out = new Uint8Array(dataBuf.readByteArray(8));
                for (let i = 0; i < 8; i++) outHex += ('0' + out[i].toString(16)).slice(-2);
            }
            return outHex;
        }
    };
    console.log('[rpc] exports installed: loadBfkey, bfEncrypt, bfEncryptBulk');
}

})();
"""


def hexdump(label: str, b: bytes, max_bytes: int = 384) -> None:
    print(f"=== {label} ({len(b)} bytes) ===")
    for i in range(0, min(len(b), max_bytes), 16):
        chunk = b[i:i + 16]
        h = " ".join(f"{x:02x}" for x in chunk)
        a = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        print(f"  {i:04x}  {h:<48}  {a}")
    if len(b) > max_bytes:
        print(f"  ... +{len(b) - max_bytes} more bytes")


import struct as _struct


def bf_cfb64_decrypt(ct: bytes, encrypt_block, iv: bytes = b"\x00" * 8, num: int = 0) -> bytes:
    """
    OpenSSL BF_cfb64_encrypt with enc=0, modeled byte-precise.

    OpenSSL's BF_cfb64_encrypt internally:
      - reads the 8 ivec bytes as TWO BIG-ENDIAN u32s (v0, v1)
      - calls BF_encrypt({v0, v1}, schedule) — BF_encrypt reads data[0],data[1]
        as host-endian u32s, so on x86 the memory bytes passed in are the LE
        encoding of v0, v1
      - reads the keystream byte as the next BE byte of (v0, v1)
      - on decrypt, after producing pt, inserts the CIPHERTEXT byte back into
        the (v0, v1) BE-byte position
      - every 8 bytes, re-runs BF_encrypt on the updated (v0, v1)

    BF_encrypt is invoked via the `encrypt_block(8_bytes) -> 8_bytes` callable
    which expects/returns the host-endian byte form (i.e. what ends up in
    memory at data[0..7]).
    """
    out = bytearray(len(ct))
    # Maintain v0, v1 as conceptual u32s.
    v0, v1 = _struct.unpack(">II", iv)
    keystream = bytearray(8)  # populated after each BF_encrypt

    def refresh():
        nonlocal keystream
        # Pass v0,v1 to BF_encrypt as host-endian (LE on x86) bytes
        host_in = _struct.pack("<II", v0, v1)
        host_out = encrypt_block(host_in)
        # Interpret BF_encrypt's output as host-endian u32s, then write them
        # back as BE bytes — that's the keystream order.
        nv0, nv1 = _struct.unpack("<II", host_out)
        keystream[:] = _struct.pack(">II", nv0, nv1)

    if num == 0:
        refresh()

    for i, c in enumerate(ct):
        p = c ^ keystream[num]
        # Replace this position in (v0, v1) (BE byte order) with the ciphertext
        # byte. Equivalent to writing keystream[num] = c.
        keystream[num] = c
        out[i] = p
        num = (num + 1) & 0x7
        if num == 0:
            # Pull updated v0, v1 back out of keystream (which now holds the
            # 8 most-recent ciphertext bytes in BE-byte form).
            v0, v1 = _struct.unpack(">II", bytes(keystream))
            refresh()
    return bytes(out)


def main():
    if len(sys.argv) < 2:
        print("Usage: python frida_bf_rpc_decrypt.py <PID> [s2c.bin] [N_bytes]")
        sys.exit(1)
    pid = int(sys.argv[1])
    s2c_path = sys.argv[2] if len(sys.argv) >= 3 else None
    n_bytes = int(sys.argv[3]) if len(sys.argv) >= 4 else 512

    session = frida.attach(pid)
    script = session.create_script(JS)

    def on_message(msg, _data):
        if msg["type"] == "send":
            print("[js]", msg["payload"])
        elif msg["type"] == "error":
            print("[js ERROR]", msg["description"])
    script.on("message", on_message)
    script.load()
    time.sleep(0.3)  # let the JS finish setting up

    # Load the captured BF_KEY into the in-process buffer.
    print(script.exports_sync.load_bfkey(DR654_BFKEY.hex()))

    # === Self-test against the two Frida-captured ground-truth pairs ===
    print("\n=== Self-test ===")
    test_in_1 = "0000000000000000"
    out_1 = script.exports_sync.bf_encrypt(test_in_1)
    print(f"  bf_encrypt(0..0)         = {out_1}")
    print(f"  expected                  = bb4be38f1018b6a8")
    print(f"  MATCH: {out_1.lower() == 'bb4be38f1018b6a8'}")

    test_in_2 = "7869553d216f335a"
    out_2 = script.exports_sync.bf_encrypt(test_in_2)
    print(f"  bf_encrypt(7869...335a)  = {out_2}")
    print(f"  expected                  = 4afb2d269e0896d3")
    print(f"  MATCH: {out_2.lower() == '4afb2d269e0896d3'}")

    if out_1.lower() != "bb4be38f1018b6a8":
        print("\n[!] Self-test failed — RPC is wired up but BF_encrypt isn't producing")
        print("    the expected output. Stopping before decrypting captured data.")
        session.detach()
        return

    # === Decrypt captured s2c.bin ===
    if s2c_path:
        with open(s2c_path, "rb") as f:
            ct = f.read()
        ct = ct[:n_bytes]
        print(f"\n=== Decrypting first {len(ct)} bytes of {s2c_path} ===")

        # Wrap the RPC call as the cipher primitive.
        def encrypt_block(b: bytes) -> bytes:
            return bytes.fromhex(script.exports_sync.bf_encrypt(b.hex()))

        pt = bf_cfb64_decrypt(ct, encrypt_block)
        hexdump("Plaintext", pt)

        # Save to a file too
        out_path = s2c_path + ".decrypted.bin"
        with open(out_path, "wb") as f:
            f.write(pt)
        print(f"\nSaved {len(pt)} decrypted bytes to {out_path}")

    session.detach()


if __name__ == "__main__":
    main()
