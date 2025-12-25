#!/usr/bin/env python3
"""Prints the DTLS 1.2 AES-GCM record vectors that tests/test_dtls_decrypt.cpp embeds.

Nothing here calls the code under test, and nothing needs a package that is not in the Python standard library:

  * AES and GCM are implemented from the specifications (FIPS 197, NIST SP 800-38D) and checked against NIST's GCM test
    cases 4 (AES-128, with AAD) and 16 (AES-256, with AAD) before any vector is produced; the script stops if they differ.
  * the TLS 1.2 PRF (RFC 5246 section 5, P_SHA256 / P_SHA384) is computed with hmac/hashlib and, when the OpenSSL 3 command
    line tool is found, compared with `openssl kdf ... TLS1-PRF`.
  * the records are sealed the way RFC 6347 section 4.1.2.1 and RFC 5288 section 3 describe:
        nonce = write_IV (4 byte salt) || explicit nonce (8 bytes carried in the record)
        AAD   = epoch (2) || sequence number (6) || type || version || plaintext length
        fragment = explicit nonce || ciphertext || tag

Usage: python3 tools/make_dtls_vectors.py
"""
import hashlib
import hmac
import os
import subprocess

# ---- AES (FIPS 197) -----------------------------------------------------------------------------------------------
def _xtime(a):
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a

def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r

def _make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ _xtime(p)                       # multiply p by 3
        q ^= q << 1; q ^= q << 2; q ^= q << 4   # divide q by 3
        q &= 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) & 0xff ^ (q << 2 | q >> 6) & 0xff ^ (q << 3 | q >> 5) & 0xff ^ (q << 4 | q >> 4) & 0xff
        sbox[p] = (x ^ 0x63) & 0xff
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox

SBOX = _make_sbox()
assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7c and SBOX[0x53] == 0xed, "S-box"

def expand_key(key):
    nk = len(key) // 4
    rounds = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(rounds + 1)]

def aes_encrypt_block(round_keys, block):
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    for r in range(1, len(round_keys)):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]            # ShiftRows (column-major state)
        if r != len(round_keys) - 1:
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [_gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3],
                        a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3],
                        a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3),
                        _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)]
            s = out
        s = [b ^ k for b, k in zip(s, round_keys[r])]
    return bytes(s)

# FIPS 197 appendix C.1 / C.3
_k = expand_key(bytes(range(16)))
assert aes_encrypt_block(_k, bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128"
_k = expand_key(bytes(range(32)))
assert aes_encrypt_block(_k, bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "8ea2b7ca516745bfeafc49904b496089", "AES-256"

# ---- GCM (NIST SP 800-38D) ----------------------------------------------------------------------------------------
def _ghash_mul(x, y):
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xe1 << 120) if v & 1 else v >> 1
    return z

def _ghash(h, aad, ct):
    def blocks(data):
        for i in range(0, len(data), 16):
            yield int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big")
    y = 0
    for b in list(blocks(aad)) + list(blocks(ct)) + [(len(aad) * 8) << 64 | len(ct) * 8]:
        y = _ghash_mul(y ^ b, h)
    return y

def gcm_seal(key, nonce12, aad, plaintext):
    rk = expand_key(key)
    h = int.from_bytes(aes_encrypt_block(rk, bytes(16)), "big")
    j0 = int.from_bytes(nonce12 + b"\0\0\0\1", "big")
    ct = b""
    for i in range(0, len(plaintext), 16):
        counter = (j0 + 1 + i // 16) & ((1 << 128) - 1)
        ks = aes_encrypt_block(rk, counter.to_bytes(16, "big"))
        ct += bytes(a ^ b for a, b in zip(plaintext[i:i + 16], ks))
    tag = _ghash(h, aad, ct) ^ int.from_bytes(aes_encrypt_block(rk, j0.to_bytes(16, "big")), "big")
    return ct, tag.to_bytes(16, "big")

# NIST GCM test case 4 (AES-128) and 16 (AES-256), both with 20 bytes of AAD
_p = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
_a = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
_iv = bytes.fromhex("cafebabefacedbaddecaf888")
_ct, _tag = gcm_seal(bytes.fromhex("feffe9928665731c6d6a8f9467308308"), _iv, _a, _p)
assert _ct.hex() == "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" and \
       _tag.hex() == "5bc94fbc3221a5db94fae95ae7121a47", "GCM test case 4"
_ct, _tag = gcm_seal(bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"), _iv, _a, _p)
assert _ct.hex() == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" and \
       _tag.hex() == "76fc6ece0f4e1768cddf8853bb2d551b", "GCM test case 16"

# ---- TLS 1.2 PRF (RFC 5246 section 5) -----------------------------------------------------------------------------
def prf(hashname, secret, label, seed, length):
    seed = label + seed
    a, out = seed, b""
    while len(out) < length:
        a = hmac.new(secret, a, hashname).digest()
        out += hmac.new(secret, a + seed, hashname).digest()
    return out[:length]

MASTER = bytes(range(0x30, 0x30 + 48))
CLIENT_RANDOM = bytes(range(0x00, 0x20))
SERVER_RANDOM = bytes(range(0x80, 0xa0))
OPENSSL = "/opt/homebrew/opt/openssl@3/bin/openssl"

def key_block(hashname, key_len):
    n = 2 * key_len + 8
    block = prf(hashname, MASTER, b"key expansion", SERVER_RANDOM + CLIENT_RANDOM, n)
    if os.path.exists(OPENSSL):
        ref = subprocess.check_output([OPENSSL, "kdf", "-keylen", str(n), "-kdfopt", "digest:" + hashname.upper(), "-kdfopt", "hexsecret:" + MASTER.hex(),
                                       "-kdfopt", "hexseed:" + (b"key expansion" + SERVER_RANDOM + CLIENT_RANDOM).hex(), "-binary", "TLS1-PRF"])
        assert ref == block, "PRF differs from openssl kdf"
    return (block[:key_len], block[key_len:2 * key_len], block[2 * key_len:2 * key_len + 4], block[2 * key_len + 4:])

def seal_record(keys, from_client, rtype, epoch, seq, plaintext, explicit=None, version=0xfefd):
    key_c, key_s, salt_c, salt_s = keys
    key, salt = (key_c, salt_c) if from_client else (key_s, salt_s)
    if explicit is None:
        explicit = epoch.to_bytes(2, "big") + seq.to_bytes(6, "big")
    aad = epoch.to_bytes(2, "big") + seq.to_bytes(6, "big") + bytes([rtype]) + version.to_bytes(2, "big") + len(plaintext).to_bytes(2, "big")
    ct, tag = gcm_seal(key, salt + explicit, aad, plaintext)
    fragment = explicit + ct + tag
    header = bytes([rtype]) + version.to_bytes(2, "big") + epoch.to_bytes(2, "big") + seq.to_bytes(6, "big") + len(fragment).to_bytes(2, "big")
    return header + fragment

def finished(msg_seq):   # DTLS handshake header: type 20, length 12, message_seq, fragment_offset 0, fragment_length 12
    return bytes([20, 0, 0, 12]) + msg_seq.to_bytes(2, "big") + bytes([0, 0, 0, 0, 0, 12]) + bytes(range(0xa0, 0xac))

if __name__ == "__main__":
    for name, hashname, key_len in (("AES-128-GCM (0xc02f)", "sha256", 16), ("AES-256-GCM (0xc030)", "sha384", 32)):
        keys = key_block(hashname, key_len)
        print("# " + name)
        records = [
            ("client Finished  epoch 1 seq 0", seal_record(keys, True, 22, 1, 0, finished(5))),
            ("server Finished  epoch 1 seq 0", seal_record(keys, False, 22, 1, 0, finished(6))),
            ("client app data  epoch 1 seq 1 'hello dtls'", seal_record(keys, True, 23, 1, 1, b"hello dtls")),
            ("server app data  epoch 1 seq 5 'pong' (explicit nonce 0102030405060708)", seal_record(keys, False, 23, 1, 5, b"pong", explicit=bytes(range(1, 9)))),
        ]
        for label, rec in records:
            print(label)
            print("  " + rec.hex())
