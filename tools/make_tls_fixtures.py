#!/usr/bin/env python3
"""Generates the TLS fixtures in tests/data/tls/ from REAL handshakes (Python's ssl module on both ends, OpenSSL inside).

For TLS 1.2 and TLS 1.3 it writes
  tlsNN.pcapng  one TCP connection 10.0.0.1:50000 -> 10.0.0.2:443 (handshake, a request, a response, close), TLS split
                into TCP segments of at most 400 bytes, with a Decryption Secrets Block that holds the key log
  tlsNN.keys    the same key log as a stand-alone SSLKEYLOGFILE
and prints the expected values the tests check. Those are derived here by a separate, minimal record parser (client and
server random, negotiated version, cipher suite, records per direction, ChangeCipherSpec positions) and cross-checked
against the key log lines OpenSSL wrote, so the C++ session mapping is compared with something it shares no code with.

The certificate and keys are random, so running this again produces different (equally valid) files; the tests do not
depend on any particular value because they read the expectations from the files they load (see tests/test_tls_session.cpp).

With --decrypt it writes the fixtures of the record decryptor instead (tests/test_tls_decrypt.cpp): decrypt_tls13.json /
decrypt_tls12.json, one case per supported cipher suite. Each case is a real connection between `openssl s_client` and
`openssl s_server` (OpenSSL 3, loopback, a small relay in between records the bytes of both directions) that
  - negotiated exactly that suite (checked against the hellos on the wire),
  - requested a page with a known body; the plaintext the tests expect is what the client sent (known by construction)
    and what s_client printed after OpenSSL decrypted the response (so OpenSSL is the oracle, not the C++ code),
  - wrote the key log (-keylogfile) the decryptor gets its secrets from, and
  - for TLS 1.3 sent a KeyUpdate (s_client command "K": both directions update); the key log lines OpenSSL writes for
    the updated secrets are stored too (`update_secrets`) as an independent check of traffic_secret_N+1.
Only the protected records are stored (TLS 1.3: every record with outer type 23; TLS 1.2: the records after the
ChangeCipherSpec of each direction), as hex of the bytes after the 5 byte record header.

Usage: python3 tools/make_tls_fixtures.py [output directory]               (the session fixtures)
       python3 tools/make_tls_fixtures.py --decrypt [13|12|all] [output directory]
"""
import json
import os
import ssl
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

OPENSSL = "/opt/homebrew/opt/openssl@3/bin/openssl"
MSS = 400
CLIENT = ("10.0.0.1", 50000)
SERVER = ("10.0.0.2", 443)


def ip4(text):
    return bytes(int(p) for p in text.split("."))


def tcp_packet(src, dst, seq, ack, flags, payload=b""):
    tcp = struct.pack(">HHIIBBHHH", src[1], dst[1], seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x1000, 0x4000, 64, 6, 0, ip4(src[0]), ip4(dst[0])) + tcp
    return bytes.fromhex("aabbccddeeff") + bytes.fromhex("001122334455") + b"\x08\x00" + ip


def make_certificate(directory):
    key, cert = os.path.join(directory, "key.pem"), os.path.join(directory, "cert.pem")
    subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj",
                    "/CN=imshark.test", "-days", "36500", "-keyout", key, "-out", cert], check=True, capture_output=True)
    return cert, key


def handshake_flights(version, cert, key, keylog_path):
    """Runs a TLS connection in memory and returns [(direction, bytes)] in the order the bytes were produced."""
    wanted = ssl.TLSVersion.TLSv1_2 if version == 12 else ssl.TLSVersion.TLSv1_3
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    cctx.minimum_version = cctx.maximum_version = wanted
    cctx.keylog_filename = keylog_path
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert, key)
    sctx.minimum_version = sctx.maximum_version = wanted
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client = cctx.wrap_bio(c_in, c_out, server_hostname="imshark.test")
    server = sctx.wrap_bio(s_in, s_out, server_side=True)
    flights = []

    def pump():
        moved = True
        while moved:
            moved = False
            data = c_out.read()
            if data:
                flights.append(("c2s", data)); s_in.write(data); moved = True
            data = s_out.read()
            if data:
                flights.append(("s2c", data)); c_in.write(data); moved = True

    def step(fn, *args):
        try:
            return fn(*args)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return None

    for _ in range(20):
        step(client.do_handshake)
        pump()
        step(server.do_handshake)
        pump()
    client.write(b"GET /index.html HTTP/1.1\r\nHost: imshark.test\r\n\r\n")
    pump()
    step(server.read, 4096)
    server.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    pump()
    step(client.read, 4096)
    step(client.unwrap)
    pump()
    return flights


def parse_records(stream):
    """Splits a TLS byte stream into (type, version, body) records."""
    out, pos = [], 0
    while pos + 5 <= len(stream):
        ctype, ver, length = struct.unpack(">BHH", stream[pos:pos + 5])
        out.append((ctype, ver, stream[pos + 5:pos + 5 + length]))
        pos += 5 + length
    return out


def hello_facts(records):
    """(random, legacy version, cipher or None, negotiated version or None) of the first hello in `records`."""
    for index, (ctype, _, body) in enumerate(records):
        if ctype != 22 or body[0] not in (1, 2):
            continue
        kind = body[0]
        version = struct.unpack(">H", body[4:6])[0]
        random = body[6:38]
        sid = body[38]
        at = 39 + sid
        cipher = None
        if kind == 2:
            cipher = struct.unpack(">H", body[at:at + 2])[0]
            at += 3
        else:
            at += 2 + struct.unpack(">H", body[at:at + 2])[0]
            at += 1 + body[at]
        negotiated = None
        ext_len = struct.unpack(">H", body[at:at + 2])[0]
        at += 2
        end = at + ext_len
        while at + 4 <= end:
            etype, elen = struct.unpack(">HH", body[at:at + 4])
            if etype == 43 and kind == 2:
                negotiated = struct.unpack(">H", body[at + 4:at + 6])[0]
            at += 4 + elen
        return {"kind": kind, "random": random.hex(), "legacy_version": version, "cipher": cipher,
                "negotiated": negotiated or version, "record": index}
    return None


def pcapng(packets, keylog_text):
    def block(btype, body):
        return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)

    def pad(data):
        return data + b"\0" * ((4 - len(data) % 4) % 4)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    secrets = keylog_text.encode()
    dsb = block(0x0A, struct.pack("<II", 0x544C534B, len(secrets)) + pad(secrets))
    out = shb + idb + dsb
    for i, frame in enumerate(packets):
        ticks = 1700000000 * 1000000 + i * 1000
        out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + pad(frame))
    return out


def build(version, cert, key, outdir):
    keylog = os.path.join(tempfile.mkdtemp(), "keys.log")
    flights = handshake_flights(version, cert, key, keylog)
    keylog_text = open(keylog).read()

    # the TCP connection: three-way handshake, then every flight cut into segments
    seq = {"c2s": 1000, "s2c": 5000}
    packets = [
        tcp_packet(CLIENT, SERVER, seq["c2s"], 0, 0x02),
        tcp_packet(SERVER, CLIENT, seq["s2c"], seq["c2s"] + 1, 0x12),
        tcp_packet(CLIENT, SERVER, seq["c2s"] + 1, seq["s2c"] + 1, 0x10),
    ]
    seq = {"c2s": seq["c2s"] + 1, "s2c": seq["s2c"] + 1}
    streams = {"c2s": b"", "s2c": b""}
    for direction, data in flights:
        streams[direction] += data
        for at in range(0, len(data), MSS):
            chunk = data[at:at + MSS]
            src, dst = (CLIENT, SERVER) if direction == "c2s" else (SERVER, CLIENT)
            other = "s2c" if direction == "c2s" else "c2s"
            packets.append(tcp_packet(src, dst, seq[direction], seq[other], 0x18, chunk))
            seq[direction] += len(chunk)

    records = {d: parse_records(s) for d, s in streams.items()}
    client_hello, server_hello = hello_facts(records["c2s"]), hello_facts(records["s2c"])
    assert client_hello and client_hello["kind"] == 1 and server_hello and server_hello["kind"] == 2

    # cross-check against what OpenSSL logged: the key log is keyed by the ClientHello random
    lines = [l.split() for l in keylog_text.splitlines() if l and not l.startswith("#")]
    assert lines and all(l[1] == client_hello["random"] for l in lines), "key log random differs from the wire"
    labels = sorted(l[0] for l in lines)

    name = "tls%d" % version
    with open(os.path.join(outdir, name + ".pcapng"), "wb") as f:
        f.write(pcapng(packets, keylog_text))
    with open(os.path.join(outdir, name + ".keys"), "w") as f:
        f.write(keylog_text)
    return {
        "packets": len(packets),
        "client_random": client_hello["random"],
        "server_random": server_hello["random"],
        "negotiated_version": server_hello["negotiated"],
        "cipher_suite": server_hello["cipher"],
        "key_labels": labels,
        "records": {d: len(r) for d, r in records.items()},
        "change_cipher_spec": {d: [i for i, r in enumerate(rs) if r[0] == 20] for d, rs in records.items()},
        "hello_record": {"c2s": client_hello["record"], "s2c": server_hello["record"]},
    }


# ---- decryptor fixtures (openssl s_client / s_server through a recording relay) ---------------------------------

# (IANA id, OpenSSL name, certificate type) per version; the TLS 1.3 names are -ciphersuites values
SUITES_13 = [
    (0x1301, "TLS_AES_128_GCM_SHA256", "ec"),
    (0x1302, "TLS_AES_256_GCM_SHA384", "ec"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256", "ec"),
]
SUITES_12 = [
]
PAGE_BODY = b"imshark decrypt fixture page\n" * 12
REQUEST = b"GET /index.html HTTP/1.0\r\n\r\n"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_cert(directory, kind):
    key, cert = os.path.join(directory, kind + ".key"), os.path.join(directory, kind + ".crt")
    newkey = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"] if kind == "ec" else ["-newkey", "rsa:2048"]
    subprocess.run([OPENSSL, "req", "-x509"] + newkey + ["-nodes", "-subj", "/CN=imshark.test", "-days", "36500", "-keyout", key,
                                                          "-out", cert], check=True, capture_output=True)
    return cert, key


def openssl_connection(version, suite, cert, key, workdir):
    """One HTTP/1.0 request through s_client / s_server for `suite`. Returns (flights, client stdout, key log text)."""
    with open(os.path.join(workdir, "index.html"), "wb") as f:
        f.write(PAGE_BODY)
    keylog = os.path.join(workdir, "keys.log")
    if os.path.exists(keylog):
        os.remove(keylog)
    if version == 13:
        proto, select = "-tls1_3", ["-ciphersuites", suite]
    else:
        proto, select = "-tls1_2", ["-cipher", suite]
    server_port = free_port()
    server = subprocess.Popen([OPENSSL, "s_server", "-accept", str(server_port), "-cert", cert, "-key", key, "-WWW", "-no_ticket", proto]
                              + select, cwd=workdir, stdout=open(os.path.join(workdir, "server.log"), "wb"), stderr=subprocess.STDOUT)
    time.sleep(1.0)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(20)
    relay_port = listener.getsockname()[1]
    flights, lock = [], threading.Lock()

    def relay():
        client, _ = listener.accept()
        upstream = socket.create_connection(("127.0.0.1", server_port))

        def pump(src, dst, name):
            while True:
                try:
                    data = src.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                with lock:
                    flights.append((name, data))
                try:
                    dst.sendall(data)
                except OSError:
                    break
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        threads = [threading.Thread(target=pump, args=(client, upstream, "c2s")), threading.Thread(target=pump, args=(upstream, client, "s2c"))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    thread = threading.Thread(target=relay)
    thread.start()
    # -no_ign_eof makes s_client act on the command letters at the start of a line: "K" = KeyUpdate that asks the peer to update too
    commands = [b"K\n"] if version == 13 else []
    client = subprocess.Popen([OPENSSL, "s_client", "-connect", "127.0.0.1:%d" % relay_port, "-quiet", "-no_ign_eof", "-crlf", proto,
                               "-keylogfile", keylog] + select, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.8)
    for line in commands + [REQUEST.replace(b"\r\n", b"\n")]:
        client.stdin.write(line)
        client.stdin.flush()
        time.sleep(0.5)
    thread.join(15)
    try:
        client.stdin.close()
    except OSError:
        pass
    try:
        out, err = client.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        client.kill()
        out, err = client.communicate()
    server.kill()
    listener.close()
    assert out.endswith(PAGE_BODY), "s_client did not receive the page: %r %r" % (out[:200], err[-300:])
    return flights, out, open(keylog).read()


def decrypt_case(version, ident, suite, cert_kind, certs, workdir):
    flights, client_out, keylog_text = openssl_connection(version, suite, certs[cert_kind][0], certs[cert_kind][1], workdir)
    streams = {"c2s": b"", "s2c": b""}
    for direction, data in flights:
        streams[direction] += data
    records = {d: parse_records(s) for d, s in streams.items()}
    for d, s in streams.items():
        assert sum(5 + len(r[2]) for r in records[d]) == len(s), "relay cut a record"
    client_hello, server_hello = hello_facts(records["c2s"]), hello_facts(records["s2c"])
    assert client_hello and server_hello
    assert server_hello["cipher"] == ident, "negotiated %04x, wanted %04x" % (server_hello["cipher"], ident)
    assert server_hello["negotiated"] == (0x0304 if version == 13 else 0x0303)
    lines = [l.split() for l in keylog_text.splitlines() if l and not l.startswith("#")]
    assert lines and all(l[1] == client_hello["random"] for l in lines), "key log random differs from the wire"

    protected = {}
    for d, rs in records.items():
        if version == 13:
            protected[d] = [r for r in rs if r[0] == 23]
        else:
            ccs = [i for i, r in enumerate(rs) if r[0] == 20]
            assert len(ccs) == 1, "expected one ChangeCipherSpec per direction"
            protected[d] = rs[ccs[0] + 1:]
    case = {
        "name": suite,
        "version": 0x0304 if version == 13 else 0x0303,
        "cipher": ident,
        "client_random": client_hello["random"],
        "server_random": server_hello["random"],
        "keylog": keylog_text,
        "c2s": [{"type": r[0], "version": r[1], "fragment": r[2].hex()} for r in protected["c2s"]],
        "s2c": [{"type": r[0], "version": r[1], "fragment": r[2].hex()} for r in protected["s2c"]],
        # known plaintext of the application_data records: what the client sent, what s_client printed after decrypting
        "c2s_application_data": REQUEST.hex(),
        "s2c_application_data": client_out.hex(),
    }
    if version == 13:
        update = {l[0]: l[2] for l in lines if l[0] in ("CLIENT_TRAFFIC_SECRET_N", "SERVER_TRAFFIC_SECRET_N")}
        assert len(update) == 2, "no KeyUpdate secrets were logged"
        case["update_secrets"] = {"c2s": update["CLIENT_TRAFFIC_SECRET_N"], "s2c": update["SERVER_TRAFFIC_SECRET_N"]}
    return case


def make_decrypt_fixtures(which, outdir):
    os.makedirs(outdir, exist_ok=True)
    workdir = tempfile.mkdtemp()
    certs = {"ec": make_cert(workdir, "ec"), "rsa": make_cert(workdir, "rsa")}
    for version, table in ((13, SUITES_13), (12, SUITES_12)):
        if which not in ("all", str(version)) or not table:
            continue
        cases = [decrypt_case(version, ident, name, kind, certs, workdir) for ident, name, kind in table]
        path = os.path.join(outdir, "decrypt_tls%d.json" % version)
        with open(path, "w") as f:
            json.dump({"cases": cases}, f, indent=1)
            f.write("\n")
        print("%s: %d cases, %d bytes" % (path, len(cases), os.path.getsize(path)))


def main():
    args = sys.argv[1:]
    default_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data", "tls")
    if args and args[0] == "--decrypt":
        which = args[1] if len(args) > 1 and args[1] in ("13", "12", "all") else "all"
        rest = [a for a in args[1:] if a not in ("13", "12", "all")]
        make_decrypt_fixtures(which, rest[0] if rest else default_dir)
        return
    outdir = args[0] if args else default_dir
    os.makedirs(outdir, exist_ok=True)
    cert, key = make_certificate(tempfile.mkdtemp())
    expected = {"tls%d" % v: build(v, cert, key, outdir) for v in (12, 13)}
    with open(os.path.join(outdir, "expected.json"), "w") as f:
        json.dump(expected, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
