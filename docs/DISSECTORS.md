# Adding a Protocol Dissector to ImShark

This guide describes how dissectors are really written in this repository: where the files go, how a dissector is
registered, how load-time state and detail building (Replay) interact, how filter fields are added, and which tests a
delivery needs. Read it together with the "Ortak teslim kuralları" section of `ROADMAP.md`, which is the binding
list of delivery rules.

## What a dissector is

A dissector decodes `length` bytes starting at `data` and never reads beyond them. It fills the packet summary
(`ctx.pack`: protocol, Info text, `app_*` facts, addresses where it owns them), optionally builds the field tree for the
details pane, and may hand the payload to the next layer through `ctx.registry`. The signature is (`core/src/dissect/context.h`):

```cpp
using Dissector = std::function<void(Context &ctx, const char *data, size_t length)>;
```

### The `Context`

- `ctx.pack` is the `packet::PacketInfo` being filled in. It is deliberately small (a `static_assert` in
  `tests/test_reader.cpp` caps it at 336 bytes): do **not** add members. Use `app_type`, `app_flags`, `app_code`,
  `app_stream`, `app_text`, `app_text2`, existing unions, or a session table (below).
- `ctx.frame` / `ctx.frameLength` are the captured frame; `ctx.offsetOf(p)` turns a pointer into an absolute offset for
  field nodes.
- `ctx.mode` is a `ParseMode`: `Summary` (load pass: list columns only, no tree), `Full` (summary and tree, used by
  tests and tools) or `Replay` (details of one packet of an already loaded capture). `ctx.wantFields()` is false in
  `Summary`; skip tree building then.
- `ctx.sessions` is the `core::SessionTables`; `ctx.streams`, `ctx.reassembler` and the `completed*` members carry TCP and
  IP reassembly. `ctx.tcpStreamSeq` identifies a stream message.
- `ctx.addLayer(name, offset, length)` appends a top-level tree layer and returns a `Field &`; `Field::add(text, offset,
  length)` adds a child node. Every node must lie inside the frame.
- `ctx.markMalformed(reason)` flags the packet (it feeds Expert Info). Call it after you set the summary, because the
  Info text is overwritten.

## The two passes: load pass and Replay

This is the rule that matters most. A capture is dissected **once, in order, in `Summary` mode** (the load pass). Later,
when the user selects a packet, that single packet is dissected again in `Replay` mode with the tables frozen.

- Everything that depends on earlier packets (a TLS upgrade, a MySQL greeting that tells the server direction, a USB
  control request whose completion has no setup, reassembly) is **decided in the load pass and stored**: in
  `app_flags` / `app_type` / `app_code` or in `SessionTables` (`core/src/dissect/session.h`).
- Replay only **reads** that state. `SessionTables::freeze()` makes the tables refuse writes during Replay; a dissector
  must not recompute cross-packet state from the single packet, or the details would differ from the list.
- State needs a bound: the tables have a memory budget and record a "state lost" flag when it is exceeded.
- The Info column text comes from `pack.info` in both passes, so the list and the details agree.

TCP protocols whose messages span segments (or share one) register a `StreamProtocol` (framer + dissector for one
complete message); datagram reassembly uses `network::DatagramReassembler`. Existing examples: `ldap.cpp`
(`frameLdap`), `postgres.cpp`, `tds.cpp`, `dtls.cpp`.

## Step 1: the dissector file

Dissectors live in `core/src/dissect/`, one file per protocol (a few related ones share a file, e.g. `voip.cpp`,
`industrial.cpp`). Declare the entry point in the protocol's own header (`igmp.h`, `ospf.h`, ...) or, for older
dissectors, in `protocols.h`. Use the bounds-checked helpers instead of raw pointer arithmetic:

- `reader.h`: `ByteReader` (`u8`, `u16_be`/`u16_le`, `u24_be`, `u32_be`/`u32_le`, `skip`, `sub(len)`; once a read would pass the
  end it enters a failed state, `ok()` is false).
- `asn1.h` (BER/DER), `xdr.h` (XDR), `util.h` (`be16`, `ip4`, `hexString`, `printableText` for bounded printable text),
  `checksum.h` (Internet checksum, CRC-32C, pseudo headers).

A minimal sketch:

```cpp
#include "myproto.h"
#include "reader.h"
#include "util.h"

using packet::Field;

void dissect::dissectMyProto(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "MYPROTO";

    ByteReader r(data, length);
    const uint16_t type = r.u16_be();
    const uint16_t len = r.u16_be();
    if (!r.ok()) {                       // shorter than the fixed header
        pack.info = "MyProto [Truncated]";
        ctx.markMalformed("MyProto header truncated");
        return;
    }
    pack.app_type = type;                // facts the filter reads (summary only, no tree)
    pack.info = "MyProto message type " + std::to_string(type);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("My Protocol", o, length);
        l.add("Type: " + std::to_string(type), o, 2);
        l.add("Length: " + std::to_string(len), o + 2, 2);
    }
}
```

Claim a port or payload only when the content validates (a wrong claim hides what the packet really is); otherwise
decline and let the generic UDP/TCP path show it. Mark data that is encrypted or protected as such; never present it
as plain text.

## Step 2: register it

`core/src/dissect/registry.cpp` (`Registry::builtin()`):

- Link layer / network / transport: `registerLinkType`, `registerEtherType`, `registerIpProtocol`.
- Application: `registerTcpPort`, `registerUdpPort`; heuristics `registerTcpHeuristic`, `registerUdpHeuristic`.
- TCP message streams: `registerTcpStream(port, StreamProtocol{name, framer, dissect})` and
  `registerTcpStreamHeuristic`.
- Decode As: `registerProtocolName(name, Handlers{udp, tcp, stream})` makes the protocol selectable by name for any
  port. A protocol that is never dispatched automatically (RTP/RTCP) is reachable **only** through this.

Source lists are explicit: add the `.cpp` to `core/CMakeLists.txt` (`imshark_core`) and the test file to
`tests/CMakeLists.txt`. CMake does not glob.

## Step 3: filter fields

Display filters read **summary** data (`PacketInfo`), never the field tree. Fields live in the central table in
`core/src/filter/fields.cpp` (`buildTable()`); the table is built once before any filter is compiled or any packet is
dissected. Add rows there:

```cpp
{"myproto", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MYPROTO") o.addU(1); }, "My Protocol"},
{"myproto.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MYPROTO") o.addU(p.app_type); }, "My Protocol Message Type"},
```

Gate every extractor on the protocol (an ungated field matches unrelated packets). `filter::registerField` exists for
fields that are not part of the built-in table (plugins, tests); dissectors do not call it and must not register fields
lazily from their own function. Not every dissector has filter fields yet: `docs/KNOWN_ISSUES.md` lists the gaps.

`docs/FILTER_FIELDS.md` is generated from this table and a test compares them: after adding rows run the tests once
with `IMSHARK_UPDATE_DOCS=1` (`IMSHARK_UPDATE_DOCS=1 ctest --test-dir build -R Docs`) and commit the regenerated file.

Also add the protocol to the hierarchy and application names in `core/src/stats/statistics.cpp` if it should appear
under its own name in Statistics.

## Step 4: tests

`ctest` runs one GoogleTest binary (`tests/`). Three kinds of test are expected for a dissector:

1. **Real captures, optional.** Entries of kind `real` in `tests/corpus/manifest.json` (source URL, SHA-256, expected
   counts, facts) are read from the directory in `IMSHARK_CORPUS_DIR` and skipped when it is not set; nothing is ever
   downloaded. A dissector test can look for manifest entries naming its protocol (`framesweep::checkCorpus`,
   `*.RealCapturesWhenAvailable` tests). The manifest also holds a few synthetic files generated by
   `tools/make_corpus.py` for capture-format and IP edge cases. For the v1.1 to v1.9 protocols no real capture is in the
   manifest yet, so these hooks currently skip.
2. **Hand-built messages with an independent oracle.** Build the bytes from the specification (RFC examples, vendor
   documents), and compute the expected numbers by another route than the code under test: a Python stdlib
   computation, `openssl asn1parse`, a published test vector. Say in a comment how the vector was obtained.
3. **Truncation and mutation sweep.** Cut the frame at every length and flip seeded random bytes, and assert that nothing
   crashes (run it under ASan) and that every field offset + length stays inside the frame. Use the shared helpers:
   `tests/frame_sweep.h` (`framesweep::sweep`, `expectInside`, frame builders for Ethernet/IPv4/IPv6/UDP, any link
   type) and, for TCP conversations, `tests/app_flow.h` (`appflow::Flow`, `expectReplayEqualsLoad`, `sweepPayload`).

If the dissector keeps cross-packet state, also test that Replay equals the load pass (`expectReplayEqualsLoad`).

Build and run the sanitizer configuration before you commit:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DIMSHARK_SANITIZE=ON
cmake --build build-asan -j && (cd build-asan && ctest --output-on-failure)   # run serially
```

There is no separate fuzzing harness; the mutation sweeps above, run under ASan/UBSan, are the memory-safety check.

## Delivery checklist (apply it to every protocol)

This is a template, not a one-time task: go through it for each dissector you deliver.

- [ ] Specification and version named in `docs/PROTOCOLS.md`, with known deviations stated honestly.
- [ ] Dissector file in `core/src/dissect/`, header, entry in `core/CMakeLists.txt`, registration in `registry.cpp`
      (and a Decode As name if appropriate).
- [ ] Cross-packet state decided in the load pass and stored; Replay only reads it; `PacketInfo` did not grow.
- [ ] `ctx.wantFields() == false` skips the tree; the Info text is the same in both passes.
- [ ] Filter fields in `core/src/filter/fields.cpp`, gated on the protocol; hierarchy name in `statistics.cpp`.
- [ ] Tests: hand-built messages with an independent oracle, truncation/mutation sweep, corpus hook (skipping when
      `IMSHARK_CORPUS_DIR` is not set), Replay equality for stateful protocols.
- [ ] Encrypted or protected content is labelled and never shown as plain text.
- [ ] Full `ctest` passes in a normal build and in `-DIMSHARK_SANITIZE=ON`.
- [ ] `docs/KNOWN_ISSUES.md` (functional limits), `docs/SUPPORT_MATRIX.md`, `docs/PROTOCOLS.md` and the README feature
      list describe exactly what the code does, including what it does not do.

## Worked example (compiled and run by the test suite)

`tests/test_dissector_guide.cpp` holds a complete toy protocol, "TOY": UDP port 40000, a big-endian `u16` type, a `u16`
payload length, then the payload. It is registered on a private copy of the built-in registry, so it never touches the
real one. The three code blocks below are not illustrations: the test `DissectorGuide.TheCodeInTheGuideIsTheCodeCompiledHere`
fails when a block here differs from the marked region of the test file. If you change an API this guide uses, change
the test and this section together.

The dissector (Step 1). It reads only through `ByteReader`, fills the summary (`protocol`, `info`, `app_type`) in every mode,
builds the field tree only when `wantFields()` is true, and reports a length that does not fit as malformed:

<!-- guide:dissector -->
```cpp
void dissectToy(dissect::Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "TOY";

    dissect::ByteReader r(data, length);
    const uint16_t type = r.u16_be();
    const uint16_t len = r.u16_be();
    if (!r.ok()) {                           // shorter than the 4-byte header
        pack.info = "Toy [Truncated]";
        ctx.markMalformed("Toy header truncated");
        return;
    }
    pack.app_type = type;                    // a fact the filter reads: summary data, not the field tree
    pack.info = "Toy message type " + std::to_string(type);
    if (len > r.remaining()) {
        ctx.markMalformed("Toy length exceeds the datagram");
        return;
    }

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &layer = ctx.addLayer("Toy Protocol", o, 4 + len);
        layer.add("Type: " + std::to_string(type), o, 2);
        layer.add("Length: " + std::to_string(len), o + 2, 2);
        if (len) layer.add("Payload", o + 4, len);
    }
}
```

Registration (Step 2). `registerUdpPort` makes the port dispatch to it; `registerProtocolName` makes it selectable in
Decode As (UDP only here, since no TCP handler is given). `Registry` is copyable, which is what makes a private registry
cheap; `packet::PacketParser parser(registry)` then uses it:

<!-- guide:registry -->
```cpp
dissect::Registry toyRegistry() {
    dissect::Registry r = dissect::Registry::builtin();
    r.registerUdpPort(40000, dissectToy);
    r.registerProtocolName("TOY", {dissectToy, nullptr, nullptr});   // Decode As: UDP only
    return r;
}
```

A filter field (Step 3). The extractor is a plain function pointer, gated on the protocol, reading summary data. A
built-in protocol adds a row to `buildTable()` in `core/src/filter/fields.cpp` instead; `registerField` is the route for
tests and plugins (it is why the test uses it; the generated filter reference in `docs/FILTER_FIELDS.md` is built from the
built-in table only, so such fields never appear there):

<!-- guide:field -->
```cpp
void toyType(const packet::PacketInfo &p, const filter::Context &, filter::Values &out) {
    if (p.protocol == "TOY") out.addU(p.app_type);
}

bool registerToyField() {
    static const bool done = filter::registerField({"toy.type", filter::FieldType::Unsigned, toyType, "Toy Protocol Message Type"});
    return done;
}
```

The tests in the same file show what each step buys you: the toy message decodes with a tree in `Full` mode and without
one in `Summary` mode, the built-in registry is untouched, Decode As moves the protocol to another port, the filter
`toy.type == 7` matches only TOY packets, and a truncation plus seeded-mutation sweep keeps every field inside the frame.
Copy the test file as the starting point of a new dissector's test.
