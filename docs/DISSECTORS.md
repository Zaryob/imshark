# Adding a New Protocol Dissector to ImShark

This guide explains how to write a new protocol dissector, register it, add display filter support, and test it in ImShark.

## What is a Dissector?

In ImShark, a dissector is a function responsible for parsing a specific network protocol. It receives a byte buffer representing the protocol payload and is expected to:
1. Populate summary fields for the packet list.
2. Build a protocol tree (`Field` tree) for the packet details view.
3. Hand off the remaining payload to the next layer (if applicable) via the `Registry`.

A dissector function matches the following signature (defined in `core/src/dissect/context.h`):
```cpp
using Dissector = std::function<void(Context &ctx, const char *data, size_t length)>;
```

### The `Context` Object

The `Context` object (`ctx`) provides everything needed during parsing:
- `ctx.pack`: The `PacketInfo` struct to fill with summary data and tree fields.
- `ctx.frame` & `ctx.frameLength`: The absolute start and length of the captured frame.
- `ctx.tcp`: TCP state tracking (for relative sequence/acknowledgment numbers).
- `ctx.registry`: The registry used to look up and invoke the next dissector in the stack.
- `ctx.mode`: The current `ParseMode`. If `ctx.wantFields()` is false, the dissector should skip building the field tree for performance.
- `ctx.addLayer()`: Helper to create a new top-level protocol layer in the tree.

## Step 1: Create the Dissector File

Protocol dissectors are placed in `core/src/dissect/`. Create a new `.cpp` file (e.g., `myproto.cpp`) and declare your dissector in `core/src/dissect/protocols.h`.

Example `core/src/dissect/myproto.cpp`:

```cpp
#include "protocols.h"
#include <network/utils.h>

using packet::Field;

namespace dissect {

void dissectMyProto(Context &ctx, const char *data, size_t length) {
    if (length < 4) return; // Malformed or truncated

    // 1. Populate Summary Fields
    ctx.pack.protocol = "MYPROTO";
    ctx.pack.info = "MyProto Message";

    // You can use app_* fields to store protocol-specific data for filters
    uint16_t msg_type = be16(data);
    ctx.pack.app_type = msg_type; 
    ctx.pack.app_text = "Type " + std::to_string(msg_type);

    // 2. Build the Field Tree (only if needed)
    if (ctx.wantFields()) {
        size_t offset = ctx.offsetOf(data);
        Field& layer = ctx.addLayer("My Protocol", offset, length);

        layer.children.push_back({"Message Type: " + std::to_string(msg_type), static_cast<uint32_t>(offset), 2, {}});
        
        uint16_t payload_len = be16(data + 2);
        layer.children.push_back({"Payload Length: " + std::to_string(payload_len), static_cast<uint32_t>(offset + 2), 2, {}});
    }

    // 3. Hand off to the next layer (optional)
    // If MyProto encapsulates another protocol, invoke it via ctx.registry
    // Example: next_dissector(ctx, data + 4, length - 4);
}

} // namespace dissect
```

## Step 2: Register the Dissector

Once the dissector is written, it needs to be registered so ImShark knows when to invoke it. This is done in `core/src/dissect/registry.cpp` within the `Registry::builtin()` method.

The `Registry` supports multiple registration methods based on the transport layer:
- **Link Layer:** `registerLinkType(type, dissector)`
- **Network Layer:** `registerEtherType(type, dissector)`
- **Transport Layer:** `registerIpProtocol(protocol, dissector)`
- **Application Layer (Port-based):** 
  - `registerTcpPort(port, dissector)`
  - `registerUdpPort(port, dissector)`
- **Application Layer (Heuristic):**
  - `registerTcpHeuristic(heuristic_dissector)`
  - `registerUdpHeuristic(heuristic_dissector)`

Example registration in `registry.cpp`:
```cpp
registry.registerUdpPort(12345, dissectMyProto);
```

## Step 3: Add Display Filter Fields

ImShark filters operate **only on summary fields** (data stored directly in `PacketInfo`), not the field tree. This allows lightning-fast filtering without touching the PCAP file.

To make your protocol filterable, add field definitions to `core/src/filter/fields.cpp` in the `buildTable()` function.

1. Ensure your dissector populates `PacketInfo` fields like `app_type`, `app_flags`, `app_code`, `app_text`, or `app_text2`.
2. Add a new row to the table in `fields.cpp`:

```cpp
{"myproto", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MYPROTO") o.addU(1); }, "My Protocol"},
{"myproto.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MYPROTO") o.addU(p.app_type); }, "My Protocol Message Type"},
```

## Step 4: State Management and Session Tables

For protocols that span multiple packets or require state tracking (e.g., handshake completion, sessions), use the `SessionTables` inside the `Context`.

- TCP reassembly and connection tracking are automatically handled by `network::TCPConnection` and `TcpStreams`.
- For application-level sessions (like TLS or DTLS), look at `core/src/dissect/session.h` (`ctx.sessions`).
- Remember that ImShark reads packets in multiple passes. Store state keyed by invariant identifiers (like `tcpStreamSeq` + `pack.number` or endpoint addresses) so it behaves correctly during single-packet replays (`ParseMode::Replay`).

## Step 5: Testing

ImShark uses rigorous testing. You must provide tests for your new dissector.

1. **Synthetic Tests:** Generate synthetic PCAP files using `tools/make_corpus.py`. Define the expected output (summary, tree, filters) in `tests/corpus/manifest.json`. The CI will automatically run the PCAP through the pipeline and assert the output matches.
2. **Fuzzing:** The dissector is automatically fuzz-tested under ASan/UBSan via the core fuzzing targets. Ensure you check buffer lengths strictly (`length < expected`) to prevent out-of-bounds reads.

## Delivery Checklist

Before opening a PR, ensure you have:
- [ ] Created the dissector file in `core/src/dissect/`.
- [ ] Registered the dissector in `core/src/dissect/registry.cpp`.
- [ ] Added relevant summary data to `PacketInfo`.
- [ ] Added filter definitions to `core/src/filter/fields.cpp`.
- [ ] Handled `ctx.wantFields() == false` correctly to skip tree building.
- [ ] Added a synthetic test PCAP and expectations to `manifest.json`.
- [ ] Run `ctest` locally with ASan and UBSan enabled.
- [ ] Verified that display filters for your protocol work as expected.
