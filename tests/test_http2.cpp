#include <gtest/gtest.h>

#include "dissect/context.h"
#include "dissect/hpack.h"
#include "dissect/protocols.h"
#include "dissect/registry.h"
#include "filter/filter.h"
#include "support.h"

#include <vector>
#include <string>

#include <core.h>

using namespace dissect;

namespace {

Context makeCtx(packet::PacketInfo &pack, const char *data, size_t length, network::TCPConnection &tcp) {
    return Context{pack, data, length, tcp, Registry::builtin()};
}

bool matches(const std::string &expr, const packet::PacketInfo &p) {
    auto r = filter::Filter::compile(expr);
    EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
    return r.ok && r.filter.matches(p);
}

} // namespace

TEST(Http2Dissect, ConnectionPreface) {
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    packet::PacketInfo pack;
    network::TCPConnection tcp;
    Context ctx = makeCtx(pack, preface.data(), preface.size(), tcp);

    dissectHttp2(ctx, preface.data(), preface.size());
    EXPECT_EQ(pack.protocol, "HTTP2");
    EXPECT_NE(pack.info.find("Connection Preface"), std::string::npos);
    EXPECT_EQ(pack.app_type, 254u);
}

TEST(Http2Dissect, SettingsFrame) {
    const uint8_t frame[] = {
        0x00, 0x00, 0x06,       // Length: 6
        0x04,                   // Type: SETTINGS
        0x00,                   // Flags: 0
        0x00, 0x00, 0x00, 0x00, // Stream: 0
        0x00, 0x03,             // ID: SETTINGS_MAX_CONCURRENT_STREAMS (3)
        0x00, 0x00, 0x00, 0x64  // Value: 100
    };

    packet::PacketInfo pack;
    network::TCPConnection tcp;
    Context ctx = makeCtx(pack, reinterpret_cast<const char*>(frame), sizeof(frame), tcp);

    dissectHttp2(ctx, reinterpret_cast<const char*>(frame), sizeof(frame));
    EXPECT_EQ(pack.protocol, "HTTP2");
    EXPECT_EQ(pack.app_type, 4u);
    EXPECT_EQ(pack.app_stream, 0u);
    EXPECT_NE(pack.info.find("SETTINGS: 1 parameter(s)"), std::string::npos);

    // Test fields tree
    ASSERT_FALSE(pack.fields.empty());
    const auto &root = pack.fields[0];
    EXPECT_NE(root.text.find("HTTP/2"), std::string::npos);
}

TEST(Http2Dissect, HeadersAndDataFrames) {
    // Frame 1: HEADERS stream 1, flags=0x05 (END_STREAM | END_HEADERS)
    const uint8_t headersFrame[] = {
        0x00, 0x00, 0x02,
        0x01,
        0x05,
        0x00, 0x00, 0x00, 0x01,
        0x82, 0x87
    };

    packet::PacketInfo pack;
    network::TCPConnection tcp;
    Context ctx = makeCtx(pack, reinterpret_cast<const char*>(headersFrame), sizeof(headersFrame), tcp);

    dissectHttp2(ctx, reinterpret_cast<const char*>(headersFrame), sizeof(headersFrame));
    EXPECT_EQ(pack.protocol, "HTTP2");
    EXPECT_EQ(pack.app_type, 1u);
    EXPECT_EQ(pack.app_flags, 0x05);
    EXPECT_EQ(pack.app_stream, 1u);
    EXPECT_EQ(pack.app_text, "GET");
    EXPECT_NE(pack.info.find("HEADERS[stream 1]"), std::string::npos);

    // Frame 2: DATA stream 1, flags=0x01 (END_STREAM), length=5, "hello"
    const uint8_t dataFrame[] = {
        0x00, 0x00, 0x05,
        0x00,
        0x01,
        0x00, 0x00, 0x00, 0x01,
        'h', 'e', 'l', 'l', 'o'
    };

    packet::PacketInfo dpack;
    network::TCPConnection dtcp;
    Context dctx = makeCtx(dpack, reinterpret_cast<const char*>(dataFrame), sizeof(dataFrame), dtcp);
    dissectHttp2(dctx, reinterpret_cast<const char*>(dataFrame), sizeof(dataFrame));
    EXPECT_EQ(dpack.protocol, "HTTP2");
    EXPECT_EQ(dpack.app_type, 0u);
    EXPECT_EQ(dpack.app_flags, 0x01);
    EXPECT_EQ(dpack.app_stream, 1u);
    EXPECT_NE(dpack.info.find("DATA[stream 1]: 5 bytes (END_STREAM)"), std::string::npos);
}

TEST(Http2Dissect, PingRstGoawayWindowUpdate) {
    // PING ACK frame (type 6, flags 0x01, stream 0, length 8)
    const uint8_t pingFrame[] = {
        0x00, 0x00, 0x08,
        0x06,
        0x01,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    packet::PacketInfo pack;
    network::TCPConnection tcp;
    Context ctx = makeCtx(pack, reinterpret_cast<const char*>(pingFrame), sizeof(pingFrame), tcp);
    dissectHttp2(ctx, reinterpret_cast<const char*>(pingFrame), sizeof(pingFrame));
    EXPECT_EQ(pack.app_type, 6u);
    EXPECT_NE(pack.info.find("PING: ACK"), std::string::npos);

    // RST_STREAM frame (type 3, stream 3, error CANCEL=0x8)
    const uint8_t rstFrame[] = {
        0x00, 0x00, 0x04,
        0x03,
        0x00,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x08
    };
    packet::PacketInfo rpack;
    network::TCPConnection rtcp;
    Context rctx = makeCtx(rpack, reinterpret_cast<const char*>(rstFrame), sizeof(rstFrame), rtcp);
    dissectHttp2(rctx, reinterpret_cast<const char*>(rstFrame), sizeof(rstFrame));
    EXPECT_EQ(rpack.app_type, 3u);
    EXPECT_NE(rpack.info.find("RST_STREAM"), std::string::npos);
    EXPECT_NE(rpack.info.find("CANCEL"), std::string::npos);

    // WINDOW_UPDATE (type 8, stream 1, increment 65535)
    const uint8_t winFrame[] = {
        0x00, 0x00, 0x04,
        0x08,
        0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0xff, 0xff
    };
    packet::PacketInfo wpack;
    network::TCPConnection wtcp;
    Context wctx = makeCtx(wpack, reinterpret_cast<const char*>(winFrame), sizeof(winFrame), wtcp);
    dissectHttp2(wctx, reinterpret_cast<const char*>(winFrame), sizeof(winFrame));
    EXPECT_EQ(wpack.app_type, 8u);
    EXPECT_NE(wpack.info.find("WINDOW_UPDATE"), std::string::npos);
    EXPECT_NE(wpack.info.find("65535"), std::string::npos);

    // GOAWAY (type 7, stream 0, last stream 3, error PROTOCOL_ERROR=0x1)
    const uint8_t goawayFrame[] = {
        0x00, 0x00, 0x08,
        0x07,
        0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x01
    };
    packet::PacketInfo gpack;
    network::TCPConnection gtcp;
    Context gctx = makeCtx(gpack, reinterpret_cast<const char*>(goawayFrame), sizeof(goawayFrame), gtcp);
    dissectHttp2(gctx, reinterpret_cast<const char*>(goawayFrame), sizeof(goawayFrame));
    EXPECT_EQ(gpack.app_type, 7u);
    EXPECT_NE(gpack.info.find("GOAWAY"), std::string::npos);
    EXPECT_NE(gpack.info.find("PROTOCOL_ERROR"), std::string::npos);
}

TEST(Http2Framer, FrameHttp2Stream) {
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    // Complete preface
    auto f = frameHttp2(preface.data(), preface.size());
    EXPECT_EQ(f.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f.length, 24u);

    // Incomplete preface
    f = frameHttp2(preface.data(), 10);
    EXPECT_EQ(f.kind, StreamFrame::Kind::NeedMore);
    EXPECT_EQ(f.length, 14u);

    // Non-HTTP/2 text rejected
    const char *http1 = "GET /index.html HTTP/1.1\r\n";
    f = frameHttp2(http1, std::strlen(http1));
    EXPECT_EQ(f.kind, StreamFrame::Kind::Reject);

    // Non-HTTP/2 POST rejected
    const char *post = "POST /api HTTP/1.1\r\n";
    f = frameHttp2(post, std::strlen(post));
    EXPECT_EQ(f.kind, StreamFrame::Kind::Reject);

    // Valid SETTINGS frame
    const uint8_t frame[] = {
        0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64
    };
    f = frameHttp2(reinterpret_cast<const char*>(frame), sizeof(frame));
    EXPECT_EQ(f.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f.length, 15u);

    // Incomplete frame
    f = frameHttp2(reinterpret_cast<const char*>(frame), 8);
    EXPECT_EQ(f.kind, StreamFrame::Kind::NeedMore);
    EXPECT_EQ(f.length, 1u);
}

TEST(Http2Filter, FilterExpressions) {
    packet::PacketInfo pack;
    pack.protocol = "HTTP2";
    pack.app_type = 1;       // HEADERS
    pack.app_stream = 5;  // stream ID 5
    pack.app_flags = 0x05;   // END_STREAM | END_HEADERS
    pack.app_text = "GET";
    pack.app_text2 = "/v1/items";
    pack.app_code = 200;

    EXPECT_TRUE(matches("http2", pack));
    EXPECT_TRUE(matches("http2.type == 1", pack));
    EXPECT_TRUE(matches("http2.streamid == 5", pack));
    EXPECT_TRUE(matches("http2.flags == 5", pack));
    EXPECT_TRUE(matches("http2.headers.method == \"GET\"", pack));
    EXPECT_TRUE(matches("http2.headers.path == \"/v1/items\"", pack));
    EXPECT_TRUE(matches("http2.headers.status == 200", pack));

    EXPECT_FALSE(matches("http2.type == 0", pack));
    EXPECT_FALSE(matches("http2.streamid == 1", pack));
    EXPECT_FALSE(matches("http2.headers.method == \"POST\"", pack));
    EXPECT_FALSE(matches("http2.headers.status == 404", pack));
}

TEST(Http2Dissect, TruncatedAndFuzzedPayloads) {
    packet::PacketInfo pack;
    network::TCPConnection tcp;

    // 0 length
    Context ctx1 = makeCtx(pack, "", 0, tcp);
    dissectHttp2(ctx1, "", 0);

    // Partial header (fewer than 9 bytes)
    const uint8_t partial[] = { 0x00, 0x00, 0x05, 0x00 };
    Context ctx2 = makeCtx(pack, reinterpret_cast<const char*>(partial), sizeof(partial), tcp);
    dissectHttp2(ctx2, reinterpret_cast<const char*>(partial), sizeof(partial));

    // Declared length greater than buffer
    const uint8_t declaredTooLong[] = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xaa, 0xbb
    };
    Context ctx3 = makeCtx(pack, reinterpret_cast<const char*>(declaredTooLong), sizeof(declaredTooLong), tcp);
    dissectHttp2(ctx3, reinterpret_cast<const char*>(declaredTooLong), sizeof(declaredTooLong));
}

// The stream id must not share storage with the TCP reassembly bookkeeping: rebuilding the details of a packet that
// holds a whole HTTP/2 message from the file has to give the same result as the loading pass.
TEST(Http2Replay, DetailsRebuiltFromTheFileAgreeWithTheLoadingPass) {
    std::string stream(reinterpret_cast<const char *>("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 24);
    const std::string settings("\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x64", 15);          // SETTINGS, one parameter
    const std::string data("\x00\x00\x05\x00\x01\x00\x00\x00\x07hello", 14);                                      // DATA on stream 7
    auto seg = [&](uint32_t seq, const std::string &payload) {
        char s[16];
        std::snprintf(s, sizeof s, "%08x", seq);
        return support::tcpPacket("0a000001", "0a000002", "c350", "1f90", s, "00000001", "18", payload);
    };
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const std::string path = support::writeTemp("http2_replay.pcap", support::pcapBytes({seg(1000, stream + settings), seg(1039, data)}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    ASSERT_EQ(packets.size(), 2u);
    EXPECT_EQ(packets[1].protocol, "HTTP2");
    EXPECT_EQ(packets[1].app_stream, 7u);
    for (const auto &p: packets) {
        packet::PacketInfo d;
        ASSERT_TRUE(core::buildPacketDetails(path, p, d, &packets, &fp.captureInfo()));
        EXPECT_EQ(d.protocol, p.protocol) << p.number;
        EXPECT_EQ(d.info, p.info) << p.number;
        EXPECT_FALSE(d.fields.empty());
    }
    std::remove(path.c_str());
}
