// Adapts the capture queue to the file processor; kept separate from device/IPC recording.
#include "live_capture.h"

namespace capture {
    size_t appendCapturedPackets(LiveCapture &live, core::FileProcessor &processor, std::vector<packet::PacketInfo> &packets,
                                 size_t maxPackets, std::vector<uint32_t> *amended) {
        std::vector<CapturedPacket> batch;
        if (live.takePackets(batch, maxPackets) == 0) return 0;
        if (processor.captureInfo().interfaces.empty()) processor.beginLive(live.linkType(), live.snaplen());

        const std::string path = live.tempPath();
        std::ifstream file(core::pathFromUtf8(path), std::ios::binary);
        size_t appended = 0;
        std::vector<char> frame;
        for (const CapturedPacket &p: batch) {
            frame.resize(p.capturedLength);
            file.clear();
            file.seekg(static_cast<std::streamoff>(p.fileOffset));
            if (p.capturedLength > 0 && !file.read(frame.data(), p.capturedLength)) {
                live.setError("Cannot read captured packets back from " + path);
                continue;
            }
            processor.appendLivePacket(packets, p.tsSeconds, p.tsMicros, p.linkType, p.fileOffset, p.originalLength, frame, amended);
            ++appended;
        }
        return appended;
    }
} // namespace capture
