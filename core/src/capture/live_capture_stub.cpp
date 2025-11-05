// Live capture without libpcap (IMSHARK_LIVE_CAPTURE=OFF or the library was not found): every device operation
// reports kNotAvailable. The temp file writer, the packet queue and the consumer in live_capture.cpp still work.

#include "live_capture.h"

namespace capture {
    bool liveCaptureAvailable() { return false; }

    InterfaceList listInterfaces() {
        InterfaceList result;
        result.error = kNotAvailable;
        return result;
    }

    FilterCheck validateCaptureFilter(const std::string &, uint32_t, uint32_t) {
        FilterCheck check;
        check.error = kNotAvailable;
        return check;
    }

    bool LiveCapture::openDevice(const CaptureOptions &, uint32_t &, std::string &error) {
        error = kNotAvailable;
        return false;
    }

    void LiveCapture::breakCapture() {}
    void LiveCapture::closeDevice() {}
    void LiveCapture::captureLoop() {}
} // namespace capture
