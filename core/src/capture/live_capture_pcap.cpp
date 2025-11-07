// The libpcap backed part of live capture (built when IMSHARK_HAVE_LIVE_CAPTURE is defined).

#include "live_capture.h"

#include <pcap.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <chrono>
#include <cstring>
#include <mutex>

namespace capture {
    namespace {
        // libpcap's DLT_ numbers differ from the LINKTYPE_ numbers of capture files for a few types (DLT_RAW is 12 on
        // most systems, LINKTYPE_RAW is 101; DLT_LOOP is 12 on OpenBSD). The file and the packet model use LINKTYPE_.
        uint32_t dltToLinkType(int dlt) {
#ifdef DLT_RAW
            if (dlt == DLT_RAW) return 101;
#endif
#ifdef DLT_LOOP
            if (dlt == DLT_LOOP) return 108;
#endif
            return static_cast<uint32_t>(dlt);
        }

        int linkTypeToDlt(uint32_t linkType) {
#ifdef DLT_RAW
            if (linkType == 101) return DLT_RAW;
#endif
#ifdef DLT_LOOP
            if (linkType == 108) return DLT_LOOP;
#endif
            return static_cast<int>(linkType);
        }

        std::string addressText(const sockaddr *sa) {
            if (!sa) return {};
            char buf[INET6_ADDRSTRLEN] = {0};
            if (sa->sa_family == AF_INET) {
                if (inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in *>(sa)->sin_addr, buf, sizeof(buf))) return buf;
            } else if (sa->sa_family == AF_INET6) {
                if (inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr, buf, sizeof(buf))) return buf;
            }
            return {};
        }

        bool looksLikePermissionError(const std::string &text) {
            return text.find("ermission denied") != std::string::npos || text.find("not permitted") != std::string::npos;
        }

        // pcap_compile() is not thread safe in older libpcap versions
        std::mutex &compileMutex() {
            static std::mutex m;
            return m;
        }
    } // namespace

    bool liveCaptureAvailable() { return true; }

    InterfaceList listInterfaces() {
        InterfaceList result;
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_if_t *devices = nullptr;
        if (pcap_findalldevs(&devices, errbuf) != 0) {
            result.error = errbuf[0] ? std::string("Cannot list the capture interfaces: ") + errbuf : "Cannot list the capture interfaces";
            return result;
        }
        for (const pcap_if_t *d = devices; d; d = d->next) {
            InterfaceDesc itf;
            itf.name = d->name ? d->name : "";
            itf.description = d->description ? d->description : "";
            itf.loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
#ifdef PCAP_IF_UP
            itf.up = (d->flags & PCAP_IF_UP) != 0;
            itf.running = (d->flags & PCAP_IF_RUNNING) != 0;
#else
            itf.up = itf.running = true;   // older libpcap: no connection state
#endif
#ifdef PCAP_IF_WIRELESS
            itf.wireless = (d->flags & PCAP_IF_WIRELESS) != 0;
#endif
            for (const pcap_addr_t *a = d->addresses; a; a = a->next) {
                const std::string text = addressText(a->addr);
                if (text.empty()) continue;
                if (!itf.addresses.empty()) itf.addresses += ", ";
                itf.addresses += text;
            }
            if (!itf.name.empty()) result.interfaces.push_back(std::move(itf));
        }
        pcap_freealldevs(devices);
        return result;
    }

    FilterCheck validateCaptureFilter(const std::string &expr, uint32_t linkType, uint32_t snaplen) {
        FilterCheck check;
        pcap_t *dead = pcap_open_dead(linkTypeToDlt(linkType), static_cast<int>(snaplen ? snaplen : 262144));
        if (!dead) {
            check.error = "Cannot prepare the filter compiler";
            return check;
        }
        bpf_program program{};
        int rc;
        {
            std::lock_guard<std::mutex> lock(compileMutex());
            rc = pcap_compile(dead, &program, expr.c_str(), 1, PCAP_NETMASK_UNKNOWN);
        }
        if (rc != 0) {
            check.error = pcap_geterr(dead);
        } else {
            pcap_freecode(&program);
            check.ok = true;
        }
        pcap_close(dead);
        return check;
    }

    bool LiveCapture::openDevice(const CaptureOptions &options, uint32_t &linkType, std::string &error) {
        if (options.interfaceName.empty()) {
            error = "No capture interface selected";
            return false;
        }
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *h = pcap_create(options.interfaceName.c_str(), errbuf);
        if (!h) {
            error = looksLikePermissionError(errbuf) ? std::string(kPermissionDenied) + " (" + errbuf + ")"
                                                     : "Cannot open " + options.interfaceName + ": " + errbuf;
            return false;
        }
        pcap_set_snaplen(h, static_cast<int>(options.snaplen ? options.snaplen : 262144));
        pcap_set_promisc(h, options.promiscuous ? 1 : 0);
        pcap_set_timeout(h, 100);          // ms: the capture thread wakes up at least this often to notice stop()
        pcap_set_immediate_mode(h, 1);     // hand packets over as they arrive instead of waiting for a full buffer

        const int rc = pcap_activate(h);
        if (rc < 0) {
            const std::string detail = pcap_geterr(h);
            if (rc == PCAP_ERROR_PERM_DENIED || looksLikePermissionError(detail)) {
                error = std::string(kPermissionDenied) + (detail.empty() ? "" : " (" + detail + ")");
            } else {
                error = "Cannot open " + options.interfaceName + ": " + (detail.empty() ? pcap_statustostr(rc) : detail);
            }
            pcap_close(h);
            return false;
        }

        if (!options.filter.empty()) {
            bpf_program program{};
            int crc;
            {
                std::lock_guard<std::mutex> lock(compileMutex());
                crc = pcap_compile(h, &program, options.filter.c_str(), 1, PCAP_NETMASK_UNKNOWN);
            }
            if (crc != 0) {
                error = "Invalid capture filter: " + std::string(pcap_geterr(h));
                pcap_close(h);
                return false;
            }
            const int src = pcap_setfilter(h, &program);
            pcap_freecode(&program);
            if (src != 0) {
                error = "Cannot apply the capture filter: " + std::string(pcap_geterr(h));
                pcap_close(h);
                return false;
            }
        }
        linkType = dltToLinkType(pcap_datalink(h));
        device_ = h;
        return true;
    }

    void LiveCapture::breakCapture() {
        if (device_) pcap_breakloop(device_);
    }

    void LiveCapture::closeDevice() {
        if (device_) {
            pcap_close(device_);
            device_ = nullptr;
        }
    }

    void LiveCapture::captureLoop() {
        pcap_t *h = device_;
        auto onPacket = [](u_char *user, const pcap_pkthdr *header, const u_char *bytes) {
            auto *self = reinterpret_cast<LiveCapture *>(user);
            self->writeRecord(static_cast<uint64_t>(header->ts.tv_sec), static_cast<uint32_t>(header->ts.tv_usec),
                              reinterpret_cast<const char *>(bytes), header->caplen, header->len);
        };
        auto updateStats = [&] {
            pcap_stat st{};
            if (pcap_stats(h, &st) == 0) dropped_ = st.ps_drop;
        };
        auto lastStats = std::chrono::steady_clock::now();
        while (!stopRequested_) {
            const int n = pcap_dispatch(h, -1, onPacket, reinterpret_cast<u_char *>(this));
            publish();
            if (n == PCAP_ERROR_BREAK || writeFailed_) break;   // stop(), or the temp file cannot be written any more
            if (n < 0) {
                setError("Capture stopped: " + std::string(pcap_geterr(h)));
                break;
            }
            const auto now = std::chrono::steady_clock::now();
            if (now - lastStats > std::chrono::milliseconds(250)) {
                updateStats();
                lastStats = now;
            }
        }
        updateStats();
    }
} // namespace capture
