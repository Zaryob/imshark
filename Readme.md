# ImShark

ImShark, [Dear ImGui](https://github.com/ocornut/imgui) ile yazılmış, Wireshark'tan esinlenen hafif bir **offline paket analizörüdür**. `.pcap` ve `.pcapng` dosyalarını açar; paketleri liste halinde, katman katman ayrıştırılmış ayrıntılarla ve etkileşimli bir hex/ASCII görünümüyle gösterir.

> Durum: erken aşama (prototip). Yalnızca dosyadan okuma yapar; canlı yakalama, filtreleme ve akış analizi henüz yoktur. Bkz. [ROADMAP.md](ROADMAP.md).

## Özellikler (bugün)

- `.pcap` (klasik, little-endian, mikro-saniye) ve `.pcapng` (SHB/IDB/EPB/NRB/ISB bloklarını okur) desteği; dosya türü magic number ile otomatik algılanır
- Ethernet II üzerinde: ARP/RARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP
- Uygulama katmanı özetleri: DNS (A/AAAA/SOA), DHCP, SNMP (yalnızca uzunluk), Telnet, SMTP, BGP (mesaj türü) — port numarasına göre tahmin edilir
- TCP için bağıl (relative) seq/ack numaraları
- Paket listesi (No, Time, Source, Destination, Protocol, Length, Info), çoklu seçim
- Katman ağacı (L2/L3/L4/L7) ve alan seçince hex/ASCII panelinde ilgili baytların vurgulanması
- Dosya açma penceresi (ImGuiFileDialog)

## Derleme

Gereksinimler: C++20 derleyici, CMake ≥ 3.13, OpenGL, `pkg-config`, GLFW 3.

```bash
# macOS
brew install glfw pkg-config cmake
# Debian/Ubuntu
sudo apt install build-essential cmake pkg-config libglfw3-dev libgl1-mesa-dev
```

```bash
cmake -S . -B build
cmake --build build
./build/imshark
```

Ardından **File → Open** ile bir `.pcap`/`.pcapng` dosyası seçin.

Not: kod `<arpa/inet.h>` kullandığı için şu an yalnızca POSIX (macOS/Linux) hedeflidir.

## Dizin yapısı

```
imshark/
├── CMakeLists.txt          # kök: imshark çalıştırılabilir dosyası
├── src/main.cpp            # GLFW penceresi + tüm ImGui arayüzü
└── core/                   # `imshark_core` paylaşımlı kütüphanesi
    ├── CMakeLists.txt
    ├── backends/glfw/      # imgui GLFW backend'i
    └── src/
        ├── core.{h,cpp}            # FileProcessor: pcap / pcapng okuyucu
        ├── packet_parser.cpp       # katman ayrıştırma + protokol özetleri
        ├── tcp_connection.cpp      # TCP bağıl seq/ack takibi
        ├── packet/                 # PacketInfo, PacketParser
        ├── network/                # l2/l3/l4/l7 başlık yapıları, yardımcılar
        ├── pcap/, pcapng/          # dosya formatı yapıları
        ├── imgui/                  # vendored Dear ImGui 1.91.1
        └── thirdparty/             # vendored ImGuiFileDialog
```

Mimari ayrıntılar için [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), bilinen sorunlar için [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) dosyalarına bakın.

## Lisans

GPL-3.0 — bkz. [LICENSE](LICENSE). Vendored bileşenler (Dear ImGui, stb, ImGuiFileDialog) kendi lisansları altındadır.
