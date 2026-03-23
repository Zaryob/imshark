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

Gereksinimler: C++20 derleyici, CMake ≥ 3.21, OpenGL ve GLFW 3. İki yoldan biriyle derlenir.

### Seçenek 1 — vcpkg (önerilen, tüm platformlar)

[vcpkg](https://github.com/microsoft/vcpkg) kurulu ve `VCPKG_ROOT` tanımlıysa bağımlılıklar (`glfw3`) `vcpkg.json` manifestinden otomatik kurulur:

```bash
cmake --preset vcpkg
cmake --build --preset vcpkg
./build-vcpkg/imshark
```

### Seçenek 2 — sistem paketleri

```bash
# macOS
brew install glfw cmake
# Debian/Ubuntu
sudo apt install build-essential cmake pkg-config libglfw3-dev libgl1-mesa-dev
```

```bash
cmake --preset default
cmake --build --preset default
./build/imshark
```

GLFW, önce CMake paket yapılandırmasıyla (`find_package(glfw3)`), bulunamazsa `pkg-config` ile aranır.

### Kullanım

```bash
./build/imshark                    # File → Open ile dosya seçin
./build/imshark tests/data/sample.pcap   # dosyayı doğrudan açın
```

`python3 tools/make_sample_pcap.py` örnek yakalama dosyasını (`tests/data/sample.pcap`) yeniden üretir: ARP, ICMP, DNS, TCP (seçeneklerle), SMTP, IPv6, VLAN, bilinmeyen EtherType ve kırpık paket içerir.

Not: kod `<arpa/inet.h>` kullandığı için şu an yalnızca POSIX (macOS/Linux) hedeflidir (Windows, yol haritasında).

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
