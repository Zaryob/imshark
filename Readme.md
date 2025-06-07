# ImShark

ImShark, [Dear ImGui](https://github.com/ocornut/imgui) ile yazılmış, Wireshark'tan esinlenen hafif bir **offline paket analizörüdür**. `.pcap` ve `.pcapng` dosyalarını açar; paketleri liste halinde, katman katman ayrıştırılmış ayrıntılarla ve etkileşimli bir hex/ASCII görünümüyle gösterir.

> Durum: erken aşama (prototip). Yalnızca dosyadan okuma yapar; canlı yakalama, filtreleme ve akış analizi henüz yoktur. Bkz. [ROADMAP.md](ROADMAP.md).

## Özellikler (bugün)

- `.pcap` (little/big-endian, mikro/nano-saniye) ve `.pcapng` (SHB/IDB/EPB/SPB, `if_tsresol`) desteği; dosya türü magic number ile otomatik algılanır
- Ethernet II üzerinde: ARP/RARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP
- Uygulama katmanı özetleri: DNS (A/AAAA/SOA), DHCP, SNMP (yalnızca uzunluk), Telnet, SMTP, BGP (mesaj türü) — port numarasına göre tahmin edilir
- TCP için bağıl (relative) seq/ack numaraları
- Paket listesi (No, Time, Source, Destination, Protocol, Length, Info), çoklu seçim
- Genişletilebilir protokol ağacı (Frame, Ethernet/VLAN, IP, ARP, ICMP, TCP/UDP, DNS, DHCP…); bir alan seçilince hex/ASCII panelinde ilgili baytlar vurgulanır, hex'te bir bayta tıklayınca o bayta ait en özel alan ağaçta açılır
- Link type desteği: Ethernet (802.1Q/QinQ), NULL/Loopback, Raw IP, Linux SLL/SLL2
- Bozuk/kırpık dosya ve paketlerde çökmez: `[Malformed Packet]` işaretler, yükleme sorunlarını durum çubuğunda gösterir
- Büyük dosyalar: arka planda yükleme (ilerleme çubuğu, iptal), paket başına ~0,5 KB bellek (500 bin paket ≈ 265 MB); ham bayt ve alan ağacı yalnızca seçilen paket için dosyadan okunur
- **Görüntüleme filtresi** (Wireshark benzeri): `tcp.port in {80 443} && !tcp.flags.rst`, `ip.addr == 10.0.0.0/8`, `info contains "GET"`, `frame.time_delta > 1` … Yazarken doğrulanır (hata konumuyla), geçmişi tutulur, `?` düğmesi alan listesini açar; 500 bin pakette 8–18 ms
- Paket bulma (Ctrl+F, F3), renklendirme kuralları (düzenlenebilir), zaman görünümü (başlangıca göre / önceki paketten / UTC / epoch)
- Sütuna göre sıralama, klavyeyle gezinme (↑ ↓ PgUp PgDn Home End), kopyalama menüleri (alan, bayt hex/ASCII, hex dump, satır)
- Son açılan dosyalar, sürükle-bırak ile açma, koyu/açık tema; ayarlar kullanıcı yapılandırma klasöründe saklanır
- Dosya açma penceresi (ImGuiFileDialog), Ctrl+O / Ctrl+W

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

Windows (MSVC): vcpkg yolu kullanılır — `cmake --preset vcpkg` ardından `cmake --build --preset vcpkg --config Release`. Çekirdek hiçbir POSIX/Winsock başlığına bağımlı değildir (bayt sırası ve IP adres biçimlendirme `core/src/network/byteorder.h` içindedir). **Not:** Windows derlemesi bu depoda henüz bir Windows makinesinde denenmedi; CI işi eklendi ama ilk çalıştırmada düzeltme gerekebilir.

## Test

```bash
cmake -S . -B build -DIMSHARK_SANITIZE=ON     # ASan + UBSan (isteğe bağlı)
cmake --build build
ctest --test-dir build --output-on-failure
```

Testler GoogleTest ile yazılmıştır (`brew install googletest` / `apt install libgtest-dev`; vcpkg'de `tests` özelliği varsayılan açıktır). Ayrıştırıcı/okuyucu için birim ve mutasyon-fuzz testleri, arayüz için ise pencere açmadan çalışan ImGui duman testleri içerir. GoogleTest yoksa testler uyarıyla atlanır; `-DIMSHARK_BUILD_TESTS=OFF` ile kapatılabilir.

## Dizin yapısı

```
imshark/
├── CMakeLists.txt, CMakePresets.json, vcpkg.json
├── src/
│   ├── main.cpp            # GLFW/OpenGL penceresi ve ana döngü
│   └── ui/                 # `imshark_ui`: AppState, yükleme işi, menü/durum çubuğu, paket listesi, ayrıntı ağacı, hex görünümü, ayarlar, kopyalama
├── core/src/               # `imshark_core` (UI bağımsız statik kütüphane)
│   ├── core.{h,cpp}        #   FileProcessor: pcap / pcapng okuyucular
│   ├── packet_parser.cpp   #   link katmanı, dissector'lara devretme
│   ├── dissect/            #   dissector'lar (ip, arp, icmp, tcp, udp, dns, dhcp…) ve Registry
│   ├── tcp_connection.cpp  #   TCP bağıl seq/ack takibi
│   ├── packet/             #   PacketInfo, Field, PacketParser
│   └── network/            #   başlık yapıları, byteorder.h (taşınabilir ntoh/inet_ntop), yardımcılar
├── third_party/            # Dear ImGui 1.91.1 (+ GLFW/OpenGL3 backend), ImGuiFileDialog
├── tests/                  # GoogleTest testleri ve tests/data/sample.pcap
├── tools/make_sample_pcap.py
└── .github/workflows/ci.yml
```

Mimari ayrıntılar için [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), bilinen sorunlar için [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) dosyalarına bakın.

## Lisans

GPL-3.0 — bkz. [LICENSE](LICENSE). Vendored bileşenler (Dear ImGui, stb, ImGuiFileDialog) kendi lisansları altındadır.
