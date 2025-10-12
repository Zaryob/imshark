# ImShark

ImShark, [Dear ImGui](https://github.com/ocornut/imgui) ile yazılmış, Wireshark'tan esinlenen hafif bir **offline paket analizörüdür**. `.pcap` ve `.pcapng` dosyalarını açar; paketleri liste halinde, katman katman ayrıştırılmış ayrıntılarla ve etkileşimli bir hex/ASCII görünümüyle gösterir.

> Durum: offline analiz özellikleri tamamlandı (filtreleme, akış analizi, protokol çözümleyiciler, dışa aktarma); canlı yakalama henüz yok. Bkz. [ROADMAP.md](ROADMAP.md).

## Özellikler (bugün)

- `.pcap` (little/big-endian, mikro/nano-saniye) ve `.pcapng` (SHB/IDB/EPB/SPB/ISB/NRB, `if_tsresol`, paket yorumları) desteği, **gzip sıkıştırılmış** (`.gz`) dosyalar dahil; dosya türü magic number ile otomatik algılanır
- Protokoller: Ethernet/VLAN, ARP, IPv4/IPv6 (parça birleştirme, uzantı başlığı seçenekleri), ICMP/ICMPv6 (hata gövdeleri, neighbor discovery, MLD), TCP (analiz, SACK, Multipath TCP seçenekleri), UDP, **DNS** (tüm bölümler; DNSSEC, EDNS, SVCB/HTTPS; TCP üzerinden, mDNS), **DHCP** (seçenekler, option overload), **NTP** (zaman, control ve private mesajları, kimlik doğrulama), **HTTP/1.x** (Content-Length/chunked/gzip gövde), **TLS** (kayıt ve el sıkışma birleştirme, hello eklentileri, sertifika konu/veren/geçerlilik/SAN), **SNMP** (v1/v2c/v3, USM, varbind'ler, MIB adları), **BGP** (OPEN yetenekleri, UPDATE yol öznitelikleri/NLRI, NOTIFICATION, akış birleştirme), **Telnet** (IAC komutları, seçenek müzakeresi, SB/NAWS/Terminal-Type), **SMTP** (komut/yanıt ayrımı, çok satırlı yanıtlar, adresler, başlıklar ve STARTTLS), **FTP / FTP-DATA** (komut/yanıt, PASV/EPSV/PORT veri bağlantısı dinamik port takibi), **TFTP** (RRQ/WRQ/DATA/ACK/ERROR/OACK ve UDP TID dinamik oturum takibi), **SSH** (banner, KEXINIT açık algoritmaları, anahtar değişimi, şifreli paket tespiti). HTTP, TLS ve standart dışı portlardaki DNS içerikten tanınır; **Analyze > Decode As** bir portu seçilen protokole bağlar
- **TCP mesaj birleştirme:** birden çok segmente yayılan HTTP/TLS/DNS mesajları tek mesaj olarak çözülür (sıra dışı, yeniden iletilen, kayıp segmentlerle); önceki segmentler `[Reassembled in #N]` ile işaretlenir. **Checksum doğrulaması** (IPv4/TCP/UDP/ICMP/ICMPv6): hatalılar ile offload/kesilme nedeniyle doğrulanamayanlar Expert Information'da ayrılır
- TCP için bağıl (relative) seq/ack numaraları
- Paket listesi (No, Time, Source, Destination, Protocol, Length, Info), çoklu seçim
- Genişletilebilir protokol ağacı (Frame, Ethernet/VLAN, IP, ARP, ICMP, TCP/UDP, DNS, DHCP…); bir alan seçilince hex/ASCII panelinde ilgili baytlar vurgulanır, hex'te bir bayta tıklayınca o bayta ait en özel alan ağaçta açılır
- Link type desteği: Ethernet (802.1Q/QinQ), NULL/Loopback, Raw IP, Linux SLL/SLL2
- Bozuk/kırpık dosya ve paketlerde çökmez: `[Malformed Packet]` işaretler, yükleme sorunlarını durum çubuğunda gösterir
- Büyük dosyalar: arka planda yükleme (ilerleme çubuğu, iptal); pakette yalnızca özet tutulur (500 bin paket ≈ 190 MB, yükleme < 1 sn), ham bayt ve alan ağacı yalnızca seçilen paket için dosyadan okunur
- **Görüntüleme filtresi** (Wireshark benzeri): `tcp.port in {80 443} && !tcp.flags.rst`, `ip.addr == 10.0.0.0/8`, `info contains "GET"`, `frame.time_delta > 1` … Yazarken doğrulanır (hata konumuyla), geçmişi tutulur, `?` düğmesi alan listesini açar; 500 bin pakette 8–18 ms
- **Akış analizi:** Statistics menüsünde Protocol Hierarchy, Conversations (IPv4/IPv6/TCP/UDP), Endpoints, Expert Information; satıra çift tıklayınca filtre uygulanır. TCP analizi (yeniden iletim, dup-ACK, sıra dışı, kayıp segment, sıfır pencere…) Info sütununda ve `tcp.analysis.*` filtre alanlarında. **Follow TCP/UDP Stream** (Analyze menüsü) yeniden birleştirilmiş veriyi iki yönü renkli gösterir. IPv4 ve IPv6 parçalanmış datagramlar birleştirilir (RFC 5722 çakışma kuralı, 60 sn zaman aşımı) ve Follow Stream'e katkıda bulunur.
- Paket bulma (Ctrl+F, F3; özet metni, filtre, **hex bayt** ve **baytlarda metin** aramaları), renklendirme kuralları (düzenlenebilir), zaman görünümü (başlangıca göre / önceki paketten / UTC / epoch)
- Sütuna göre sıralama, klavyeyle gezinme (↑ ↓ PgUp PgDn Home End), kopyalama menüleri (alan, bayt hex/ASCII, hex dump, satır)
- **Dışa aktarma:** File > Export Packets (tümü / görüntülenen / seçili → pcapng, pcap, CSV, JSON), Follow Stream'de ham bayt olarak kaydetme; File > Capture File Properties (arayüzler, istatistikler, yorumlar, ad çözümleme)
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

**Regresyon corpus'u:** `tests/corpus/` küçük sentetik sınır durumlarını (FCS, eski Packet Block, zaman ofseti, tanımsız arayüz, IPv4/IPv6 parçaları, QinQ…) ve `manifest.json` içinde tarif edilen gerçek Wireshark örnek yakalamalarını (URL + SHA-256 + beklenen sonuç) içerir. Sentetik dosyalar `python3 tools/make_corpus.py` ile deterministik üretilir. Gerçek yakalamalar depoya konmaz; bir dizine indirip `IMSHARK_CORPUS_DIR=/dizin ctest …` ile çalıştırırsanız doğrulanır, yoksa atlanır (CI de indirmez).

**Kapsama:** `tools/coverage.sh` (clang kaynak tabanlı kapsama; `--html` ile HTML rapor) birim testlerinin dosya bazında kapsamını verir. Şu an çekirdek ve UI birlikte satır kapsamı ≈ %92, dal kapsamı ≈ %79; en zayıf yerler menü/pencere etkileşimleri (`chrome.cpp`, `details.cpp`).

`-DIMSHARK_SANITIZE=ON` çekirdek dahil tüm hedefleri ASan+UBSan ile derler (yapılandırma, çekirdek instrument edilmeden kalırsa hata verir).

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
│   ├── dissect/            #   dissector'lar (ip, arp, icmp, tcp, udp, dns, dhcp, ntp, http, tls…) ve Registry
│   ├── filter/ stats/ stream/ export/   # görüntüleme filtresi, istatistikler, Follow Stream, dışa aktarım
│   ├── gzip.cpp, capture_reader.cpp     # gzip çözücü, çerçeve okuma/tarama
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
