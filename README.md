# ImShark

ImShark, [Dear ImGui](https://github.com/ocornut/imgui) ile yazılmış, Wireshark'tan esinlenen hafif bir **offline paket analizörüdür**. `.pcap` ve `.pcapng` dosyalarını açar; paketleri liste halinde, katman katman ayrıştırılmış ayrıntılarla ve etkileşimli bir hex/ASCII görünümüyle gösterir.

> Durum: offline analiz özellikleri tamamlandı (filtreleme, akış analizi, protokol çözümleyiciler, dışa aktarma, libpcap ile canlı yakalama). Bkz. [ROADMAP.md](ROADMAP.md).

## Özellikler (bugün)

- `.pcap` (little/big-endian, mikro/nano-saniye) ve `.pcapng` (SHB/IDB/EPB/SPB/ISB/NRB, `if_tsresol`, paket yorumları) desteği, **gzip sıkıştırılmış** (`.gz`) dosyalar dahil; dosya türü magic number ile otomatik algılanır
- Protokoller: Ethernet/VLAN, ARP, IPv4/IPv6 (parça birleştirme, uzantı başlığı seçenekleri), ICMP/ICMPv6 (hata gövdeleri, neighbor discovery, MLD), TCP (analiz, SACK, Multipath TCP seçenekleri), UDP, **DNS** (tüm bölümler; DNSSEC, EDNS, SVCB/HTTPS; TCP üzerinden, mDNS), **DHCP** (seçenekler, option overload), **NTP** (zaman, control ve private mesajları, kimlik doğrulama), **HTTP/1.x** (Content-Length/chunked/gzip gövde), **HTTP/2** (açık metin bağlantı önsözü, 9 baytlık çerçeve başlığı, DATA/HEADERS/SETTINGS/PING/GOAWAY vb. çerçeveler ve HPACK RFC 7541 başlık çözücü), **TLS** (kayıt ve el sıkışma birleştirme, hello eklentileri, sertifika konu/veren/geçerlilik/SAN; `SSLKEYLOGFILE` ve pcapng Decryption Secrets Block anahtar malzemesi okunur, bağlantı başına random/sürüm/şifre takımı/kayıt indeksi eşlenir ve ayrıntı ağacı anahtar durumunu gösterir; **TLS şifre çözme**: TLS 1.2/1.3 × AES-128/256-GCM ve ChaCha20-Poly1305 (OpenSSL 3 ile, `core/src/tls/`) anahtar günlüğüyle yükleme sırasında çözülür; çözülen veri ayrıntı ağacında "Decrypted TLS (N bytes)" katmanı olarak ve ALPN `h2` ise HTTP/2, aksi halde HTTP/1.x olarak ayrıştırılır, Protocol/Info sütunları ve protokol hiyerarşisi TLS → HTTP gösterir; doğru anahtar / yanlış anahtar (etiket hatası, düz metin yok) / eksik anahtar / desteklenmeyen takım / eksik TCP verisi / durum kaybı ayrı ayrı bildirilir; filtre alanları `tls.decrypted`, `tls.decryption_status`), **DTLS** (UDP üzerinde RFC 6347 kaydı: içerikten tanıma ve 4433/5684 portları, epoch ve 48 bit sıra no, birden çok kayıt; el sıkışma parçaları datagramlar arasında birleştirilir ve `[Reassembled in #N]` ile işaretlenir; HelloVerifyRequest ve cookie, ClientHello/ServerHello/Certificate TLS ile aynı ayrıştırıcılarla; **DTLS 1.2 AES-128/256-GCM** `SSLKEYLOGFILE` `CLIENT_RANDOM` satırıyla çözülür, doğru/yanlış/eksik anahtar ayrılır; DTLS 1.3 yalnızca tanınır; filtre alanları `dtls.*`), **SNMP** (v1/v2c/v3, USM, varbind'ler, MIB adları), **BGP** (OPEN yetenekleri, UPDATE yol öznitelikleri/NLRI, NOTIFICATION, akış birleştirme), **Telnet** (IAC komutları, seçenek müzakeresi, SB/NAWS/Terminal-Type), **SMTP** (komut/yanıt ayrımı, çok satırlı yanıtlar, adresler, başlıklar ve STARTTLS), **FTP / FTP-DATA** (komut/yanıt, PASV/EPSV/PORT veri bağlantısı dinamik port takibi), **TFTP** (RRQ/WRQ/DATA/ACK/ERROR/OACK ve UDP TID dinamik oturum takibi), **SSH** (banner, KEXINIT açık algoritmaları, anahtar değişimi, şifreli paket tespiti), **EAPOL / 802.1X** (EAPOL-Key, WPA/WPA2 4 yönlü el sıkışması, EAP Request/Response/Identity), **STP / RSTP / MSTP** (Config, RSTP, TCN BPDU'ları, root/bridge ID, cost, flags, port). **PPP / PPPoE** (Discovery ve Session, LCP, IPCP), **MPLS** (etiket yığını: label/TC/S/TTL, IPv4/IPv6 iç yükü), **IP-in-IP** (IPv4/IPv6) ve **GRE** (checksum/key/sequence, **ERSPAN** Type II/III dahil; iç IP adresleri ve protokoller görünür), **LLDP** (TLV'ler), **LACP** ve **Ethernet MAC Control** (PAUSE, Priority Flow Control). HTTP, TLS, HTTP/2 ve standart dışı portlardaki DNS içerikten tanınır; **Analyze > Decode As** bir portu seçilen protokole bağlar
- **Ağ, kurumsal, veritabanı ve düşük seviye protokoller (v1.1–v1.9):** IGMP (v1/v2/v3, v3 grup kayıtları ve kaynak listeleri), OSPFv2/v3 (Hello, Database Description, LSR, LSU, LSAck, LSA gövdeleri, v2 kimlik doğrulama alanları, paket checksum'u ve LSA Fletcher sağlaması), SCTP (IP ve UDP 9899; CRC-32C, INIT/SACK/HEARTBEAT/ABORT/ERROR/SHUTDOWN/COOKIE/FORWARD-TSN gövdeleri ve parametreleri, DATA/I-DATA parça birleştirme, çoklu akış), UDP-Lite, IPsec AH (IPv4/IPv6, korunan protokol çözülür) / ESP (ESP-NULL sezgisi isteğe bağlı, varsayılan kapalı; aksi halde içerik şifreli diye etiketlenir) ve IKEv1/IKEv2 (SA önerileri, KE, ID, CERT, AUTH, Notify, TS vb. yük içerikleri; SK/SKF ve şifreli IKEv1 gövdeleri etiketlenir, IKEv2 parçaları numaralanır ama birleştirilemez), LDAP, Kerberos, SMB2/3 (SPNEGO/NTLMSSP/Kerberos oturum açma, ağaç → paylaşım ve dosya kimliği → ad eşleme, istek/yanıt eşleme, named pipe işareti; şifreli SMB3 içeriği yorumlanmaz), DCE/RPC (bağlantı yönelimli ve bağlantısız PDU'lar, parça birleştirme, kimlik doğrulama doğrulayıcısı etiketi, SMB named pipe taşıması, endpoint mapper yanıtlarından dinamik port tablosu), ONC RPC/NFS, PostgreSQL, MySQL, TDS (SQL Server; Login7 parolası maskelenir), USB (Linux usbmon ve USBPcap), Bluetooth HCI/L2CAP/ATT ve IEEE 802.15.4, SIP/SDP, RTP/RTCP (yalnızca Decode As), RTSP, Modbus/TCP, DNP3 ve SocketCAN. Çözülen alanlar ve **sınırlar** (ör. SCTP payload protocol ID iç ayrıştırıcıya verilmez, OSPF'te opak LSA gövdeleri çözülmez, DNP3 CRC-16 (bağlantı başlığı ve veri blokları) doğrulanır, SIP/RTP/Modbus/CAN için süzgeç alanı yok, DNP3 için yalnızca CRC durum alanları var) `docs/SUPPORT_MATRIX.md`, `docs/PROTOCOLS.md` ve `docs/KNOWN_ISSUES.md` dosyalarındadır. Dosya okuyucuları ortak bir `CaptureFileReader` arayüzünün ve sihirli sayıyla seçen bir kayıt defterinin arkasındadır (pcap, pcapng, Sun snoop, Microsoft Network Monitor 2.x (.cap), Endace ERF ve AIX iptrace 2.0; gzip kayıt defterinde sarmalayıcı olarak tanınır). Ortamı çözülemeyen çerçeveler (Token Ring, FDDI, ATM, ...) 'Unsupported link type' olarak, baytlarıyla listelenir. snoop, NetMon, ERF ve iptrace dosyaları gerçek bir yakalamayla karşılaştırılmadı (iptrace düzeni belgelenmiş alt kümedir, bkz. `docs/KNOWN_ISSUES.md`). Bu protokollerin gerçek yakalama örnekleri yoktur; testler elle kurulmuş mesajlar ve kesme/bayt bozma taramalarıdır.
- **TCP mesaj birleştirme:** birden çok segmente yayılan HTTP/TLS/DNS mesajları tek mesaj olarak çözülür (sıra dışı, yeniden iletilen, kayıp segmentlerle); önceki segmentler `[Reassembled in #N]` ile işaretlenir. **Checksum doğrulaması** (IPv4/TCP/UDP/ICMP/ICMPv6): hatalılar ile offload/kesilme nedeniyle doğrulanamayanlar Expert Information'da ayrılır
- TCP için bağıl (relative) seq/ack numaraları
- Paket listesi (No, Time, Source, Destination, Protocol, Length, Info), çoklu seçim
- Genişletilebilir protokol ağacı (Frame, Ethernet/VLAN, IP, ARP, ICMP, TCP/UDP, DNS, DHCP…); bir alan seçilince hex/ASCII panelinde ilgili baytlar vurgulanır, hex'te bir bayta tıklayınca o bayta ait en özel alan ağaçta açılır
- Link type desteği: Ethernet (802.1Q/QinQ, IEEE 802.3 ve IEEE 802.2 LLC/SNAP ayrımı), NULL/Loopback, Raw IP, Linux SLL/SLL2, IEEE 802.11 kablosuz çerçeveleri (Yönetim, Kontrol, Korumalı veri ve LLC/SNAP ile IP/TCP/HTTP iç katmanlarına yönlendirme), Radiotap (127) ve PPI (192)
- Bozuk/kırpık dosya ve paketlerde çökmez: `[Malformed Packet]` işaretler, yükleme sorunlarını durum çubuğunda gösterir
- Büyük dosyalar: arka planda yükleme (ilerleme çubuğu, iptal); pakette yalnızca özet tutulur, ham bayt ve alan ağacı yalnızca seçilen paket için dosyadan okunur. Ölçüm (Apple M4, 16 GiB, Release, sentetik yakalamalar; yöntem ve ham çıktılar ROADMAP.md v1.0): 500 bin paketlik DNS yakalaması ≈ 0,7 sn ve ≈ 185 MB, 500 bin paketlik karışık (TCP/UDP/DNS, çok akışlı) yakalama ≈ 0,9 sn ve ≈ 266 MB, ≈ 1 GB'lık karışık yakalama (1,74 milyon paket) ≈ 3 sn ve ≈ 890 MB tepe bellek. Gerçek trafikte süre ve bellek farklı olabilir
- **Görüntüleme filtresi** (Wireshark benzeri): `tcp.port in {80 443} && !tcp.flags.rst`, `ip.addr == 10.0.0.0/8`, `info contains "GET"`, `frame.time_delta > 1` … Yazarken doğrulanır (hata konumuyla), geçmişi tutulur, `?` düğmesi alan listesini açar; 500 bin pakette tek süzgeç geçişi 13–20 ms (Apple M4, sentetik yakalamalar, ROADMAP.md v1.0)
- **Akış analizi:** Statistics menüsünde Protocol Hierarchy, Conversations (IPv4/IPv6/TCP/UDP/SCTP, Ethernet MAC, WLAN, Bluetooth, USB aygıt ve USB uç nokta), Endpoints, Expert Information; satıra çift tıklayınca filtre uygulanır. TCP analizi (yeniden iletim, dup-ACK, sıra dışı, kayıp segment, sıfır pencere…) Info sütununda ve `tcp.analysis.*` filtre alanlarında. **Follow TCP/UDP Stream** (Analyze menüsü) yeniden birleştirilmiş veriyi iki yönü renkli gösterir; TCP akışında **"TLS (decrypted)"** seçimi TLS uygulama verisini çözülmüş olarak gösterir. IPv4 ve IPv6 parçalanmış datagramlar birleştirilir (RFC 5722 çakışma kuralı, 60 sn zaman aşımı) ve Follow Stream'e katkıda bulunur.
- Paket bulma (Ctrl+F, F3; özet metni, filtre, **hex bayt** ve **baytlarda metin** aramaları), renklendirme kuralları (düzenlenebilir), zaman görünümü (başlangıca göre / önceki paketten / UTC / epoch)
- Sütuna göre sıralama, klavyeyle gezinme (↑ ↓ PgUp PgDn Home End), kopyalama menüleri (alan, bayt hex/ASCII, hex dump, satır)
- **TLS anahtar günlüğü:** **Edit > Preferences...** penceresinde `SSLKEYLOGFILE` dosyasının yolu (dosya seçici ile) ayarlanır; ayar kaydedilir, değişince açık yakalama yeni anahtarlarla yeniden yüklenir, okunamayan dosya açık bir iletiyle bildirilir, bozuk satırlar sayılır ve atlanır. pcapng dosyalarındaki Decryption Secrets Block anahtarları otomatik kullanılır (kullanıcının dosyası öncelikli). Destek matrisi ve sınırlar için bkz. [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).
- **Dışa aktarma:** File > Export Packets (tümü / görüntülenen / seçili → pcapng, pcap, CSV, JSON), Follow Stream'de ham bayt olarak kaydetme; File > Capture File Properties (arayüzler, istatistikler, yorumlar, ad çözümleme)
- **Canlı yakalama** (libpcap / Windows'ta Npcap): **Capture > Interfaces…** arayüzleri (ad, açıklama, adresler, bayraklar) listeler; yazarken doğrulanan BPF yakalama filtresi, snaplen ve promiscuous seçenekleri; Start/Stop (Ctrl+E), Restart (Ctrl+R), Interfaces (Ctrl+K). Yakalama sürerken paket listesi her karede sınırlı iş yapılarak büyür (otomatik kaydırma menüden açılıp kapanır), görüntüleme filtresi ve renklendirme yeni paketlere uygulanır, durum çubuğu "Capturing on en0 - N packets, D dropped" gösterir, seçilen paketin ayrıntısı geçici dosyadan okunur. Durdurulunca yakalama açılmış dosya gibi davranır (dışa aktarma, istatistikler, Follow Stream); kaydedilmemiş yakalama kapatılırken/çıkılırken dışa aktarma ya da silme sorulur ve geçici dosya silinince kaldırılır. Son arayüz, filtre, snaplen ve promiscuous seçimi ayar dosyasında saklanır. Yakalama olmadan derlendiğinde menü pasif olur ve araç ipucu nedenini söyler. Ayrıcalık gerekir: macOS'ta `/dev/bpf*` erişimi (ChmodBPF ya da `sudo`), Linux'ta `CAP_NET_RAW` (`sudo setcap cap_net_raw,cap_net_admin=eip ./build/imshark` ya da root), Windows'ta Npcap kurulu olmalı
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

Windows (MSVC): vcpkg yolu kullanılır — `cmake --preset vcpkg` ardından `cmake --build --preset vcpkg --config Release`. Ayrıştırıcı hiçbir POSIX/Winsock başlığına bağımlı değildir (bayt sırası ve IP adres biçimlendirme `core/src/network/byteorder.h` içindedir); yalnızca isteğe bağlı canlı yakalama modülü (`core/src/capture/`) libpcap'e (Windows'ta Npcap SDK) bağlanır. **Not:** Windows derlemesi bu depoda henüz bir Windows makinesinde denenmedi; CI işi eklendi ama ilk çalıştırmada düzeltme gerekebilir.

## Test

```bash
cmake -S . -B build -DIMSHARK_SANITIZE=ON     # ASan + UBSan (isteğe bağlı)
cmake --build build
ctest --test-dir build --output-on-failure
```

Canlı yakalama çekirdeği `-DIMSHARK_LIVE_CAPTURE=ON` (varsayılan) ile libpcap bulunursa derlenir (macOS SDK'sında hazırdır; Linux'ta `libpcap-dev`; Windows'ta `-DNPCAP_SDK_DIR=...`). Kütüphane yoksa ya da `OFF` verilirse aynı arayüz "Live capture is not available in this build" diyen bir taslakla derlenir. Gerçek arayüz yakalaması ayrıcalık ister (macOS `/dev/bpf*`, Linux `CAP_NET_RAW`, Windows'ta Npcap kurulumu ve SDK); testler bunu alamazsa ilgili testi atlar. Arayüz duman testleri yakalama oturumunu aygıtsız enjeksiyon dikişiyle sürer.

TLS şifre çözme çekirdeği `-DIMSHARK_TLS_DECRYPT=ON` (varsayılan) ile OpenSSL 3 (libcrypto) bulunursa derlenir (macOS'ta `brew install openssl@3`, `/opt/homebrew/opt/openssl@3` otomatik denenir; Linux'ta `libssl-dev`; başka bir yer için `-DOPENSSL_ROOT_DIR=...`). OpenSSL yoksa ya da `OFF` verilirse aynı arayüz "TLS decryption is not available in this build" diyen bir taslakla derlenir (CI Windows'ta kapalıdır). **Lisans ve paketleme:** OpenSSL 3 Apache-2.0 lisanslıdır, GPL-3.0 ile uyumludur; varsayılan olarak dinamik bağlanır, yani dağıttığınız paket libcrypto'ya bağımlı olur (kendi paketinizde OpenSSL'i birlikte dağıtırsanız Apache-2.0 bildirimini ve lisans metnini ekleyin). `OFF` derleme OpenSSL gerektirmez.

Testler GoogleTest ile yazılmıştır (`brew install googletest` / `apt install libgtest-dev`; vcpkg'de `tests` özelliği varsayılan açıktır). Ayrıştırıcı/okuyucu için birim ve mutasyon-fuzz testleri, arayüz için ise pencere açmadan çalışan ImGui duman testleri içerir. GoogleTest yoksa testler uyarıyla atlanır; `-DIMSHARK_BUILD_TESTS=OFF` ile kapatılabilir.

**Regresyon corpus'u:** `tests/corpus/` küçük sentetik sınır durumlarını (FCS, eski Packet Block, zaman ofseti, tanımsız arayüz, IPv4/IPv6 parçaları, QinQ…) ve `manifest.json` içinde tarif edilen gerçek Wireshark örnek yakalamalarını (URL + SHA-256 + beklenen sonuç) içerir. Sentetik dosyalar `python3 tools/make_corpus.py` ile deterministik üretilir. Gerçek yakalamalar depoya konmaz; bir dizine indirip `IMSHARK_CORPUS_DIR=/dizin ctest …` ile çalıştırırsanız doğrulanır, yoksa atlanır (CI de indirmez).

**Kapsama:** `tools/coverage.sh` (clang kaynak tabanlı kapsama; `--html` ile HTML rapor) birim testlerinin dosya bazında kapsamını verir. Şu an çekirdek ve UI birlikte satır kapsamı ≈ %92, dal kapsamı ≈ %79; en zayıf yerler menü/pencere etkileşimleri (`chrome.cpp`, `details.cpp`).

**Performans ölçümü:** `python3 tools/benchmark.py` (Release derleme, `-DIMSHARK_BUILD_BENCH=ON` ile `bench_driver` hedefi) sentetik bir yakalamayı geçici dizinde üretir, uygulamanın yükleyicisinin çağırdığı `processFile` ile yükler, bir süzgeç geçişi çalıştırır, süreleri ve tepe RSS'i yazar ve yakalamayı siler (`--profile mixed --size-mb 1024` ≈ 1 GB'lık dosya). Yakalama dosyaları depoya konmaz.

`-DIMSHARK_SANITIZE=ON` çekirdek dahil tüm hedefleri ASan+UBSan ile derler (yapılandırma, çekirdek instrument edilmeden kalırsa hata verir).

## Dizin yapısı

```
imshark/
├── CMakeLists.txt, CMakePresets.json, vcpkg.json
├── src/
│   ├── main.cpp            # GLFW/OpenGL penceresi ve ana döngü
│   └── ui/                 # `imshark_ui`: AppState, yükleme işi, menü/durum çubuğu, paket listesi, ayrıntı ağacı, hex görünümü, ayarlar, kopyalama
├── core/src/               # `imshark_core` (UI bağımsız statik kütüphane)
│   ├── core.{h,cpp}        #   FileProcessor: tüm biçimler için ortak yükleme sürücüsü
│   ├── io/                 #   CaptureFileReader arayüzü, biçim kayıt defteri, pcap / pcapng okuyucuları
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

Kullanım için [docs/USER_GUIDE.md](docs/USER_GUIDE.md) (süzgeç alanları: [docs/FILTER_FIELDS.md](docs/FILTER_FIELDS.md)), dissector yazmak için [docs/DISSECTORS.md](docs/DISSECTORS.md); mimari ayrıntılar için [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), bilinen sorunlar için [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) dosyalarına bakın.

## Lisans

GPL-3.0 — bkz. [LICENSE](LICENSE). Vendored bileşenler (Dear ImGui, stb, ImGuiFileDialog) kendi lisansları altındadır.
