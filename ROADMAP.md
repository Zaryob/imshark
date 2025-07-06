# ImShark Yol Haritası

Öncelik sırası: önce **güvenilirlik ve doğruluk**, sonra **mimari**, sonra **özellikler**. Bir analizör yanlış veri gösteriyorsa ya da bozuk dosyada çöküyorsa ek özelliğin değeri yoktur. Ayrıntılı bulgular: [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) (numaralar `#N` ile referanslanır).

Boyut tahminleri: **S** ≈ 1–2 gün, **M** ≈ 3–7 gün, **L** ≈ 1–3 hafta.

## v0.2 — Sağlamlaştırma (stabil temel) ✅ tamamlandı

Hedef: hiçbir girdi dosyası uygulamayı çökertmesin, gösterilen veri doğru olsun.

- [x] Ayrıştırıcıda tüm okumalar `span` + sınır denetimli; kısa/bozuk pakette "Malformed" işareti (#1, #2, #5, #6) — **M**
- [x] Dosya okuyucuda girdi doğrulama: `incl_len`/`block_total_length` üst sınırı, `read` sonuç kontrolü, `exit()` kaldırma, hata bilgisini UI'ya döndürme (#3, #4, #3b, #24) — **M**
- [x] pcap: byte-swapped ve nanosaniye magic desteği; pcapng: SHB byte-order, `if_tsresol`, EPB `captured_length` + padding, SPB ayrıştırma (#7, #9, #10) — **M**
- [x] Link type desteği: Ethernet, Linux SLL/SLL2, Null/Loopback, Raw IP; VLAN (802.1Q/QinQ) (#8) — **M**
- [x] Başlık yapılarının düzeltilmesi: IPv4 flags/frag_off, IPv6 bit alanı ve uzantı başlıkları, TCP seçenekleri ve tüm bayraklar (#11, #12) — **M**
- [x] `utils.h` inline/include düzeni, `<variant>` vb. eksik include'lar, tanımsız değişkenler (#14 başlatılmamış seq/ack, #18, #19) — **S**
- [x] TCP takibi: anahtar olarak `ConnectionID` (hash değil), doğru hash birleştirme, yön normalizasyonu (#14) — **S**
- [x] Hata ayıklama `std::cout` çıktılarının kaldırılması, göreli zaman düzeltmesi, pencere başlığı (#9, #16, #23) — **S**
- [x] Hata/başarı durumunu gösteren durum çubuğu ve hata diyaloğu — **S**

## v0.3 — Mimari ve test altyapısı ✅ tamamlandı

Hedef: çekirdek UI'dan bağımsız, test edilebilir; geliştirme güvenli ve hızlı.

- [x] `imshark_core`'dan ImGui/GLFW/ImGuiFileDialog'u ayır; UI bağımsız **statik** `libimshark` (io + dissect + model) (#22) — **M**
- [x] Dissector arayüzü + kayıt defteri (`dissect::Registry`: EtherType → IP protokolü → TCP/UDP portu); protokol başına tek dosya; özel registry ile genişletilebilir — **L**
- [x] `main.cpp`'yi böl (`main.cpp` + `src/ui/`), global durumu `AppState`'e taşı, hex görünümü kopyalarını kaldır (#21) — **M**
- [x] Test altyapısı (GoogleTest): birim testleri, bozuk/kırpık girdiler, mutasyon-fuzz, UI duman testleri. *(libFuzzer hedefi yapılmadı)* — **M**
- [x] CI (GitHub Actions): macOS + Linux derleme, test, `-Wall -Wextra`, ASan/UBSan — **S**
- [x] CMake: GLFW için vcpkg manifesti + presets, `file(GLOB)` yerine açık dosya listesi, `.clang-format` — **S**
- [x] Windows desteği: çekirdekte POSIX/Winsock bağımlılığı yok, UTF-8 yollar, MSVC ayarları, CI işi. *(Windows'ta henüz çalıştırılıp doğrulanmadı)* — **M**

## v0.4 — Performans ve kullanılabilirlik ✅ tamamlandı

Hedef: yüz binlerce paketlik dosyalar akıcı açılsın.

- [x] Arka plan iş parçacığında yükleme + ilerleme çubuğu + iptal — **M**
- [x] Yükleme sırasında yalnızca hafif özet tutulur; ham bayt dosyada kalır (`file_offset`) ve seçilen paketin bayt/alan ağacı isteğe bağlı dosyadan okunup yeniden kurulur. *(`mmap` yerine ofset + okuma kullanıldı; 500k paket: 1,7 GB → 265 MB)* — **L**
- [x] Paket tablosunda `ImGuiListClipper`, sütun sıralama ve yeniden boyutlandırma — **S**
- [x] Son açılan dosyalar, sürükle-bırak ile açma, ayarlar dosyası (tema, liste yüksekliği). *(Pencere boyutu/konumu ve ImGui yerleşimi kalıcı değil)* — **S**
- [x] Klavye: Ctrl+O/Ctrl+W, ↑/↓/PgUp/PgDn/Home/End ile paket gezinme; koyu/açık tema. *(Ctrl+F arama v0.5'te)* — **S**
- [x] Paket detay panelinde kopyala (hex, ASCII, alan değeri) — **S**

## v0.5 — Filtreleme ve arama ✅ tamamlandı

Hedef: büyük bir yakalamada aranan paketi hızla bulmak.

- [x] IP adreslerini ayrıştırma (IPv4/IPv6, CIDR) ve özet bilgileri genişletme: portlar, IP protokolü, TCP bayrakları, TTL — **S**
- [x] **Görüntüleme filtresi dili** (`ip.addr == 10.0.0.0/8 && tcp.port in {80 443}`): lexer, ayrıştırıcı, alan kaydı, değerlendirici — **L**
- [x] Filtre çubuğu (geçerli/hatalı gösterimi, "Displayed X of Y") — **S**
- [x] Renklendirme kuralları (varsayılanlar + düzenleme penceresi, ayarlarda kalıcı) — **S**
- [x] Paket bulma (Ctrl+F): metin ve görüntüleme filtresi, ileri/geri (F3). *(bayt/hex arama v0.6'da)* — **M**
- [x] Zaman görünümü (yakalama başlangıcına göre / önceki paketten beri / UTC) ve `frame.time_*` alanları — **S**

## v0.6 — Akış analizi ✅ tamamlandı

Hedef: paketlerden konuşmalara ve oturumlara çıkmak.

- [x] Yakalamayı baytlarıyla tarayan altyapı (`CaptureReader`, `scanPackets`; ilerleme + iptal) — **M**
- [x] Konuşmalar/uç noktalar tablosu ve protokol hiyerarşisi istatistikleri — **M**
- [x] TCP analizi: yeniden iletim, dup-ACK, sıra dışı, kayıp segment, sıfır pencere, keep-alive, pencere güncellemesi; Expert Information penceresi — **M**
- [x] **Follow TCP/UDP stream** ve TCP yeniden birleştirme (reassembly) — **L**
- [x] IPv4 parçalanma birleştirme (#11). *(IPv6 parçaları henüz yok)* — **M**
- [x] Bayt/hex arama (tarama altyapısı üzerinden) — **S**

## v0.7 — Protokoller ve dışa aktarım

- [ ] Yeni dissector'lar: HTTP/1.x, TLS (handshake/SNI), DNS tam (CNAME/MX/TXT/PTR), DHCP seçenekleri, NTP, mDNS, ICMP tam (#15) — **L**
- [ ] Seçili/filtreli paketleri pcap/pcapng olarak kaydet; CSV/JSON dışa aktarım — **M**
- [ ] pcapng yorumları (comment option) ve IDB/ISB/NRB bilgilerini arayüzde gösterme — **S**
- [ ] Sıkıştırılmış girdiler (`.pcap.gz`) — **S**

## v0.8 — Canlı yakalama

- [ ] Canlı yakalama (libpcap/Npcap): arayüz seçimi, BPF yakalama filtresi, başlat/durdur — **L**

## v1.0 — Yayın hazırlığı

- [ ] Dokümantasyon sitesi/kullanım kılavuzu ve ekran görüntüleri (`docs/`), katkı rehberi (`CONTRIBUTING.md`)
- [ ] Paketleme: macOS `.app`/dmg, Linux AppImage, Windows zip; sürüm etiketleme ve otomatik release
- [ ] Protokol dissector eklemek için geliştirici kılavuzu (`docs/DISSECTORS.md`)
- [ ] Performans referansı (ör. 1 GB pcap'i X saniyede açar, tepe bellek Y)

## Fikirler (kalıcı öncelik değil)

- Lua/WASM ile kullanıcı dissector'ları
- TLS anahtar günlüğü (SSLKEYLOGFILE) ile şifre çözme; pcapng DSB desteği
- Paket diff / iki yakalamayı karşılaştırma
- I/O grafiği ve akış/zaman dizisi görselleştirme
- Uzak yakalama (SSH/`tcpdump` üzerinden)

## Kapsam dışı (şimdilik)

Tam Wireshark eşdeğerliği, yüzlerce protokol, VoIP/RTP analizörleri ve 802.11 şifre çözme; proje önce küçük, hızlı ve güvenilir bir çekirdek olmayı hedefler.
