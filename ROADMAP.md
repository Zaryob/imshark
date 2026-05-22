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

## v0.5 — Analiz özellikleri

Hedef: ilk gerçek "Wireshark alternatifi" değeri.

- [ ] **Görüntüleme filtresi** (ör. `ip.addr == 10.0.0.1 && tcp.port == 443`): ifade ayrıştırıcı + alan kaydı — **L**
- [ ] Arama (metin / hex / regex, paket listesi ve bayt içinde), zaman referansı işaretleme — **M**
- [ ] Renklendirme kuralları (TCP RST, ICMP hata, DNS hata vb.) — **S**
- [ ] Konuşmalar/uç noktalar tablosu ve temel istatistikler (protokol hiyerarşisi, paket/bayt sayıları) — **M**
- [ ] **Follow TCP/UDP stream** ve TCP yeniden birleştirme (reassembly), yeniden iletim/dup-ACK işaretleme — **L**
- [ ] IPv4 parçalanma birleştirme (#11) — **M**
- [ ] Yeni dissector'lar: HTTP/1.x, TLS (handshake/SNI), DNS tam (CNAME/MX/TXT/PTR, sıkıştırma), DHCP seçenekleri, NTP, mDNS, ICMP tam, QUIC başlığı (#15) — **L**
- [ ] Zaman görünümü seçenekleri (göreli / mutlak / önceki paketten beri) — **S**

## v0.6 — Dışa aktarım ve canlı yakalama

- [ ] Seçili/filtreli paketleri pcap/pcapng olarak kaydet; CSV/JSON dışa aktarım — **M**
- [ ] pcapng yorumları (comment option) ve IDB/ISB/NRB bilgilerini arayüzde gösterme — **S**
- [ ] Canlı yakalama (libpcap/Npcap): arayüz seçimi, BPF yakalama filtresi, başlat/durdur — **L**
- [ ] Sıkıştırılmış girdiler (`.pcap.gz`) — **S**

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
