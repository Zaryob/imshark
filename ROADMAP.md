# ImShark yol haritası

Öncelik sırası doğruluk, doğrulanabilirlik ve kullanılabilirliktir. Bu dosya henüz tamamlanmamış işleri tutar; mevcut özelliklerin referansı [destek matrisi](docs/SUPPORT_MATRIX.md), işlevsel sınırların referansı [bilinen sorunlar](docs/KNOWN_ISSUES.md) dosyasıdır. Güncel kaynak sürümü ve yayımlanmış kararlı sürüm `1.0.0`'dır; sürümün kaynağı `CMakeLists.txt` içindeki `project(... VERSION ...)` ve `vcpkg.json` içindeki `version` değeridir. Sonraki sürümler SemVer ve [1.x uyumluluk sözü](docs/COMPATIBILITY.md) ile ilerler. Eski plan notlarındaki tarihsel başlıklar (`v1.1`–`v1.9` gibi) yayımlanmış sürümler değildir. Bağımsız corpus doğrulaması ve temiz makine testleri aşağıda açık işler olarak izlenir; 1.0.0 yayımlanmış olması bu kontrollerin tamamlandığı anlamına gelmez.

## Doğruluk ve gerçek veri

- [ ] Snoop, NetMon, ERF ve özellikle AIX iptrace okuyucularını üretici araçlarının yazdığı gerçek dosyalarla karşılaştır; belirtimden kurulmuş sentetik örnekleri bağımsız doğrulama sayma.
- [ ] TLS/DTLS, kurumsal protokoller, veritabanları, USB, Bluetooth ve 802.15.4 için lisansı uygun gerçek corpus örneklerini URL, SHA-256 ve bağımsız beklentilerle ekle.
- [ ] Corpus'u sabitlenmiş tshark sürümü ve tercihleriyle karşılaştır; bilinen farklılıkları paket kaybı veya yanlış sınıflandırmadan ayrı raporla.
- [ ] HTTP/2 HPACK dinamik tablosunu bağlantı boyunca koru; TLS kayıtlarına bölünmüş iç HTTP mesajlarının yeniden birleştirilmesini ekle.
- [ ] Uzun/kapanışla sınırlanan HTTP yanıtları ve HEAD yanıtları için sınırlandırmayı güçlendir.

## Protokol kapsamını derinleştirme

- [ ] NFSv4.1 pNFS aygıt/layout gövdeleri ve NFSv4.2 işlemleri; NFS/RPC eşlemesini gerçek üretici yakalamalarıyla doğrulama.
- [ ] TDS sonuç token'ları, COLMETADATA ve RPC parametreleri (PostgreSQL Bind/DataRow/COPY ve MySQL satır değerleri/hazırlanmış ifadeleri tamamlandı).
- [ ] USB sınıfa özgü tanımlayıcı/yükler; Bluetooth L2CAP yeniden birleştirme ve GATT/SDP ayrıntıları.
- [ ] 802.15.4 adres/güvenlik ayrıntıları; ayrı ihtiyaç doğarsa 6LoWPAN ve Zigbee.
- [ ] SIP oturumları ve SDP'den RTP eşleme; RTCP SR/RR gövdeleri; Modbus yazmaçları ve DNP3 nesneleri.
- [ ] Eksik protokol filtre alanları; ayrıntı ağacındaki bir alanın süzgeçten erişilebilir olduğunu varsayma.

Her başlık bağımsız bir çalışma olarak ele alınmalıdır. Protokol adı göstermek, tam uygulama desteği değildir. Teslim kuralları [CONTRIBUTING.md](CONTRIBUTING.md#code-and-delivery-rules) ve [DISSECTORS.md](docs/DISSECTORS.md#delivery-checklist-apply-it-to-every-protocol) içindedir.

## Kullanılabilirlik ve performans

- [x] Büyük yakalamalarda düzenli ifade filtrelerini UI iş parçacığından çıkar veya işi dilimle (filtreler arka plan iş parçacığında değerlendirilir; ilerleme gösterilir, iptal edilebilir; ölçüm: [PORTFOLIO_VALIDATION.md](docs/PORTFOLIO_VALIDATION.md)).
- [ ] IP adreslerini sayısal sırala ve Decode As kurallarını kalıcı yap (pencere boyutu/konumu artık kalıcı).
- [x] Nanosaniyelik yakalamaların dışa aktarımında zaman hassasiyetini koru (pcap nanosaniye sihirli sayısı, pcapng `if_tsresol`, CSV/JSON tam hassasiyet).
- [ ] Yeni bağımlılık/dissector sürümlerinden sonra yükleme, filtre ve tepe bellek ölçümünü tekrarla; yöntemi ve ham çıktıyı kaydet.
- [x] Menü, sağ tık, sürükle-bırak ve dışa aktarma gibi etkileşimlere daha geniş GUI doğrulaması ekle.

## Yayın doğrulaması

- [ ] Windows'ta temiz makinede dosya açma, dışa aktarma ve paket çalıştırma testi; isteğe bağlı Npcap yolunu gerçek aygıtla doğrula. Test prosedürü [RELEASING.md](docs/RELEASING.md#9-windows-clean-machine-checklist) içindedir (İngilizce); sonuç henüz kaydedilmedi.
- [ ] macOS Developer ID imzası ve noter onayı; Linux/Windows paketlerinin bağımlılık ve lisanslarını temiz makinelerde denetle.
- [x] Etiket tetiklemeli release iş akışının gerçek çalışmasını ve üretilen AppImage/DMG/ZIP paketlerini doğrula ([v0.9.2](https://github.com/Zaryob/imshark/releases/tag/v0.9.2): bütün platform kontrolleri geçti, SHA256SUMS ve DMG içindeki uygulama sürümü doğrulandı).

## 1.0 teslim kaydı ve açık doğrulamalar

`v1.0.0` için engelleyici işler ve durumları. Kod tarafındaki bütün engeller `master` üzerinde birleştirildi; Windows temiz makine testi 1.0'da yapılmadı ve bilinen sınır olarak kaldı.

| İş | Durum | Bağlantı |
|---|---|---|
| Linux/macOS yakalama yardımcısı (ayrıcalıklı süreç yalnızca aygıtı açar, sonra yetkilerini bırakır; sistem genelinde izin değişikliği yok) | tamamlandı | [#8](https://github.com/Zaryob/imshark/pull/8) |
| Fuzzing (libFuzzer koşum takımları, CI'da çalıştırma, bulunan ayrıştırıcı hatalarının düzeltilmesi) | tamamlandı | [#13](https://github.com/Zaryob/imshark/pull/13) |
| Statik analiz (CodeQL, clang-tidy, tek uyarı kümesi) | tamamlandı | [#12](https://github.com/Zaryob/imshark/pull/12) |
| Ayar dosyası sürümü, uyumluluk sözü ve tehdit modeli | tamamlandı | [#10](https://github.com/Zaryob/imshark/pull/10) |
| gzip açma sınırı ve güvenli geçici dosyalar | tamamlandı | [#9](https://github.com/Zaryob/imshark/pull/9) |
| Arka planda görüntüleme filtresi ve nanosaniye hassasiyetiyle dışa aktarma | tamamlandı | [#11](https://github.com/Zaryob/imshark/pull/11) |
| CHANGELOG, RELEASING, USER_GUIDE güncellemesi ve yayımlanmış paketlerin lisans denetimi | tamamlandı ([#14](https://github.com/Zaryob/imshark/pull/14)) | [CHANGELOG.md](CHANGELOG.md), [RELEASING.md](docs/RELEASING.md), [VALIDATION.md](docs/VALIDATION.md#third-party-licence-notices-in-the-published-packages) |
| Windows temiz makine testi | açık; 1.0'da yapılmadı, insan gerektirir | [kontrol listesi](docs/RELEASING.md#9-windows-clean-machine-checklist) |
| macOS ad hoc imza | bilinçli karar: 1.0 için Developer ID imzası ve noter onayı yok; kullanıcılar Gatekeeper'da "Open Anyway" adımını izler | [RELEASING.md](docs/RELEASING.md#7-macos-signing) |
| Düzenli ifadelerin sınırlı PCRE2 ile değerlendirilmesi (fuzzing'in bulduğu ReDoS) | tamamlandı | [#15](https://github.com/Zaryob/imshark/pull/15) |

Bu tablo 1.0 hazırlığının tarihsel kaydıdır. Açık doğrulamalar sonraki sürümler için izlenmeye devam eder.

## 1.0 sonrası

Bunlar 1.0'ı engellemez; sıralama bağlayıcı değildir.

- [ ] Windows kurulum paketi (MSI) ve Windows kod imzalama.
- [ ] Release imzaları, SBOM ve GitHub attestations (paketlerin kaynağını doğrulanabilir yapmak).
- [ ] Kod kapsamı raporunun CI'a eklenmesi (`tools/coverage.sh` şimdilik yalnızca yerel çalışır).
- [ ] Güncelleme kontrolü (kullanıcıya yeni sürümü bildirmek; açık onay olmadan ağ isteği yapmadan).
- [ ] Çökme raporlama (yerel, kullanıcının onayıyla paylaşılan).
- [ ] Erişilebilirlik: klavyeyle gezinme, yazı ölçekleme ve renk körlüğüne uygun renk kuralları.
- [ ] Linux arm64 ve Flatpak paketleri.
- [ ] macOS Intel paketi.
- [x] Windows kaynak koduna UAC ve Named Pipe üzerinden yetkili yakalama yardımcısı ekle (Npcap ile isteğe bağlı derleme; yayımlanmış ZIP çevrimdışıdır).
- [x] Windows Named Pipe ve süreç senaryolarını yerel Windows API'leriyle sınayan otomatik kontroller; Npcap SDK ile derleme/bağlama kontrolü ([doğrulama kaydı](docs/WINDOWS_CAPTURE_VALIDATION.md)).
- [ ] Windows yardımcısının gerçek Npcap aygıtıyla UAC kabul/iptal, başlat/durdur/yeniden başlat ve dışa aktarma senaryolarını doğrula ([kontrol listesi](docs/RELEASING.md#10-windows-live-capture-checklist)).

Tam Wireshark eşdeğerliği, bütün SampleCaptures koleksiyonunu eksiksiz çözme ve medya çözümü şu anki hedefler arasında değildir. Yeni protokol sayısından önce mevcut çıktının doğruluğu gelir.
