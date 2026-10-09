# ImShark yol haritası

Öncelik sırası doğruluk, doğrulanabilirlik ve kullanılabilirliktir. Bu dosya henüz tamamlanmamış işleri tutar; mevcut özelliklerin referansı [destek matrisi](docs/SUPPORT_MATRIX.md), işlevsel sınırların referansı [bilinen sorunlar](docs/KNOWN_ISSUES.md) dosyasıdır. Sürümleme henüz `v1.x` aşamasına geçmemiştir; sürümler `v0.x.y` serisi üzerinden SemVer ile ilerler (`v0.8.x` → `v0.9.x` → `v0.10.x` ...). Eski taahhüt ve plan notlarındaki tarihsel başlıklar (`v1.1`–`v1.9` gibi) yayın sürümü değildi; gerçek sürüm `CMakeLists.txt` ve `vcpkg.json` içindeki `project(... VERSION ...)` değeridir. `v1.0.0` sürümü yol haritasındaki bağımsız doğrulama, üretici yakalama karşılaştırmaları ve çoklu platform paketleme denetimleri tamamlandığında hedeflenecektir.

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

- [ ] Büyük yakalamalarda düzenli ifade filtrelerini UI iş parçacığından çıkar veya işi dilimle.
- [ ] IP adreslerini sayısal sırala; pencere boyutu/konumu ve Decode As kurallarını kalıcı yap.
- [ ] Nanosaniyelik yakalamaların dışa aktarımında zaman hassasiyetini koru.
- [ ] Yeni bağımlılık/dissector sürümlerinden sonra yükleme, filtre ve tepe bellek ölçümünü tekrarla; yöntemi ve ham çıktıyı kaydet.
- [ ] Menü, sağ tık, sürükle-bırak ve dışa aktarma gibi etkileşimlere daha geniş GUI doğrulaması ekle.

## Yayın doğrulaması

- [ ] Windows'ta temiz makinede dosya açma, dışa aktarma ve paket çalıştırma testi; isteğe bağlı Npcap yolunu gerçek aygıtla doğrula.
- [ ] macOS Developer ID imzası ve noter onayı; Linux/Windows paketlerinin bağımlılık ve lisanslarını temiz makinelerde denetle.
- [ ] Etiket tetiklemeli release iş akışının gerçek çalışmasını ve üretilen AppImage/DMG/ZIP paketlerini doğrula.

Tam Wireshark eşdeğerliği, bütün SampleCaptures koleksiyonunu eksiksiz çözme ve medya çözümü şu anki hedefler arasında değildir. Yeni protokol sayısından önce mevcut çıktının doğruluğu gelir.
