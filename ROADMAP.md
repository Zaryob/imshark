# ImShark Yol Haritası

Öncelik sırası: önce **güvenilirlik ve doğruluk**, sonra **mimari**, sonra **özellikler**. Bir analizör yanlış veri gösteriyorsa ya da bozuk dosyada çöküyorsa ek özelliğin değeri yoktur. Ayrıntılı bulgular: [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) (numaralar `#N` ile referanslanır).

Boyut tahminleri: **S** ≈ 1–2 gün, **M** ≈ 3–7 gün, **L** ≈ 1–3 hafta.

Protokol kapsamının referansı: [Wireshark SampleCaptures](https://wiki.wireshark.org/samplecaptures). Koleksiyon pcap/pcapng yanında başka dosya formatları, farklı link type'lar, eski protokol sürümleri ve kasıtlı bozuk paketler içerir; tek bir standart uygunluk testi değildir. **Dosyanın açılması, protokolün tanınması ve alanlarının çözülmesi ayrı başarı ölçütleridir.** Aşağıdaki yeni maddeler planlanmıştır; uygulanıp doğrulanana kadar işaretlenmez.

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

## v0.7 — Protokoller ve dışa aktarım ✅ tamamlandı

- [x] Yeni dissector'lar: HTTP/1.x başlıkları, TLS record/ClientHello/ServerHello/SNI, DNS (tüm bölümler; A/AAAA/NS/CNAME/PTR/MX/TXT/SOA/SRV; TCP üzerinden ve mDNS), yaygın DHCP seçenekleri, NTP temel başlığı, ICMP/ICMPv6 temel mesajları (#15). *(DNS/TCP, HTTP ve TLS mesajları TCP segmentleri arasında birleştirilmez; diğer DNS kayıtlarının RDATA'sı, DHCP overload ve ICMPv6 seçenekleri kısmi; kalan işler aşağıda)* — **L**
- [x] File > Export Packets: tüm / görüntülenen / seçili paketleri pcap, pcapng, CSV, JSON olarak kaydet; Follow Stream "Save As" — **M**
- [x] pcapng yorumları, arayüz/istatistik/ad çözümleme bilgileri: File > Capture File Properties — **S**
- [x] Sıkıştırılmış girdiler (`.pcap.gz`, `.pcapng.gz`): harici kütüphanesiz akış tabanlı gzip çözücü — **S**

## v0.7.1 — Dosya ve parça doğruluğu ✅ tamamlandı

Hedef: geçerli paketleri sessizce atlamamak veya yanlış protokol başlığı gibi yorumlamamak. Yeni protokol eklemeden önce bu aşama tamamlanır.

- [x] pcap `LinkType` alanını alt 16 bitten oku; FCS varlık/uzunluk bilgisini ayrı tut ve çerçeve sonundaki FCS'yi protokol yükünden ayır. *(Yapıldı; `LinkTypeMaskingWithFcsFlags` ve `FcsStrippedFromDissection` testleri)* — **S**
- [x] pcapng eski Packet Block (`0x00000002`) desteği; SHB/IDB/EPB/SPB ile birlikte paket sayısı ve bayt ofsetlerini doğrula. *(Yapıldı; `LegacyPacketBlockIsLoaded` testi)* — **S**
- [x] pcapng `if_tsoffset`, arayüz/FCS seçenekleri ve EPB arayüz kimliği doğrulaması; tanımsız arayüzü Ethernet varsayma. *(Yapıldı: `if_tsoffset` (işaretli, arayüz başına, iki bayt sırası), tanımsız arayüz `kUndefinedLinkType` ile korunur ve dosya mesajında bildirilir, arayüzler bölüm kapsamlıdır)* — **M**
- [x] IPv6 Fragment Header: offset/M/identification alanlarını çöz; ilk olmayan parçayı L4 başlığı gibi yorumlama; henüz birleştirilemeyen parçayı açıkça işaretle. *(Yapıldı: ilk olmayan parça asla L4 sayılmaz, atomik parça bütün paket gibi çözülür)* — **S**
- [x] IPv6 parçalanma birleştirme: eksik, yinelenen, sıra dışı ve çakışan parçalar; sınırlı bellek/zaman aşımı; alan ağacında kaynak paketler. *(Yapıldı: RFC 5722 çakışma kuralı, 60 sn zaman aşımı, 1024 datagram / 64 MB sınırı, uzantı başlıkları birleşmiş yükte de çözülür)* — **M**
- [x] IPv4/IPv6 birleştirilmiş datagram yükünü Follow Stream'e aktar; ham çerçeve ofseti ile birleştirilmiş veri ofsetini ayır. *(Yapıldı: `ip_frag == 2` iken `payload_offset/length` birleşmiş yüke göre; parça toplama `core::reassembleIpPayload`)* — **M**
- [x] Küçük regresyon corpus'u ve manifesti: kaynak URL, dosya SHA-256, format/link type, beklenen paket sayısı, protokol ve temel alanlar. Sentetik sınır durumlarını ve seçilmiş gerçek yakalamaları ASan/UBSan altında çalıştır; indirilebilir büyük koleksiyonu CI'ın her çalışmasında çekme. *(Yapıldı: `tests/corpus/` 14 sentetik dosya + `manifest.json` (URL, SHA-256, beklentiler); gerçek yakalamalar depoda tutulmaz, `IMSHARK_CORPUS_DIR` ile bulunursa doğrulanır; her dosya ayrıntı/filtre/istatistik/dışa aktarma hattından geçer)* — **M**

Kabul ölçütü: FCS'li Ethernet ve eski Packet Block paketleri kaybolmaz; IPv6 parçaları tamamlanmadan sahte TCP/UDP alanları üretmez; mevcut pcap/pcapng endian, zaman çözünürlüğü ve gzip desteği korunur. Referanslar: [pcap dosya yapısı](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-opsawg-pcap-09.html), [pcapng blokları](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng-06), [IPv6 / RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html).

## v0.7.2 — Mesaj birleştirme ve mevcut protokollerin eksikleri

Hedef: bir protokolün adını göstermekten mesajı ve alanlarını doğru çözmeye geçmek.

- [x] TCP mesaj birleştirmeyi dissector'lara aç: iki yönlü akış, sıra dışı/yeniden iletilmiş segmentler, eksik bayt aralıkları, bağlantı kapanışı ve bellek sınırları; paket detayını yeniden kurarken aynı sonuç — **L**
- [ ] TCP seçeneklerinde SACK bloklarının sınırlarını ve MPTCP alt tür/alanlarını çöz; çok yollu akışları birleştirmeyi ayrı genişleme olarak tut — **M**
- [ ] DNS/TCP uzunluk öneki ve mesaj gövdesi segmentlere bölündüğünde birleştir; aynı TCP yükündeki birden fazla DNS mesajını ayrı çöz — **M**
- [ ] HTTP/1.x mesaj sınırları: bölünmüş başlık/gövde, Content-Length, chunked aktarım ve aynı akıştaki ardışık mesajlar; gzip gövdeyi çöz, çözülmüş boyutu sınırla — **L**
- [ ] TLS record ve handshake mesajlarını TCP segmentleri ve record'lar arasında birleştir; Client/ServerHello, extension ve açık Certificate alanlarını genişlet. *(Şifre çözme ayrı aşama)* — **L**
- [ ] Protokol seçimini port + içerik + oturum durumu ile yap; kullanıcıya TCP/UDP için Decode As eşlemesi sun. Standart dışı portta DNS tanıma ve SMTP STARTTLS sonrası TLS'ye geçiş; yanlış pozitiflere karşı mesaj yapısını doğrula — **M**
- [ ] DNS RDATA kapsamı: SOA'nın kalan zaman alanları, EDNS seçenekleri/extended RCODE, DS/DNSKEY/RRSIG/NSEC ve SVCB/HTTPS; desteklenmeyen kayıtları ham veri olarak açıkça göster — **M**
- [ ] DHCP option overload (52): `sname`/`file` alanlarını tara; pad/end bulunmayan ve kırpık seçenekleri işle. Uzun seçenek birleştirme, relay alt seçenekleri ve authentication seçeneğini çöz — **M**
- [ ] ICMP/ICMPv6 mesaj gövdeleri: MTU/pointer, alıntılanan IPv6 paketleri, router/neighbor discovery bayrakları ve seçenekleri, multicast listener mesajları; IPv6 uzantı başlıklarının TLV alanları — **M**
- [ ] NTP control/private mesajlarını temel 48 baytlık zaman paketinden ayır; extension/authentication alanlarını çöz — **M**
- [ ] IPv4/TCP/UDP/ICMP checksum doğrulaması; doğrulanmış hata ile kesilmiş paket veya checksum offload nedeniyle doğrulanamayan durumu Expert Information'da ayır — **M**

Kabul ölçütü: `dns_port.pcap` DNS olarak çözülür; `PRIV_bootp-both_overload*.pcap` içindeki overload seçenekleri görünür; bölünmüş ve birleştirilmiş DNS/HTTP/TLS girdileri aynı mesaj/alanları üretir. Eksik yakalama mesajı tamamlanmış sayılmaz; mevcut özetten filtreleme performansı korunur.

## v0.7.3 — Temel kapsüllemeler ve Ethernet kontrol protokolleri

Hedef: desteklenen IP/TCP/UDP dissector'larına farklı kapsüllemeler üzerinden ulaşmak. İç içe ayrıştırmada derinlik ve uzunluk sınırları ortak uygulanır.

- [ ] IEEE 802.3 uzunluk alanını Ethernet II EtherType'tan ayır; LLC/SNAP ve STP/RSTP/MSTP BPDU alanları — **M**
- [ ] PPP ve PPPoE: discovery/session, LCP/IPCP/IPv6CP, IPv4/IPv6 yüküne yönlendirme — **M**
- [ ] MPLS label stack: label/TC/S/TTL, çoklu etiket ve IPv4/IPv6 iç yükü — **M**
- [ ] IP-in-IP (IPv4/IPv6) ve GRE: optional checksum/key/sequence, iç protokole yönlendirme; ERSPAN başlıkları — **M**
- [ ] LLDP TLV'leri, LACP ve Ethernet pause/control çerçeveleri — **M**
- [ ] Her kapsülleme için özet, alan ağacı, bayt aralıkları, görüntüleme filtresi ve protokol hiyerarşisini birlikte güncelle — **M**

Kabul ölçütü: `stp.pcap`, `telecomitalia-pppoe.pcap`, `mpls-basic.cap` ve tünel örneklerinde dış/iç katmanlar ve iç IP adresleri görünür. Kırpık veya aşırı iç içe başlıklarda sınır ihlali olmaz. Bu dosyalar ilk incelemede çalıştırılmadı; beklenen alanlar corpus'a eklenirken doğrulanır.

## v0.8 — Canlı yakalama

Ön koşul: v0.7.1–v0.7.3. Canlı gelen paketler de aynı okuyucu/dissector doğruluk ve kaynak sınırlarından yararlanır.

- [ ] Canlı yakalama (libpcap/Npcap): arayüz seçimi, BPF yakalama filtresi, başlat/durdur — **L**

## v0.9 — Yaygın protokoller (küçük teslimler)

### v0.9.1 — Özet dissector'larını alan düzeyine çıkar

- [ ] SNMP: sınır denetimli ASN.1/BER, sürüm/community, PDU/request-id/error, OID/varbind; SNMPv3 USM başlığı ve şifreli içerik göstergesi. *(SNMPv3 şifre çözme kapsam dışı)* — **L**
- [ ] BGP: mesaj sınırları, OPEN capabilities, UPDATE withdrawn routes/path attributes/NLRI, NOTIFICATION — **L**
- [ ] Telnet IAC negotiation/subnegotiation ve SMTP komut/yanıt/çok satırlı yanıt/DATA durumları; STARTTLS geçişini v0.7.2 altyapısına bağla — **M**
- [ ] FTP kontrol komutları ve veri bağlantısı eşleştirme; TFTP opcode/block/options; SSH banner ve açık key-exchange başlıkları. *(Şifreli SSH/SFTP içeriğini çözme ayrı iş)* — **L**

Kabul ölçütü: SNMP/Telnet/SMTP/BGP yalnızca port etiketi ve ham veri göstermez; mesaj alanları filtrelenir ve detay ağacında görünür. Her protokol ayrı commit/test kümesiyle teslim edilir; TCP'ye dayananlar v0.7.2'nin mesaj birleştirmesini kullanır.

### v0.9.2 — Kablosuz çerçeveleri aç

- [ ] LINKTYPE_IEEE802_11 (105), Radiotap (127) ve PPI (192): değişken başlık uzunluğu, present bitmap/TLV ve hizalama; link katmanından 802.11'e yönlendirme — **L**
- [ ] 802.11 management/control/data, adres alanları/DS bayrakları, QoS ve information element'ler; şifresiz data → LLC/SNAP → IP — **L**
- [ ] EAPOL/802.1X mesajları ve WPA handshake başlıkları; korumalı yükü açıkça göster. *(802.11 şifre çözme yapılmaz)* — **M**

Kabul ölçütü: `http_PPI.cap` içindeki 140 paketin tamamının `Unknown` kalması giderilir; her çerçeve kendi tipine göre çözülür, HTTP taşıyan şifresiz çerçevelerde iç katmanlara ulaşılır. Radiotap ve PPI için kırpık, bilinmeyen alanlı ve farklı hizalamalı örnekler doğrulanır.

### v0.9.3 — Modern uygulama mesajları ve TLS anahtarları

- [ ] HTTP/2 açık metin frame/stream yönetimi ve HPACK; güncel standart örneklerini tarihî draft örneklerinden ayır — **L**
- [ ] TLS anahtar günlüğü (SSLKEYLOGFILE) ve pcapng Decryption Secrets Block (DSB); TLS 1.2/1.3 için desteklenen cipher'ları aşamalı ekle, çözülmüş HTTP/1.x/HTTP/2 yükünü dissector'a aktar — **L**
- [ ] DTLS record/handshake, message sequence ve fragment birleştirme; ilk teslimde açık alanları çöz, şifre çözmeyi destek matrisiyle genişlet — **L**

Kabul ölçütü: anahtar olmayan yakalamada şifreli veri açık metin gibi yorumlanmaz; doğru/yanlış/eksik anahtar örnekleri ayrılır. Kripto ve HPACK bağımlılıkları seçilip lisans/paketleme etkileri belgelenir; eski draft yakalamaları güncel uyumluluğun kanıtı sayılmaz.

## v1.0 — Yayın hazırlığı

- [ ] Dokümantasyon sitesi/kullanım kılavuzu ve ekran görüntüleri (`docs/`), katkı rehberi (`CONTRIBUTING.md`)
- [ ] Paketleme: macOS `.app`/dmg, Linux AppImage, Windows zip; sürüm etiketleme ve otomatik release
- [ ] Protokol dissector eklemek için geliştirici kılavuzu (`docs/DISSECTORS.md`)
- [x] Paket özeti: üyeler boyuta göre sıralandı (328 → 312 bayt), okuyucular dosya boyutundan üst sınır tahminiyle `reserve` yapıyor (tepe RSS 370 → 190 MB, 500 bin paket). *(Daha fazlası için `raw_data`/`fields`/metinleri ayrı bir tabloya taşımak gerekir)*
- [ ] Performans referansı (ör. 1 GB pcap'i X saniyede açar, tepe bellek Y)
- [ ] Destek matrisi: dosya formatı → link type → kapsülleme → protokol → çözülen alanlar/şifre çözme; README ve bilinen sorunlardaki "tam"/"desteklenir" ifadelerini bu matrisle eşleştir
- [ ] Regresyon corpus'unda paket kaybı, yanlış sınıflandırma ve alan doğruluğunu Wireshark/tshark ile seçilmiş alanlar üzerinden karşılaştır; sürüm/preference/Decode As ayarlarını sabitle. Bilinen `Unknown`, şifreli ve kasıtlı bozuk örnekleri ayrı raporla
- [ ] macOS/Linux arayüzünü ekran görüntüleriyle doğrula; Windows'ta gerçek derleme/çalıştırma ve dosya açma/dışa aktarma testi
- [ ] Yeni parser'larla 500 bin paket yükleme/filtreleme/tepe bellek ölçümünü tekrarla; corpus'un tamamına ilişkin kapsama oranını küçük örnek kümesinden çıkarma

## v1.1+ — Seçmeli protokol ve yakalama genişlemeleri

Öncelik: önce yaygın ağ/kurumsal kullanım, sonra cihaz ve uzmanlık protokolleri. Her aile ayrı bir sürüm/teslim olarak ele alınır; hepsinin tamamlanması v1.0 için koşul değildir.

- [ ] Ağ/taşıma: IGMP, OSPF, SCTP chunk'ları ve birleştirme, UDP-Lite; DCCP daha sonra — **L** (aile başına)
- [ ] IPsec: AH alanları, ESP başlığı/şifreli yük, IKEv1/v2 mesaj ve payload'ları; anahtarlı çözme ayrı destek matrisi — **L**
- [ ] Kurumsal dosya/kimlik: sınır denetimli RPC/XDR/ASN.1 altyapısı üzerine SMB2/3, NFS, DCE/RPC, LDAP ve Kerberos; protokol sürümleri ve şifreli yükleri aşamalı ele al — **L** (protokol başına)
- [ ] Veritabanları: PostgreSQL, MySQL, TDS; bağlantı kurma, sorgu/yanıt ve TLS geçişleri — **L** (protokol başına)
- [ ] USB: raw/usbmon/USBPcap link type'ları, transfer/control/setup ve descriptor alanları; Darwin/usbdump gibi yakalama biçimleri ayrı okuyucu işi — **L**
- [ ] Bluetooth HCI/H4/pseudo-header → ACL/L2CAP/ATT; IEEE 802.15.4 → 6LoWPAN/ZigBee için ayrı aşamalar — **L** (aile başına)
- [ ] SIP/SDP, RTP/RTCP/RTSP temel mesaj/başlıkları; medya çözümü ve VoIP analizörleri kapsam dışı — **L**
- [ ] Endüstriyel/telekom/otomotiv: EtherCAT, S7COMM, DNP3, IEC 60870-5-104, GSM/UMTS/SIGTRAN, CAN/otomotiv protokolleri; ihtiyaç ve gerçek corpus'a göre protokol seç — **L** (protokol başına)
- [ ] Eski/üretici dosya okuyucuları: NetMon, snoop, ERF, iptrace; önce açık "desteklenmeyen dosya formatı" teşhisi, sonra talebe göre okuyucu — **L** (format başına)

## SampleCaptures incelemesinin başlangıç ölçümü

Mevcut parser ile indirilebilen **10 gerçek dosya** çalıştırıldı; bu sonuçlar bütün koleksiyonun kapsama oranı değildir. Diğer ailelerin eksikleri kayıt defteri/kod incelemesinden çıkarıldı. Corpus manifesti hazırlanırken kaynak dosya/hash ve beklenen alanlar ayrıca sabitlenecek.

| Örnek | Mevcut sonuç | Planlanan aşama |
|---|---|---|
| `dhcp.pcap`, `dhcp-nanosecond.pcap` | Her birinde 4 DHCP paketi tanındı; tüm alanların eksiksizliğini kanıtlamaz | v0.7.1 regresyon |
| `NTP_sync.pcap` | 30 NTP + 2 DNS tanındı | v0.7.2 alan kapsamı |
| `dns_port.pcap` | 2 DNS paketi UDP olarak kaldı | v0.7.2 tanıma/Decode As |
| `PRIV_bootp-both_overload.pcap`, `PRIV_bootp-both_overload_empty-no_end.pcap` | DHCP tanındı; option 52 bilinmiyor, `sname`/`file` seçenekleri çözülmedi | v0.7.2 DHCP |
| `ipv4frags.pcap` | 3 paket: 2 ICMP, 1 IPv4; tamamlanan datagram ICMP olarak çözüldü | v0.7.1 regresyon |
| `http.cap` | 43 paket: 5 HTTP, 2 DNS, 36 TCP; TCP etiketi tek başına eksik ayrıştırma kanıtı değildir | v0.7.2 mesaj sınırları |
| `http_PPI.cap` | 140 paketin tamamı `Unknown`, link type 192 | v0.9.2 PPI/802.11 |
| `BT_USB_LinCooked_Eth_80211_RT.ntar.gz` | Çok bölümlü/çok link type'lı pcapng açıldı; 27.228 paketin 27.152'si `Unknown` | v0.9.2 ve v1.1+ USB/Bluetooth |

Sentetik doğrulamalar: FCS bayrağı taşıyan Ethernet'in yanlış link type olması, eski pcapng Packet Block'un sessizce atlanması ve ilk olmayan IPv6 parçanın UDP gibi çözülmesi. Üçü de v0.7.1'in öncelikli regresyonlarıdır.

## Fikirler (kalıcı öncelik değil)

- Lua/WASM ile kullanıcı dissector'ları
- Paket diff / iki yakalamayı karşılaştırma
- I/O grafiği ve akış/zaman dizisi görselleştirme
- Uzak yakalama (SSH/`tcpdump` üzerinden)

## Kapsam dışı (şimdilik)

Tam Wireshark eşdeğerliği, bütün SampleCaptures koleksiyonunun eksiksiz çözülmesi, VoIP/RTP medya analizörleri ve 802.11 şifre çözme; proje önce küçük, hızlı ve güvenilir bir çekirdek olmayı hedefler. Temel 802.11 çerçeve ve RTP başlık ayrıştırması bu sınırdan ayrı, yukarıdaki aşamalarda planlanmıştır.
