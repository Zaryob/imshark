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

## v0.7.2 — Mesaj birleştirme ve mevcut protokollerin eksikleri ✅ tamamlandı

Hedef: bir protokolün adını göstermekten mesajı ve alanlarını doğru çözmeye geçmek.

- [x] TCP mesaj birleştirmeyi dissector'lara aç: iki yönlü akış, sıra dışı/yeniden iletilmiş segmentler, eksik bayt aralıkları, bağlantı kapanışı ve bellek sınırları; paket detayını yeniden kurarken aynı sonuç — **L**
- [x] TCP seçeneklerinde SACK bloklarının sınırlarını ve MPTCP alt tür/alanlarını çöz; çok yollu akışları birleştirmeyi ayrı genişleme olarak tut — **M**
- [x] DNS/TCP uzunluk öneki ve mesaj gövdesi segmentlere bölündüğünde birleştir; aynı TCP yükündeki birden fazla DNS mesajını ayrı çöz — **M**
- [x] HTTP/1.x mesaj sınırları: bölünmüş başlık/gövde, Content-Length, chunked aktarım ve aynı akıştaki ardışık mesajlar; gzip gövdeyi çöz, çözülmüş boyutu sınırla — **L**
- [x] TLS record ve handshake mesajlarını TCP segmentleri ve record'lar arasında birleştir; Client/ServerHello, extension ve açık Certificate alanlarını genişlet. *(Şifre çözme ayrı aşama)* — **L**
- [x] Protokol seçimini port + içerik + oturum durumu ile yap; kullanıcıya TCP/UDP için Decode As eşlemesi sun. Standart dışı portta DNS tanıma ve SMTP STARTTLS sonrası TLS'ye geçiş; yanlış pozitiflere karşı mesaj yapısını doğrula — **M**
- [x] DNS RDATA kapsamı: SOA'nın kalan zaman alanları, EDNS seçenekleri/extended RCODE, DS/DNSKEY/RRSIG/NSEC ve SVCB/HTTPS; desteklenmeyen kayıtları ham veri olarak açıkça göster — **M**
- [x] DHCP option overload (52): `sname`/`file` alanlarını tara; pad/end bulunmayan ve kırpık seçenekleri işle. Uzun seçenek birleştirme, relay alt seçenekleri ve authentication seçeneğini çöz — **M**
- [x] ICMP/ICMPv6 mesaj gövdeleri: MTU/pointer, alıntılanan IPv6 paketleri, router/neighbor discovery bayrakları ve seçenekleri, multicast listener mesajları; IPv6 uzantı başlıklarının TLV alanları — **M**
- [x] NTP control/private mesajlarını temel 48 baytlık zaman paketinden ayır; extension/authentication alanlarını çöz — **M**
- [x] IPv4/TCP/UDP/ICMP checksum doğrulaması; doğrulanmış hata ile kesilmiş paket veya checksum offload nedeniyle doğrulanamayan durumu Expert Information'da ayır — **M**

Kabul ölçütü: `dns_port.pcap` DNS olarak çözülür; `PRIV_bootp-both_overload*.pcap` içindeki overload seçenekleri görünür; bölünmüş ve birleştirilmiş DNS/HTTP/TLS girdileri aynı mesaj/alanları üretir. Eksik yakalama mesajı tamamlanmış sayılmaz; mevcut özetten filtreleme performansı korunur.

## v0.7.3 — Temel kapsüllemeler ve Ethernet kontrol protokolleri ✅ tamamlandı

Hedef: desteklenen IP/TCP/UDP dissector'larına farklı kapsüllemeler üzerinden ulaşmak. İç içe ayrıştırmada derinlik ve uzunluk sınırları ortak uygulanır.

- [x] IEEE 802.3 uzunluk alanını Ethernet II EtherType'tan ayır; LLC/SNAP ve STP/RSTP/MSTP BPDU alanları — **M**
- [x] PPP ve PPPoE: discovery/session, LCP/IPCP/IPv6CP, IPv4/IPv6 yüküne yönlendirme — **M**
- [x] MPLS label stack: label/TC/S/TTL, çoklu etiket ve IPv4/IPv6 iç yükü — **M** *(Yapıldı: `dissect/mpls.cpp` — EtherType 0x8847/0x8848, en çok 16 etiket, ayrılmış etiket adları, pseudowire kontrol sözcüğü ve iç Ethernet; `mpls`, `mpls.label/exp/ttl/bottom_of_stack/label1` filtreleri; kırpık/aşırı derin yığın `[Malformed Packet]`)*
- [x] IP-in-IP (IPv4/IPv6) ve GRE: optional checksum/key/sequence, iç protokole yönlendirme; ERSPAN başlıkları — **M** *(Yapıldı: `dissect/ipip.cpp` (IP protokol 4/41) ve `dissect/gre.cpp` — C/R/K/S alanları, kaynak rota girdileri, IPv4/IPv6/ARP/PPP/MPLS/şeffaf Ethernet köprüleme yönlendirmesi, ERSPAN Type II/III başlığı ve yansıtılan çerçeve; `ipip`, `gre`, `gre.proto/version/flags.*/key/sequence_number` filtreleri)*
- [x] LLDP TLV'leri, LACP ve Ethernet pause/control çerçeveleri — **M** *(Yapıldı: `dissect/lldp.cpp` (0x88CC, chassis/port/TTL/ad/açıklama/yetenek/yönetim/OUI TLV'leri), `dissect/slow_protocols.cpp` (0x8809, LACP actor/partner/collector) ve `dissect/mac_control.cpp` (0x8808, PAUSE ve PFC); `lldp.*`, `lacp.*`, `mac_control.*`, `pause.time`, `pfc.class_enable` filtreleri)*
- [x] Her kapsülleme için özet, alan ağacı, bayt aralıkları, görüntüleme filtresi ve protokol hiyerarşisini birlikte güncelle — **M** *(Yapıldı: her dissector Info/protokol özetini, `fields` ağacını ve `fields.cpp` filtre alanlarını birlikte üretir; `stats::chain()` katman zincirini (PPPoE/MPLS/IP-in-IP/GRE/ERSPAN/LLDP/LACP/MAC Control/802.3 STP) Protocol Hierarchy'de gösterir; `tests/test_encap_ranges.cpp` her alan ağacı düğümünün çerçeve içinde kaldığını elle hesaplanmış ofsetlerle ve kırpma/mutasyon taramasıyla doğrular — bu tarama kırpık PAUSE/PFC çerçevelerinde taşan bayt aralığını yakalayıp düzeltti)*

Kabul ölçütü: `stp.pcap`, `telecomitalia-pppoe.pcap`, `mpls-basic.cap` ve tünel örneklerinde dış/iç katmanlar ve iç IP adresleri görünür. Kırpık veya aşırı iç içe başlıklarda sınır ihlali olmaz. Gerçek `stp.pcap`, `telecomitalia-pppoe.pcap`, `mpls-basic.cap` ve tünel dosyaları bu makinede bulunmadığından çalıştırılmadı; zincirler sentetik testlerle (`test_llc_stp`, `test_pppoe_ppp`, `test_mpls`, `test_ipip_gre`, `test_lldp_lacp`, `test_hierarchy`, `test_encap_ranges`) kapsanır ve beklenen alanlar gerçek dosyalar `IMSHARK_CORPUS_DIR` ile bulunup corpus'a eklenirken doğrulanır.

## v0.8 — Canlı yakalama ✅ tamamlandı

Ön koşul: v0.7.1–v0.7.3. Canlı gelen paketler de aynı okuyucu/dissector doğruluk ve kaynak sınırlarından yararlanır.

- [x] Canlı yakalama (libpcap/Npcap): arayüz seçimi, BPF yakalama filtresi, başlat/durdur — **L** *(Yapıldı: `core/src/capture/` (libpcap arka plan iş parçacığı → geçici klasik pcap, `FileProcessor::appendLivePacket` ile artımlı özet) ve Capture menüsü (Interfaces…, Start/Stop Ctrl+E, Restart; yazarken doğrulanan BPF filtresi, snaplen, promiscuous, son seçimin ayarlarda saklanması); paket listesi her karede sınırlı iş yaparak büyür, görüntüleme filtresi/renk yeni ve sonradan değişen satırlara uygulanır, durdurunca dosya gibi davranır, kaydedilmemiş yakalama için dışa aktar/sil sorusu, yakalama yokken menü pasif. Gerçek aygıt yakalaması bu makinede ayrıcalık olmadığından denenmedi; enjeksiyon dikişiyle test edildi)*

## v0.9 — Yaygın protokoller (küçük teslimler)

Durum: v0.7.2 tamamlandı — TCP mesaj birleştirme, DNS/HTTP/TLS mesaj çözümü, Decode As, checksum doğrulaması, ICMP/NTP/DHCP/DNS ayrıntıları. v0.7.3 tamamlandı — 802.3/LLC/SNAP/STP, PPP/PPPoE, MPLS, IP-in-IP/GRE/ERSPAN, LLDP/LACP/MAC Control ve kapsülleme katmanlarının protokol hiyerarşisi. v0.8 (canlı yakalama) tamamlandı; bu bölümdeki iki bağımlılık v0.7.3'ten geliyordu (aşağıda işaretli) ve artık karşılanmıştır.

### Ortak teslim kuralları (her madde için)
1. **Bir madde = bir commit** (gerekirse altyapı ayrı commit). Commit'ten önce `ctest` + ASan/UBSan paketi temiz olmalı.
2. **Üç tür test:** (a) gerçek örnek yakalama — manifestte kaynak URL + SHA-256 + beklenen sonuç, `IMSHARK_CORPUS_DIR` ile çalışır, yoksa atlanır; (b) sentetik, elle kurulmuş mesajlar (RFC örnekleri); (c) mutasyon-fuzz: bozuk/kırpık girdide çökmez ve her alan ofseti çerçeve içinde kalır.
3. **Bağımsız doğrulama (oracle):** çıkan sayı/alan, kodun kendisinden değil ayrı bir yoldan doğrulanır (RFC test vektörleri, bağımsız Python hesabı veya `tools/compare_tshark.py`).
4. **Durum bilgisi özette saklanır, Replay'de yeniden hesaplanmaz.** Bir dissector önceki paketlerdeki bir şeye bağlıysa (BGP AS4 modu, SMTP DATA durumu, FTP veri portu, TLS sürümü) bu karar **yükleme geçişinde** özete yazılır (`app_flags`/`app_type`); detay kurulurken yalnızca okunur. Aksi halde tek paketten kurulan detay yükleme sonucundan sapar.
5. **`PacketInfo` bütçesi:** boyut şu an 336 bayt (`sizeof(packet::PacketInfo)` ölçüldü), test üst sınırı da 336 (`tests/test_reader.cpp` static_assert). Yeni alan eklemek yerine mevcut `app_type/app_flags/app_code/app_text/app_text2` kullanılır; büyük/çok değerli durum için oturum tabloları kullanılır.
6. **Filtre alanları:** her protokol kendi alanlarını `core/src/filter/fields.cpp` tablosuna ekler.
7. Her teslimde `docs/KNOWN_ISSUES.md` "işlevsel sınırlar" bölümü ve README özellik listesi güncellenir.

### Sıra ve bağımlılıklar
Önerilen sıra: **0.9.1 → 0.9.3-a/b → 0.9.2 → 0.9.3-c → 0.9.3-d.**
- 0.9.1 yalnız mevcut altyapıyı kullanır ve hızlı değer verir.
- 0.9.2, v0.7.3'ün link-katmanı kaydı ve 802.3/LLC/SNAP işine bağlıdır.
- 0.9.3-a/b (oturum tabloları + HTTP/2), TLS şifre çözme (0.9.3-c) öncesi gereklidir.
- DTLS (0.9.3-d), datagram birleştirme altyapısı ister.

### v0.9.1 — Özet dissector'larını alan düzeyine çıkar

- [x] **0.9.1-a: Ortak bounds-checked okuyucu ve BER/ASN.1** — **M**
  - `core/src/dissect/reader.h`: `ByteReader{data, size, pos}` — `u8/u16/u24/u32/u64` (big/little-endian), `skip`, `sub(len)`, taşmada hata durumuna geçer (`ok()` false).
  - `core/src/dissect/asn1.h`: BER TLV okuyucu (`tag class/constructed/number`, kesin/belirsiz uzunluk, 4 bayta kadar), INTEGER (64-bit), OID → "1.3.6.1…", OCTET STRING, SEQUENCE yineleyici. `x509.cpp` bunun üzerine taşınır.
  - Testler: BER/DER test vektörleri (RFC 3416, X.690), uzunluk taşması, iç içe derinlik sınırı (32).
- [x] **0.9.1-b: SNMP (v1, v2c, v3)** — **L**
  - Sürümler v1, v2c, v3. Mesaj başlığı: version, community (v1/v2c) ya da `msgGlobalData` + USM `msgSecurityParameters` (engine ID/boots/time/user, auth/priv parametre uzunlukları) (v3); `scopedPDU` şifreliyse "şifreli — çözülmedi" göstergesi (şifre çözme kapsam dışı).
  - PDU türleri: Get/GetNext/Response/Set/Trap v1/GetBulk/Inform/Trap v2/Report; request-id, error-status/index (adlarıyla), non-repeaters/max-repetitions; varbind listesi (OID + tür: INTEGER, OCTET STRING, OID, IpAddress, Counter32/64, Gauge32, TimeTicks, Null, noSuchObject/Instance/EndOfMibView).
  - OID adı tablosu (RFC 1213/3418: sysDescr, sysUpTime, ifTable...), bilinmeyenler sayısal.
  - Filtre: `snmp.version`, `snmp.community`, `snmp.pdu_type`, `snmp.request_id`, `snmp.error_status`, `snmp.oid`.
- [x] **0.9.1-c: BGP** — **L**
  - Akış framer'ı: 16 bayt `0xff` işaretçisi + 2 bayt uzunluk (19–4096).
  - Mesajlar: OPEN (sürüm, AS, hold time, router ID, capabilities: multiprotocol, route refresh, 4-octet AS, graceful restart, ADD-PATH), UPDATE (withdrawn routes, path attributes: ORIGIN, AS_PATH/AS4_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES, MP_REACH/MP_UNREACH_NLRI, NLRI), NOTIFICATION (hata kod/alt kod adları), KEEPALIVE, ROUTE-REFRESH.
  - Durum: AS_PATH 2/4 bayt seçimi OPEN capability'sinden yükleme geçişinde `app_flags`'e yazılır; yoksa tahmin edilip "[AS size guessed]" işaretlenir.
  - Filtre: `bgp.type`, `bgp.as`, `bgp.nlri`, `bgp.notification.code`.
- [x] **0.9.1-d: Telnet, SMTP, FTP, TFTP, SSH** — **L**
  - [x] Oturum tabloları (FTP/TFTP): yükleme geçişinde `SessionTables` doldurulur (`app_flags`), Replay oradan okur.
  - [x] Telnet: IAC komutları (WILL/WONT/DO/DONT/SB…SE), seçenek adları (ECHO, SGA, TERMINAL-TYPE, NAWS, LINEMODE…), alt-müzakere verisi.
  - [x] SMTP: komut/yanıt ayrımı, çok satırlı yanıtlar (`250-`/`250 `), STARTTLS sonrası TLS geçişi, DATA durumu (satır satır `.` ile bitiş; From/To/Subject ağaçta).
  - [x] FTP: komut/yanıt, `PASV`/`EPSV` ve `PORT`/`EPRT` veri bağlantısı oturum tablosu → "FTP-DATA" eşleştirmesi; Follow Stream desteği.
  - [x] TFTP: opcode (RRQ/WRQ/DATA/ACK/ERROR/OACK), dosya adı/mod/seçenekler, blok no; UDP dinamik port oturum tablosu.
  - [x] SSH: banner (`SSH-2.0-…`), `KEXINIT` (açık algoritmalar), anahtar değişimi mesajları (DH/ECDH), `NEWKEYS` sonrası "şifreli" işareti (şifre çözme kapsam dışı).

Kabul ölçütü: SNMP/Telnet/SMTP/BGP yalnızca port etiketi ve ham veri göstermez; mesaj alanları filtrelenir ve detay ağacında görünür. Her protokol ayrı commit/test kümesiyle teslim edilir; TCP'ye dayananlar v0.7.2'nin mesaj birleştirmesini kullanır.

### v0.9.2 — Kablosuz çerçeveleri aç

Ön koşul: v0.7.3 link katmanı kaydı (`Registry::registerLinkType`) ve 802.3/LLC/SNAP.

- [x] **4.1: Radiotap (127) ve PPI (192)** — **L**
  - Radiotap: `it_version`, `it_len`, `it_present` (genişletme bitleri), doğal hizalamalı alanlar (TSFT, flags, rate, channel, dBm signal/noise, antenna, MCS, A-MPDU, VHT, HE...). FCS present bayrağı sondaki 4 baytı ayırır.
  - PPI: `pph_version/flags/len/dlt`, TLV alanları (802.11-Common=2, AMPDU...), dlt=105 → 802.11 yönlendirmesi.
  - Filtre: `radiotap.channel.freq`, `radiotap.dbm_antsignal`, `radiotap.datarate`, `ppi.dlt`.
- [x] **4.2: IEEE 802.11 çerçeveleri (105)** — **L**
  - Frame Control (tür/alt tür, ToDS/FromDS, Retry, PwrMgt, Protected, Order...), süre, DS bayraklarına göre adresler (RA/TA/DA/SA/BSSID), sequence control, QoS Control, HT Control.
  - Yönetim: Beacon, Probe Req/Resp (timestamp, interval, capability, Information Elements: SSID, rates, DS, TIM, country, RSN, HT/VHT/HE...), Auth/Deauth, Assoc/Disassoc, Action.
  - Kontrol: RTS, CTS, ACK, Block Ack. Data: Data/QoS Data/Null; Protected bayrağı varsa "korumalı veri (CCMP/TKIP/WEP IV)", şifresizse LLC/SNAP → IP/HTTP iç katmanlarına yönlendirme.
  - Filtre: `wlan.fc.type`, `wlan.fc.subtype`, `wlan.sa/da/ra/ta/bssid`, `wlan.ssid`, `wlan.fc.protected`, `wlan.seq`.
- [x] **4.3: EAPOL / 802.1X ve WPA el sıkışması** — **M**
  - EtherType 0x888E: sürüm, tür (Packet/Start/Logoff/Key), EAP (Identity, TLS, PEAP...).
  - EAPOL-Key: descriptor tipi, Key Information bitleri, replay counter, nonce, IV, RSC, MIC, key data (RSN IE, PMKID KDE, GTK KDE). Info'da "Message 1 of 4" vb. sınıflandırma. (802.11 şifre çözme kapsam dışı).

Kabul ölçütü: `http_PPI.cap` içindeki 140 paketin tamamının `Unknown` kalması giderilir; her çerçeve kendi tipine göre çözülür, HTTP taşıyan şifresiz çerçevelerde iç katmanlara ulaşılır.

### v0.9.3 — Modern uygulama mesajları ve TLS anahtarları

- [x] **5.1: Oturum tabloları (0.9.3-a)** — **M**
  - `core::SessionTables`: yükleme sırasında `FileProcessor` tarafından doldurulan, yükleme bitince değişmez (immutable) hale gelen ve `buildPacketDetails`'e geçirilen tür-güvenli tablolar (TLS oturumu, HPACK durumu, FTP veri bağlantıları).
  - Tablo başına bellek üst sınırı (ör. 64 MB), taşmada "durum kayıp" teşhisi.
- [x] **5.2: HTTP/2 açık metin ve HPACK (0.9.3-b)** — **L**
  - Tanıma: `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` ön eki, `Upgrade: h2c`, ALPN `h2`, Decode As. 9 baytlık çerçeve başlığı (uzunluk, tür, bayraklar, stream ID) akış framer'ı.
  - Çerçeve türleri: DATA, HEADERS (+PRIORITY), PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION. HEADERS/CONTINUATION blok birleştirme.
  - HPACK (RFC 7541): statik tablo (61 giriş), Huffman kod çözücü (257 sembol), dinamik tablo (boyut güncellemesi, kovma). Bağlantı yönü başına sıralı durum; Replay'de blok taze çözücüden geçer.
  - Filtre: `http2.type`, `http2.streamid`, `http2.flags`, `http2.headers.method/path/status/authority`, `http2.header.name/value`.
- [x] **5.3: TLS anahtar günlüğü ve şifre çözme (0.9.3-c)** — **L** *(1. kısım: anahtar günlüğü, DSB ve oturum eşlemesi; 2. kısım: OpenSSL kripto sarmalayıcı ve kayıt çözücü; 3. kısım: yükleme geçişi, ayrıntı ağacı, HTTP/1.x ve HTTP/2, filtre alanları, hiyerarşi, Expert Information, Follow Stream "TLS (decrypted)" ve Edit > Preferences anahtar günlüğü ayarı. Sınırlar docs/KNOWN_ISSUES.md'de: 0-RTT çözülmez, yeniden müzakere izlenmez, HPACK durumu mesajlar arası tutulmaz)*
  - Kripto: İsteğe bağlı CMake özelliği `IMSHARK_TLS_DECRYPT` ile OpenSSL 3 / libcrypto (AES-GCM, ChaCha20-Poly1305, HKDF/HMAC). Kapalıysa "şifre çözme bu derlemede yok" notu.
  - Anahtar kaynakları: `SSLKEYLOGFILE` metni (CLIENT_RANDOM, TLS 1.3 secrets) ve pcapng Decryption Secrets Block (DSB, tip `0x544c534b`). UI'da keylog dosyası yolu ayarı.
  - ClientHello random → oturum tablosu eşleme, kayıt sıra no sayımı, KeyUpdate takibi.
  - Destek matrisi: TLS 1.2/1.3 × {AES-128/256-GCM, ChaCha20-Poly1305}. Çözülmüş yük sanal TCP akışı olarak HTTP/1.x veya HTTP/2 dissector'ına verilir; Follow Stream "TLS (çözülmüş)" sekmesi.
  - Doğru/yanlış/eksik anahtar ayrımı: etiket doğrulanmadan açık metin gösterilmez.
- [x] **5.4: DTLS ve datagram birleştirme (0.9.3-d)** — **L** *(1. kısım: datagram birleştirici; 2. kısım: DTLS dissector'ı, yükleme geçişinde el sıkışma birleştirme, DTLS 1.2 AES-GCM şifre çözme, `dtls.*` filtre alanları, hiyerarşi ve Expert Information. Sınırlar docs/KNOWN_ISSUES.md'de: DTLS 1.3 yalnızca tanınır, ChaCha20/CBC/DTLS 1.0 çözülmez, yeniden müzakere izlenmez)*
  - Datagram mesaj birleştirme altyapısı: UDP üzerinde `(bağlantı, epoch, message_seq)` parçalarını birleştiren sınırlı bellekli yapı (SCTP için de ortak). *(Yapıldı: `network::DatagramReassembler`, bkz. B2; DTLS kaydı ve el sıkışma ayrıştırması sonraki parçalarda)*
  - Kayıt başlığı (tür, sürüm, epoch, 48-bit sıra no, uzunluk), el sıkışma (msg_type, fragment_offset/length), HelloVerifyRequest + cookie, ClientHello/ServerHello/Certificate alanları. DTLS 1.2 AES-GCM şifre çözme. *(Yapıldı: `core/src/dissect/dtls.cpp`; içerikle (kayıt başlığı doğrulaması, her kayıt geçerli ve datagramı doldurur) ve 4433/5684 portları ile Decode As `DTLS` ile tanıma, 3478/5349 yalnızca içerik uyunca; DTLS 1.3 birleşik başlığı tanınıp işaretlenir. El sıkışma parçaları yükleme geçişinde `DatagramReassembler` ile birleştirilir, tamamlayan paket mesajı TLS ayrıştırıcılarıyla çözer ve kaynak paketleri listeler, önceki parçalar `[Reassembled in #N]` der; yeniden iletim, çelişen çakışma ve uzunluk uyuşmazlığı işaretlenir. Ortak TLS ayrıştırıcıları `tls_handshake.{h,cpp}` dosyasına çıkarıldı. DTLS 1.2 AES-128/256-GCM `CLIENT_RANDOM` ile çözülür, durumlar TLS ile aynı)*

Kabul ölçütü: anahtar olmayan yakalamada şifreli veri açık metin gibi yorumlanmaz; doğru/yanlış/eksik anahtar örnekleri ayrılır. Kripto ve HPACK bağımlılıkları seçilip lisans/paketleme etkileri belgelenir.

## v1.0 — Yayın hazırlığı

- [ ] Dokümantasyon sitesi/kullanım kılavuzu ve ekran görüntüleri (`docs/`), katkı rehberi (`CONTRIBUTING.md`) — *(Kısmen: `CONTRIBUTING.md` (ön ayarlar, vcpkg, testler, sanitizer, `tools/coverage.sh`, corpus kuralları, teslim kuralları) ve `docs/` altında ARCHITECTURE, DISSECTORS, KNOWN_ISSUES, PROTOCOLS, SUPPORT_MATRIX, USER_GUIDE ile süzgeç alanlarından üretilen FILTER_FIELDS var; testler (`tests/test_docs.cpp`) alan listesinin ve Decode As adlarının kılavuzla uyumunu denetler. Eksik: ekran görüntüleri (bu makinede `screencapture` Ekran Kaydı izni olmadığından siyah görüntü verdi; `docs/USER_GUIDE.md` başında TODO olarak listelendi) ve barındırılan bir dokümantasyon sitesi)*
- [ ] Paketleme: macOS `.app`/dmg, Linux AppImage, Windows zip; sürüm etiketleme ve otomatik release — *(Kısmen: CMake `MACOSX_BUNDLE` + CPack var; macOS'ta `cpack` ile `imshark.app` imajın kökünde olan bir `.dmg` bu makinede üretildi ve hazırlama dizini incelendi (önceden uygulama `bin/imshark.app` altına düşüyordu, düzeltildi). `.github/workflows/release.yml` `v*` etiketinde Linux (tar.gz, deb), macOS (dmg) ve Windows (zip) paketlerini yükler, etiket CMake sürümüyle (`0.8.0`) uyuşmazsa durur; workflow GitHub'da hiç çalıştırılmadı, Windows paketi hiç üretilmedi. Eksik: AppImage CI'da üretilmiyor (`tools/make_appimage.sh` elle çalıştırılan, linuxdeploy'u kullanıcının sağlaması gereken bir yardımcı); paketler GLFW/OpenSSL'i içermez (macOS uygulaması Homebrew kütüphanelerine bağlanır); imzalama/noter onayı yok; sürüm hâlâ `0.8.0`)*
- [x] Protokol dissector eklemek için geliştirici kılavuzu (`docs/DISSECTORS.md`) — *Yapıldı: dissector yazma, Registry kaydı (akış protokolleri ve Decode As dahil), yükleme geçişi/Replay kuralı ve oturum tabloları, merkezi filtre tablosu, üç tür test ve `tests/frame_sweep.h`/`tests/app_flow.h` yardımcıları, ASan/UBSan komutu ve protokol başına uygulanan teslim kontrol listesi; var olmayan fuzz hedefi ve manifeste sentetik pcap ekleme talimatları kaldırıldı; derlenip çalışan örnek: `tests/test_dissector_guide.cpp` (özel kayıt defterinde oyuncak protokol) ve kılavuzdaki kod blokları bu dosyayla karşılaştırılır*
- [x] Paket özeti: üyeler boyuta göre sıralandı (tarihsel not, o günkü değerler: 328 → 312 bayt; güncel boyut 336), okuyucular dosya boyutundan üst sınır tahminiyle `reserve` yapıyor (tepe RSS 370 → 190 MB, 500 bin paket). *(Daha fazlası için `raw_data`/`fields`/metinleri ayrı bir tabloya taşımak gerekir)*
- [x] Performans referansı (ör. 1 GB pcap'i X saniyede açar, tepe bellek Y) — *Yapıldı (yeniden ölçüldü): `tools/bench_driver.cpp` CMake hedefi (`-DIMSHARK_BUILD_BENCH=ON`, varsayılan KAPALI; uygulamayla aynı kütüphanelere bağlanır), `tools/benchmark.py`, `tools/make_bench_pcap.py`. Makine: Apple M4 (10 çekirdek), 16 GiB RAM, macOS 27.0, Apple clang 21.0.0, Release derlemesi (`build-bench/`). Yükleme `FileProcessor::processFile` (uygulamanın yükleyicisinin çağrısı) + tek süzgeç geçişi (`udp && ip.addr == 8.8.8.8`); dosyalar az önce yazıldığı için sayfa önbelleğinde; ölçüm sırasında makinede başka işler de çalışıyordu (yük ortalaması 11–20). Ham çıktılar (sentetik yakalamalar): `dns` profili, 500 000 paket (43 500 024 bayt, hep aynı paket) 5 çalıştırma: `load_ms` 692, 708, 718, 701, 702; `filter_ms` 19–20; tepe RSS 185 MB. `mixed` profili, 500 000 paket (308 417 297 bayt; 2000 TCP bağlantısı + değişen DNS + 512 baytlık UDP) 3 çalıştırma: `load_ms` 889, 883, 853; `filter_ms` 13; tepe RSS 266 MB. `mixed`, ≈ 1 GB (1 740 571 paket, 1 073 742 844 bayt) 3 çalıştırma: `load_ms` 3034, 3047, 3065; `filter_ms` 46–47; tepe RSS 889–890 MB (`/usr/bin/time -l`: 931–933 MB maximum resident set, 3,11–3,14 sn gerçek süre). `dns`, ≈ 1 GB (12 341 860 paket) tek çalıştırma: `load_ms` 17667, `filter_ms` 736, tepe RSS 3954 MB (`time -l`: 4146 MB). Komutlar: `python3 tools/make_bench_pcap.py --output F --profile mixed --size-mb 1024`, `build-bench/bench_driver F`. İçerik rastgele baytlı sentetik trafiktir (DNS dışında uygulama ayrıştırıcısı çalışmaz); sayılar bu makineye ve bu içeriğe aittir. Önceki 'yükleme ≈ 938 ms, hedef < 1 sn ve < 200 MB' ifadesi yeniden üretilemediği ve hedef ölçülmediği için kaldırıldı)*
- [x] Destek matrisi: dosya formatı → link type → kapsülleme → protokol → çözülen alanlar/şifre çözme; README ve bilinen sorunlardaki "tam"/"desteklenir" ifadelerini bu matrisle eşleştir — *Yapıldı: `docs/SUPPORT_MATRIX.md` bölüm 0 zinciri tek tabloda verir (dosya biçimi → link type → kapsülleme → ağ/taşıma → uygulama protokolü → alanlar/şifre çözme) ve Decode As adlarını sayar; alan adları `filter/fields.cpp` ile karşılaştırıldı, README ve KNOWN_ISSUES'taki "tam"/"desteklenir" ifadeleri satır satır tarandı (kalan eski denetim tabloları KNOWN_ISSUES'ta "giderildi" diye işaretlidir); `tests/test_docs.cpp` her filtre alanını, çözülen her link type kimliğini ve her Decode As adını belgelerde arar*
- [ ] Regresyon corpus'unda paket kaybı, yanlış sınıflandırma ve alan doğruluğunu Wireshark/tshark ile seçilmiş alanlar üzerinden karşılaştır; sürüm/preference/Decode As ayarlarını sabitle. Bilinen `Unknown`, şifreli ve kasıtlı bozuk örnekleri ayrı raporla
- [ ] macOS/Linux arayüzünü ekran görüntüleriyle doğrula; Windows'ta gerçek derleme/çalıştırma ve dosya açma/dışa aktarma testi
- [ ] Yeni parser'larla 500 bin paket yükleme/filtreleme/tepe bellek ölçümünü tekrarla; corpus'un tamamına ilişkin kapsama oranını küçük örnek kümesinden çıkarma — *(Kısmen: 500 bin paketlik yükleme + süzgeç geçişi + tepe RSS v1.9 sonrası kodla bu makinede yeniden ölçüldü (yukarıdaki Performans referansı satırı: aynı-paket 692–718 ms ve 185 MB, karışık 853–889 ms ve 266 MB). Eksik: corpus kapsama oranı hesaplanmadı; gerçek yakalamalar (`IMSHARK_CORPUS_DIR`) bu makinede yok ve v1.1–v1.9 protokollerinin hiçbiri için manifest girdisi bulunmuyor)*

## v1.1+ — Seçmeli protokol ve yakalama genişlemeleri

Öncelik: önce yaygın ağ/kurumsal kullanım, sonra cihaz ve uzmanlık protokolleri. Her aile ayrı bir sürüm/teslim olarak ele alınır; hiçbirinin tamamlanması v1.0 için koşul değildir.

### İlkeler
1. **Talebe ve gerçek örneğe göre seç:** En az iki gerçek yakalama örneği ve kamuya açık şartname olmadan başlanmaz.
2. **Her aile bağımsız teslim:** Aileler birbirine yalnızca ortak altyapı üzerinden bağlıdır.
3. **Altyapı önce:** İhtiyaç duyulan ortak altyapı işi ayrı commit ve testleriyle teslim edilir.
4. **Şifreli içerik açıkça işaretlenir;** anahtarlı şifre çözme ayrı destek matrisiyle gelir.
5. **Performans bütçesi:** 500 bin paketlik yükleme ve filtreleme ölçümü bozulmaz.

*(Not: v1.1–v1.9 protokolleri ilke 1'e uymadan, gerçek yakalama örneği olmadan, yalnızca şartnameye ve elle kurulmuş mesajlara dayanarak yazıldı; gerçek örnekle karşılaştırma yapılmadı, bkz. `docs/KNOWN_ISSUES.md`.)*

### Ortak altyapı geriçizelgesi
- [x] **B1: Oturum tabloları** (`core::SessionTables`, v0.9.3-a) — Durumlu çözümde Replay eşitliği (TLS, SMB, SQL, SIP/RTP) — **M** *(Not: SMB2 ve SIP henüz oturum tablosu kullanmıyor; tablolar TLS, DTLS, FTP/TFTP, USB isteği, STARTTLS geçişi ve sunucu uç noktaları için var)*
- [x] **B2: Datagram/mesaj birleştirme** (`network::DatagramReassembler`, v0.9.3-d) — UDP üzerinde parça birleştirme, sınırlı bellek + zaman aşımı (SCTP, DTLS) — **M** *(Yapıldı: opak anahtar, ilk kopya kazanır + çelişen çakışma bayrağı, farklı toplam uzunlukta mesaj atılır, 1024 mesaj / 64 MiB / mesaj başına 16 MiB sınırı ve en eski önce çıkarma, yakalama zamanıyla 60 sn zaman aşımı; DTLS 5.4'te kullanıyor, SCTP henüz kullanmıyor)*
- [x] **B3: Bayt okuyucu + BER/ASN.1** (v0.9.1-a) ve **XDR okuyucu** (4 bayt hizalı, uzunluk önekli) (LDAP, Kerberos, RPC/NFS) — **M + S** *(Yapıldı: BER/ASN.1 `core/src/dissect/asn1.h`, XDR `core/src/dissect/xdr.h` (`XdrReader`, `nfs.cpp` kullanır), `tests/test_xdr.cpp`)*
- [ ] **B4: Dissector başına filtre alanı kaydı** — Alanların merkezi `fields.cpp` yerine dissector tarafından kaydedilmesi — **M** *(Kısmen: `filter::registerField` var (mutex + kararlı depolama, `tests/test_filter.cpp`), ancak dissector'lar kendi alanlarını kaydetmiyor: v1.1+ protokollerinin alanları bilerek merkezi `fields.cpp` tablosuna taşındı, çünkü dissector içinden tembel kayıt alanı ilk pakete kadar görünmez kılıyor ve tabloyu kullanımdayken değiştiriyordu. Eksik: dissector başına kayıt)*
- [ ] **B5: Dosya okuyucu kaydı** — Sihirli sayıyla biçim tanıma, `CaptureReader` arayüzü, "desteklenmeyen biçim" teşhisi — **M** *(Kısmen: `core::detectFileFormat`, `formatName`, `unsupportedFormatDiagnostic` ve NetMon/snoop/ERF/iptrace teşhisleri var (`tests/test_file_formats.cpp`). Eksik: `CaptureReader` arayüzü ve okuyucu kaydı yok; tanıma sabit bir `if` zinciri)*
- [x] **B6: Link katmanı kaydı** (v0.7.3) — USB, Bluetooth, 802.15.4, CAN link türleri — **M** *(Yapıldı: `registerLinkType` ile 189/220/249 (USB), 187/254 (Bluetooth), 195/215/230 (802.15.4), 227 (CAN) `registry.cpp`'de kayıtlı)*
- [ ] **B7: CRC-32C ve diğer sağlama toplamları** (`checksum.h` genişlemesi) — SCTP, DNP3 — **S** *(Kısmen: SCTP CRC-32C doğrulanıyor (bağımsız Python CRC'siyle sınandı); OSPF, IGMP ve UDP-Lite için Internet sağlaması `checksum.h`'dadır. Eksik: DNP3 CRC-16 okunuyor ama doğrulanmıyor)*
- [ ] **B8: İstatistik ad alanı genelleştirme** — USB cihaz/uç nokta, Bluetooth, WLAN, SCTP uç noktaları — **M** *(Kısmen: `stats::AddressKind` Sctp/Ethernet/Wlan/Bluetooth/Usb ile genişletildi, UI sekmeleri, `test_stats.cpp` ayrıştırılmış paketlerle; eksik: USB uç nokta (epnum) bazlı istatistik yok, yalnızca cihaz (`bus.aygıt`) ve 'host'; ayrıca `PacketInfo` MAC ve IP'yi birlikte tutamadığından Ethernet sekmesi yalnızca IP olmayan çerçeveleri listeler, USB uç noktası epnum içermez, bkz. KNOWN_ISSUES)*
### Sürümler ve aile ayrıntıları

- [ ] **v1.1 — Ağ ve taşıma:** IGMP (v1/v2/v3, MLD deseniyle grup/kaynak listeleri), OSPF (v2/v3 ortak başlık, Hello, DD, LSA türleri 1-5/7, Fletcher checksum), SCTP (CRC-32C, chunk'lar, DATA parça birleştirme B2, çoklu akış, payload protocol ID), UDP-Lite (checksum kapsamı). (Ön koşul: B2, B4, B7) — **L** *(Kısmen: IGMP v1/v2/v3 başlığı ve grup adresi, v3'te yalnızca kayıt sayısı (`igmp.cpp`); OSPFv2 Hello ve DD (LSA başlıkları), v3 yalnızca ortak başlık, paket sağlaması RFC 2328 D.4 / v3 sahte başlık (`ospf.cpp`); SCTP CRC-32C, chunk listesi ve DATA alanları (TSN, akış, SSN, PPID) (`sctp.cpp`); UDP-Lite RFC 3828 sağlaması (`udp.cpp`). Eksik: IGMPv3 grup/kaynak listeleri ve MLD (MLD `icmp.cpp`'de ayrı), OSPF LSA türleri/gövdeleri ve LSA Fletcher sağlaması (`fletcher16()` kullanılmıyor), SCTP DATA parça birleştirme (B2 kullanılmıyor), çoklu akış tabloları, DATA dışı chunk gövdeleri; B4 ön koşulu kısmen)*
- [ ] **v1.2 — IPsec:** AH (IPv4/IPv6 SPI, sıra no, iç protokol), ESP (SPI, sıra no, ESP-NULL yük sezgisi veya şifreli göstergesi), IKEv1/IKEv2 (ISAKMP başlığı, SA/KE/ID/CERT/AUTH payload zinciri, 500/4500 NAT-T, IKE parçalama). (Ön koşul: B4) — **L** *(Kısmen: AH SPI/sıra no/ICV (IPv4), ESP SPI/sıra no ve 'şifreli' etiketi, ESP-in-UDP, IKEv1/IKEv2 başlığı ve içerikle doğrulanan genel payload zinciri, 4500 Non-ESP marker ve keepalive (`ipsec.cpp`). Eksik: AH iç protokolünün çözülmesi, IPv6 AH alanları, ESP-NULL sezgisi, SA/KE/ID/CERT/AUTH payload içerikleri, IKE parçalama)*
- [ ] **v1.3 — Kurumsal dosya ve kimlik (LDAP → Kerberos → SMB2/3 → DCE/RPC → NFS):** *(Kısmen, aşağıda alt madde başına; her alt maddenin kaydı, alan ve test ayrıntıları `docs/KNOWN_ISSUES.md`'de)*
  - LDAP (B3 BER): Bind/Search/Modify, filtre ağacı, StartTLS geçişi. *(Kısmen: Bind, Search (kapsam, RFC 4515 süzgeç metni), sonuç kodları, genişletilmiş istek/yanıt, StartTLS geçişi ve çerçeveleyici var; Modify değişiklikleri, nitelik değerleri, kontroller ve SASL belirteçleri çözülmez)*
  - Kerberos (B3 DER): AS/TGS/AP istek/yanıt, KRB-ERROR, PA-DATA, TCP/UDP. *(Yapıldı: RFC 4120 etiketleri, PA-DATA türleri ve hata adları, UDP + TCP; şifreli kısımlar ve KRB-SAFE/PRIV/CRED çözülmez)*
  - SMB2/3: NetBIOS çerçeveleme, Negotiate, Session Setup (SPNEGO/NTLMSSP), Tree Connect, Create/Read/Write/Close, imzalı/şifreli bayrakları; oturum tablosu (B1) ile paylaşım ve dosya adı eşleme. *(Kısmen: NBSS, Negotiate, Session Setup (NTLMSSP kullanıcısı), Tree Connect yolu, Create dosya adı, Read/Write, imzalı/şifreli bayrakları, NT durum adları; Close gövdesi ve ağaç/dosya kimliği → ad eşlemesi için oturum tablosu yok)*
  - DCE/RPC: CO/CL PDU, UUID tablosu, opnum, parça birleştirme (SMB named pipe taşıması). *(Kısmen: CO PDU'ları, Bind bağlamları ve arayüz UUID adları, opnum; CL PDU, parça birleştirme ve SMB named pipe taşıması yok)*
  - NFS (B3 XDR): ONC RPC, portmapper, NFSv3/v4 COMPOUND. (Ön koşul: B1, B3) — **L (protokol başına)** *(Kısmen: ONC RPC kayıt işaretleme, portmapper/mount, NFSv3 çağrıları, NFSv4 COMPOUND'ta yalnızca ilk işlem; sonuç gövdeleri ve çağrı/yanıt eşleme yok)*
- [ ] **v1.4 — Veritabanları (PostgreSQL → MySQL → TDS):** *(Kısmen, alt madde başına)*
  - PostgreSQL: başlangıç mesajı, SSLRequest → TLS, auth türleri, sorgu mesajları (Q, P/B/D/E/S, RowDescription, DataRow...). *(Kısmen: başlangıç/SSLRequest/Cancel, SSLRequest → TLS geçişi, yöne göre tipli mesajlar, sorgular, kimlik doğrulama türleri, ErrorResponse SQLSTATE; Bind parametreleri, DataRow değerleri ve COPY verisi çözülmez)*
  - MySQL: sunucu el sıkışması, auth plugin, SSLRequest → TLS, komutlar (COM_QUERY...), sonuç kümesi. *(Kısmen: yön bilinçli selamlama, giriş isteği (parola özeti gösterilmez), SSLRequest → TLS, komutlar, OK/ERR/EOF ve sonuç kümesi paketleri; satır değerlerinden yalnızca ilki, ikili sonuç kümesi yok)*
  - TDS (SQL Server): Pre-Login (TLS-in-TDS), Login7, SQL Batch, token akışı (COLMETADATA, ROW, DONE...). Parolalar varsayılan olarak maskelenir. (Ön koşul: B1) — **L (protokol başına)** *(Kısmen: Pre-Login seçenekleri ve sarılı TLS el sıkışmasının etiketlenmesi, Login7 (parola maskeli), SQL Batch, RPC, ERROR belirteci; COLMETADATA/ROW/DONE token akışı yok, TLS-in-TDS çözülemez)*
- [ ] **v1.5 — USB:** `LINKTYPE_USB_LINUX` (189), `USB_LINUX_MMAPPED` (220), `USBPCAP` (249); URB id, yön, transfer türleri, setup paketi, standart tanımlayıcılar (device, config, interface, endpoint, HID). Cihaz/uç nokta istatistikleri (B8). (Ön koşul: B6, B8) — **L** *(Kısmen: üç link türü, 64 bit URB/IRP kimliği, uç nokta adresinden yön, transfer türleri, setup paketi, GET_DESCRIPTOR tamamlanmasında device/configuration/interface/endpoint tanımlayıcıları (`usb.cpp`, istek oturum tablosunda), `bus.aygıt` istatistikleri. Eksik: HID tanımlayıcısı yalnızca adlandırılır, alanları çözülmez; uç nokta bazlı istatistik ve sınıfa özgü yükler yok; gerçek yakalama yok, USBPcap IRP eşlemesi belgeye dayanır)*
- [ ] **v1.6 — Bluetooth ve 802.15.4:** HCI H4 (187), pseudo-header (201), Linux monitor (254), USB-HCI; L2CAP (parça birleştirme), ATT/GATT, SDP; IEEE 802.15.4 (195/215), 6LoWPAN (IPHC sıkıştırması, FRAG1/FRAGN birleştirmesi B2), Zigbee NWK/APS. (Ön koşul: B6, v1.5) — **L** *(Kısmen: H4 (187) ve Linux monitor (254) HCI komut/olay/ACL, L2CAP başlığı, ATT işlem kodu/MTU/tutamaç, IEEE 802.15.4 (195/215/230) MAC çerçeveleri (`bluetooth.cpp`). Eksik: pseudo-header (201), USB-HCI, L2CAP parça birleştirme ve sinyalleşme, SDP, GATT ayrıntısı, 6LoWPAN, Zigbee; 802.15.4 adresleri/güvenlik başlığı çözülmez)*
- [ ] **v1.7 — SIP/SDP, RTP/RTCP, RTSP:** SIP (metin ayrıştırma, Content-Length framer'ı, başlıklar, SDP gövdesi, Call-ID oturum tablosu), RTP/RTCP (başlık alanları, SDP portlarından dinamik RTP tanıma B1, RTCP SR/RR), RTSP. Medya çözümü ve VoIP grafikleri kapsam dışı. (Ön koşul: B1) — **L** *(Kısmen: SIP başlangıç satırı doğrulaması, sınırlı Content-Length çerçeveleyicisi, CSeq/Call-ID/From/To, SDP satırları; RTP v2 sabit başlığı, RTCP ortak başlığı + SSRC ve RTSP ilk satırı (`voip.cpp`). Eksik: Call-ID oturum tablosu, SDP portlarından dinamik RTP tanıma (RTP/RTCP yalnızca Decode As ile çözülür), RTCP SR/RR gövdeleri, protokollere özgü süzgeç alanları)*
- [ ] **v1.8 — Endüstriyel, telekom, otomotiv (talebe göre):** Modbus/TCP, IEC 60870-5-104, DNP3 (CRC-16), S7COMM, EtherCAT, CAN/SocketCAN (227), GSM/UMTS/SIGTRAN (SCTP üstünde). — **L (protokol başına)** *(Kısmen: Modbus/TCP (MBAP + işlev/istisna kodu), DNP3 (bağlantı katmanı + ilk uygulama işlev kodu; CRC-16 gösterilir ama doğrulanmaz), CAN/SocketCAN (227, CAN FD dahil) (`industrial.cpp`). Eksik: IEC 60870-5-104, S7COMM, EtherCAT, GSM/UMTS/SIGTRAN; DNP3 CRC-16 doğrulaması ve nesneler; Modbus yazmaç alanları)*
- [ ] **v1.9 — Eski ve üretici dosya biçimleri:** B5 dosya biçimi sihirli sayı tanıma ve teşhis mesajı ("Desteklenmeyen dosya biçimi: X"); NetMon (.cap), Sun snoop, ERF (Endace), AIX iptrace için `CaptureReader` okuyucuları. — **L (biçim başına)** *(Kısmen: dört biçim sihirli sayı/başlık sezgisiyle tanınır ve teşhis iletisi verilir (`core::detectFileFormat`, `tests/test_file_formats.cpp`). Eksik: bu biçimlerin hiçbiri için okuyucu yok, `CaptureReader` arayüzü yok)*
### Teslim kontrol listesi
*(Bu liste her protokol teslimine ayrı ayrı uygulanan bir şablondur, tek seferlik bir görev değildir; bu yüzden maddeleri hiçbir zaman toptan işaretlenmez, ilerleme sürüm satırlarındaki notlardadır.)*
- [ ] Şartname bağlantısı ve sürüm (`docs/PROTOCOLS.md`); bilinen sapmalar.
- [ ] Gerçek örnekler manifestte (URL + SHA-256 + beklenen sayılar + `tree_contains` olguları).
- [ ] Sentetik testler: RFC örnekleri, sınır değerler, birleştirme senaryoları.
- [ ] Mutasyon-fuzz + ASan/UBSan; tüm alan ofsetleri çerçeve içinde.
- [ ] Replay eşitliği testi (durumlu protokollerde özellik testi).
- [ ] Filtre alanları, Info metni, protokol hiyerarşisi, Decode As adı.
- [ ] `KNOWN_ISSUES.md` ve README güncellendi; 500 bin paket bellek/hız ölçümü korundu.
- [ ] Şifreli/korumalı içerik açıkça etiketli; asla açık metin gibi yorumlanmıyor.

## SampleCaptures incelemesinin başlangıç ölçümü

Mevcut parser ile indirilebilen **10 gerçek dosya** çalıştırıldı; bu sonuçlar bütün koleksiyonun kapsama oranı değildir. Diğer ailelerin eksikleri kayıt defteri/kod incelemesinden çıkarıldı. Corpus manifesti hazırlanırken kaynak dosya/hash ve beklenen alanlar ayrıca sabitlenecek.

| Örnek | Mevcut sonuç | Planlanan aşama |
|---|---|---|
| `dhcp.pcap`, `dhcp-nanosecond.pcap` | Her birinde 4 DHCP paketi tanındı; tüm alanların eksiksizliğini kanıtlamaz | v0.7.1 regresyon |
| `NTP_sync.pcap` | 30 NTP + 2 DNS tanındı; checksum'lar doğrulanır (hepsi geçerli) | tamamlandı (v0.7.2) |
| `dns_port.pcap` | 2 DNS paketi, içerikle tanınır (portu standart değil) | tamamlandı (v0.7.2) |
| `PRIV_bootp-both_overload.pcap`, `PRIV_bootp-both_overload_empty-no_end.pcap` | DHCP; option 52 ve `sname`/`file` seçenekleri çözülüyor | tamamlandı (v0.7.2) |
| `ipv4frags.pcap` | 3 paket: 2 ICMP, 1 IPv4; tamamlanan datagram ICMP olarak çözüldü | v0.7.1 regresyon |
| `http.cap` | 43 paket: 7 HTTP, 2 DNS, 34 TCP (çok segmentli yanıtların ilk segmentleri artık HTTP olarak çözülür) | tamamlandı |
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
