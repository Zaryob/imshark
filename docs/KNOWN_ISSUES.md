# Bilinen Sorunlar (Kod Analizi Bulguları)

Statik kod incelemesiyle tespit edilmiştir (derleme/çalıştırma ile ayrıca doğrulanmadı). Önem: **K** = kritik (çökme/güvenlik/yanlış veri), **O** = orta, **D** = düşük.

## Güncel durum (v0.7.2)

İlk analizdeki #1–#24 giderildi. Aşağıdakiler **hâlâ açık** olanlardır; ilgili ROADMAP sürümü parantez içinde.

**İşlevsel sınırlar**
- HTTP/2: çerçeveler ve HPACK çözülür, ancak HPACK dinamik tablosu mesajlar arasında tutulmaz (her mesaj taze çözücüyle okunur); önceki bir başlık bloğunun dinamik girişlerine başvuran başlıklar bu yüzden çözülemeyebilir. Bağlantı başına durum oturum tablolarıyla eklenecek (PLAN_v0.9, 5.2). TLS içindeki h2 şifre çözme gelene kadar görünmez.
- TLS şifre çözme yok (v0.9+); TLS kayıtları ve kayıtlara yayılan el sıkışma mesajları (ör. uzun Certificate) birleştirilir, sertifikalar konu/veren/geçerlilik/SAN ile gösterilir (imza ve zincir doğrulanmaz). HTTP/1.x ve DNS/TCP mesajları birleştirilir; kapanışa kadar süren HTTP yanıtlarında yalnızca başlıklar mesaj sayılır, gövde segment olarak görünür; 4 MiB'tan büyük gövdeler arabelleğe alınmaz; HEAD yanıtı yalnızca sonraki mesajın başlangıcına bakılarak ayırt edilir.
- NTP control/private ayrıntıları kısmi (v0.7.2).
- Desteklenmeyen link türleri (PPI, 802.11, Radiotap) `Unknown` görünür; 802.3/LLC, PPPoE, MPLS, GRE yok (v0.7.3, v0.9).
- TCP analizi Wireshark'a göre sadeleştirilmiştir (spurious retransmission ve hızlı yeniden iletim ayrımı yok).
- Decode As (Analyze menüsü) TCP/UDP portunu adla bir protokole bağlar ve yakalamayı yeniden yükler; kurallar oturum boyunca durur, ayar dosyasına kaydedilmez ve ImGui arayüzü ekran görüntüsüyle doğrulanmadı (yalnızca başsız duman testi).
- Checksum doğrulaması IPv4 başlığı, TCP, UDP, ICMP ve ICMPv6 için her zaman açıktır (`*.checksum.status`, Expert Information); offload bırakıp doldurulmamış (0 ya da kısmi sahte başlık toplamı) ve snaplen ile kesilmiş segmentler "doğrulanamadı" sayılır, hatalı değil. Kapatma seçeneği yok.
- Filtre yalnızca özette tutulan alanları görür; `matches` (std::regex) 500 bin pakette ~1,7 sn ve arayüz iş parçacığında çalışır.
- Dışa aktarma mikro-saniye çözünürlüğündedir (nanosaniye yakalamada son 3 hane kaybolur). IP adresleri sayısal değil metin olarak sıralanır. ImGui pencere yerleşimi kalıcı değil.

**Bellek / performans**
- Paket özeti 328 bayt (testlerde üst sınır 336), `info` metni paket başına ~63 bayt yığın tutar: 500 bin paket ≈ 190 MB, yükleme < 1 sn.

**Doğrulama boşlukları**
- Arayüz hiç ekran görüntüsüyle incelenmedi; menü, sağ tık ve sürükle-bırak etkileşimleri otomatik test edilmiyor (`chrome.cpp` kapsamı ≈ %50).
- Windows derlemesi bir Windows makinesinde denenmedi.
- Gerçek yakalama corpus'u yalnızca `IMSHARK_CORPUS_DIR` ile çalışır; CI'da yalnızca sentetik dosyalar koşar.

**Güvence (neyin nasıl doğrulandığı)**
- 420 test çekirdek dahil ASan+UBSan altında geçer (bir dönem sanitizer çekirdeği kapsamıyordu: CMake seçenek sırası; düzeltildi ve yapılandırma artık denetliyor). Arka plan iş parçacıkları için ThreadSanitizer temiz.
- Satır kapsamı ≈ %92 (`tools/coverage.sh`).

## Güvenlik ve sağlamlık

| # | Sev | Dosya | Sorun |
|---|---|---|---|
| 1 | K | `packet_parser.cpp` `parsePacket` | Hiçbir yerde uzunluk denetimi yok. Kısa/bozuk pakette Ethernet/IP/TCP/UDP başlıklarına `reinterpret_cast` ile taşma okuması olur. Kötü amaçlı bir pcap uygulamayı çökertebilir. |
| 2 | K | `packet_parser.cpp` DNS/`network/utils.h` `getDomainName` | Etiket uzunluğu ve offset paket sınırına karşı denetlenmiyor; sıkıştırma işaretçileri (0xC0) desteklenmiyor → yanlış isim ve taşma. `qType/ttl` okumaları da sınırsız. |
| 3 | K | `pcap/…`, `core.cpp` | `incl_len` doğrulanmadan `std::vector<char>(incl_len)` ayrılıyor; bozuk dosya GB'lık tahsis yaptırabilir. Okuma başarısızlığı (`file.read`) hiç kontrol edilmiyor. |
| 4 | K | `pcapng/enhanced_packet_block.h` | `dataLength = block_total_length - 32` ile ayrılıyor; `block_total_length` küçükse `size_t` taşması/devasa tahsis. Ayrıca bu değer **padding ve options'ı da paket verisine katıyor** (`captured_length` kullanılmıyor). |
| 3b | O | `core.cpp` | `exit(0)` çağrıları (SPB/ISB içinde) — kütüphane kodu uygulamayı sonlandırıyor. |
| 5 | O | `parseTelnet/parseSMTP` | `std::string(data, length)`'de `length` gerçek payload'ı aşabilir; `substr(0,50)` yalnızca kısaltma yapar, sınır denetimi değil. |
| 6 | O | `parseBGP` | `data[18]` okuması uzunluk denetimsiz. |

## Doğruluk (yanlış çıktı üretenler)

| # | Sev | Sorun |
|---|---|---|
| 7 | K | **Endianness**: pcap okuyucu yalnızca native `0xa1b2c3d4` kabul eder; byte-swapped (`0xd4c3b2a1`) ve nanosaniye (`0xa1b23c4d`) dosyalar reddedilir. pcapng'de SHB byte-order magic hiç kullanılmıyor. |
| 8 | K | **Link type** yok sayılıyor: her paket Ethernet sanılır (Linux cooked `SLL`, loopback/`NULL`, raw IP, 802.11 bozuk çıkar). VLAN (0x8100) ve diğer EtherType'lar desteklenmiyor. |
| 9 | O | pcapng zaman damgası çözünürlüğü (`if_tsresol`) IDB seçeneklerinden okunmuyor, sabit "milisaniye" varsayılıyor (`fullTimestamp *= 1.0/1000` tamsayıya kırpılıyor). `tsTimeOffset == 0` kontrolü "ilk paket" mantığını bozabilir. Klasik pcap'te `tsTimeOffset/usTimeOffset` hiç atanmadığı için (hep 0) zaman "göreli" değil mutlak epoch çıkar; `10e-7` yazımı da okunabilirlik için `1e-6` olmalı. |
| 10 | O | SPB (Simple Packet Block) içeriği hiç ayrıştırılmıyor; boş `PacketInfo` listeye ekleniyor. |
| 11 | O | `IPHeader`: `flags` (3 bit) ve `frag_off` (13 bit) iki ayrı `uint8_t` olarak tanımlı → parçalanma bilgisi yanlış. IPv4 seçenekleri/parçalanma (fragment reassembly) yok. `IPv6Header` bit alanları ağ sırasına göre yanlış dizilir; uzantı başlıkları (hop-by-hop, fragment…) desteklenmiyor, `next_header` doğrudan L4 sanılıyor. |
| 12 | O | `TCPHeader.data_offset` ham byte; TCP seçenekleri (MSS, SACK, WS, TS) ayrıştırılmıyor; `flags` ECE/CWR/NS eksik. |
| 13 | O | `pack.length` anlamı tutarsız (TCP'de `payload - data_offset*4`, UDP'de `udp.len`, ARP'de sabit). |
| 14 | O | TCP bağıl numaralar: `trackTCPConnections` bağlantıyı **hash değeriyle** anahtarlıyor (çakışma durumunda yanlış eşleşme) ve `hash<ConnectionID>` operatör önceliği hatalı (`^` ve `+` karışık). SYN sonrası `ack`'te `+1` kaydırması, RST/FIN, seq sarması, yeniden iletim işaretleme yok. `seq`/`ack` SYN dışı bir dalda atanmazsa **başlatılmamış** `int64_t` okunur (`parseProtocolPacket`). |
| 15 | O | DNS: yalnızca A/AAAA/SOA; CNAME/MX/TXT/PTR vb. cevaplar için veri yazılmıyor, `authority/additional` bölümleri atlanıyor. TCP üzerinden DNS (53/tcp) ve mDNS/LLMNR yok. DHCP: seçenekler (53 mesaj tipi vb.) çözülmüyor; `Request/Reply` yerine gerçek DHCP mesaj türü gösterilmeli. |
| 16 | D | Protokol tespiti yalnızca port numarasıyla; `Telnet`/`BGP` için `std::cout` hata ayıklama çıktıları her pakette basılıyor. |
| 17 | D | `ARP opcode 3` "Announce" değil (RARP request = 3); IPv6 paketlerinde `info` yalnızca başlık alanlarını gösterir, L4 `info`'sunu ezer. |

## Kod kalitesi / derleme

| # | Sev | Sorun |
|---|---|---|
| 18 | O | `network/utils.h` içinde **inline olmayan fonksiyon tanımları** var → birden fazla çeviri biriminde include edilirse ODR/çoklu tanım linker hatası; ayrıca kendi `#include`'larını (`<string>`, `<sstream>`, `<iomanip>`, `<arpa/inet.h>`, `ipv6_addr`) içermiyor; yalnızca include sırasına bağlı derleniyor. |
| 19 | O | `packet_info.h` `<variant>` include etmiyor (dolaylı geliyor). `std::variant` varsayılan olarak ilk alternatifi (ARP/ICMP/DHCP/`EthernetHeader`) tutar → ayarlanmamış katman yanlış türle okunabilir (`std::holds_alternative` kullanılmıyor). |
| 20 | O | `PacketInfo` kopyalama: `PacketParser` üyesi `pack`'e kopya, sonra geri kopya (`pack=packet; … packet=pack;`); her paket için `raw_data` üç kez kopyalanıyor. |
| 21 | O | `RenderHexEditor(std::vector<char> memory_buffer)` **değer ile** alıyor → her karede kopya. `toHexString` `offset/length` parametrelerini kullanmıyor (ölü kod). |
| 22 | O | `imshark_core` SHARED olarak ImGui+GLFW'yi de içeriyor; `${imsharkGUI_COMPILER_FLAGS}` tanımsız; `file(GLOB_RECURSE)` yeni dosyaları yeniden yapılandırmadan görmez; `arpa/inet.h` yüzünden Windows'ta derlenmez. |
| 23 | D | `.clang-format`/`.editorconfig`, test, CI, sürüm etiketi yok. Pencere başlığı "PCAP Hex Viewer" (proje adıyla uyumsuz). Başlıklardaki yazar yorumu ve yarım bırakılmış `// std::cout` yorum satırları temizlenmeli. |
| 24 | D | Ölü/sahte API: `printStatistics`, `printNameResolutionRecords` hiçbir şey yazmıyor; `processSectionHeaderBlock` hata durumunda dosyayı kapatıp çağıran döngüde okumaya devam ettiriyor (`file.close()` sonrası `peek()`). |

## UX

- Dosya tamamen yüklenene kadar arayüz donar, ilerleme göstergesi yok.
- Yükleme hataları yalnızca `stderr`'e yazılır; kullanıcıya görünmez.
- Paket sayısı büyüdükçe tablo clipper ile çizilmeli (kullanılıp kullanılmadığı doğrulanmadı).
- Sütun sıralama, arama, filtre, renk kuralları yok; "Close File" paketleri temizler fakat seçim durumunu (`selectedPacket`, `packetState`) sıfırlamıyor.
