# ImShark Mimarisi

## 1. Genel bakış

```
 .pcap/.pcapng ──► FileProcessor ──► PacketParser ──► vector<PacketInfo> ──► ImGui arayüzü (main.cpp)
                   (core.cpp)        (packet_parser.cpp)   (bellekte)          liste / detay / hex
                                        │
                                        └─► TCPConnection (bağıl seq/ack)
```

Dosya **arka plan iş parçacığında** okunur (`LoadJob`): okuyucular ilerleme bildirir ve iptal isteğini dinler (`core::LoadControl`, atomikler). Yükleme sırasında her pakette yalnızca **özet** (liste sütunları + dosya ofseti) tutulur; ham bayt dosyada kalır. Kullanıcı bir paketi seçince o paket dosyadan okunur ve alan ağacıyla yeniden çözülür (`core::buildPacketDetails`).

## 2. Modüller

| Modül | Dosyalar | Sorumluluk |
|---|---|---|
| Uygulama / UI | `src/main.cpp` (762 satır) | GLFW+OpenGL3 penceresi, menü, dosya diyaloğu, paket tablosu, katman ağacı, hex editörü |
| Dosya okuyucu | `core/src/core.{h,cpp}` | `FileProcessor`: pcap ve pcapng blok döngüsü, zaman damgası hesabı, `PacketInfo` üretimi |
| Paket ayrıştırıcı | `core/src/packet/packet_parser.h`, `core/src/packet_parser.cpp` | Ethernet → L3 → L4 → L7 ayrıştırma, `source/destination/protocol/info` alanlarının doldurulması |
| TCP takibi | `core/src/network/tcp_connection.h`, `core/src/tcp_connection.cpp`, `network/connection.h` | Bağlantı tablosu, ISN'e göre bağıl seq/ack |
| Başlık yapıları | `core/src/network/l*/…_header.h` | Ağ başlıklarının `struct` karşılıkları (doğrudan bayt dizisine `reinterpret_cast`) |
| Format yapıları | `core/src/pcap/`, `core/src/pcapng/` | Dosya başlıkları; pcapng blokları kendi `deserialize*` metotlarına sahip |
| Veri modeli | `core/src/packet/packet_info.h` | `PacketInfo`: özet alanlar + her katman için `std::variant` başlık + ham bayt |
| Vendored | `core/src/imgui/`, `core/src/thirdparty/` | Dear ImGui 1.91.1, stb, ImGuiFileDialog |

### Build hedefleri

- `imshark_core` — **STATIC**, UI bağımsız (OpenGL/GLFW/ImGui yok): okuyucular, ayrıştırıcı, paket modeli.
- `imshark_imgui` — `third_party/`: Dear ImGui, GLFW/OpenGL3 backend'leri, ImGuiFileDialog; GLFW önce CMake paketiyle (vcpkg dahil), yoksa pkg-config ile bulunur.
- `imshark_ui` — `src/ui/`: tüm arayüz kodu (pencere açmadan test edilebilir).
- `imshark` — yalnızca `src/main.cpp` (GLFW penceresi ve döngü).
- `imshark_tests` — GoogleTest; `imshark_core` ve `imshark_ui`'ya bağlanır.

## 3. Veri modeli: `PacketInfo`

```cpp
struct Field {                       // protokol ağacının bir düğümü
    std::string text;
    uint32_t offset, length;         // çerçeve içindeki mutlak bayt aralığı
    std::vector<Field> children;
};

struct PacketInfo {                  // yüklü bir yakalamada yalnızca özet (~232 bayt)
    int number; double time;         // göreli zaman (ilk pakete göre)
    std::string source, destination, protocol, info;
    uint32_t length, link_type; uint16_t l2_size; std::vector<uint16_t> vlan_ids;
    int64_t tcp_relative_seq, tcp_relative_ack;   // yükleme sırasında hesaplanır, ayrıntıda yeniden kullanılır
    uint64_t file_offset; uint32_t captured_length;  // çerçevenin dosyadaki yeri
    std::vector<char> raw_data;      // yüklemede boş; ayrıntı kurulunca dolar
    std::vector<Field> fields;       // yüklemede boş; ayrıntı kurulunca dolar
};
```

`PacketParser::parsePacket` üç modda çalışır (`dissect::ParseMode`): **Summary** (liste sütunları, alan ağacı yok; TCP durumunu izler), **Full** (özet + ağaç, testlerde ve tek başına kullanımda) ve **Replay** (yüklü yakalamadan tek bir paket için ağaç kurar; TCP numaralarını bağlantı tablosu yerine pakette saklanan değerlerden alır). Bir testte her paket için Replay sonucunun sıralı Full ayrıştırmayla birebir aynı olduğu doğrulanır.

### Dissector'lar (`core/src/dissect/`)

```cpp
using Dissector = std::function<void(Context &ctx, const char *data, size_t length)>;

registry.registerEtherType(0x0800, dissectIPv4);      // network layer
registry.registerIpProtocol(6, dissectTcp);            // transport layer
registry.registerUdpPort(53, dissectDns);              // application layer
```

`Context`, o an çözülen `PacketInfo`'yu, çerçevenin başlangıcını (mutlak ofsetler için), TCP takip durumunu ve registry'yi taşır. Bir dissector yalnızca kendisine verilen `length` baytı okur, `ctx.addLayer()` ile alan ağacına katman ekler ve payload'ı `ctx.registry` üzerinden bir sonraki katmana verir. `PacketParser` yalnızca link katmanını (Ethernet+VLAN, NULL/Loopback, Raw, SLL/SLL2) çözer ve EtherType ile registry'ye devreder. Yeni protokol: bir `.cpp` dosyası yaz, `registry.cpp`'de kaydet (veya `Registry::builtin()` kopyasına kendi dissector'ını ekleyip `PacketParser(registry)`'ye ver).

| Dosya | Protokoller |
|---|---|
| `ip.cpp` | IPv4, IPv6 (+ uzantı başlıkları) |
| `arp.cpp` | ARP, RARP |
| `icmp.cpp` | ICMP, ICMPv6 |
| `tcp.cpp`, `udp.cpp` | TCP (bayraklar, seçenekler, bağıl seq/ack), UDP |
| `dns.cpp`, `dhcp.cpp` | DNS (sıkıştırma dahil), DHCP |
| `simple.cpp` | SNMP, Telnet, SMTP, BGP (yalnızca özet) |

### Görüntüleme filtresi (`core/src/filter/`)

`Filter::compile(text)` bir ifadeyi (`&& || ! and or not`, `== != < > <= >=`, `contains`, `matches`, `in {…}`, CIDR) ayrıştırıp değerlendirilebilir bir ağaca çevirir; hata durumunda ileti ve bayt konumu döner. Alanlar `fields.cpp`'deki sıralı bir tabloda tanımlıdır (ad, tür, özetten değer okuyan fonksiyon, açıklama) ve **yalnızca paket özetini** kullanır (`PacketInfo`'daki EtherType, IP sürümü/protokolü, TTL, TCP bayrakları, portlar, adresler, zaman…), bu yüzden bir yakalamayı filtrelemek dosyaya hiç dokunmaz. Yeni bir alan eklemek = tabloya bir satır. `!=` daima `==`'in tam olumsuzudur (alan yoksa da). Aynı motor renklendirme kurallarında ve "Paket bul" aramasında kullanılır.

## 5. Arayüz (`src/ui/`)

- `AppState` (`app_state.h`): paket özetleri, görüntü sırası, yükleme işi/durumu, seçili paket + onun ayrıntısı (`detail`), seçili alan/bayt aralığı, ayarlar; global değişken yok.
- `loader.cpp`: `LoadJob` (arka plan iş parçacığı), ilerleme popup'ı, `pollLoad` ile sonucun yayımlanması; başarısız/iptal edilen yükleme açık yakalamayı bozmaz.
- `settings.cpp`: tema, liste yüksekliği, son dosyalar (platforma göre yapılandırma klasöründe `settings.ini`).
- `clipboard.cpp`: kopyalama biçimlendirme yardımcıları (saf fonksiyonlar).
- `chrome.cpp`: ana menü (File, Ctrl+O), ImGuiFileDialog, durum çubuğu, yükleme sorunu popup'ı.
- `filter_bar.cpp`: filtre çubuğu (canlı doğrulama, geçmiş, başvuru penceresi), `applyFilter`/`refilter` görünür paket kümesini hesaplar.
- `find.cpp`/`find_bar.cpp`: Ctrl+F paket bulma (saf `findPacket` fonksiyonu + çubuk).
- `color_rules.cpp`/`color_editor.cpp`: renklendirme kuralları (filtre motoruyla eşleşir) ve düzenleme penceresi.
- `time_format.cpp`: Time sütunu biçimleri (UTC dönüşümü platformdan bağımsız).
- `packet_list.cpp`: 7 sütunlu, sıralanabilir tablo; gösterilen sıra = filtreyi geçenler + sıralama; klavyeyle gezinme; `ImGuiListClipper` ile yalnızca görünen satırlar çizilir.
- `details.cpp`: `fields` ağacı (alan tıklanınca bayt aralığı seçilir) ve hex/ASCII görünümü (bayta tıklayınca en özel alan seçilip ağaçta açılır).
- `main_window.cpp`: yerleşim ve liste/ayrıntı bölücüsü.

## 6. Mimari gözlemler

**Güçlü yanlar**
- Çekirdek UI'dan bağımsız ve testli; ayrıştırıcı sanitizer altında fuzz edilir.
- Alan ağacı sayesinde ayrıştırma ve arayüz arasındaki sözleşme net (ad + bayt aralığı).
- Bağımlılıklar az; vcpkg veya sistem paketleriyle kurulur.

**Kalan zayıf yanlar** (ayrıntı: [KNOWN_ISSUES.md](KNOWN_ISSUES.md))
- Windows derlemesi için gerekli değişiklikler yapıldı ama bir Windows makinesinde henüz doğrulanmadı.

## 7. Hedef mimari

```
libimshark (statik, UI bağımsız)         imshark (uygulama)
├─ io/       pcap_reader, pcapng_reader   ├─ app/     pencere, ana döngü
├─ dissect/  ethernet, ip, tcp, dns…      ├─ ui/      paket listesi, detay, hex
│            (registry: EtherType/IP proto/port)
└─ model/    Packet, Field (ad + ofset + uzunluk)
```

- Dissector'lar `(Context&, data, length)` alıp `PacketInfo`/`Field` üretir; protokol eklemek = tek bir dissector yazıp `Registry`'ye kaydetmek (**yapıldı**, `core/src/dissect/`).
- Yükleme arka plan iş parçacığında, paketler özet + dosya ofseti ile tutulur (**yapıldı**, v0.4).
