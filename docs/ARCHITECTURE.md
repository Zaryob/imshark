# ImShark Mimarisi

## 1. Genel bakış

```
 .pcap/.pcapng ──► FileProcessor ──► PacketParser ──► vector<PacketInfo> ──► ImGui arayüzü (main.cpp)
                   (core.cpp)        (packet_parser.cpp)   (bellekte)          liste / detay / hex
                                        │
                                        └─► TCPConnection (bağıl seq/ack)
```

Akış hâlâ **tek iş parçacıklı ve eşzamanlıdır**: kullanıcı dosya seçtiğinde ana (UI) döngüsünde dosyanın tamamı okunur, ayrıştırılır ve `std::vector<PacketInfo>` içine konur. Sonraki her karede arayüz bu vektörü çizer.

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
    uint32_t offset, length;         // raw_data içindeki mutlak bayt aralığı
    std::vector<Field> children;
};

struct PacketInfo {
    int number; double time;         // göreli zaman (ilk pakete göre)
    std::string source, destination, protocol, info;
    uint32_t length;
    uint32_t link_type; uint16_t l2_size; std::vector<uint16_t> vlan_ids;
    std::variant<...> l2_header, l3_header, l4_header, l7_header;   // ham başlık kopyaları
    std::vector<char> raw_data;
    std::vector<Field> fields;       // Frame, Ethernet, IP, TCP/UDP, DNS … (en dıştan içe)
};
```

Arayüz artık `fields` ağacını çizer; başlık `variant`'ları yalnızca testler ve özet hesapları için tutulur.

## 4. Ayrıştırma hattı

1. **Dosya türü** (`ui/loader.cpp`): ilk 4 bayt `0x0A0D0D0A` ise pcapng, değilse klasik pcap.
2. **pcap** (`processPcapFile`): magic'ten byte order ve mikro/nano-saniye belirlenir; her kayıt dosya boyutuna ve üst sınıra karşı doğrulanır; link type her pakete yazılır.
3. **pcapng** (`processPcapngFile`): her blok tamamen belleğe alınıp sınır denetimli okunur. SHB byte order'ı, IDB link type ve `if_tsresol`'u, EPB `captured_length`'i, SPB içeriği işlenir; diğer bloklar atlanır. Hatalı kuyruğa kadar okunan paketler korunur.
4. **`PacketParser::parsePacket`**: link type'a göre (Ethernet+VLAN, NULL/Loopback, Raw, SLL/SLL2) L3'ün başlangıcı ve protokolü bulunur; EtherType'a göre IPv4/IPv6 (uzantı başlıkları dahil)/ARP çözülür, `parseProtocolPacket` IP protokol numarasına göre (1, 6, 17, 58) L4'e geçer. Her okuma uzunluk denetimlidir.
5. **L7** yalnızca **port numarasına** bakılarak seçilir (23, 25, 179, 53, 67/68, 161/162).
6. Sonuç `PacketInfo`'ya yazılır ve vektöre eklenir.

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

## 5. Arayüz (`src/ui/`)

- `AppState` (`app_state.h`): paketler, yükleme durumu, seçili paket/alan/bayt aralığı, bölücü yüksekliği; global değişken yok.
- `chrome.cpp`: ana menü (File, Ctrl+O), ImGuiFileDialog, durum çubuğu, yükleme sorunu popup'ı.
- `packet_list.cpp`: 7 sütunlu tablo, `ImGuiListClipper` ile yalnızca görünen satırlar çizilir.
- `details.cpp`: `fields` ağacı (alan tıklanınca bayt aralığı seçilir) ve hex/ASCII görünümü (bayta tıklayınca en özel alan seçilip ağaçta açılır).
- `main_window.cpp`: yerleşim ve liste/ayrıntı bölücüsü.

## 6. Mimari gözlemler

**Güçlü yanlar**
- Çekirdek UI'dan bağımsız ve testli; ayrıştırıcı sanitizer altında fuzz edilir.
- Alan ağacı sayesinde ayrıştırma ve arayüz arasındaki sözleşme net (ad + bayt aralığı).
- Bağımlılıklar az; vcpkg veya sistem paketleriyle kurulur.

**Kalan zayıf yanlar** (ayrıntı: [KNOWN_ISSUES.md](KNOWN_ISSUES.md))
- Dosya tamamen eşzamanlı yüklenir; her paket ham baytıyla RAM'de tutulur (v0.4).
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
- Yükleme arka plan iş parçacığında, paketler indeks + `mmap` ile tembel okunur (v0.4).
