# ImShark Mimarisi

## 1. Genel bakış

```
 .pcap/.pcapng ──► FileProcessor ──► PacketParser ──► vector<PacketInfo> ──► ImGui arayüzü (main.cpp)
                   (core.cpp)        (packet_parser.cpp)   (bellekte)          liste / detay / hex
                                        │
                                        └─► TCPConnection (bağıl seq/ack)
```

Akış tamamen **tek iş parçacıklı ve eşzamanlıdır**: kullanıcı dosya seçtiğinde ana (UI) döngüsünde dosyanın tamamı okunur, ayrıştırılır ve `std::vector<PacketInfo>` içine konur. Sonraki her karede arayüz bu vektörü çizer.

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

- `imshark_core` — **SHARED** kütüphane. İçine yalnızca ayrıştırma kodu değil, **ImGui, GLFW backend'i ve ImGuiFileDialog** da girer; OpenGL ve GLFW (pkg-config) `PUBLIC` bağımlılıktır.
- `imshark` — `src/main.cpp`'den üretilen çalıştırılabilir dosya, `imshark_core`'a bağlanır.

## 3. Veri modeli: `PacketInfo`

```cpp
struct PacketInfo {
    int number; double time;                 // göreli zaman (ilk pakete göre)
    std::string source, destination, protocol, info;
    uint32_t length;
    std::variant<EthernetHeader> l2_header;
    std::variant<ARPHeader, IPv6Header, IPHeader> l3_header;
    std::variant<ICMPHeader, TCPHeader, UDPHeader> l4_header;
    std::variant<DHCPHeader, DNSHeader> l7_header;
    std::vector<char> raw_data;
};
```

UI, `std::visit` ile varyantları gezerek "katman ağacını" ve hex panelindeki vurgulanacak bayt aralıklarını (`packetState` haritası) üretir.

## 4. Ayrıştırma hattı

1. **Dosya türü**: `isPcapng()` ilk 4 baytı `0x0A0D0D0A` ile karşılaştırır; değilse klasik pcap varsayılır.
2. **pcap** (`processPcapFile`): 24 baytlık global header okunur, magic `0xa1b2c3d4` değilse reddedilir; sonra `PacketHeader + incl_len` bayt döngüsü.
3. **pcapng** (`processPcapngFile`): `BlockHeader` okunur, `block_type`'a göre SHB/IDB/SPB/ISB/EPB/NRB işlenir, bilinmeyen bloklar atlanır.
4. **`PacketParser::parsePacket`**: EtherType'a göre (0x0800 IPv4, 0x86DD IPv6, 0x0806 ARP, 0x8035 RARP) L3 başlığı çözülür, `parseProtocolPacket` IP protokol numarasına göre (1, 6, 17, 58) L4'e geçer.
5. **L7** yalnızca **port numarasına** bakılarak seçilir (23, 25, 179, 53, 67/68, 161/162).
6. Sonuç `PacketInfo`'ya yazılır ve vektöre eklenir.

## 5. Arayüz (`src/main.cpp`)

- `main()` → GLFW/OpenGL 3.2 core penceresi, ImGui başlatma, kare döngüsü.
- `ShowFileOpenDialog` → ana menü (File: Open / Close File / Exit) ve ImGuiFileDialog; seçilen dosyayı **doğrudan UI iş parçacığında** işler.
- `HexView` → tam pencere; içinde `displayPackets`:
  - üst bölüm: 7 sütunlu paket tablosu, çoklu seçim,
  - sürüklenebilir ayırıcı (splitter),
  - alt bölüm: `processL2/L3/L4/L7` ile doldurulan ağaç + `RenderHexEditor` (hex ve ASCII alanı, bayt aralığı seçimi/vurgulama).
- Durum **global değişkenlerde** tutulur (`packetState`, `selectedPacket`, `selected_byte*`, `selectedIndices`, `splitter_size`, `top_height`).

## 6. Mimari gözlemler

**Güçlü yanlar**
- Katmanlı dizin yapısı (l2/l3/l4/l7) ve `PacketInfo` ile ayrıştırıcı/arayüz ayrımı doğru yönde.
- Hex panelinde alan↔bayt eşlemesi, ürünün en değerli kısmı ve iyi bir temel.
- Bağımlılıklar az; vendored ImGui ile kurulum basit.

**Zayıf yanlar** (ayrıntı: [KNOWN_ISSUES.md](KNOWN_ISSUES.md))
- Çekirdek kütüphane UI'dan bağımsız değil (ImGui/GLFW `imshark_core` içinde); ayrıştırıcı tek başına test edilemez veya yeniden kullanılamaz.
- `main.cpp` monolitik ve global durumlu.
- Ayrıştırıcı güvensiz: sınır denetimi yok, ham `reinterpret_cast` ile okuma.
- Tüm dosya senkron okunur, her paket ham baytıyla birlikte RAM'de tutulur; büyük yakalamalarda UI donar.
- Test, CI ve dokümantasyon yoktu.

## 7. Önerilen hedef mimari

```
libimshark (statik, UI bağımsız)         imshark (uygulama)
├─ io/       pcap_reader, pcapng_reader   ├─ app/     pencere, ana döngü
│            (endian, tsresol, linktype)  ├─ ui/      paket tablosu, detay, hex
├─ dissect/  ethernet, ip, tcp, dns…      └─ model/   PacketStore, filtre, seçim durumu
│            (bounds-checked, registry)
└─ model/    Packet, Field tree (ofset+uzunluk)
```

- Dissector'lar `span<const uint8_t>` alıp `FieldTree` (ad, değer, bayt aralığı) üretir; UI `std::visit` yerine bu ağacı çizer.
- Dosya yükleme arka plan iş parçacığında, paketler artımlı olarak (indeks + mmap) sunulur.
- Protokol eklemek = tek bir dissector kaydetmek.
