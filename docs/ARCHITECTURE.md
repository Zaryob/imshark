# ImShark mimarisi

ImShark'ın çekirdeği pencere sisteminden bağımsızdır. Aynı okuyucu, dissector ve filtre motoru masaüstü uygulamasında, başsız araçlarda ve testlerde kullanılır.

```text
Yakalama dosyası / canlı yakalama
              │
              ▼
        FileProcessor ──► CaptureFileReader (dosya biçimi)
              │
              ▼
         PacketParser ──► Registry ──► dissector'lar
              │                           │
              ▼                           ▼
     PacketInfo özetleri             SessionTables
              │                           │
              ├──► filtre / istatistik     │
              └──► seçili paket ──► Replay ┘
                          │
                          ▼
                  alan ağacı + ham baytlar
                          │
                          ▼
                    Dear ImGui arayüzü
```

## Derleme hedefleri

| Hedef | Sorumluluk |
|---|---|
| `imshark_core` | Statik, UI bağımsız okuyucu, ayrıştırıcı, filtre, istatistik, akış, dışa aktarma ve canlı yakalama kütüphanesi |
| `imshark_imgui` | vcpkg'den gelen Dear ImGui, GLFW/OpenGL3 backend'leri ve ImGuiFileDialog bağlantıları |
| `imshark_ui` | `src/ui/`: uygulama durumu ve pencere açmadan test edilebilen arayüz bileşenleri |
| `imshark` | `src/main.cpp`: GLFW/OpenGL başlatma, ana döngü ve kapanış |
| `imshark_tests` | Çekirdek ve arayüz için GoogleTest testleri |
| `imshark_dump` | Başsız JSON alan dökümü; tshark karşılaştırmasının ImShark tarafı |
| `bench_driver` | İsteğe bağlı yükleme/filtre performans ölçümü |

Bağımlılıklar [vcpkg manifesti](../vcpkg.json) ile yönetilir; derleme seçenekleri [BUILDING.md](BUILDING.md) içinde açıklanır.

## Okuma ve veri modeli

`core/src/io/` içindeki `CaptureFileReader` arayüzünü pcap, pcapng, snoop, NetMon, ERF ve iptrace okuyucuları uygular. `format_registry` dosyanın içeriğinden uygun okuyucuyu seçer. Gzip, uygulamanın yükleyicisinde geçici dosyaya açılan bir sarmalayıcıdır; `FileProcessor::processFile` doğrudan gzip açmaz.

Geçici dosyalar (`core/src/temp_file.{h,cpp}`): her işlem, `temp_directory_path()` altında `mkdtemp` ile (POSIX, kip 0700; Windows'ta kullanıcıya özel `%TEMP%` altında rastgele adlı klasör) tek bir özel klasör oluşturur. Canlı yakalama pcap'i ve açılmış gzip kopyası bu klasörde `O_CREAT|O_EXCL|O_NOFOLLOW`, kip 0600 (Windows'ta `CREATE_NEW`) ile oluşturulur; böylece önceden yerleştirilmiş sembolik bağlar izlenmez ve içerik diğer kullanıcılara açılmaz. Dosya oluşturulup kapatılır, sonra yalnızca sahibinin girebildiği klasörde `std::ofstream` ile yeniden açılır. Klasör normal çıkışta silinir (en iyi çaba); çöküşte kalan klasörler temizlenmez. Gzip açma çıktısı `GunzipLimits` ile sınırlıdır: varsayılan en çok min(16 GiB, boş disk − 1 GiB) ve 1 GiB'ı aştıktan sonra 1000:1 genişleme oranı; aşılırsa kısmi dosya silinir.

`FileProcessor` biçimden bağımsız yükleme döngüsünü, zaman damgalarını, yakalama metaverisini ve paket başına ayrıştırmayı yönetir. Yükleme sırasında yalnızca `packet::PacketInfo` özetleri bellekte kalır; ham baytlar dosyada tutulur. `PacketInfo` boyutu kaynakta `kPacketInfoSizeBudget` ve `static_assert` ile sınırlandırılır. 64 bit derlemelerde mevcut boyut libc++ ile 336 bayt, libstdc++/MSVC ile 384 bayttır; standart kütüphanelerin metin nesnesi boyutları farklıdır. Dinamik metinler ve oturum tabloları ek bellek kullanır; bu sayı paket başına toplam bellek değildir.

Bir paket seçilince `CaptureReader` dosya ofsetinden baytları okur, `buildPacketDetails` alan ağacını yeniden oluşturur. `packet::Field` bir metin, çerçeve içindeki bayt aralığı ve alt düğümlerden oluşur. Türetilmiş alanların uzunluğu sıfır olabilir. Birleştirilmiş/verisi çözülmüş yükler ayrı katmanlar olarak gösterilir; bu yüklerdeki ofsetler ham çerçeve ofsetleriyle karıştırılmamalıdır.

## Ayrıştırma ve oturum durumu

`PacketParser` link katmanını açar ve yükü `dissect::Registry` üzerinden EtherType, IP protokolü, port veya içerik tanıma kurallarına devreder. **Decode As** kullanıcı tarafından seçilen TCP/UDP port eşlemelerini uygular. Dissector'lar `Context &`, veri işaretçisi ve sınırlandırılmış uzunluk alır.

Üç ayrıştırma modu vardır:

- **Summary:** sıralı yükleme geçişi; liste/filtre bilgileri üretilir, alan ağacı kurulmaz.
- **Full:** özet ve alan ağacı birlikte üretilir; testlerde ve bağımsız ayrıştırmada kullanılır.
- **Replay:** yüklü yakalamanın tek bir paketinin ayrıntıları, yükleme geçişinde saklanan kararlarla yeniden kurulur.

Önceki paketlere bağlı kararlar yükleme geçişinde alınır. `SessionTables` TLS anahtar/şifre çözme sonuçlarını, protokol yükseltmelerini, istek/yanıt ilişkilerini ve dinamik portları tutar. Replay bu tabloları yalnızca okur; dondurulmuş tablolara yazılmaz. Durum tablolarının bellek bütçesi dolduğunda durum kaybı bildirilir.

`network/` TCP sıra/ACK analizi ve IP/datagram yeniden birleştirmeyi sağlar. TCP mesaj çerçeveleyicileri ve `StreamProtocol`, birden çok segmente yayılan uygulama mesajlarını dissector'lara sunar. Replay'in yükleme geçişiyle eşitliği stateful protokol testleriyle denetlenir. Yeni protokol için [DISSECTORS.md](DISSECTORS.md) temel sözleşmedir.

## Filtre, istatistik ve akış

`core/src/filter/` ifadeyi derler ve paket özetleri üzerinde değerlendirir; sıradan filtreleme paket baytlarını dosyadan okumaz. Alanlar `core/src/dissect/*_fields.cpp` modüllerinden açık bir kayıt sırasıyla eklenir. Yerleşik alan tablosu kullanım öncesinde oluşturulur ve sonrasında değişmez. `docs/FILTER_FIELDS.md` bu tablodan üretilir ve testle karşılaştırılır.

`core/src/stats/` özetlerden hiyerarşi, konuşma, uç nokta ve Expert Information üretir. Ethernet adres tablosu gibi bağlamsal kayıtlar gerektiğinde filtre/istatistik bağlamına aktarılır. `core/src/stream/` Follow TCP/UDP Stream ve çözülen TLS uygulama verisini oluşturur. Baytlarda arama, Follow Stream ve dışa aktarma `CaptureReader`/`scanPackets` altyapısını kullanır.

`core/src/export/` pcap/pcapng veya liste sütunlarını CSV/JSON olarak yazar. Pcapng dışa aktarımı gömülü TLS sırlarını korur; sır içeren dosyalar paylaşılırken bunu dikkate alın.

## Arayüz ve iş parçacıkları

`ui::AppState` uygulama durumunu taşır. `PacketList` arka plan işlerine değişmez bir anlık görüntü (`share()`) verir; görünen liste UI iş parçacığında güncellenir. Yükleme, baytlarda arama, Follow Stream ve dışa aktarma işleri ilerleme ve iptal mekanizmaları kullanır. Yakalama değişmeden önce ilgili işler durdurulur.

| Dosya grubu (`src/ui/`) | İşlev |
|---|---|
| `loader`, `live_capture` | Dosya yükleme ve artımlı canlı yakalama |
| `chrome`, `main_window` | Menü/diyaloglar, durum çubuğu ve ana yerleşim |
| `packet_list`, `details` | Kırpılmış satır çizimi, seçim, protokol ağacı ve hex/ASCII görünümü |
| `filter_bar`, `find*`, `color*` | Filtre, arama ve renklendirme |
| `stats_windows`, `follow*` | İstatistik ve akış pencereleri |
| `export_dialog`, `capture_info_window`, `preferences` | Dışa aktarma, metaveri ve TLS anahtar ayarları |
| `settings`, `clipboard`, `time_format` | Kalıcı ayarlar ve saf biçimlendirme yardımcıları |

Canlı yakalama çekirdeği `core/src/capture/` altında libpcap kullanır; paketleri geçici pcap dosyasına yazıp aynı paket başı ayrıştırma yoluna verir. Canlı yakalama yetki gereksinimleri ve platformlar arası geçici ayrıcalık mimarisi [CAPTURE_PRIVILEGES.md](CAPTURE_PRIVILEGES.md) belgesinde ayrıntılı olarak açıklanmaktadır. TLS/DTLS şifre çözme çekirdeği `core/src/tls/` altında OpenSSL libcrypto kullanır. Bu özelliklerin kapalı derlemeleri aynı arayüzün kullanılabilirlik bildiren uygulamalarını sağlar.
