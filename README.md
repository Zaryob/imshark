# ImShark

[![CI](https://github.com/Zaryob/imshark/actions/workflows/ci.yml/badge.svg)](https://github.com/Zaryob/imshark/actions/workflows/ci.yml)

[Dear ImGui](https://github.com/ocornut/imgui) ile geliştirilmiş, Wireshark'tan esinlenen bir paket analizörü. Yakalama dosyalarını açar, protokolleri ayrıştırır ve paket listesini etkileşimli protokol ağacı ile hex/ASCII görünümüyle bir araya getirir. libpcap üzerinden canlı yakalama da desteklenir.

![Linux üzerinde ImShark: paket listesi, protokol ağacı ve hex/ASCII görünümü](docs/images/imshark-linux.png)

*Ubuntu 24.04 Docker ortamında, Mesa yazılım OpenGL ile açılan gerçek uygulama. Görsel, depodaki sentetik `sample.pcap` dosyasından alınmıştır. [Tekrarlanabilir doğrulama](docs/VALIDATION.md).*

## Neler yapar?

- **Yakalama dosyaları:** pcap ve pcapng; gzip sıkıştırılmış dosyalar; Sun snoop, NetMon 2.x, Endace ERF ve AIX iptrace 2.0 okuyucuları.
- **Paket inceleme:** sıralanabilir ve renklendirilebilir liste, alanlarla eşleşen bayt vurgulama, metin/hex arama ve kopyalama.
- **Görüntüleme filtreleri:** protokol ve alan sorguları, CIDR, kümeler ve düzenli ifadeler; yazarken doğrulama ve alan başvurusu.
- **Akış ve istatistikler:** TCP/UDP Follow Stream, TCP ve IP yeniden birleştirme, konuşmalar, uç noktalar, protokol hiyerarşisi ve Expert Information.
- **TLS/DTLS:** anahtar günlüğü veya pcapng gömülü anahtarlarıyla desteklenen TLS 1.2/1.3 ve DTLS 1.2 şifre takımlarını çözme.
- **Dışa aktarma:** tüm, görüntülenen veya seçili paketleri pcap, pcapng, CSV ve JSON; akış verisini ham bayt olarak kaydetme.
- **Canlı yakalama:** arayüz seçimi, BPF filtresi, snaplen, promiscuous mode ve başlat/durdur/yeniden başlat.

Ethernet, kablosuz, IP, DNS, HTTP, TLS, kurumsal ağ, veritabanı, USB ve Bluetooth protokolleri için ayrıntılı kapsam [destek matrisinde](docs/SUPPORT_MATRIX.md). Protokolün tanınması bütün alanlarının çözülmesi anlamına gelmez; [bilinen sınırlar](docs/KNOWN_ISSUES.md) hangi verilerin çözülemediğini açıklar.

## Hızlı başlangıç

Dear ImGui **[1.92.9b](https://github.com/ocornut/imgui/releases/tag/v1.92.9b)** ve GLFW/OpenGL3 backend’leri vcpkg üzerinden kurulur.

C++20 derleyici, CMake ≥ 3.21, Ninja, Git ve önyüklenmiş [vcpkg](https://github.com/microsoft/vcpkg) gerekir. `VCPKG_ROOT` vcpkg dizinini göstermelidir. Varsayılan derlemenin üçüncü taraf C/C++ kütüphaneleri sürümü sabitlenmiş vcpkg manifestinden kurulur; platform ön koşulları ve Windows'ta isteğe bağlı Npcap kurulumu için [derleme rehberine](docs/BUILDING.md) bakın.

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Örnek yakalamayı açın:

```sh
# Linux
./build/imshark tests/data/sample.pcap

# macOS
./build/imshark.app/Contents/MacOS/imshark tests/data/sample.pcap

# Windows (PowerShell)
.\build\imshark.exe tests/data/sample.pcap
```

`imshark --help` komut satırı seçeneklerini gösterir; `--version` ekran sunucusu olmadan çalışır.

Dosya seçici için **File > Open** (Ctrl+O; macOS'ta Cmd+O) kullanın veya bir dosyayı pencereye bırakın. Örnek dosyayı `python3 tools/make_sample_pcap.py` ile yeniden üretebilirsiniz.

Örnek görüntüleme filtreleri:

```text
tcp.port in {80 443} && !tcp.flags.rst
ip.addr == 10.0.0.0/8 && frame.len > 1000
dns or arp
tls.decrypted
```

## Belgeler

| İhtiyacınız | Belge |
|---|---|
| Platform ön koşulları, vcpkg, test ve Docker doğrulaması | [Derleme rehberi](docs/BUILDING.md) |
| Çalıştırılan kontroller ve paket doğrulama kanıtı | [Doğrulama kaydı](docs/VALIDATION.md) |
| Arayüz, filtreler, akışlar ve canlı yakalama | [Kullanım rehberi](docs/USER_GUIDE.md) |
| Kabul edilen görüntüleme filtresi alanları | [Üretilen alan başvurusu](docs/FILTER_FIELDS.md) |
| Dosya/link/protokol desteği | [Destek matrisi](docs/SUPPORT_MATRIX.md) |
| Protokol belirtimleri ve uygulama dosyaları | [Protokol referansları](docs/PROTOCOLS.md) |
| İşlevsel sınırlar ve doğrulama boşlukları | [Bilinen sorunlar](docs/KNOWN_ISSUES.md) |
| Veri akışı ve modüller | [Mimari](docs/ARCHITECTURE.md) |
| Geliştirme ve yeni dissector ekleme | [Katkı rehberi](CONTRIBUTING.md), [dissector rehberi](docs/DISSECTORS.md) |
| Sonraki öncelikler | [Yol haritası](ROADMAP.md) |

## Lisans

[GPL-3.0](LICENSE). vcpkg ile getirilen bağımlılıklar kendi lisanslarına tabidir. Paketleme adımı bu bağımlılıkların lisans bildirimlerini dağıtıma ekler.
