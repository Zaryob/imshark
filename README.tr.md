# ImShark

[English](README.md) | **Türkçe**

[![CI](https://github.com/Zaryob/imshark/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Zaryob/imshark/actions/workflows/ci.yml)
[![Release workflow](https://github.com/Zaryob/imshark/actions/workflows/release.yml/badge.svg)](https://github.com/Zaryob/imshark/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/Zaryob/imshark?include_prereleases&sort=semver)](https://github.com/Zaryob/imshark/releases)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C.svg)](CMakeLists.txt)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

[Dear ImGui](https://github.com/ocornut/imgui) ile geliştirilmiş, Wireshark'tan esinlenen bir paket analizörü. Yakalama dosyalarını açar, protokolleri ayrıştırır ve paket listesini etkileşimli protokol ağacı ile hex/ASCII görünümüyle bir araya getirir. libpcap üzerinden canlı yakalama da desteklenir.

![macOS üzerinde ImShark: koyu tema, seçili HTTP paketi, protokol ağacı ve hex görünümü](docs/images/imshark-macos.png)

*macOS (Apple Silicon) üzerinde yerel derleme; görsel, depodaki sentetik `sample.pcap` dosyasından alınmıştır.*

<details><summary>Linux (Docker, yazılım OpenGL) — arayüz yenilemesinden önceki görünüm</summary>

![Linux üzerinde ImShark: paket listesi, protokol ağacı ve hex/ASCII görünümü](docs/images/imshark-linux.png)

*Ubuntu 24.04 Docker ortamında, Mesa yazılım OpenGL ile açılan gerçek uygulama. [Tekrarlanabilir doğrulama](docs/VALIDATION.md).*

</details>

## Neler yapar?

- **Yakalama dosyaları:** pcap ve pcapng; gzip sıkıştırılmış dosyalar; Sun snoop, NetMon 2.x, Endace ERF ve AIX iptrace 2.0 okuyucuları.
- **Paket inceleme:** sıralanabilir ve renklendirilebilir liste, alanlarla eşleşen bayt vurgulama, metin/hex arama ve kopyalama.
- **Görüntüleme filtreleri:** protokol ve alan sorguları, CIDR, kümeler ve düzenli ifadeler; yazarken doğrulama ve alan başvurusu.
- **Akış ve istatistikler:** TCP/UDP Follow Stream, TCP ve IP yeniden birleştirme, konuşmalar, uç noktalar, protokol hiyerarşisi ve Expert Information.
- **TLS/DTLS:** anahtar günlüğü veya pcapng gömülü anahtarlarıyla desteklenen TLS 1.2/1.3 ve DTLS 1.2 şifre takımlarını çözme.
- **Dışa aktarma:** tüm, görüntülenen veya seçili paketleri pcap, pcapng, CSV ve JSON; akış verisini ham bayt olarak kaydetme.
- **Canlı yakalama:** arayüz seçimi, BPF filtresi, snaplen, promiscuous mode ve başlat/durdur/yeniden başlat.
- **Arayüz:** koyu ve açık tema, son dosyaları gösteren açılış ekranı, araç çubuğu, sürüklenebilir paneller; pencere boyutu ve konumu hatırlanır.

Ethernet, kablosuz, IP, DNS, HTTP, TLS, kurumsal ağ, veritabanı, USB ve Bluetooth protokolleri için ayrıntılı kapsam [destek matrisinde](docs/SUPPORT_MATRIX.md). Protokolün tanınması bütün alanlarının çözülmesi anlamına gelmez; [bilinen sınırlar](docs/KNOWN_ISSUES.md) hangi verilerin çözülemediğini açıklar.

## İndir

Son sürümü [GitHub Releases](https://github.com/Zaryob/imshark/releases/latest) sayfasından indirin: Linux x86_64 için AppImage, DEB ve tar.gz; macOS Apple Silicon için DMG; Windows x86_64 için ZIP. İndirdiğiniz dosyayı `SHA256SUMS.txt` ile doğrulayın. Yayın iş akışı paketleri yalnızca bütün platform kontrolleri geçtiğinde yayımlar. macOS uygulaması ad hoc imzalıdır, Developer ID imzası/notarization içermez (ilk açılışta Sistem Ayarları > Gizlilik ve Güvenlik > Yine de Aç ile izin verin); Windows derlemesinde canlı yakalama yoktur.

Sürümler `v0.x.y` serisi üzerinden SemVer ile ilerler (`v0.8.x` → `v0.9.x` → `v0.10.x` ...); yayın iş akışı `vMAJOR.MINOR.PATCH` tag'iyle tetiklenir. `v0.9.0` etiketi Windows (MSVC) test derlemesi yüzünden paket üretmedi; `v0.9.1` Linux GUI kontrolünde Docker Hub kesintilerine takıldı; ilk yayımlanan sürüm [`v0.9.2`](https://github.com/Zaryob/imshark/releases/tag/v0.9.2)'dir. Kalan yayın kontrolleri [yayın backlog'unda](https://github.com/Zaryob/imshark/issues/2) izleniyor; yerel test sonuçları [portföy doğrulama kaydında](docs/PORTFOLIO_VALIDATION.md).

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
| Her sürümde neyin değiştiği | [Değişiklik günlüğü](CHANGELOG.md) (İngilizce) |

## Lisans

[GPL-3.0](LICENSE). vcpkg ile getirilen bağımlılıklar kendi lisanslarına tabidir. Paketleme adımı bu bağımlılıkların lisans bildirimlerini dağıtıma ekler.
