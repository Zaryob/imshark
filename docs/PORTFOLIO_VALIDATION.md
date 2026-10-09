# Portföy için yerel doğrulama kaydı

**9 Ekim 2026, Europe/Istanbul.** Kaynak commit: `64c36b5eb0e633dfcfc04736a33f21f2a807d0af` (manifest 0.8.2). Bu PR üretim kodunu veya testleri değiştirmez. Önceki [VALIDATION.md](VALIDATION.md) kaydının tarihsel kapsamını korur; onun sonucunu yeni sürüme genellemez.

Ortam: macOS 27.0 arm64, Apple M4 / 16 GiB, Xcode 27.0 / Apple Clang 21.0.0. vcpkg manifest baseline: `2750401336fb7c95f6619657a46a7e798661341c`. vcpkg aracı 2026-09-26 sürümü; üçüncü taraf bağımlılıkların derleme önbelleği kullanılabilir. Debug derlemede ASan + UBSan açık, TLS decryption ve live capture derleme seçenekleri açıktı.

```sh
# VCPKG_ROOT: önyüklenmiş vcpkg checkout'unuzun yolu
cmake --preset debug -DIMSHARK_SANITIZE=ON -DIMSHARK_BUILD_BENCH=ON
cmake --build --preset debug --parallel 6
ctest --preset debug --parallel 1 --output-on-failure
```

| Kontrol | Gerçek sonuç |
| --- | --- |
| Debug + ASan/UBSan derleme | Başarılı |
| İlk CTest koşusu, parallel 2 | 1.295 kayıtlı test: 1.244 geçti, 23 başarısız, 28 atlandı |
| Başarısız testleri seri tekrar | 23/23 geçti |
| Tam paketi seri tekrar | **1.267 geçti, 0 başarısız, 28 atlandı**; 302,62 saniye |
| Karışık sentetik fixture ile benchmark aracının işlev kontrolü | 10.000 paket yüklendi, filtre 1.961 eşleşme buldu; başarılı çıkış |

Paralel koşunun başarısızlıkları capture-reader, fragment, gzip ve stream fixture testlerindeydi. Bunların sabit geçici dosya adlarını paylaşması çakışma ihtimalini ortaya koyuyor; seri tekrarın geçmesi üretim kodunda 23 ayrı hata bulunduğu anlamına gelmez. Test izolasyonu ayrıca ele alınmalıdır. Test başına terminal çıktıları depoda tutulmaz; yukarıdaki komutlarla yerel loglar yeniden üretilebilir.

Bu seri koşuda ASan/UBSan tanısı gözlenmedi. Bu, çalıştırılan girdilerle sınırlıdır. Atlanan 28 test; isteğe bağlı gerçek capture'lar, bu derlemede geçerli olmayan backend/stub kontrolleri, loopback live-capture testi ve `tshark` karşılaştırmasını içerir. `tshark` kurulu değildi; karşılaştırma başarısı iddia edilmez. Ayrı bir uzun süreli fuzzer, Windows runtime, imzalı macOS kurulum, gerçek ağ yakalama veya tüm protokollerin uygunluğu doğrulanmadı.

## Ölçümün yeniden üretilmesi

```sh
python3 tools/make_bench_pcap.py --profile mixed --packets 10000 --output /tmp/imshark-bench-smoke.pcap
build-debug/bench_driver /tmp/imshark-bench-smoke.pcap --filter 'udp && ip.addr == 8.8.8.8'
```

Generator'ın `mixed` profili varsayılan seed 1 kullanır. Bu koşudaki dosya 6212628 bayt; SHA-256 `bd3960acc8a7cbec9ea80cd1bb082c884c5dcfa181e185b27ddad98dcdf73c03`. Capture dosyası commit edilmez. Benchmark aracının çıktısı terminalden alınır; ayrı bir `.txt` dosyası commit edilmez. Debug + sanitizer, küçük sentetik veri ve yoğun paylaşılan host nedeniyle bu süreler **ürün performansı/throughput benchmark'ı değildir**. Release karşılaştırmalarında derleme ayarlarını, fixture hash'ini, gerçek capture kapsamını, çoklu tekrarları ve ortamı ayrıca kaydedin. Mevcut `tools/benchmark.py` çalışma yolunu koruruz.

## Yayın engelleri

Denetimde yayımlanmış GitHub Release veya hazır binary yoktu. [İncelenen release çalışması](https://github.com/Zaryob/imshark/actions/runs/37850000156) başarısız: Windows MSVC derlemesinde `PacketInfo` union/anonymous-struct varsayılan alan başlatıcıları; Linux debug koşusunda SCTP I-DATA retransmission testi. Bu yerel macOS sonucu o platformları yeşil kabul ettirmez. [#2](https://github.com/Zaryob/imshark/issues/2) bu engelleri kapatmadan yeni tag/binary yayımlanmaz. Yerel parser/evidence ve test izolasyonu [#1](https://github.com/Zaryob/imshark/issues/1) ile izlenir.
