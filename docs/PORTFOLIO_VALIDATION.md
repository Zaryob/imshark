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

## Arka plan filtre ölçümü (düzenli ifade filtreleri)

Makine: macOS 27 arm64 (Apple M4), ölçüm sırasında başka derlemelerle paylaşılan yoğun yük (load average 25-45); süreler gürültülüdür, yalnızca aynı koşudaki öncesi/sonrası karşılaştırması anlamlıdır. Capture: `python3 tools/make_bench_pcap.py --profile mixed --packets 200000 --output mixed200k.pcap` (118,2 MB, 200.000 paket). Filtre: `http.request.uri matches "^/a.*b$" || dns.qry.name matches ".*example.*"` (39.841 eşleşme).

**Önce** (Release, `bench_driver`, 0.9.2 kaynağı; filtre adımı UI iş parçacığındaki eski tek geçişle aynıdır, yani pencere bu süre boyunca donar):

```
$ bench_driver mixed200k.pcap --filter '<yukarıdaki ifade>'   (3 koşu)
packets=200000 load_ms=1808 load_peak_rss_mb=123 filter_ms=245 filter_matched=39841 peak_rss_mb=124
packets=200000 load_ms=1381 load_peak_rss_mb=124 filter_ms=272 filter_matched=39841 peak_rss_mb=124
packets=200000 load_ms=1238 load_peak_rss_mb=124 filter_ms=280 filter_matched=39841 peak_rss_mb=124
```

Daha ağır bir desen (`info matches "^(.*[0-9])+.*(Len|Win|Seq)=.*[0-9]+$"`) eski kodda `bench_driver`'ı şu çıktıyla çökertti: `libc++abi: terminating due to uncaught exception of type std::__1::regex_error: The complexity of an attempted match against a regular expression exceeded a pre-set level.` Yeni kod bu hatayı yakalar ve "eşleşmez" sayar.

**Sonra** (Debug + ASan/UBSan, aynı ifade; UI çerçeve döngüsü başsız ImGui ile çalıştırılır; `IMSHARK_BENCH_PCAP=... IMSHARK_BENCH_FILTER=... imshark_tests --gtest_filter='FilterBackground.MeasureUiThreadCost'`). Aynı koşuda eski davranışa denk tek bloklu geçiş de ölçülür:

```
MEASURE packets=200000 matched=39841 blocking_pass_ms=4772.9 background: apply_call_ms=10.77 frames_while_running=1172 longest_frame_ms=199.9 total_to_publish_ms=5069.9
```

Yorum: eskiden UI iş parçacığı `blocking_pass_ms` kadar (burada 4,8 sn) bloke olurdu. Şimdi filtreyi uygulama çağrısı 10,8 ms sürer (anlık görüntü ve tablo kopyası), filtre sürerken 1172 çerçeve çizilir; en uzun çerçeve (sonucu yayımlayan, sıralamayı yeniden kuran çerçeve dahil) 199,9 ms'dir (ASan'lı Debug). Toplam süre aynı büyüklüktedir; kazanç yanıt verebilirliktir, hız değil. Önceki sonuç, yenisi yayımlanana dek ekranda kalır.

Tasarım notları: iş parçacığı yalnızca kendi sahip olduğu paket anlık görüntüsünü, MAC/IPsec tablo kopyalarını ve değişmez derlenmiş filtreyi okur (ayrıntı/yeniden çözümleme yoktur). `std::regex` korundu: bağımlılık kümesinde (glfw, imgui, openssl, libpcap, gtest) daha güvenli bir motor yok; RE2 gibi bir bağımlılık eklemek ECMAScript sözdizimi uyumunu ve paketlemeyi bozar. Bunun yerine değerin yalnızca ilk 4096 baytı aranır ve motor hataları "eşleşmez" sayılır. Felaket geri izleme (catastrophic backtracking) tek bir satırı yine de uzatabilir; bu durumda iptal edilen iş UI'yi bloke etmeden bitene dek park edilir, ancak uygulama kapanırken bitmesini bekler.

`FilterBackground.*` testleri TSan altında (`-fsanitize=thread`) uyarısız geçti ve Debug/ASan altında `--repeat until-fail:20` ile 20 kez tekrarlandı.

**Güncelleme (güvenlik):** `matches` artık `std::regex` değil, PCRE2 (yorumlayıcı kipi, JIT yok) kullanır; her aramada eşleşme (100000), derinlik (1000) ve yığın (1 MiB) sınırı vardır. Sınırı aşan değer "eşleşmez" sayılır ve durum çubuğunda raporlanır; ilk 4096 bayt sınırı kaldırıldı (`core/src/filter/bounded_regex.h`).
