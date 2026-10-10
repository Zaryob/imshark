# Bilinen sınırlar ve doğrulama boşlukları

Bu belge mevcut işlevsel sınırları tutar. Giderilmiş hatalar Git geçmişindedir; protokol kapsamı ve belirtimler [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) ve [PROTOCOLS.md](PROTOCOLS.md) içindedir. Sentetik testlerin geçmesi bütün gerçek yakalamaların doğru çözüldüğünü kanıtlamaz.

## HTTP, TLS ve DTLS

- **HTTP/1.x:** kapanışa kadar süren yanıtlarda başlık sonrası gövde ayrı segmentler olarak görünebilir; 4 MiB'tan büyük gövdeler arabelleğe alınmaz. HEAD yanıtı sınırlandırması sonraki mesajın başlangıcına bakar.
- **HTTP/2:** HPACK dinamik tablosu mesajlar arasında tutulmaz; önceki başlık bloklarının dinamik girişlerini kullanan başlıklar çözülemeyebilir. Aynı sınır TLS içindeki HTTP/2 için de geçerlidir.
- **TLS şifre çözme:** anahtar günlüğü veya pcapng Decryption Secrets Block gerekir. Desteklenen takımlar aşağıdaki tablodadır. Sertifika alanları gösterilir; imza ve sertifika zinciri doğrulanmaz.
- **Eksik TLS verisi:** yönün kayıt sırası kaybolduğunda sonraki kayıtlar `capture_gap` olarak bildirilir; bu yön otomatik yeniden eşitlenmez. ServerHello yoksa `no_handshake`, tablo bütçesi dolarsa `state_lost` görülebilir.
- **TLS içindeki HTTP:** uygulama ayrıştırması TLS mesajı/kaydı düzeyindedir; kayıtlara bölünmüş HTTP gövdeleri veya HTTP/2 çerçeveleri birleşmez. Bir kayıttaki ikinci HTTP mesajı gösterilmeyebilir. Ayrıntı ağacı bir TLS mesajının ilk 16 kaydını gösterir; şifre çözme tüm kayıtları işler.
- **Desteklenmeyen TLS:** TLS 1.1 ve öncesinin şifre çözümü, CBC/CCM/PSK takımları, QUIC, 0-RTT ve TLS 1.2 yeniden müzakeresi. TLS 1.3 KeyUpdate desteklenir; anahtar günlüğünün ilk trafik sırlarından sonraki nesiller türetilir.
- **DTLS:** yalnızca DTLS 1.2 AES-GCM şifre çözümü vardır. DTLS 1.0/1.3, ChaCha20-Poly1305, CBC/CCM ve Connection ID çözülmez. Yeniden müzakere/sonraki epoch anahtarları izlenmez; çözülen uygulama verisi gösterilir ama CoAP gibi iç protokollere ayrıştırılmaz. Tamamlanmış el sıkışmanın yalnızca tek parçası yeniden gelirse zaman aşımına kadar bekleyen yeni bir mesaj başlatabilir.

| Protokol | Şifre çözme kapsamı |
|---|---|
| TLS 1.2 | RSA / DHE_RSA / ECDHE_RSA / ECDHE_ECDSA ile AES-128/256-GCM ve ChaCha20-Poly1305; takım kimlikleri `009C–009F`, `C02B`, `C02C`, `C02F`, `C030`, `CCA8–CCAA` |
| TLS 1.3 | AES-128-GCM (`1301`), AES-256-GCM (`1302`), ChaCha20-Poly1305 (`1303`) |
| DTLS 1.2 | AES-128/256-GCM; takım kimlikleri `009C–009F`, `C02B`, `C02C`, `C02F`, `C030`; `CLIENT_RANDOM` anahtar günlüğü satırı |

Yanlış/eksik anahtar, desteklenmeyen takım, bozuk kayıt ve durum kaybı ayrı bildirilir. AEAD etiketi doğrulanmayan düz metin gösterilmez. TLS anahtar deposu ve oturum tabloları sınırlıdır; çok büyük anahtar günlükleri veya yakalamalar için bazı sırlar/durumlar tutulmayabilir. Pcapng sırları bölüm başına yalıtılmaz. Pcapng dışa aktarımı bütün gömülü sırları, paket alt kümesi seçilmiş olsa da, korur.

Anahtar günlüğünü değiştirmek açık dosyayı yeniden yükler. Canlı yakalamada yeni anahtarlar yalnızca sonraki paketlere uygulanır; önceki paketleri yeniden çözmek için yakalamayı kaydedip açın. Follow Stream, aynı uç noktalar arasındaki birden çok TLS bağlantısında en yeni bağlantıyı kullanır.

## Ağ ve kapsülleme

- TCP analizinin yeniden iletim/sıra dışı/ACK sezgileri Wireshark'a göre sadeleştirilmiştir; hızlı veya gereksiz yeniden iletim sınıfları ayrı değildir.
- OSPF opak LSA gövdeleri çözülmez. Kimlik doğrulama alanlarının gösterilmesi kimlik doğrulamasının doğrulandığı anlamına gelmez.
- SCTP DATA/I-DATA yeniden birleştirilir ve PPID adlandırılır; PPID'ye göre M3UA/Diameter/S1AP gibi iç dissector'lara dağıtım yapılmaz.
- UDP-Lite çözümü başlık düzeyindedir. NTP control/private ayrıntıları kısmidir.
- AH iç protokolü açar; ICV doğrulaması yapmaz. ESP varsayılan olarak şifreli etiketlenir. İsteğe bağlı ESP-NULL sezgisi bir tahmindir, şifre çözme değildir. IKE'nin şifreli yükleri ve IKEv2 parça içerikleri birleştirilmez/çözülmez.
- IEEE 802.11 korumalı veri çözülmez; WPA anahtarlarıyla şifre çözme yoktur. Desteklenmeyen link türleri ham baytlarıyla listelenir.
- Kapsüllenmiş paketlerde özet ve `ip.*`/`tcp.*` alanları en içteki çözülen başlığı yansıtır; dış katman ayrıntı ağacında kalır. MPLS filtreleri ilk iki etiketi tutar (yığın en fazla 16 etiket). GRE key/sequence filtreleri alt 16 bit ile sınırlıdır; tam 32 bit ağaçta gösterilir. Ayrı `erspan.*` filtreleri yoktur.
- LLDP'nin bazı TLV yükleri ham gösterilir; LACP Marker protokolü çözülmez. Ayrıntılı kapsam matriste belirtilir.

## Kurumsal ve veritabanı protokolleri

- SMB3 şifreli Transform içeriği çözülmez; SMB imzaları doğrulanmaz. SMB1 desteği negotiate tanımayla sınırlıdır.
- DCE/RPC taşıma/PDU ve endpoint mapper çözümü vardır; genel arayüzlere özgü NDR stub çözümü yoktur. Paket gizliliğinde mühürlü stub verisi şifreli etiketlenir.
- ONC RPC çağrı/yanıt eşleme, çok parçalı TCP kayıtları, Portmap/rpcbind/Mount sonuçları ve NFSv3 çağrı/sonuç gövdeleri desteklenir. NFSv4.0/4.1 COMPOUND işlem dizileri çözülür; desteklenmeyen işlem veya attribute düzeninde güvenli biçimde durur. NFSv4.1 pNFS aygıt/layout gövdeleri, GET_DIR_DELEGATION ve NFSv4.2 işlemleri tam çözülmez; NLM/NSM gövdeleri ve RPCSEC_GSS şifreli içerik çözülmez. Eşleme için çağrının yakalamada bulunması gerekir; durum tabloları bellek bütçesiyle sınırlıdır.
- PostgreSQL ve MySQL oturum tablosu (`db_session.cpp`): PostgreSQL Parse/Bind/Describe/Execute/Close ifadeleri ve sorgu eşlemesi, Bind parametreleri, tiplendirilmiş DataRow değerleri ve metin/ikili COPY imzası desteklenir. MySQL uçuştaki komut aşamaları, metin ve ikili sonuç kümesi satırları, COM_STMT_PREPARE sorgu eşlemesi ve tiplendirilmiş parametreler çözülür. Durum tabloları bütçe ve sınır korumalıdır (en çok 256 ifade, 64 portal, 1024 bayt sorgu metni, değer başına 64 karakter); bütçe aşımında ham/türsüz gösterim korunur. COM_STMT_FETCH (imleçli okuma), sıkıştırılmış MySQL protokolü ve binary COPY alan ayrıştırması çözülmez.
- TDS sonuç token akışı (COLMETADATA/ROW/DONE) yoktur. TLS-in-TDS el sıkışması Pre-Login içinde sarılıdır ve anahtar günlüğüyle şifre çözme yoluna verilmez. Login7 parolası maskelenir.
- LDAP StartTLS, PostgreSQL SSLRequest ve MySQL SSLRequest sonrası TLS geçişi izlenir; şifre çözme yukarıdaki TLS sınırlarına tabidir. Kerberos şifreli gövdeleri ve SNMPv3 özel içerik çözülmez.

## USB, Bluetooth, VoIP ve endüstriyel protokoller

- USB Linux usbmon/USBPcap başlıkları ve standart GET_DESCRIPTOR tamamlanmaları çözülür. Isochronous tanımlayıcılar ve HID/kütle depolama gibi sınıfa özgü yükler çözülmez. İlgili istek yakalanmamışsa tamamlanma tanımlayıcıları açılamayabilir.
- Bluetooth H4 ve Linux Monitor desteklenir; HCI pseudo-header (201), USB-HCI, L2CAP yeniden birleştirme/sinyalleşme ve SDP yoktur. ATT yalnızca temel alanları gösterir. H4 ACL yönü kayıtta bulunmadığı için varsayımsaldır; BD_ADDR eşlemesi bağlantı olayının yakalanmasına bağlıdır.
- IEEE 802.15.4 MAC çözümü sınırlıdır; adres/güvenlik ayrıntıları, 6LoWPAN ve Zigbee yoktur.
- SIP Call-ID oturum tablosu ve SDP'den RTP portu çıkarımı yoktur. RTP/RTCP yalnızca **Decode As** ile erişilir; RTP uzantı/dolgu ve RTCP SR/RR gövdeleri çözülmez. RTSP ilk satırla sınırlıdır.
- Modbus/TCP MBAP ve işlev/istisna kodlarını gösterir; yazmaç/bobin çözümü yoktur. DNP3 başlık/veri CRC'lerini denetler ama nesneleri ve taşıma parçalarını birleştirmez. SocketCAN/CAN FD başlıkları gösterilir.
- SIP, RTP, RTCP, RTSP, Modbus, CAN, ATT ve 802.15.4 için özel görüntüleme filtresi alanları yoktur. DNP3 için protokol varlığı ve CRC durum alanları vardır. Kabul edilen kesin liste [FILTER_FIELDS.md](FILTER_FIELDS.md) içindedir.

## Dosya biçimleri ve dışa aktarma

- Snoop yalnızca sürüm 2, NetMon yalnızca 2.x, iptrace yalnızca 2.0 alt kümesini okur. NetMon dosya sonu çerçeve tablosu kesilmişse önceki paketler de yüklenemez; başlıktaki SYSTEMTIME UTC kabul edilir. Metaveri tablolarının çoğu okunmaz.
- ERF sayaç/META kayıtlarını atlar; bazı taşıma türleri ham veridir. İlk kayıtla sezgisel tanıma bozuk bir dosyayı yanlışlıkla ERF sayabilir. Ethernet FCS uzunluğu bilinmez.
- AIX iptrace yerleşimi gerçek AIX çıktısıyla doğrulanmamıştır; bu okuyucunun sonuçlarına özellikle temkinli yaklaşılmalıdır. Eşlenemeyen ortamlar desteklenmeyen link türü olarak korunur.
- Pcap/pcapng dışa aktarımı mikro-saniye çözünürlüğündedir; nanosaniye girişin son üç hanesi korunmaz. Klasik pcap tek link türü taşır ve pcapng metaverisini/gömülü sırlarını korumaz.

## Arayüz, canlı yakalama ve bellek

- Düzenli ifade (`matches`) filtreleri UI iş parçacığında çalışır; büyük yakalamada gecikmeye yol açabilir. Filtreler özet alanlarını kullanır, ayrıntı ağacındaki her alan süzgeçlenemez.
- IP adresleri metin olarak sıralanır. ImGui pencere yerleşimi ve Decode As kuralları oturumlar arasında saklanmaz.
- Canlı yakalama tek arayüz/tek link türüdür ve geçici klasik pcap yazar; pcapng açıklama/ISB metaverisi yoktur. Yakalama sırasında arka plan işler başladıkları andaki paket listesinin görüntüsünü kullanır. Decode As için yakalamayı durdurup dışa aktarılan dosyayı açın.
- Gzip yakalamalar en çok min(16 GiB, geçici klasördeki boş disk − 1 GiB) boyuta açılır; 1 GiB'tan sonra 1000:1'i aşan genişleme de reddedilir. Meşru ama çok sıkışan büyük bir dosya bu yüzden açılmayabilir; dosyayı harici bir araçla açıp doğrudan yükleyin. Çökmeyle sonlanan bir oturumun özel geçici klasörü silinmez.
- 64 bit paket özeti libc++ ile 336, libstdc++/MSVC ile 384 bayttır; metinler, adres/oturum tabloları ve yeniden birleştirme tamponları bunun üstüne eklenir. Çok büyük yakalamalarda durum tabloları bütçe dolması nedeniyle eksik ilişkilendirme bildirebilir. Tek bir sentetik performans sonucu bütün protokollerin bellek/hız garantisi değildir.

## Doğrulamanın kapsamı

- Birim testleri bağımsız vektörler, kesme/bayt bozma taramaları, Replay eşitliği ve pencere açmayan ImGui testleri içerir. Ayrı bir libFuzzer harness'i yoktur; sanitizer sonucu yalnızca çalıştırılan girdiler için kanıttır.
- Gerçek corpus dosyaları `IMSHARK_CORPUS_DIR` verilmediğinde atlanır. Birçok gelişmiş protokol ve eski dosya biçimi yalnızca sentetik girdilerle sınanmıştır; [katkı rehberi](../CONTRIBUTING.md#regression-corpus) bu ayrımı açıklar.
- `tests/data/tshark` içindeki elle yazılmış JSON'lar karşılaştırma aracını sınar. Bunlar gerçek tshark kaydı veya Wireshark ile eşitlik kanıtı değildir.
- Linux Docker duman testi bir yazılım OpenGL/Xvfb ortamını kullanır. Fiziksel ağ arayüzü, Npcap sürücüsü, gerçek masaüstü etkileşimleri ve hardware GPU doğrulamasının yerini tutmaz.
- Windows canlı yakalama ve temiz makinede paket çalıştırma ayrıca doğrulanmalıdır. macOS dağıtımı ad hoc imzalıdır; Developer ID/noter onayı yoktur.

Tekrarlanabilir derleme, test ve Docker komutları [BUILDING.md](BUILDING.md) içindedir. Güncel test sayısı, atlanan kontroller ve derlenen özellikler çalıştırmanın loglarından okunmalıdır; burada sabit bir kapsam yüzdesi veya test sayısı verilmez.
