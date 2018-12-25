# Fastnetmon Kullanımı

![fastnetmon_client_screen](../img/fastnetmon_screen.png)

Fastnetmon, açık kaynak DDOS saldırılarını izleme çözümüdür. Temel odak noktası volumetrik ataklardır.

Trafiğin **kaynak IP, hedef IP, kaynak port, hedef port ve protokol** kısımlarını tanımlar. 

Trafiği **packets/bytes/flows** olarak takip eder ve ayar dosyasında bu parametrelere verilen eşik değerleri aşıldığında uyarı ve rapor üretir. Eğer engelleme yapılacak ise engelleme script'ini çağırır.

**Desteklediği atak algılama türler**

-   **syn_flood:** TCP packets with enabled SYN flag
-   **udp_flood:** flood with UDP packets (so recently in result of amplification)
-   **icmp flood:** flood with ICMP packets
-   **ip_fragmentation_flood:** IP packets with MF flag set or with non zero fragment offset
-   **DNS amplification** (nDPI)
-   **NTP amplification** (nDPI)
-   **SSDP amplification** (nDPI)
-   **SNMP amplification** (nDPI)

Diğer özelliklerine [linkteki](https://github.com/pavel-odintsov/fastnetmon#features) listeden bakınız.

**Paket yakalama yöntemleri**

- NetFlow v5, v9
- IPFIX 
- sFlow v4 (since 1.1.3), v5
- SnabbSwitch 
- Netmap 
- PF_RING
- PF_RING Zero Copy
- PCAP
- AF_PACKET 

> **PF_RING** kullanılması durumunda kernel modülü derlenmesi gerekir.

> **PF_RING_ZC** ücret karşılığında alınabiliyor. Özel ethernet sürücüleri ve kernel modülü'nün yüklenmesi gerekir. [Bakınız.](https://www.ntop.org/products/packet-capture/pf_ring/pf_ring-zc-zero-copy/)

>**Netmap** Kernel modülü çıkartılmalı ve Ethernet sürücülerine yama yapılması gerekir. Genelde tek başına kullanıldığı durumda yapılması önerilir. Başka bileşenler ile aynı anda kullanılması normal network yapılandırmasını etkileyebilir. Desteklediği sürücüler igb, ixgbe, i40.

> Paket yakalama yöntemlerinin **lisans** ve **performans** karşılaştırma [tablosu](https://fastnetmon.com/docs/capture_backends/)'na bakınız.


## Kurulum

Aşağıdaki komut ile paket depo'dan kurulur. 

> **Note:** Ansible ile kurulum ve ayarlar için lütfen [tıklayınız](../kurulum-yonergeleri)

```
apt install fastnetmon
```

## Ayarlar
**fastnetmon.conf** dosyasındaki ayarlar aşağıdaki bölümlerden oluşur.

- Genel ayarlar
- Paket yakalama yöntemleri
- Global eşik değeri ayarları
- Ağ Grupları bazlı eşik değeri ayarları
- Atak algıldandıktan sonra yapılması gerekenler
- İstemci ayarları
- Diğer ayarlar

**Ayar dosyası:** /etc/fastnetmon/fastnetmon.conf
**networks_list_path** = /etc/fastnetmon/networks_list
**white_list_path** = /etc/fastnetmon/networks_whitelist


### Ana Konfigürasyon Parametreleri

#### 1. Syslog Ayarları

Lokal syslog servisi için aşağıdaki parametre açılır.
**logging:local_syslog_logging** = off

Uzak syslog servisi için aşağıdaki parametre açılır ve uzak syslog sunucu IP adresi ve portu tanımlanır.

**logging:remote_syslog_logging** = off

Uzak syslog sunucu IP adresi ve Portu

**logging:remote_syslog_server** = 10.10.10.10  

**logging:remote_syslog_port** = 514

> Syslog ayarları yapılmasa da **/var/log/fastnetmon.log** dosyasına olay kayıtlarını **/var/log/fastnetmon_attacks/** dizinine **atak raporlarını** ve **pcap** kayıtlarını alır.

#### 2. Global Opsiyonlar

Aşağıdaki parametre ile sistem üzerindeki IP adresler sanal IP adresleri ile birlikte otomatik olarak izlenir. Sadece Linux tabanlı sistemlerde çalışmaktadır.

**monitor_local_ip_addresses** = on


İzlenmesi istenilen IP ve ağ adresleri aşağıdaki dosya içerisine satır satır yazılır. Bu dosyada yazılacak IP ve ağ adresleri CIDR formatında yazılmalı. Örn: 192.0.2.2/32 veya 192.0.2.0/24

Bu dosyada yazılan IP adreslerini izleyerek trafiğin gelen mi giden mi olduğuna karar verir. 

**Tanımlanan IP ve ağ adresleri ağınıza ait olmalıdır.**

**networks_list_path** = /etc/fastnetmon/networks_list

network list dosyasında bulunan **alt ağlar** içirisinde **hariç** bırakılmak istenen bir IP adresi var ise bu dosyada satır satır tanımlanır.

**white_list_path** = /etc/fastnetmon/networks_whitelist

Atak algılandığında notify kabuk programını çağırarak engellenmesi için bu parametre açılır.

**enable_ban** = on

Gelen trafik için analiz yapılacak ise aşağıdaki parametre açılır.

**process_incoming_traffic** = on  

Giden trafik için analiz yapılacak ise aşağıdaki parametre açılır.

**process_outgoing_traffic** = on

Atak için kaç adet paket toplanacağı belirlenir.

**ban_details_records_count** = 500

Atak yaptığı tespit edilen IP adresinin ne kadar süre ile engelleneceği **saniye** cinsinden belirlenir.

**ban_time** = 1900

Engelleme süresi bitince engelin kaldırılması için **notify** script'i çağrılması isteniyor ise bu seçenek **off** yapılır. **on** durumunda ise atack devam ettiği sürece notify script'i çağrılmaz. **on** durumda olması önerilir.

**unban_only_if_attack_finished** = on

network_list dosyasında belirlenen her bir alt ağ için ayrı paket/bayt sayacı çalıştırmak için aşağıdaki parametre **on** yapılır.

**enable_subnet_counters** = off

**festnetmon_client** yazılımının ekranının güncellenme periyodu.

**check_period** = 1

Bağlantı izleme için bu parametre **on** yapılır. Atak algılama için çok kullanışlı bir özellik olmasına rağmen çok fazla **CPU gücü** harcadığı için **büyük** ağlarda **önerilmez**.

**enable_connection_tracking** = off

#### 3. Global engelleme ve eşik değerleri

**pps, bandwidth veya flows** eşik değerleri aşıldığında engelleme yapmak içi bu opsiyonlar açılır.

- **ban_for_pps** = on  
- **ban_for_bandwidth** = on  
- **ban_for_flows** = off  

**Global eşik değerleri**

- **threshold_pps** = 20000  
- **threshold_mbps** = 1000  
- **threshold_flows** = 3500

#### 4. Protokol bazlı atak ve engelleme ayarları
Buradaki ayarlar **Global** eşik değerlerinden **küçük** olmalıdır.
Global threshold'dan farkı protokol bazında eşik değeri aşıldığında uyarı üretir. Eğer protokol bazlı engelleme ayarları açık ise engelleme yapar. Global threshold toplam değerlere göre hareket eder.

**Eşik değeri ayarları**

- **threshold_tcp_mbps** = 100000 
- **threshold_udp_mbps** = 100000 
- **threshold_icmp_mbps** = 100000  
- **threshold_tcp_pps** = 100000  
- **threshold_udp_pps** = 100000  
- **threshold_icmp_pps** = 100000  

**Engelleme ayarları**

- **ban_for_tcp_bandwidth** = off  
- **ban_for_udp_bandwidth** = off  
- **ban_for_icmp_bandwidth** = off  
- **ban_for_tcp_pps** = off  
- **ban_for_udp_pps** = off  
- **ban_for_icmp_pps** = off

### Paket yakalama yöntemleri

>**Performans** karşılaştırma [tablosu](https://fastnetmon.com/docs/capture_backends/)'na bakınız. Ayrıca [bakınız.](https://fastnetmon.com/docs/performance_tests/)

#### Global Ayarlar

İnterface ayarlanır. Birden fazla interface için her bir interface arasına virgül (,) konulacak şekile ayar yapılır. **Örn:** eth1,eth2

**interfaces** = eth1

> İnterface desteği olan modüller: netmap, mirror, pcap, afpacket

Her bir alt ağ için trafik hızı averajı hesaplama değeri saniye cinsinden tanımlanır.

**average_calculation_time_for_subnets** = 20

#### 1. PF_RING yöntemi

PF_RING ntopng geliştiricileri tarafından geliştirilen paket yakalamak için kullanılan bir modüldür.

**mirror** = off  

**pfring_sampling_ratio** = 1

> Kullanımı için kernel modülünün derlenmesi gerekir. 

#### 2. Netmap yöntemi
Çok hızlı paket işleyebilme yeteneğine sahip açık kaynak bir uygulamadır. Bu uygulamanın çalıştırılması için kernel modülü derlenmeli ve ethernet sürücülerine yama yapılmalıdır. Desteklediği sürücüler igb, ixgbe, i40'dir.
Bu yöntemin tek başına DDOS cihazı yapılandırmasında kullanılması önerilir. Normal IP yapılandırmasını etkileyebilmektedir.

**mirror_netmap** = off  

**netmap_sampling_ratio** = 1  

**netmap_read_packet_length_from_ip_header** = off

> **netmap_read_packet_length_from_ip_header** opsiyonu sadece junniper cihazlarından yapılan mirror trafiği  var ise kullanılır. first X bytes of packet: maximum-packet-length 110;

#### 3. SnabbSwitch yöntemi
Snap switch paket yakalama yönteminin kullanılabilmesi için snabbswitch uygulamasına ihtiyaç vardır. [SnabbSwitch](https://github.com/snabbco/snabb)

Aktif etmek için off > on olarak değiştirilir.

**mirror_snabbswitch** = off

Ethernet PCI yolu tanımlanır. Bunun için **lspci | grep -i -E "ethernet|network"** komutu kullanılabilir.
Birden fazla ethernet aralarında **virgül** (,) olacak şekilde yazılır.

**interfaces_snabbswitch** = 0000:04:00.0,0000:04:00.1,0000:03:00.0,0000:03:00.1

#### 4. AF_PACKET yöntemi
Linux 3.16+ dan sonra verimli bir şekilde çalışır. Bu yöntem standart Linux dağıtımlarında en kolay kullanılabilir yöntemdir. Ek bir gereksinimi yoktur. Performans olarak **1.5-2 mpps** arasında donanım yapılandırmasına göre paket yakalayabilmektedir. 

Kolay ve verimli entegrasyon için bu yöntemin kullanılması önerilmektedir.

Çok yüksek bir performans gereksinimi var ise **PF_RING_ZC** veya **Netmap** Yöntemlerine bakınız.

Ön tanımlı olarak aktif gelmektedir.

**mirror_afpacket** = on

#### 5. PCAP yöntemi

Bu yöntemin canlı sistemlerde kullanılması **önerilmez.** Çok yavaş çalışmaktadır.

**pcap** = off

#### 6. Netflow yöntemi

Bu yöntem ile network destekli Ağ cihazlarından gönderilen veriler analiz edilerek DDoS saldırıları analiz edilir. Netflow v5, v9 ve IPFIX desteklemektedir. Ancak bu yöntemin kullanımında göndericiler(router) üzerinde gecikmeler oluştuğu için analiz gecikmeleri oluşmaktadır.

Aktif etmek için **on** yapılır.
**netflow** = off

Paketleri dinleyeceği port veya portlar tanımlanır. Birden fazla port için **virgül** (,) kullanılır.

**netflow_port** = 2055

Hangi IP adresi üzerinde dinleme yapacağı belirlenir. Bütün IP adresleri için **0.0.0.0** yazılır.

**netflow_host** = 0.0.0.0

Netflow verisi örneklem ayarıdır.

**netflow_sampling_ratio** = 1

Bazen netflow verisi çok büyük boyutlarda olabilir. Bu şekilde gelen veriyi farklı zamanlara bölerek analiz etmek için bu opsiyon aktif edilir.

**netflow_divide_counters_on_interval_length =** off

Netflow verisi için lua dilinde betik yazılarak inceleme yapılabilir. 

**netflow_lua_hooks_path** = /etc/fastnetmon/netflow_hooks.lua

#### 7. sFLOW yöntemi
sFlow yöntemi de netflow yöntemine benzer bir şekilde çalışmaktadır. Ağ cihazları üzerinden gelen verilere analiz ederek saldırı algılaması yapar. Netflow'a göre daha iyi çalışmaktadır.

Aktif etmek için **on** yapılır.

**sflow** = off

sFlow'un dinleyeceği portlar belirlenir. Birden fazla port için **virgül** (,) kullanılır.

**sflow_port** = 6343

Hangi IP adresi üzerinde dinleme yapacağı belirlenir. Bütün IP adresleri için **0.0.0.0** yazılır.

**sflow_host** = 0.0.0.0

Netflow verisi için lua dilinde betik yazılarak inceleme yapılabilir. 

**sflow_lua_hooks_path** = /usr/src/fastnetmon/src/sflow_hooks.lua

QinQ vlan protokolü incelemesini aktif etmek için **on** yapılır.

**sflow_qinq_process** = off

QinQ protokolü ethernet türü ayarlamak için aşağıdaki ayar kullanılır.

**sflow_qinq_ethertype** = 0x8100

#### 8. PF_RING_ZC(Zero Copy) 
Bu yöntem ile yüksek seviyede paket analizi yapılarak atak algılaması yapılabilir. Ancak **lisanslı** bir modüldür. PF_RING geliştiricilerinden bu lisans alındıktan sonra kernel modülü ve ethernet sürücüleri yeniden bu uygulamaya göre derlenmelidir. [Bakınız.](https://www.ntop.org/products/packet-capture/pf_ring/pf_ring-zc-zero-copy/)

Aktif etmek için **on** yapılır.

**enable_pf_ring_zc_mode** = off

### Atak algılandıktan sonra yapılacak işlemler

#### 1. Bilgilendirme betiği ayarları

Bilgilendirme/Engelleme betiğinin çalıştırılması işlemini yapar. Bu betik ile istenilen herhangi bir şey yapılabilir. Betiğe **ban** ve **unban** ile birlikte atağa ilişkin veri gönderir.

**notify_script_path** = /usr/sbin/notify_about_attack.sh

Atak ile ilgili detaylı bilgilerin script'e gönderilmesi için aktif edilir. **ban** durumunda detaylı verileri yolar ancak **unban** olduğunda atak ile ilgili detayları göndermez.

**notify_script_pass_details** = on

#### 2. PCAP ayarları

Atak ile ilgili PCAP kaydı alınması isteniyor ise bu seçenek aktif edilir. PCAP dosyaları **/var/log/fastnetmon_attacks/** dizinine kayıt edilir.

**collect_attack_pcap_dumps** = off

#### 3. NDPI ayarları

NDPI uygulama seviyesinde analiz yapılmasını sağlayan bir kütüphanedir. Bu kütüphane kullanılarak aşağıdaki türlerdeki saldırılar tespit edilmeye çalışılır. 

-   **DNS amplification**
-   **NTP amplification**
-   **SSDP amplification**
-   **SNMP amplification**

Aktif etmek için aşağıdaki seçenek **on** yapılır. 

**process_pcap_attack_dumps_with_dpi** = off

> Çalışabilmesi için **PCAP ayarlarının açık** olması gerekmektedir.

#### 4. Redis ayarları
Redis, yüksek performans sağlamak amacı ile geliştirilmiş Anahtar-Değer ikilisini saklayan bir veri tabanınıdır. Bu veri tabanının en önemli özellikleri **NoSQL** olması ve **RAM** üzerinde çalışmasıdır.

Atak algılandığında ilgili verilerin Redis veri tabanında saklanması isteniyor ise aşağıdaki ayarlar yapılır. 
Farklı uygulamalar ile entegrasyon için bu ayar yapılabilir.

Aktif etmek için **on** yapılır.

**redis_enabled** = off

Redis sunucu port ayarı.

**redis_port** = 6379

Redis sunucu IP adresi.

**redis_host** = 127.0.0.1

Redis sunucu prefix ayarı

**redis_prefix** = mydc1


#### 5. MongoDB ayarları

Redis benzeri NoSQL veri tabanı olan mongodb ile entegrasyon için aşağıdaki yapılandırma ayarları kullanılır. Redis'ten farkı verileri RAM'de değil Disk üzerinde tutmasıdır.

Aktif etmek için **on** yapılır.

**mongodb_enabled** = off

MongoDB sunucu IP adresi.
**mongodb_host** = localhost

MongoDB sunucu portu.

**mongodb_port** = 27017

MongoDB veritabanı adı.
**mongodb_database_name** = fastnetmon


#### 6. PF_RING uygulama filtresi

Eğer NDPI açık ise ve PF_RING yöntemi ile paket yakalama yapılıyor ise uygulama bazlı engelleme yapılabilir. 

**pfring_hardware_filters_enabled**  = off

> Engellemeyi kaldırmak için fastnetmon bir işlem yapmaz.

#### 6. EXA BGP ayarları
Atak algılandıktan sonra BGP protokolü kullanılarak yönlendiriciler bu durumdan haberdar edilerek null route gibi ayarların yapılmasını sağlar.

EXABGP, açık kaynak bir BGP uygulaması olup python ile geliştirilmiştir.

> Bu özelliğin çalışabilmesi için PCAP ve NDPI ayarlarının yapılmış olması gerekmektedir.

- **exabgp** = off
- **exabgp_command_pipe** = /var/run/exabgp.cmd
- **exabgp_community** = 65001:666
- **exabgp_community** = [65001:666 65001:777]
- **exabgp_community_subnet** = 65001:667
- **exabgp_community_host** = 65001:668
- **exabgp_next_hop** = 10.0.3.114
- **exabgp_announce_host** = on
- **exabgp_announce_whole_subnet** = off
- **exabgp_flow_spec_announces** = off

> Entegrasyon örnekleri için aşağıdaki adreslere bakılabilir.  
> Ayrıca **/usr/share/doc/fastnetmon** dizin altına bakılabilir.
> http://fastnetmon.com/documentation/bgp_flow_spec/
> http://fastnetmon.com/docs/exabgp_integration
> https://fastnetmon.com/fastnetmon-community-and-exabgp-without-socat/
> https://fastnetmon.com/subnet-collection-from-bgp/

#### 7. GO BGP ayarları
EXABGP alternatifi olan GOBGP isminden de anlaşılacağı gibi GO dilinde yazılmıştır.

- **gobgp** = off
- **gobgp_next_hop** = 0.0.0.0
- **gobgp_announce_host** = on
- **gobgp_announce_whole_subnet** = off

> Entegrasyon örnekleri için aşağıdaki adreslere bakılabilir.  
> Ayrıca **/usr/share/doc/fastnetmon** dizin altına bakılabilir.
> http://fastnetmon.com/docs/gobgp-integration/

#### Graphite Izleme ayarları
InfluxDB desteği ile atak ile ilgili verileri Graphite ile izlenebilir.

- **graphite** = off
- **graphite_host** = 127.0.0.1
- **graphite_port** = 2003
- **graphite_prefix** = fastnetmon


> Entegrasyon için aşağıdaki adrese veya **/usr/share/doc/fastnetmon** dizin altına bakılabilir.
> https://fastnetmon.com/docs/influxdb_integration/


### Ağ adresi Grubu tabanlı eşik değeri ayarları
Bu özellik ile her bir IP veya Ağ adresleri için farklı eşik değerleri tanımlanabilir. Engelleme yapılıp yapılmayacağı ayarlanabilir.

**hostgroup** parametresi ile grup tanımı yapılır ve grup içindeki IP/Ağ adresleri tanımlanır.

**hostgroup** = **my_hosts**:10.10.10.221/32,10.10.10.222/32

> Burada **my_hosts** tanımı sizin tarafınızdan grubu tanımlamak icin atanır. Birden fazla farklı grup için farklı isimler kullanılır.

Aşağıda görüldüğü gibi grup adı kullanılarak her bir grup için farklı ayarlar yapılabilir.

**my_hosts**_enable_ban = off
**my_hosts**_ban_for_pps = off
**my_hosts**_ban_for_bandwidth = off
**my_hosts**_ban_for_flows = off
**my_hosts**_threshold_pps = 20000
**my_hosts**_threshold_mbps = 1000
**my_hosts**_threshold_flows = 3500


### Servis Ayarları

**pid_path** parametresi bu ayar dasyasına ilişkin fastnetmon servisinin process ID dosyasıdır. Birden fazla fastnetmon ve fastnetmon ayar dosyası var ise bu dosya ismi değiştirilmelidir.

**pid_path** = /var/run/fastnetmon.pid

### Fastnetmon Istemci ayarları

**cli_stats_file_path** parametresi fastnetmon_client uygulamasının çalışabilmesi her bir farklı fastnetmon servisi için ayrı tanımlanması gerekiyor.

**cli_stats_file_path** = /tmp/fastnetmon.dat

**fastnetmon_client** yazılımı anlık trafiği izleme işlevini yerine getiren komut satırı uygulamasıdır.
Bu uygulamanın çalışma anındaki ayarları aşağıdaki gibidir.

**sort_parameter** parametresi ile fastnetmon_client yazılımında izleme yaparken verileri hangi türe göre sıralayacağı belirlenir. Desteklenen türler **packets, bytes veya flows**'dır.

**sort_parameter** = packets

**max_ips_in_list** fastnetmon_client yazılımı ile anlık izleme yaparken ekranda görüntülenecek maksimum IP adrsi sayısıdır.

**max_ips_in_list** = 7

Eğer RPC protokolü ile bir işlem yapılacak ise bu özellik açılır. (fastnetmon_api_client)
**enable_api** = off

> Yapılandırma örnekleri için bu [adrese](https://fastnetmon.com/docs/) veya **/usr/share/doc/fastnetmon** bu dizin altına bakılabilir.


**Ahtapot Projesi**

**Fatih USTA**

**fatihusta@labrisnetworks.com**
