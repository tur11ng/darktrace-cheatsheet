---
description: >-
  DarkTrace Advanced Search cheatsheet for investigating and hunting malicious
  network activity, but also for detecting common network misconfigurations.
---

# Advanced Search Cheatsheet

## General

* Ingress traffic

{% code overflow="wrap" %}
```
@fields.source_ip:(NOT(10.* OR 192.168.* OR /fd00:.*/ OR /172\.1[6-9]\..+/ OR /172\.2[0-9]\..+/ OR /172\.3[0-1]\..+/)) AND @fields.dest_ip:(10.* OR 192.168.* OR /fd00:.*/ OR /172\.1[6-9]\..+/ OR /172\.2[0-9]\..+/ OR /172\.3[0-1]\..+/)
```
{% endcode %}

* Queries for specific VSensor

```
@fields.uid:*01 OR @fields.uid:*02
```

* Blocked traffic by Respond

```
@type:conn AND (@fields.history:*g* OR @fields.history:*G*)
```

## Compliance

### Misconfigurations

* Reverse DNS

{% code overflow="wrap" %}
```
@fields.query_type:"PTR" AND @fields.query:(/.*\.10.in-addr.arpa/ OR /.*\.168\.192.in-addr.arpa/ OR /.*\.[23][0-9]\.172.in-addr.arpa/ OR /.*\.1[6789]*\.172.in-addr.arpa/)
```
{% endcode %}

* Web Proxy Auto-Discovery Protocol (WPAD)

```
/*wpad*/
```

* Query to detect Darktrace packet loss/drop

```
@fields.note:"CaptureLoss::Packet_Drops" AND @fields.size:>29 AND @fields.msg:*dt*
```

* Invalid HTTP Proxy Traffic

```
@fields.method:"CONNECT" AND NOT @fields.dest_ip:"<http_proxy_ip"
```

* Unsual/Error Messages

```
@type: messages
```

* TCP Connections with Retransmit (R) flag set

```
@type:conn AND @fields.history:"*R*R*R*"
```

```
@type:conn AND @fields.history:"*R*R*R*R*"
```

```
@type:conn AND @fields.history:"*R*R*R*R*R*"
```

* Insecure SSL/TLS Ingress Traffic

{% code overflow="wrap" %}
```
@type:ssl AND  AND @fields.version:(TLS1.1 OR TLS1.0 OR SSL2 OR SSL3)
```
{% endcode %}

* Insecure SSL/TLS Cipher Suites

<pre data-overflow="wrap"><code><strong>@fields:ssl AND @fields.cipher:"TLS_RSA_EXPORT_WITH_RC4_40_MD5 OR TLS_RSA_WITH_RC4_128_MD5 OR TLS_RSA_WITH_RC4_128_SHA OR TLS_RSA_WITH_DES_CBC_SHA OR TLS_RSA_WITH_3DES_EDE_CBC_SHA OR TLS_RSA_WITH_AES_128_CBC_SHA OR TLS_DH_RSA_WITH_AES_128_CBC_SHA OR TLS_DH_anon_WITH_RC4_128_MD5 OR TLS_DH_anon_WITH_AES_128_CBC_SHA OR TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 OR SSL_RSA_WITH_RC4_128_MD5 OR SSL_RSA_WITH_RC4_128_SHA OR SSL_RSA_WITH_DES_CBC_SHA OR SSL_RSA_WITH_3DES_EDE_CBC_SHA OR SSL_RSA_WITH_AES_128_CBC_SHA OR SSL_DH_RSA_WITH_AES_128_CBC_SHA OR SSL_DH_anon_WITH_RC4_128_MD5 OR SSL_DH_anon_WITH_AES_128_CBC_SHA OR SSL_DH_anon_EXPORT_WITH_RC4_40_MD5"
</strong></code></pre>

* Internal Plaintext HTTP traffic

{% code overflow="wrap" %}
```
@type:conn AND @fields.local_resp:true AND @fields.local_orig:true AND (@fields.dest_port:(80 OR 8080 OR 8000 OR 8008) OR @fields.source_port:(80 OR 8080 OR 8000 OR 8008)) AND NOT @fields.service:ssl
```
{% endcode %}

### Remote Desktop Services

* TeamViewer

{% code overflow="wrap" %}
```
(@fields.dest_port:"5938" AND @fields.local_resp:"false") OR (@fields.host: /.*teamviewer.*/ OR @fields.server_name: /.*teamviewer.*/ OR @fields.query: /.*teamviewer.*/ ) OR /.*[Dd]yngate.*/
```
{% endcode %}

* Anydesk

{% code overflow="wrap" %}
```
@fields.dest_port:(80 443 6568) OR (@fields.dest_ip:239.255.102.18) OR (@fields.src_ip:239.255.102.18) OR /*.net.anydesk.*/
```
{% endcode %}

* ScreenConnect

```
@fields.dest_port:(8040 8041) OR @fields.src_port:(8040 8041)
```

* VNC

{% code overflow="wrap" %}
```
@fields.src_port:(5901 OR 5902 OR 5903 OR 5904 OR 5905 OR 5906 OR 5907 OR 5908 OR 5909 OR 5910) OR @fields.src_port:(5900 OR 5901 OR 5902 OR 5903 OR 5904 OR 5905 5906 OR 5907 OR 5908 OR 5909 OR 5910)
```
{% endcode %}

* RDP

```
@fields.src_port:3389 OR @fields.dest_port:3389
```

### Insecure Protocols/Traffic

* SMB Version 1

```
@type:smb_session AND @fields.protocol_ver:smb1
```

* Unencrypted LDAP Bind Request

```
@type:ldap_bind AND @fields.password_seen:true

```

* LDAP Traffic containing password

<pre><code><strong>_exists_:"@fields.password_seen"
</strong></code></pre>

* Passwords in URI (Internal or External)

{% code overflow="wrap" %}
```
NOT @type:"messages" AND @type:"http" AND @fields.uri: /.*assword=[^&].*/
AND @fields.client_header_names:"AUTHORIZATION" AND _exists_:"@fields.unencrypted_password"
```
{% endcode %}

* Password Files

{% code overflow="wrap" %}
```
@fields.filename: (/.*assw(or)*d.{2,20}/ OR/.*pwd.{2,20}/) AND @fields.filename: (/.*\.txt/ OR /.*\.docx?.*/ OR /.*\.xlsx?.*/) AND NOT @fields.filename:(/.*hang.*/ OR /.*orgo.*/ OR /.*olic.*/ OR /.*eset.*/ OR /.*etries.*/ OR /.*etry.*/ OR /.*anagement.*/ OR /.*rotect.*/ OR /.*no passw(or)*d.{2,20}/)
```
{% endcode %}

* HTTP Traffic containing password (HTTP Authorization)

{% code overflow="wrap" %}
```
@type:"http" AND @fields.client_header_names:"AUTHORIZATION" AND _exists_:"@fields.unencrypted_password"
```
{% endcode %}

* HTTP Traffic containing password (GET Request)

```
@type:"http" AND @fields.method:"GET" AND _exists_:"@fields.unencrypted_password"
```

* HTTP Traffic containing password

```
@type:"http" AND _exists_:"@fields.unencrypted_password"
```

* Insecure protocols

```
(telnet OR ftp OR pptp OR ldap OR ntlm OR NetBIOS OR http OR smb1 OR smb2)
```

### Suspicious traffic

* Pasting Services

```
@fields.host:(*paste*)
```

* External Windows Communications

{% code overflow="wrap" %}
```
@fields.dest_port:(137 OR 138 OR 139 OR 445) AND NOT @fields.dest_ip:(10.* OR 192.168.* OR /fd00:.*/ OR /172\.1[6-9]\..+/ OR /172\.2[0-9]\..+/ OR /172\.3[0-1]\..+/)
```
{% endcode %}

* Possible Outbound Spam

{% code overflow="wrap" %}
```
@fields.dest_port: (465 OR 25 OR 110 OR 587 OR 995 OR 143 OR 993) AND NOT @fields.dest_ip:(10.* OR 192.168.* OR /fd00:.*/ OR /172\.1[6-9]\..+/ OR /172\.2[0-9]\..+/ OR /172\.3[0-1]\..+/)
```
{% endcode %}

### Attack Tools

* Network Scanning

{% code overflow="wrap" %}
```
@fields.history:(S OR Sr OR D) AND @fields.local_resp:true AND NOT (@fields.dest_port:(53 OR 5353 OR 5355)) OR /*nmap*/
```
{% endcode %}

* Attack tools

```
kali OR metasploit
```

## Security (MITRE ATT\&CK)

### Reconnaissance&#x20;

* SMB Enumeration / Write to Hidden Share

```
@fields.action:"write" AND @fields.path:/.*$/
```

* SMB Scripts

{% code overflow="wrap" %}
```
@fields.filename: (*.ps1 OR *.cmd OR *.py* OR *.bat OR *.pl OR *.vbs OR *.wbs)
```
{% endcode %}

* Service Control Activity

```
@fields.filename: /.*svcctl/
```

* Dameware Remote Control

```
@fields.action:"write" AND @fields.filename: /.dwrcs./
```

* Write to Network Accessible WebRoot

{% code overflow="wrap" %}
```
@fields.action: "write" AND (@fields.filename: /.wwwroot./ OR @fields.path: /.wwwroot./ )
```
{% endcode %}

* SaaS Specific Password Files in SaaS

```
@fields.saas_resource_name:(/.*assw(or)*d.{2,20}/ OR /.*pwd.{2,20}/)
```

* Anonymous Access

```
@fields.saas_actor:(anonymous OR anon#)
```

* Login Failures

```
@fields.saas_metric:"Saas::FailedLogin"
```

### Resource Development&#x20;

### Initial Access&#x20;

* Executables in HTTP Traffic

```
@type:http AND @fields.uri:*.exe* AND NOT @fields.host:*.windowsupdate*
```

* Downloaded executables or scripts in HTTP Traffic

```
@type:http AND (@fields.uri:*.exe* OR @fields.uri:*.ps1* OR @fields.uri:*.bat* OR @fields.uri:*.cmd OR @fields.uri:*.vbs* OR @fields.uri:*.vbe* OR @fields.uri:*.sh) AND NOT @fields.host:*.windowsupdate* AND @fields.source_ip:(NOT(10.* OR 192.168.* OR /fd00:.*/ OR /172\.1[6-9]\..+/ OR /172\.2[0-9]\..+/ OR /172\.3[0-1]\..+/)) AND @fields.dest_ip:(10.* OR 192.168.* OR /fd00:.*/ OR /172\.1[6-9]\..+/ OR /172\.2[0-9]\..+/ OR /172\.3[0-1]\..+/)
```

### Execution

* PrintingNightmare

```
@type:dce_rpc AND 
(@fields.operation:RpcAsyncInstallPrinterDriverFromPackage OR
@fields.operation:RpcAsyncAddPrintProcessor OR
@fields.operation:RpcAddPrintProcessor OR
@fields.operation:RpcAddPrinterDriver OR
@fields.operation:RpcAddPrinterDriverEx OR
@fields.operation:RpcAsyncAddPrinterDriver)
```

* DCE-RPC

{% code overflow="wrap" %}
```
@type: dce_rpc AND ((@fields.endpoint:JobAdd AND @fields.operation:atsvc) OR (@fields.endpoint:ITaskSchedulerService AND @fields.operation:SchRpcEnableTask) OR (@fields.endpoint:ITaskSchedulerService AND @fields.operation:SchRpcRegisterTask) OR (@fields.endpoint:ITaskSchedulerService AND @fields.operation:SchRpcRun) OR (@fields.endpoint:IWbemServices AND @fields.operation:ExecMethod) OR (@fields.endpoint:IWbemServices AND @fields.operation:ExecMethodAsync) OR (@fields.endpoint:svcctl AND @fields.operation:CreateServiceA) OR (@fields.endpoint:svcctl AND @fields.operation:CreateServiceW) OR (@fields.endpoint:svcctl AND @fields.operation:StartServiceA) OR (@fields.endpoint:svcctl AND @fields.operation:StartServiceW))
```
{% endcode %}

### Privilege Escalation&#x20;

### Defense Evasion&#x20;

### Credential Access&#x20;

* Kerberos with RC4-HMAC

```
@type:"kerberos" AND @fields.auth_ticket_cipher:"rc4-hmac"
```

* Filenames containing passwords

```
fields.filename:(*passw* OR *Passw* OR *PASSW*)
```

* DC Sync

{% code overflow="wrap" %}
```
@type:"dce_rpc" AND @fields.endpoint:"drsuapi" AND @fields.operation:"DRSGetNCChanges"
```
{% endcode %}

* DC Shadow

```
@type:"dce_rpc" AND @fields.endpoint:"drsuapi" AND @fields.operation:"DRSReplicaAdd"
```

### Discovery

### Lateral Movement

### Collection

### Command and Control&#x20;

* Domain Fluxing (Numbers and/or Letters)

{% code overflow="wrap" %}
```
@fields.query:(/.*[a-z0-9]*[bcdfghjklmnpqrstvwxyz0-9]{6,}[a-z0-9]*\.[a-z]{3,}/ OR /.*[a-z0-9]*[bcdfghjklmnpqrstvwxyz0-9]{6,}[a-z0-9]*\.[a-z]{2,3}\.[a-z]{2}/ OR /.*\.*([a-z]*[0-9]+[a-z]+[0-9]*)+\.[a-z]{3,}/ OR /.*\.*([a-z]*[0-9]+[a-z]+[0-9]*)+\.[a-z]{2,3}\.[a-z]{2}/)
```
{% endcode %}

* IRC connections

```
@type:irc
```

* Cobalt-Strike

{% code overflow="wrap" %}
```
@fields.certificate_serial:*8BB00EE* OR (@type:dns AND (@fields.query:aaa.stage.* OR @fields.query:*.stage.123456.*))
```
{% endcode %}

{% code overflow="wrap" %}
```
@type:files_identified AND @fields.mime_type:"application/vnd.ms-cab-compressed" AND NOT @fields.file_ident_descr:(*.windowsupdate.com\/* OR *.microsoft.com\/*)
```
{% endcode %}

* Egress SSH connections

{% code overflow="wrap" %}
```
@type: ssh AND NOT @fields.dest_ip:(10.* OR 192.168.* OR /fd00:.*/ OR /172\.1[6-9]\..+/ OR /172\.2[0-9]\..+/ OR /172\.3[0-1]\..+/)
```
{% endcode %}

* BitTorrent

{% code overflow="wrap" %}
```
(@fields.dest_port:>6880 AND @fields.local_resp:false) OR @fields.mime_type:"application/x-bittorrent" OR *torrent*
```
{% endcode %}

### Exfiltration&#x20;

* Tor2Web

{% code overflow="wrap" %}
```
((@fields.server_name:/[a-z0-9]{10,}\.*onion\.*.*/ OR @fields.query:/[a-z0-9]{10,}\.*onion\.*.*/) OR *tor2web* OR *connect2tor.org OR *door2tor.org)
```
{% endcode %}

* Tor proxy traffic

```
@fields.dest_port:(9050 OR 9051) OR @fields.src_port:(9050 OR 9051)
```

* Tor traffic (custom)

{% code overflow="wrap" %}
```
@fields.host:( *.nkn.org OR tor2web.org OR tor2web.com OR torlink.co OR onion.to OR onion.ink OR onion.cab OR onion.nu OR onion.link OR onion.it OR onion.city OR onion.direct OR onion.top OR onion.casa OR onion.plus OR onion.rip OR onion.dog OR tor2web.fi OR tor2web.blutmagie.de OR onion.sh OR onion.lu OR onion.pet OR t2w.pw OR tor2web.ae.org OR tor2web.io OR tor2web.xyz OR onion.lt OR s1.tor-gateways.de OR s2.tor-gateways.de OR s3.tor-gateways.de OR s4.tor-gateways.de OR s5.tor-gateways.de OR hiddenservice.net OR *hidden* OR *onion*)
```
{% endcode %}

* Large External Data Transfers (over 1, 10, 100, 1000 GB) over outgoing connections

{% code overflow="wrap" %}
```
@fields.local_orig:true AND @fields.local_resp:false AND @fields.orig_bytes:>1000000000
```
{% endcode %}

{% code overflow="wrap" %}
```
@fields.local_orig:true AND @fields.local_resp:false AND @fields.orig_bytes:>10000000000
```
{% endcode %}

{% code overflow="wrap" %}
```
@fields.local_orig:true AND @fields.local_resp:false AND @fields.orig_bytes:>100000000000
```
{% endcode %}

{% code overflow="wrap" %}
```
@fields.local_orig:true AND @fields.local_resp:false AND @fields.orig_bytes:>1000000000000
```
{% endcode %}

* Large SMB Reads and Writes

```
@fields.read_size: >60000 OR @fields.write_size: >60000
```

* Large WebDAV Transfers (over 100MB)

{% code overflow="wrap" %}
```
WebDAV AND @fields.method:(PUT OR POST OR COPY) AND @fields.user_agent:*WebDAV* AND  @fields.request_body_len:>100000000
```
{% endcode %}

### Impact

* Cryptocurrency Mining

```
(@type:notice AND (mining OR miner)) OR @type:mining
```

* Cryptocurrency Mining (custom)

{% code overflow="wrap" %}
```
@fields.host: (pool.minexmr.com OR fr.minexmr.com OR de.minexmr.com OR sg.minexmr.com OR ca.minexmr.com OR us-west.minexmr.com OR pool.supportxmr.com OR mine.c3pool.com OR xmr-eu1.nanopool.org OR xmr-eu2.nanopool.org OR xmr-us-east1.nanopool.org OR xmr-us-west1.nanopool.org OR xmr-asia1.nanopool.org OR xmr-jp1.nanopool.org OR xmr-au1.nanopool.org OR xmr.2miners.com OR xmr.hashcity.org OR xmr.f2pool.com OR xmrpool.eu OR pool.hashvault.pro OR *seed* OR monerohash.com OR do-dear.com OR xmrminerpro.com OR secumine.net OR xmrpool.com OR minexmr.org OR hashanywhere.com OR xmrget.com OR mininglottery.eu OR minergate.com OR moriaxmr.com OR multipooler.com OR moneropools.com OR xmrpool.eu OR coolmining.club OR supportxmr.com OR minexmr.com OR hashvault.pro OR xmrpool.net OR crypto-pool.fr OR xmr.pt OR miner.rocks OR walpool.com OR herominers.com OR gntl.co.uk OR semipool.com OR coinfoundry.org OR cryptoknight.cc OR fairhash.org OR baikalmine.com OR tubepool.xyz OR fairpool.xyz OR asiapool.io OR coinpoolit.webhop.me OR nanopool.org OR moneropool.com OR miner.center OR prohash.net OR poolto.be OR cryptoescrow.eu OR monerominers.net OR cryptonotepool.org OR extrmepool.org OR webcoin.me OR kippo.eu OR hashinvest.ws OR monero.farm OR linux-repository-updates.com OR 1gh.com OR dwarfpool.com OR hash-to-coins.com OR pool-proxy.com OR hashfor.cash OR fairpool.cloud OR litecoinpool.org OR mineshaft.ml OR abcxyz.stream OR moneropool.ru OR cryptonotepool.org.uk OR extremepool.org OR extremehash.com OR hashinvest.net OR unipool.pro OR crypto-pools.org OR monero.net OR backup-pool.com OR mooo.com OR freeyy.me OR cryptonight.net OR shscrypto.net)
```
{% endcode %}

## Misc.

### Common ports

| Port  | Service         | Protocol |
| ----- | --------------- | -------- |
| 21    | FTP             | TCP      |
| 22    | SSH             | TCP      |
| 23    | Telnet          | TCP      |
| 25    | SMTP            | TCP      |
| 53    | DNS             | UDP/TCP  |
| 80    | HTTP            | TCP      |
| 110   | POP3            | TCP      |
| 111   | RPC             | TCP/UDP  |
| 135   | MSRPC           | TCP/UDP  |
| 139   | NetBIOS         | TCP      |
| 143   | IMAP            | TCP      |
| 443   | HTTPS           | TCP      |
| 445   | SMB             | TCP      |
| 993   | IMAPS           | TCP      |
| 995   | POP3S           | TCP      |
| 1723  | PPTP            | TCP      |
| 3306  | MySQL           | TCP      |
| 3389  | RDP             | TCP      |
| 5900  | VNC             | TCP      |
| 8080  | HTTP-Proxy      | TCP      |
| 8443  | HTTPS-ALT       | TCP      |
| 8888  | HTTP-Proxy      | TCP      |
| 199   | SMUX            | UDP      |
| 512   | REXEC           | TCP      |
| 513   | RLOGIN          | TCP      |
| 514   | RSH             | TCP/UDP  |
| 548   | AFP             | TCP/UDP  |
| 554   | RTSP            | TCP/UDP  |
| 587   | SMTP            | TCP      |
| 873   | RSYNC           | TCP/UDP  |
| 902   | VMware          | TCP      |
| 1433  | MS-SQL          | TCP      |
| 1521  | Oracle          | TCP      |
| 2049  | NFS             | UDP/TCP  |
| 3306  | MySQL           | TCP      |
| 5900  | VNC             | TCP      |
| 5984  | CouchDB         | TCP      |
| 6379  | Redis           | TCP      |
| 9090  | WebSphere       | TCP      |
| 9200  | Elasticsearch   | TCP      |
| 10000 | Webmin          | TCP      |
| 11211 | Memcached       | TCP/UDP  |
| 27017 | MongoDB         | TCP      |
| 28017 | MongoDB         | TCP      |
| 50000 | SAP             | TCP      |
| 50070 | Hadoop          | TCP      |
| 5432  | PostgreSQL      | TCP      |
| 5672  | RabbitMQ        | TCP      |
| 5900  | VNC             | TCP      |
| 5901  | VNC             | TCP      |
| 6379  | Redis           | TCP      |
| 7001  | Oracle WebLogic | TCP      |
| 7199  | JMX             | TCP      |
| 7777  | Oracle WebLogic | TCP      |
| 8000  | HTTP            | TCP      |
| 8009  | AJP             | TCP      |
| 8080  | HTTP            | TCP      |
| 8089  | Splunk          | TCP      |
| 8090  | Atlassian       | TCP      |
| 8140  | Puppet          | TCP      |
| 8161  | ActiveMQ        | TCP      |
| 8443  | HTTPS           | TCP      |
| 8888  | HTTP-Proxy      | TCP      |
| 9000  | SonarQube       | TCP      |
| 9090  | WebSphere       | TCP      |
| 9091  | Nessus          | TCP      |
| 9200  | Elasticsearch   | TCP      |
| 9418  | Git             | TCP      |
| 9999  | Ajenti          | TCP      |
| 11211 | Memcached       | TCP/UDP  |
| 12345 | NetBus          | TCP      |
| 27017 | MongoDB         | TCP      |
| 28017 | MongoDB         | TCP      |
| 3306  | MySQL           | TCP      |
| 3389  | RDP             | TCP      |
| 3690  | SVN             | TCP      |
| 50000 | SAP             | TCP      |
| 50070 | Hadoop          | TCP      |
| 5432  | PostgreSQL      | TCP      |
| 5632  | PCAnywhere      | TCP/UDP  |
| 6379  | Redis           | TCP      |
| 6666  | Doom            | TCP      |
| 7001  | Oracle WebLogic | TCP      |
| 7777  | Oracle WebLogic | TCP      |
| 8000  | HTTP            | TCP      |
| 8080  | HTTP            | TCP      |
| 8443  | HTTPS           | TCP      |
| 8888  | HTTP-Proxy      | TCP      |
| 9000  | SonarQube       | TCP      |
| 9090  | WebSphere       | TCP      |
| 9200  | Elasticsearch   | TCP      |
| 9418  | Git             | TCP      |
| 9999  | Ajenti          | TCP      |

### History

| Letter | Meaning                                                     |
| ------ | ----------------------------------------------------------- |
| s      | SYN without the ACK bit set                                 |
| h      | SYN+ACK ("handshake")                                       |
| a      | Pure ACK ("acknowledge")                                    |
| d      | Packet(s) with payload ("data")                             |
| f      | Packet with FIN bit set ("finish")                          |
| r      | Packet with RST bit set ("reset")                           |
| c      | Packet with a bad checksum                                  |
| t      | Packet with retransmitted payload                           |
| w      | Packet with a zero-window advertisement                     |
| l      | Inconsistent packet (e.g. FIN+RST bits set)                 |
| q      | Multi-flag packet (SYN+FIN or SYN+RST bits set)             |
| ^      | Connection direction was heuristically flipped              |
| g      | Darktrace RESPOND/Network reset packet(s)                   |
| m      | A content gap was seen                                      |
| n      | Part of the connection was shunted (supported environments) |

## Unclassified

* Active Directory Activity

{% code overflow="wrap" %}
```
@type:dce_rpc AND @fields.endpoint:drsuapi AND @fields.operation_result:Success AND @fields.operation:(DRSWriteSPN OR DRSGetNCChanges OR DRSDomainControllerInfo)
```
{% endcode %}
