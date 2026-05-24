# shieldnode

Bash-скрипт DDoS-защиты для VPN-нод (Reality / Xray / sing-box / Hysteria2 / WireGuard).

Стек: **nftables + CrowdSec + UFW**. Целевые ОС: Ubuntu 22.04 / 24.04, Debian 12 / 13.

## Архитектура

shieldnode фокусируется только на DDoS-защите и не вмешивается в kernel-tuning,
BBR, qdisc, NIC настройки или TCP-таймауты — это область ответственности оператора
или других инструментов. Свои security-sysctl (rp_filter, syncookies, redirects,
icmp_*, tcp_rfc1337, log_martians, UDP conntrack timeouts) shieldnode пишет в
`/etc/sysctl.d/90-shieldnode.conf` — этот префикс позволяет оператору перекрыть
наши значения через `99-z-*.conf` если нужно.

**Лимиты v3.23.3 рассчитаны на ноду с 500-1000 VPN-клиентами:**

- **conn_flood**: `ct count over 15000` per-IP (снижено с 50000 после DDoS-инцидента 2026-05-24 — атакующие держали 5k-128k conn/IP, проходили под старый лимит)
- **newconn rate**: 40000/min, burst 60000 (массовый reconnect 200 юзеров × 50 retry/min = 10000/min sustained)
- **SYN flood**: 2000/sec, burst 3000 (CGNAT × 200 юзеров × 1-2 SYN/sec = 200-400/sec baseline)
- **UDP flood**: 10000/sec, burst 20000 (Hysteria2/QUIC 4K streaming + cloud gaming)
- **SSH per-IP**: ct=5 + 8/min burst 20 (CGNAT-админы + ansible deploy на ≤5 нод параллельно)

Реальные DDoS-атаки 50k+ SYN/sec, 100k+ connections — drop на kernel level. Ban-once архитектура: первое нарушение → suspect (30 мин наблюдения без drop), второе → confirmed (15 мин drop).

**Auto-promote (v3.23.3):** IP с count>=2000 за 24ч (conn_flood/syn_flood) автоматом попадает в `custom-local.txt` навсегда. TTL 90 дней: записи удаляются если IP не атакует >30 дней. CrowdSec whitelist cross-check.

**/24 datacenter aggregator (v3.23.3):** 3+ /32 из одной /24 в suspect_v4 → whois lookup → если datacenter ASN → бан всей /24. Whois cache 24h + Team Cymru fallback. Dry-run первые 7 дней (только лог, без банов) для проверки оператором. ISP-whitelist (CGNAT провайдеры не агрегируются).

**PCAP capture (v3.23.3):** rolling SYN-only ring buffer 1GB в `/var/log/pcap/` + attack-archiver: при скачке >10k drops/min копирует current ring в `/var/lib/shieldnode/pcap-archive/attack-<TS>/` (7-day retention). Для отправки хостеру при DDoS.

**Требует:** `net.netfilter.nf_conntrack_max >= 262144` (Ubuntu 24.04 default OK на нодах ≥1GB RAM).

## Возможности

- **nftables rate-limit** (kernel-level, IPv4-only): SYN-flood, UDP-flood, conn-flood, newconn-rate
- **SSH pre-auth flood protection**: ct count + rate limit прямо на nft, защита от slowloris до того как пакеты дойдут до sshd
- **TCP flag sanity**: drop XMAS, NULL, SYN+FIN, SYN+RST, FIN+RST scan-пакетов
- **Anti-spoofing**: fib reverse-path (single-homed VPS)
- **Infrastructure bypass**: ~220 CIDR крупных CDN/cloud (Cloudflare, Google, AWS, Azure, Apple, Meta, Akamai, Fastly, GitHub, Telegram, Yandex, VK, Selectel) проходят без rate-limit и не попадают в events.db как "атакующие"
- **4 blocklist'а**:
  - `scanner` — Shodan, Censys, госсканеры РФ (shadow-netlab + CyberOK_Skipa + MISP)
  - `threat` — Spamhaus DROP + FireHOL Level 1 + blocklist.de + Feodotracker + IPSum L3 (5 источников high-confidence, ~40-50k unique IPs после dedup)
  - `tor` — Tor exit nodes (опционально, `BLOCK_TOR=1`)
  - `custom` — личный список оператора (file-based + URL union + auto-promote)
- **GitHub auto-sync**: `lists/custom.txt` синкается с репо каждые 6ч. Локальные дополнения — в `custom-local.txt`, не перезаписываются.
- **CrowdSec** + nftables firewall bouncer (SSH brute-force + community blocklist ~28k IP, stream mode 10s)
- **guard CLI** — дашборд защиты с ASN/owner column для top attackers, settings menu, upgrade/rollback
- **Aggregator**: журналы → sqlite events.db с per-IP analytics
- **Auto-detect портов** из UFW + inotify path-watcher (мгновенный sync) + 5-min catch-all timer

## Установка

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash
```

> ⚠️ Use `curl | sudo bash` вместо `bash <(curl ...)` — process substitution не
> работает на OpenVZ/LXC контейнерах и некоторых embedded environments.

## Совместимость

- Совместим с UFW (читает open ports автоматически)
- Совместим с любыми VPN-стэками (Xray Reality, sing-box, Hysteria2, WireGuard, AmneziaWG)
- Корректно сосуществует с другими nft-таблицами (использует свою `inet ddos_protect`)

## Удаление

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash -s -- --uninstall
```

## guard CLI

```bash
sudo guard            # дашборд защиты с интерактивным меню
sudo guard --once     # снимок без меню (для cron / мониторинга)
sudo guard --json     # JSON-вывод для интеграций (Zabbix, Prometheus)
sudo guard upgrade    # re-install с github (auto-snapshot для rollback)
sudo guard rollback   # откатиться к предыдущему snapshot'у
sudo guard sync       # синк custom.txt прямо сейчас
```

## Версии

- **v3.23.3** — POST-INCIDENT HARDENING (на основе DDoS-инцидента 2026-05-24):
  - **CRIT**: `ct count over` снижен с **50000 → 15000** TCP per-IP. Инцидент показал атаку где боты держали 5k-128k conn/IP, проходили под старый лимит. Замер легитимных пиков на работающих нодах: 700-750 conn/IP. Новый порог = запас 20x от пика, режет все известные ботнеты в инциденте.
  - **FEATURE**: rolling **pcap-capture** включён по умолчанию (`shieldnode-pcap.service`). Ring buffer 1GB, SYN-only, 128 байт/пакет. На нормальной нагрузке ~100-200MB/сутки. Файлы: `/var/log/pcap/syn-*.pcap`. Для отправки хостеру при DDoS.
  - **FEATURE**: **pcap attack-archiver** (`shieldnode-pcap-archiver.timer`). Каждую минуту проверяет nft drop-counters: при скачке >10k drops/min копирует current ring в `/var/lib/shieldnode/pcap-archive/attack-<TS>/` навсегда (7-day retention). Решает проблему ring buffer overflow при volumetric атаках (100k pps заполняет 1GB за ~80 сек).
  - **FEATURE**: **auto-promote** events.db → custom-local.txt каждые 6ч. IP с count>=2000 за 24ч (только conn_flood/syn_flood) → постоянный бан. **TTL 90 дней**: записи удаляются если IP больше не атакует >30 дней (защита от unbounded growth). **CrowdSec whitelist cross-check** перед каждым промоутом.
  - **FEATURE**: **/24 datacenter aggregator** (`shieldnode-subnet-aggregator.timer`). 3+ /32 из одной /24 в `suspect_v4` → whois lookup → если datacenter ASN → бан всей /24. Whois cache 24h в `/var/lib/shieldnode/whois-cache/` + Team Cymru fallback (защита от RIPE rate-limit 1000 req/h при 50+ нод за NAT). **Dry-run первые 7 дней** (только лог, без банов) для проверки оператором. ISP-whitelist расширен под мировых провайдеров (Sonatel, PALTEL, Kazakhtelecom, Globe Telecom, NOS, TOT, VNPT, Maroc Telecom, Free SAS, Telstra, Saudi Telecom, Emirates Internet и т.д.).
  - **FEATURE**: **CrowdSec scenario** `shieldnode/conn-flood` для community publication. Filter покрывает SYN-ESCALATE, UDP-ESCALATE, CONN-FLOOD, SYN-FLOOD, UFW-BLOCK. Grok pattern под реальный формат `events.log`. Acquisition пишется только если events.log существует.
  - **FEATURE**: **degraded feed health warning** в blocklist updater. Сохраняет peak entries за всё время. Если current <50% от peak — WARN в syslog (детект "тихих" поломок типа смена URL формата или удаление repo).
  - **INFRA**: **динамический DNS whitelist** из `/etc/resolv.conf` + `resolvectl` + `/run/systemd/resolve/` (вместо hardcoded `1.1.1.1`, `8.8.8.8`). MY_IP detection без `ifconfig.me` — через `ip route get 1.1.1.1` + public-IP filter в hostname fallback. Locks в `/run/shieldnode/` (вместо устаревшего `/var/run`). PCAP restart только если конфиг изменился (sha256 sequence). whois install с 3x retry + явный алерт если не установился.
- **v3.23.2** — EXTENDED THREAT FEEDS:
  - **FEATURE**: `threat` blocklist расширен с 2 до 5 источников: + **blocklist.de** (~30k IP fail2ban-агрегатор, фильтрует SYN-flood ложняки), + **Feodotracker abuse.ch** (botnet C2), + **IPSum level 3** (агрегатор 30+ источников). Все источники без регистраций и API-ключей.
  - **TUNING**: `DEFAULT_MIN_ENTRIES_THREAT` 500 → 5000 (защита от тихого деградирования: если несколько источников отвалились — updater не применяет частичный список).
- **v3.23.1** — TRUSTED_IPS + UFW FIXES + CIDR SUPPORT:
  - **CRIT**: `TRUSTED_IPS` теперь применяются через **postoverflow whitelist** (parser-level), а не только через `cscli decisions` (decision-level). Раньше: scenarios типа `crowdsecurity/http-probing` продолжали триггериться на trusted IPs → alerts уходили в CAPI + race condition между whitelist-decision и ban-decision давал короткие окна drop'а. Теперь scenarios даже не пытаются банить trusted IPs. Файл: `/etc/crowdsec/postoverflows/s01-whitelist/shieldnode-trusted.yaml`.
  - **CRIT**: `guard → Trusted IPs → Delete` теперь корректно экранирует точки в IP при поиске UFW-правил. Раньше: regex `1.2.3.4` матчил `1.2.3.40`, `1.2.3.41` и т.п. (точки в regex = любой символ). При удалении одного IP `yes | ufw delete N` без подтверждения мог снести соседние правила.
  - **FEATURE**: `TRUSTED_IPS` теперь поддерживает **CIDR** (например `10.0.0.0/24`). Раньше: только single IPs принимались, CIDR молча отбрасывались на merge → bridge подсети получали только 2 слоя защиты (nft `manual_whitelist` + scanner bypass) вместо 5. Теперь все 5 слоёв работают для CIDR: `whitelist-local.txt`, `UFW allow from <CIDR>`, `cscli decisions --range <CIDR>`, postoverflow `cidr:` секция. `guard UI Add/Delete` также принимают CIDR.
  - **MINOR**: `guard` NFT_SINCE читает `shieldnode-nftables.service` (раньше — masked `nftables.service` → всегда пустой timestamp). Дашборд "Drops since reboot" показывает реальную дату.
  - **MINOR**: `apply_trusted_ip` UFW grep тоже экранирует точки в IP. `cscli decisions list --type whitelist -o json` вместо `grep -q whitelist`.
  - **DATA FIX**: убран невалидный `17::/32` из IPv6 infrastructure baseline (был попыткой скопировать Apple AS714 IPv4 `17.0.0.0/8` в IPv6, но `17::/32` = IETF reserved space, никому не присвоен).
- **v3.22.0** — ROBUSTNESS PACK + SECURITY TUNING для 500-1000 клиентов на ноде:
  - **Лимиты подняты под реальный CGNAT load** (МТС/T2/Beeline/Tele2 200+ абонентов/IP): conn_flood 5000→50000, newconn 5000→40000/min, syn 300→2000/sec, udp 1500→10000/sec, ssh ct=3→5
  - **Aggregator robustness**: `journalctl --lines=500000` cap (защита от RAM blow-up под штормом 100k+ events/min), `PRAGMA busy_timeout=5000` (защита от SQLITE_BUSY race с guard)
  - **protected-ports timer 60s → 5min**: path-unit (inotify) ловит изменения мгновенно, timer остался как catch-all, экономия ~15% CPU на 1GB нодах
  - **guard ASN lookup**: curl timeout 2s → 0.5s + offline-mode fallback (top attackers больше не лагает на 40 сек при недоступности ipinfo.io)
  - **cleanup VACUUM**: Nice=19 + IOSchedulingClass=idle (не блокирует sshd/Xray logs на shared-disk VPS)
  - **unban_all**: + `conntrack -D -s <ip>` (FP-разбан реально работает на extreme-CGNAT)
  - **healthcheck timeouts**: `timeout 5 cscli ...` + sqlite fallback (быстрее install на нодах с ~28k CAPI decisions)
  - **Cleanup**: удалены dead counters mobile_ru_*/broadband_ru_*, changelog history >1600 строк (история в git)
- **v3.21.x** — SSH pre-auth flood defense, infrastructure_v4 bypass для CDN/cloud (~220 CIDR), Google 192.178/16 в baseline, log dedup (rsyslog kern.none + journald limits), DB cleanup (events.db + asn_cache).
- **v3.20.x** — SIMPLIFICATION (убраны mobile-RU/broadband-RU whitelist'ы), arch simplification (MSS clamp вынесен в отдельную независимую таблицу), WHITELIST CONSISTENCY (TRUSTED_IPS через все 3 слоя), aggressive logrotate.
- **v3.18.x** — TRUSTED_IPS feature, UFW-FIX, post-audit hardening, foreign CrowdSec detection.
- **v3.14.0** — GitHub auto-sync custom.txt + version check + guard settings menu.
- **v3.12.0** — blocklists архитектура (universal updater, file+URL union).
- **v3.10.x** — fib anti-spoof, TCP MSS clamping.

Полная история: https://github.com/SpofyJet/shield/commits/main/shieldnode.sh

## Лицензия

MIT — см. [LICENSE](./LICENSE).
