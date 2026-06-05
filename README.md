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

**PCAP capture (v3.23.3+):** rolling SYN-only ring buffer 1GB в `/var/log/pcap/` + attack-archiver: при скачке >10k drops/min копирует current ring в `/var/lib/shieldnode/pcap-archive/attack-<TS>/` (7-day retention). Для отправки хостеру при DDoS.

**Требует:** `net.netfilter.nf_conntrack_max >= 262144` (Ubuntu 24.04 default OK на нодах ≥1GB RAM).

## Возможности

- **nftables rate-limit** (kernel-level, IPv4-only): SYN-flood, UDP-flood, conn-flood, newconn-rate
- **SSH pre-auth flood protection**: ct count + rate limit прямо на nft, защита от slowloris до того как пакеты дойдут до sshd
- **TCP flag sanity**: drop XMAS, NULL, SYN+FIN, SYN+RST, FIN+RST scan-пакетов
- **Anti-spoofing**: fib reverse-path (single-homed VPS)
- **Infrastructure bypass**: ~220 CIDR крупных CDN/cloud (Cloudflare, Google, AWS, Azure, Apple, Meta, Akamai, Fastly, GitHub, Telegram, Yandex, VK, Selectel) проходят без rate-limit и не попадают в events.db как "атакующие"
- **4 blocklist'а**:
  - `scanner` — Shodan, Censys, госсканеры РФ (shadow-netlab + CyberOK_Skipa + MISP)
  - `threat` — Spamhaus DROP + FireHOL Level 1 + Feodotracker (3 источника high-confidence, ~7-8k unique IP). **blocklist.de и IPSum L3 убраны в v3.23.14** — это агрегаторы abuse-репортов, ловили публичные CGNAT/PAT мобильных операторов → ложные баны обычных юзеров.
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

- **v3.23.16** — SYNPROXY (default-on, SHIELD_SYNPROXY=1):
  - **FEAT**: SYNPROXY-модуль (`shieldnode-synproxy.sh`, таблица `inet shield_synproxy`). SYN-пакеты перехватываются до conntrack (syncookies) → защита от conntrack-exhaustion атак. Изолирован от `ddos_protect` (откат = удаление модуля, нода не ронит). Verify mss/wscale + auto-rollback при сбое. Boot-unit. Требует ядро >=5.14.
  - **ВАЖНО**: `SHIELD_SYNPROXY=1` теперь дефолт. Opt-out: `SHIELD_SYNPROXY=0` в shieldnode.conf.
- **v3.23.15** — SECURITY HARDENING (static audit P0-P2):
  - **P0 FIX**: SQL-injection через journald. Aggregator gsub-очистка SRC= для ВСЕХ handlers (`[shield:ddos]`, `[UFW BLOCK]`), IPv4-валидация перед INSERT.
  - **P0 FIX**: Bogon-фильтр threat-feeds: min prefix /16 (был /8 — мог забанить 1.0.0.0/8), CGNAT/TEST-NET/benchmark в bogon-list, `MAX_FEED_ENTRIES` cap (200k/100k/10k/50k).
  - **P0 FIX**: auto-promote был мёртв (nft log prefix не генерился + typo в query `syn_flood`→`syn_escalate`). Исправлено.
  - **P0 FIX**: Aggregator RAM blow-up при шторме: `MAX_UNIQUE_IPS_PER_TYPE=50000`, `MemoryMax=512M MemoryHigh=384M`.
  - **P0**: SSH-блок выше infra-accept; IaaS убран из baseline (CDN/edge only).
  - **P0**: Базовая IPv6-защита: new-conn DROP на VPN-портах + SSH/v6 rate-limit.
  - **P1**: auto-promote порог 2000→800. pcap-archiver tar.zst реально работает в runtime. conntrack snapshot полный + gzip. state-file cap 30000 entries.
  - **P2**: octet≤255 в blocklist-updater. ADMIN_IP → whitelist anti-lockout.
- **v3.23.14** — FALSE-POSITIVE + PIPE-DEADLOCK FIX:
  - **FIX**: убраны шумные threat-фиды (blocklist.de/all, IPSum L3) — агрегаторы abuse-репортов с публичными CGNAT/PAT адресами операторов → дроп NEW-коннектов реальных юзеров. Остались Spamhaus DROP + FireHOL L1 + Feodo. `MIN_ENTRIES_THREAT` 5000→3000 под урезанный набор.
  - **FIX**: self-reexec при `curl | bash` — ~480KB скрипт не влезал в pipe-буфер (64KB), bash блокировался на ожидании apt → curl обрывался (`curl: 23`), скрипт обрезался. Теперь в pipe-режиме качается копия в /tmp и exec'ается (stdin не pipe → дедлок невозможен).
  - **FIX**: `wait_for_apt_lock` — убран широкий `pgrep -f` (ловил фантомы apt-daily/dpkg-query), теперь `fuser` по lock-файлам = авторитет + показывает кто держит. Таймаут → `SHIELDNODE_FORCE_APT=1` останавливает systemd apt-таймеры и снимает lock.
- **v3.23.10** — PCAP NAME FIX (hotfix к v3.23.9):
  - **CRIT FIX**: в v3.23.9 heredoc для `shieldnode-pcap.service` использовал `<<PCAP_UNIT_EOF` без quotes (для подстановки `$TCPDUMP_BIN`), и в strftime-pattern удвоились `%` → tcpdump получал буквальное имя файла `syn-%%Y%%m%%d-%%H%%M%%S.pcap` вместо timestamp. PCAP записи были бы сломаны.
  - Fix: single-quote heredoc (literal) + targeted `sed` замена ровно одного placeholder `__TCPDUMP_BIN__` после создания файла. Никакого expand'а `$VAR`/`%`, всё literal до явной замены.
- **v3.23.9** — WHITELIST PERF FIX (анализ скриншота с `nft delete element ... 88.8% CPU`):
  - **PERF FIX**: `shieldnode-whitelist-updater` использовал 6 отдельных `nft delete` команд per-IP (каждая отдельный fork+exec+nft init). При 3 IP в TRUSTED_IPS = 18 nft процессов на каждый sync, CPU spike до 90%. На скриншоте видны `nft delete element inet ddos_protect suspect_v4 { 213.165.55.166 }` висящие в top.
  - Fix: переход на batch `nft -f -` (1 nft process для всех delete операций). Снижение CPU usage в 18x на nodes с TRUSTED_IPS. Срабатывает при path-watcher (whitelist-local.txt) и периодических sync.
  - **FIX**: `shieldnode-pcap.service status=203/EXEC` на Ubuntu 24 (tcpdump path был `/usr/sbin/tcpdump`, реальный — `/usr/bin/tcpdump`). Auto-detect через `command -v tcpdump`. apt install с 3x retry. Если tcpdump недоступен — сервис не создаётся (не висит в failed state с crashes каждые 10 сек).
- **v3.23.8** — COMPRESSION HARDENING (production-ready):
  - **FIX**: gzip rotation error logging — раньше `2>/dev/null` глотал "no space"/"permission denied", теперь все ошибки в syslog (`shieldnode-gzip`, `shieldnode-agg-retry`).
  - **FIX**: cleanup при upgrade имеет fallback на `truncate` если диск >=95% (gzip не уместится во временный файл). 80-94% → gzip (сохраняем историю), >=95% → truncate (быстро, но теряем старое).
  - **FIX**: PCAP archive теперь СЖИМАЕТСЯ в `tar.zst -19` перед удалением (раньше при critical disk удалялись >3 дней — теряли forensics). Старее 7 дней → tar.zst, старее 30 дней → удалить.
  - **FIX**: `xz -9` → `xz -6 -T 2` в cleanup'е (втрое быстрее, ratio 95% от -9). На 2GB архиве: 20 минут → 3 минуты.
  - **FIX**: системные logs cleanup использует whitelist известных паттернов (syslog.*.gz, kern.log.*.gz, auth.log.*.gz, messages-*.gz, etc) вместо broad-match `*.gz` — защита от случайного удаления docker logs, custom logs.
  - **FIX**: aggregator retry для leftover архивов — если предыдущий gzip упал и оставил `events.log.<TS>` без .gz суффикса, следующий тик пробует сжать ещё раз.
- **v3.23.7** — COMPRESSION (no data loss):
  - **CRIT FIX**: events.log при заполнении теперь СЖИМАЕТСЯ (gzip), а не truncate. Раньше >500MB → tail -c 100MB → ТЕРЯЛИ 400MB истории. Теперь >100MB → mv → events.log.<TS> → gzip в фоне → новый пустой events.log. История полностью сохранена, читается через `zless`. На 37GB → ~2GB архив (95% компрессии).
  - **FEATURE**: автоматическая ретенция архивов — .gz старее 14 дней пересжимаются в xz, старее 30 дней удаляются (раньше 1 день — слишком агрессивно).
  - **FIX**: logrotate config: maxsize 50M → 100M (меньше частых ротаций), rotate 30 дней с compress + delaycompress.
- **v3.23.6** — DEDUP CORRECTNESS (FIX блокирующего бага в v3.23.5):
  - **CRIT FIX**: should_log() в aggregator использовал `grep -F "^${key}|"` — это fixed-string режим, где `^` ищется БУКВАЛЬНО, не как anchor начала строки. Эффект: state lookup ВСЕГДА возвращал empty → каждое событие писалось как "впервые видим" → дедуп **НЕ РАБОТАЛ**. Главная фича v3.23.5 была сломана. Fix: in-memory bash associative array (`declare -A LAST_COUNT LAST_TS`), load на старте, atomic dump через `trap save_state EXIT`.
  - **CRIT FIX**: race condition в aggregator. Timer запускается каждую минуту, тики могли пересекаться. Теперь `flock` защищает.
  - **PERF FIX**: state-операции были O(N×12) grep/sed на каждом тике. Теперь O(1) bash hash lookup. На 4000 IP: 5-10 сек → 50-100 ms за тик (разница в 100x по CPU).
- **v3.23.5** — DISK-PROOF + SELF-TEST (отброшен v3.23.6 фиксом):
  - **CRIT FIX**: events.log больше не заполняет диск при длительных атаках через state-based logging (writes только если событие "значимое": новый IP/type, count вырос на 1000, прошёл час).
  - **CRIT FIX**: hard cap 500MB на events.log с auto-rotate.
  - **FIX**: logrotate config теперь с `copytruncate` (раньше падал с status=1).
  - **FIX**: systemd Restart=on-failure для shieldnode-nftables/events/pcap.
  - **FIX**: aggregator detect MY_IP в suspect_v4 → log WARNING + skip. Self-flood случаи (loopback через public_ip в nginx/proxy_pass) больше не зацикливают CPU.
  - **FEATURE**: `guard self-test` — 11 проверок ноды (services, disk, conntrack, MY_IP, threat feed health).
- **v3.23.4** — POST-INCIDENT FINAL (на основе DDoS-инцидента 2026-05-24):
  - **REMOVED**: /24 subnet aggregator + whois install (был в v3.23.3-rc, удалён до stable). CrowdSec community blocklist + threat-feeds покрывают ~90% datacenter ботнетов, дополнительная сложность не оправдана. Auto-promote events.db → custom-local + ручной custom.txt — достаточно.
  - **FEATURE**: idempotent cleanup в начале установщика (ШАГ 12.6). При upgrade с v3.23.3-rc автоматически удаляет legacy `shieldnode-subnet-aggregator.{service,timer}` + nft set `datacenter_subnet_bans_v4` + whois cache. Чистый upgrade без ручной очистки.
  - **FIX**: CrowdSec scenario `shieldnode/conn-flood` более не включает `UFW-BLOCK` в filter (это port scan, не DDoS — не должен попадать в community blocklist под `labels.type='ddos'`).
  - **FIX**: degraded feed warning теперь со скользящим peak — auto-reset если current >= 80% от peak (источник восстановился). Без этого старый peak застрял бы навсегда после временного скачка.
  - **FIX**: TTL cleanup в auto-promote логирует warning если `date` команда не сработала (silent failure removed).
  - **FIX**: PCAP archiver проверяет существование nft table перед сравнением counters — если `shieldnode-nftables` упал, пишет CRITICAL alert в syslog вместо silent skip.
  - **FIX**: CrowdSec grok pattern строже — `NOTSPACE` вместо greedy `DATA` (защита от случайного захвата лишних полей).
- **v3.23.3** — POST-INCIDENT HARDENING (DDoS-инцидент 2026-05-24, base релиз):
  - **CRIT**: `ct count over` снижен с **50000 → 15000** TCP per-IP. Инцидент показал атаку где боты держали 5k-128k conn/IP, проходили под старый лимит. Замер легитимных пиков на работающих нодах: 700-750 conn/IP. Новый порог = запас 20x от пика, режет все известные ботнеты в инциденте.
  - **FEATURE**: rolling **pcap-capture** включён по умолчанию (`shieldnode-pcap.service`). Ring buffer 1GB, SYN-only, 128 байт/пакет. На нормальной нагрузке ~100-200MB/сутки. Файлы: `/var/log/pcap/syn-*.pcap`. Для отправки хостеру при DDoS.
  - **FEATURE**: **pcap attack-archiver** (`shieldnode-pcap-archiver.timer`). Каждую минуту проверяет nft drop-counters: при скачке >10k drops/min копирует current ring в `/var/lib/shieldnode/pcap-archive/attack-<TS>/` навсегда (7-day retention). Решает проблему ring buffer overflow при volumetric атаках (100k pps заполняет 1GB за ~80 сек).
  - **FEATURE**: **auto-promote** events.db → custom-local.txt каждые 6ч. IP с count>=2000 за 24ч (только conn_flood/syn_flood) → постоянный бан. **TTL 90 дней**: записи удаляются если IP больше не атакует >30 дней (защита от unbounded growth). **CrowdSec whitelist cross-check** перед каждым промоутом.
  - **FEATURE**: **CrowdSec scenario** `shieldnode/conn-flood` для community publication. Filter покрывает SYN-ESCALATE, UDP-ESCALATE, CONN-FLOOD, SYN-FLOOD. Grok pattern под реальный формат `events.log`. Acquisition пишется только если events.log существует.
  - **FEATURE**: **degraded feed health warning** в blocklist updater. Сохраняет peak entries. Если current <50% от peak — WARN в syslog (детект "тихих" поломок типа смена URL формата или удаление repo).
  - **INFRA**: **динамический DNS whitelist** из `/etc/resolv.conf` + `resolvectl` + `/run/systemd/resolve/` (вместо hardcoded `1.1.1.1`, `8.8.8.8`). MY_IP detection без `ifconfig.me` — через `ip route get 1.1.1.1` + public-IP filter в hostname fallback. Locks в `/run/shieldnode/` (вместо устаревшего `/var/run`). PCAP restart только если конфиг изменился (sha256 sequence).
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
