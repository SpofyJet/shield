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

**Лимиты v3.23.13 рассчитаны на ноду с 500-1000 VPN-клиентами** (настраиваются через `/etc/shieldnode/limits.conf` — v3.23.13+):

- **conn_flood**: `ct count over 15000` per-IP — `SHIELD_CT_CONN_FLOOD`
- **newconn rate**: 40000/min, burst 60000 — `SHIELD_RATE_NEWCONN` + `SHIELD_RATE_NEWCONN_BURST`
- **SYN flood**: 2000/sec, burst 3000 — `SHIELD_RATE_SYN` + `SHIELD_RATE_SYN_BURST`
- **UDP flood**: 10000/sec, burst 20000 — `SHIELD_RATE_UDP` + `SHIELD_RATE_UDP_BURST`
- **SSH per-IP**: ct=5 + 8/min burst 20 — `SHIELD_SSH_CT_LIMIT`, `SHIELD_SSH_NEWCONN_RATE`
- **Auto-promote**: hits >= 2000 за 24ч → permanent ban TTL 90d — `SHIELD_AUTOPROMOTE_THRESHOLD`, `SHIELD_AUTOPROMOTE_WINDOW_HOURS`, `SHIELD_CUSTOM_LOCAL_TTL_DAYS`
- **Aggregator**: cap 50000 unique IP/type, journalctl --lines=200000 — `SHIELD_AGG_MAX_UNIQUE_IPS`, `SHIELD_AGG_JOURNAL_LINES`

Для маленьких нод (<50 клиентов): `SHIELD_CT_CONN_FLOOD=3000`. Для больших (>1000 клиентов): `SHIELD_CT_CONN_FLOOD=50000`. После изменения: `sudo systemctl restart shieldnode-nftables`.

Реальные DDoS-атаки 50k+ SYN/sec, 100k+ connections — drop на kernel level. Ban-once архитектура: первое нарушение → suspect (30 мин наблюдения без drop), второе → confirmed (15 мин drop).

**Auto-promote (v3.23.3+, оживлён в v3.23.13):** IP с count>=2000 за 24ч (conn_flood/syn_escalate/newconn_flood) автоматом попадает в `custom-local.txt` навсегда. TTL 90 дней: записи удаляются если IP не атакует >30 дней. CrowdSec whitelist cross-check. **До v3.23.13 был сломан typo + missing log prefix — теперь реально работает.**

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

- **v3.23.13** — SECURITY HARDENING (major release based on static security audit):

  **🔒 P0 Security:**
  - **BUG-002**: SQL injection через journald закрыт. Aggregator теперь фильтрует journalctl по `_TRANSPORT=kernel + SYSLOG_IDENTIFIER=kernel + SYSLOG_IDENTIFIER=crowdsec`, применяет gsub в awk для ВСЕХ SRC= handlers (раньше `[shield:ddos]` и `[UFW BLOCK]` не чистили IP), валидирует IPv4 format перед SQL INSERT. До этого любой unprivileged user мог через `logger` инжектить `[shield:ddos] SRC=...';DROP TABLE events;--` в журнал.
  - **BUG-003**: bogon-фильтр threat-feeds: min prefix `/16` для `threat` (был `/8` — compromised feed мог затолкать `1.0.0.0/8` и забанить Cloudflare). Добавлены CGNAT (`100.64/10`), TEST-NET-1/2/3, benchmark (`198.18-19`). `MAX_FEED_ENTRIES` cap (200k threat / 100k scanner / 10k tor / 50k custom). Alert при росте feed >20% от peak. **FAIL_THRESHOLD больше НЕ flush'ит set** — stale data > no protection.
  - **BUG-006**: `shield_safe_source` убрал 0644 из allowed perms. Все `shieldnode.conf` теперь `chmod 0640` (root:root). Auto-migration при upgrade с warning.

  **⚙️ P0 Functional Regression (auto-promote был мёртв):**
  - **BUG-004a**: `[shield:conn_flood]` log prefix вообще не генерился в nft template — aggregator awk парсил `/\[shield:conn_flood\]/` впустую. events.db никогда не содержала `type='conn_flood'`. Добавлен log prefix с per-IP meter rate-limit.
  - **BUG-004b**: auto-promote query искал `type='syn_flood'` — но aggregator никогда не пишет такой type (есть только `syn_escalate`, typo с рефакторинга v3.15.x). Исправлено на `IN ('conn_flood','syn_escalate','newconn_flood')`.
  - **BUG-004c**: Threat/custom/scanner/tor/ddos/syn_escalate/udp_escalate log prefix теперь **ВСЕГДА** активны (не зависят от `SHIELDNODE_VERBOSE_LOGS` toggle). events.db, auto-promote, guard top attackers — **работают по default**. `VERBOSE_LOGS=1` теперь касается только tcp_invalid + fib_spoof (real high-volume per-packet rules).

  **🛡️ P0 Resource Protection:**
  - **BUG-007**: aggregator защищён от RAM blow-up. `MAX_UNIQUE_IPS_PER_TYPE=50000` hash cap. `MemoryMax=512M MemoryHigh=384M TasksMax=20 CPUQuota=80%` на systemd unit. Под штормом 100k unique IP — раньше OOM-killer, теперь bounded.

  **🔧 P1 Robustness:**
  - **BUG-010**: pcap-archiver. tar.zst compression >7d, retention 30d теперь реально работает в archiver runtime (раньше compression жила только в install-time disk cleanup и почти никогда не срабатывала).
  - **BUG-012**: conntrack snapshot полный через `conntrack -L -o save` (netlink) + gzip. Раньше `head -10000` + uncompressed (5-15MB/archive, обрезка теряла 90% данных при шторме).
  - **BUG-014**: state-file cap `LOG_STATE_MAX_ENTRIES=30000` keep-top-by-recency через sort.
  - **BUG-015**: `VACUUM` → `VACUUM INTO + atomic mv + integrity_check + rollback`. Non-blocking, aggregator берёт shared `flock` на `/run/shieldnode/db.lock`.
  - **BUG-019**: `/etc/shieldnode/limits.conf` с **17 настраиваемыми параметрами**. Embedded скрипты через `__PLACEHOLDER__` sed-substitution. Поддерживает разные профили нагрузки без правки исходника.
  - **BUG-020**: journalctl фильтр (см. BUG-002), `--lines=500000 → 200000`.
  - **BUG-021**: финальный stale `ct=5000` в guard CLI dashboard → `ct=15000`.

  **🎯 Self-review fixes:**
  - **SR-FIX-1**: GLOBAL → **per-IP meter** для log правил (8 правил). Под массивной атакой раньше log'ировался **только 1 IP/sec total**. Теперь — каждый IP хотя бы раз в минуту через `meter NAME { ip saddr limit rate 1/min }`. **100-167× improvement** attribution fairness при ботнетах.
  - **SR-FIX-2**: `STORM_DROPPED` counter в aggregator summary — видимость drop'ов из-за hash cap'а.
  - **SR-FIX-3**: ДВУХФАЗНАЯ nft загрузка. `nft -c -f` parse-check ДО `nft -f` apply. `ExecStartPre=` в systemd unit. **Сломанный конфиг НЕ роняет защиту** — старый ruleset продолжит работать.
  - **SR-FIX-4**: `verify_no_placeholders` helper — fail loud если sed substitution не сработал (вместо silent breakage).
  - **SR-FIX-5**: explicit 0644→0640 migration step с warning в install logs.
  - **SR-FIX-6**: убран дублирующий `add @confirmed_attack_v4` в escalation chains.

  **🧹 Legacy cleanup:**
  - Удалены deprecated `mobile_ru/broadband_ru` declare-only переменные, `MAXMIND_LICENSE_KEY` упоминания.
  - Удалён install-time `cs-ssh-whitelist` cleanup (≤v3.4 EOL 2+ года, остаётся в uninstall).
  - Удалён `subnet-aggregator` block (v3.23.3-rc never released stable, 1+ год).

  **📊 Реальное улучшение для оператора:**
  - Attribution coverage под штормом 10k unique IP: было 60 IP/min, стало 10000 IP/min (167×).
  - Aggregator RAM под штормом 100k IP: было риск OOM при 2GB, стало bounded 512MB hard cap.
  - PCAP retention: было 7 дней (обещано 30), стало реальные 30 дней через tar.zst.
  - **auto-promote оживлён** — реально создаёт permanent bans для chronic attackers.
  - `limits.conf` позволяет tuning под профиль нагрузки без правки исходника.

  **⚠️ Limits & known issues:**
  - IPv6 защита всё ещё не пофикшена (архитектурный, требует full v6 ruleset).
  - `guard upgrade` без crypto verification (требует GPG/Sigstore signing).
  - Перед prod rollout рекомендуется staging-нода × 24h. Используй `nft -c -f /etc/nftables.d/ddos-protect.conf` для parse-only проверки до apply.

  Полные детали аудита: SELF-REVIEW.md и SELF-REVIEW-FIXES.md в репо.

- **v3.23.12** — COSMETIC FIX:
  - **FIX**: финальное сообщение установщика и Settings menu показывали `ct=50000` (legacy hardcoded text). Реальный лимит в nft = 15000 с v3.23.3+, но текст не был обновлён. Поправлено.
- **v3.23.11** — SYSTEMD ESCAPE FIX (hotfix к v3.23.10):
  - **CRIT FIX**: pcap-service не работал в v3.23.10. systemd unit использует `%` как СВОИ specifiers (`%H`=hostname, `%m`=machineid, `%Y`=hash). В v3.23.10 я написал `%Y%m%d` для tcpdump strftime, но systemd подставлял свои значения ДО tcpdump. Результат: tcpdump получал имя файла `syn-/etc/systemd/system07397.../sweden2.../var/lib.pcap` и падал каждые 10 секунд (`No such file or directory`).
  - Fix: вернуть `%%Y%%m%%d-%%H%%M%%S` в unit-файле. Внутри single-quote heredoc `%%` сохраняется literal → systemd получает `%%` → даёт tcpdump один `%` для strftime → правильное имя файла `syn-20260524-185857.pcap`.
  - **FIX**: `guard self-test` "integer expression expected" на line 130. `grep -c ... || echo 0` приклеивал второй "0" к выводу когда grep возвращал 0 → `[ "0\n0" -gt 5 ]` падал. Заменено на `${X:-0}` default.
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
