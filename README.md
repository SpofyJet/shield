# shieldnode

DDoS-защита для VPN-нод на уровне ядра. Один bash-скрипт: **nftables + SYNPROXY + CrowdSec**.

Целевые ОС: Ubuntu 22.04 / 24.04, Debian 12 / 13. Совместим с любым VPN-стеком (Xray Reality, sing-box, Hysteria2, WireGuard, AmneziaWG) и с UFW.

## Быстрый старт

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash
```

> Используй `curl | sudo bash`, а **не** `bash <(curl ...)` — process substitution не работает в OpenVZ/LXC.

После установки всё управление — через `sudo guard`.

## Что делает

shieldnode закрывает **L3/L4**: режет SYN/UDP/conn-флуд на уровне ядра (nftables), защищает conntrack от исчерпания (SYNPROXY), банит сканеры и известные угрозы по блоклистам, держит SSH под pre-auth rate-limit.

Kernel-tuning (BBR, qdisc, сетевые буферы, sizing conntrack) — **не** зона shieldnode, это задача парного скрипта `vpn-node-setup`. shieldnode пишет только свои security-sysctl в `/etc/sysctl.d/90-shieldnode.conf` (rp_filter, syncookies, rfc1337, redirects off, ICMP hardening, UDP conntrack timeouts). Префикс `90-` позволяет перекрыть значения через `99-*.conf`.

## Архитектура

Защита идёт слоями в таблице `inet ddos_protect` (hook prerouting):

1. **ct established** — установленные соединения пропускаются сразу.
2. **whitelist** — `manual_whitelist` + инфраструктура (~220 CIDR CDN/edge: Cloudflare, Google, Akamai, Fastly, Apple, Meta, GitHub, Telegram).
3. **anti-spoof** — fib reverse-path (single-homed VPS).
4. **TCP flag sanity** — drop XMAS / NULL / SYN+FIN / SYN+RST.
5. **blocklists** — scanner / threat / tor / custom → drop.
6. **SSH pre-auth** — ct=5 + 8/min, ещё до того как пакет дойдёт до sshd.
7. **rate-limits** — conn-flood / newconn / syn / udp.

Отдельно и изолированно — **SYNPROXY** (таблица `inet shield_synproxy`): SYN перехватывается до conntrack, проходит syncookie-хендшейк, запись в conntrack создаётся только после полного 3-way. Это защита от исчерпания conntrack-таблицы.

## SYNPROXY (v3.23.16+)

Когда флуд незавершённых SYN забивает conntrack-таблицу — нода превращается в чёрную дыру (`nf_conntrack: table full`). SYNPROXY это закрывает.

- Модуль `shieldnode-synproxy.sh`, таблица `inet shield_synproxy` — **не трогает** `ddos_protect`. Откат = удаление таблицы, нода не падает.
- По умолчанию **выключен** (`SHIELD_SYNPROXY=0`, opt-in): synproxy меняет TCP data-path, на нодах с нестандартным MTU/фаерволом включать после своей проверки. Включить: `SHIELD_SYNPROXY=1` в `shieldnode.conf` или `sudo shieldnode-synproxy.sh on`.
- Авто-детект портов / mss / wscale, verify по живому SYN-ACK, авто-откат при конфликте слоёв.
- Требует ядро **≥5.14** + модуль `nf_synproxy`. Если их нет — выводит чёткую причину, `ddos_protect` продолжает работать штатно.
- Переживает ребут (`shieldnode-synproxy.service`).

## Лимиты

Рассчитаны на ноду с **500–1000 VPN-клиентами**. Тюнятся в `/etc/shieldnode/limits.conf`.

| Параметр | Значение | Обоснование |
|---|---|---|
| conn-flood (per-IP) | ct > 15000 | легит-пик 700–750 conn/IP; запас ~20x |
| newconn | 40000/min, burst 60000 | масс-reconnect 200 юзеров × 50 retry |
| SYN | 2000/sec, burst 3000 | CGNAT 200 юзеров × 1–2 SYN/sec |
| UDP | 10000/sec, burst 20000 | Hysteria2/QUIC 4K + cloud gaming |
| SSH (per-IP) | ct=5 + 8/min | CGNAT-админ + ansible на ≤5 нод |

Реальные атаки (50k+ SYN/sec, 100k+ соединений) дропаются на уровне ядра. Архитектура **ban-once**: первое нарушение → suspect (30 мин наблюдения без drop), второе → confirmed (15 мин drop).

## Блоклисты

- **scanner** — Shodan / Censys / госсканеры РФ (shadow-netlab + CyberOK).
- **threat** — Spamhaus DROP + FireHOL Level 1 + Feodotracker (high-confidence, ~7–8k IP).
- **tor** — Tor exit nodes (опционально, `BLOCK_TOR=1`).
- **custom** — личный список оператора.

**custom** собирается из трёх источников: `lists/custom.txt` (синк с GitHub каждые 6ч) + `custom-local.txt` (локальные дополнения, не перезаписываются) + auto-promote.

**Auto-promote:** IP с count ≥ 800 за 24ч (conn/syn/udp-escalate) попадает в `custom-local.txt` навсегда. TTL 90 дней — запись удаляется, если IP не атакует > 30 дней. Перед каждым промоутом — cross-check с CrowdSec whitelist.

## PCAP-форензика

Always-on rolling capture (SYN-only, 128 байт/пакет) — нумерованный ring-buffer на 1GB в `/var/log/pcap/`. При скачке > 10k drops/min текущий ring архивируется в `/var/lib/shieldnode/pcap-archive/attack-<TS>/`. Последние ~1GB трафика всегда на диске — есть что отправить хостеру при DDoS, в том числе для атак, которые не задели пороги.

## CrowdSec

SSH brute-force + community blocklist (~28k IP, stream mode), nftables-bouncer на prerouting. `TRUSTED_IPS` применяются на parser-level (postoverflow whitelist) — trusted-IP не банятся даже сценариями; поддерживается CIDR. Чужой (foreign) CrowdSec корректно детектится и не трогается.

## guard CLI

```bash
sudo guard            # дашборд + интерактивное меню
sudo guard --once     # снимок без меню (cron / мониторинг)
sudo guard --json     # JSON-вывод (Zabbix / Prometheus)
sudo guard upgrade    # re-install с GitHub (auto-snapshot для отката)
sudo guard rollback   # откат к предыдущему снапшоту
sudo guard sync       # синк custom.txt прямо сейчас
sudo guard self-test  # быстрые проверки ноды
```

Интерактивное меню: `[2]` CrowdSec bans, `[3]` whitelist, `[6]` recent history, `[7]` top attackers (all-time), `[8]` unban all, `[s]` settings.

## Конфигурация

- `/etc/shieldnode/limits.conf` — все лимиты (tier-aware, ~17 параметров).
- `/etc/shieldnode/shieldnode.conf` — фичи: `SHIELD_SYNPROXY`, `BLOCK_TOR`, `TRUSTED_IPS` (single IP и CIDR), и др.

## Удаление

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash -s -- --uninstall
```

## Совместимость

- **UFW** — открытые порты читаются автоматически (inotify path-watcher + catch-all timer).
- **Любой VPN-стек** — терминируется отдельно, shieldnode только фильтрует трафик.
- **Другие nft-таблицы** — мирно сосуществует (своя `inet ddos_protect`, синхронно — изолированная `inet shield_synproxy`).

## Изменения (последние)

- **v3.23.19** — CRIT FIX агрегатора: под `ProtectSystem=strict` юнит не объявлял `/run/shieldnode` writable → lock падал (RO fs) → агрегатор скипал каждый тик → events.db/статистика замораживались (защита выглядела «не реагирующей», хотя nft дропал). + агрегатор теперь пишет CRITICAL вместо молчаливого skip.
- **v3.23.18** — synproxy: теперь показывает причину невключения (фикс молчаливого `set -e` + grep, явный `die` на `nft -f` при отсутствии `nf_synproxy`); custom-счётчик виден в панели всегда; чистка меню (убраны active-attacks / scanner-samples / full-log + settings force-sync/version-check).
- **v3.23.17** — FIX переполнения диска: rolling pcap рос до десятков GB (strftime-имя ломало `-W` ring). Нумерованный ring 1GB + size-cap + авто-очистка legacy. Portable-даты в guard (`LC_ALL=C`).
- **v3.23.16** — SYNPROXY (opt-in, `SHIELD_SYNPROXY=0` по умолчанию): изолированный модуль, защита от conntrack-exhaustion.
- **v3.23.15** — security hardening: SQL-inj через journald, bogon-фильтр фидов, оживление auto-promote, RAM-cap агрегатора, SSH/IPv6.
- **v3.23.14** — убраны шумные threat-фиды (ложные баны CGNAT); фикс pipe-deadlock при `curl | bash`.
- **v3.23.3** — post-incident (2026-05-24): conn-flood 50k→15k, pcap-capture, auto-promote, CrowdSec scenario.

Полная история: https://github.com/SpofyJet/shield/commits/main

## Лицензия

MIT — см. [LICENSE](./LICENSE).
