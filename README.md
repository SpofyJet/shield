# shieldnode

**DDoS-защита для VPN-нод на уровне ядра.** Один bash-скрипт: `nftables` + `SYNPROXY` + `CrowdSec` + адаптивный conntrack-guard.

Целевые ОС: **Ubuntu 22.04 / 24.04, Debian 12 / 13**. Совместим с любым VPN-стеком (Xray Reality, sing-box, Hysteria2, WireGuard, AmneziaWG) и с UFW. Терминируется отдельно — shieldnode только фильтрует трафик на L3/L4.

---

## Быстрый старт

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash
```

> Используй `curl | sudo bash`, **не** `bash <(curl ...)` — process substitution не работает в OpenVZ/LXC.

После установки всё управление — через `sudo guard`.

---

## Что делает

shieldnode закрывает **L3/L4**: режет SYN / UDP / connection-флуд на уровне ядра, защищает conntrack-таблицу от исчерпания (SYNPROXY + conntrack-guard), банит сканеры и известные угрозы по блоклистам, держит SSH под pre-auth rate-limit и переживает **распределённый connect-and-hold флуд** (см. ниже).

Kernel-tuning (BBR, qdisc, сетевые буферы, sizing conntrack) — **не** зона shieldnode, это задача парного скрипта `vpn-node-setup`. shieldnode пишет только свои security-sysctl в `/etc/sysctl.d/90-shieldnode.conf` (rp_filter, syncookies, rfc1337, redirects off, ICMP hardening, UDP/TCP conntrack timeouts). Префикс `90-` позволяет перекрыть значения через `99-*.conf`.

**Чего L3/L4 НЕ закрывает:** перегрузку самого приложения и адаптивный флуд с «живыми» сокетами. Это потолок пакетного фильтра — параллельно ставь лимиты коннектов в xray/remnawave (per-inbound).

---

## Архитектура

Защита идёт слоями в таблице `inet ddos_protect` (hook prerouting):

1. **ct established** — установленные соединения пропускаются сразу.
2. **whitelist** — `manual_whitelist` (mgmt-IP из UFW авто-синком) + инфраструктура (~220 CIDR CDN/edge: Cloudflare, Google, Akamai, Fastly, Apple, Meta, GitHub, Telegram, Yandex). Whitelist стоит **первым** — админ и mgmt-IP не блокируются ничем.
3. **anti-spoof** — fib reverse-path (single-homed VPS).
4. **TCP flag sanity** — drop XMAS / NULL / SYN+FIN / SYN+RST.
5. **blocklists** — scanner / threat / tor / custom → drop.
6. **SSH pre-auth** — ct=5 + 8/min, ещё до того как пакет дойдёт до sshd.
7. **rate-limits** — conn-flood / newconn / syn / udp с архитектурой **ban-once**.

Изолированно, в **отдельных** nft-таблицах (не трогают `ddos_protect`, откат = удаление таблицы):

- `inet shield_synproxy` — SYNPROXY (защита от conntrack-exhaustion).
- `inet shield_ctguard` — adaptive conntrack-guard + phantom-эвикт (защита от connect-and-hold).

Приоритеты hook'ов согласованы: CrowdSec-bouncer `-200` → ctguard `-160/-159` → ddos_protect `-150/-100`. SYNPROXY перехватывает SYN ещё раньше (`-300`).

---

## conntrack-guard / phantom-защита (v3.26)

**Проблема — распределённый connect-and-hold флуд.** Сотни IP открывают тысячи TCP-соединений, проходят handshake и **бросают** их. Записи висят в conntrack, приложение (xray) захлёбывается — при этом conntrack-таблица может быть заполнена лишь на 7–20%, так что классический «fill ≥90%» триггер молчит. Per-IP-порог тоже бесполезен: пик атаки (~1800–2300 conn/IP) **пересекается** с легит-CGNAT-потолком (~2200 conn/IP) — счётчиком не разделить.

**Решение — детект по ЖИВЫМ сокетам (`shieldnode-ctguard`):**

- **Признак фантома:** у источника `conntrack ≫ живых сокетов (ss)`. Атакер бросил соединение → живых сокетов 0; легит держит трафик → `live ≈ conntrack`. Это `acct`-free (не зависит от `nf_conntrack_acct`).
- **Триггер attack-mode:** `ss-phantom-ratio` (доля conntrack без живого сокета). Норма ≤3%, атака 96–98%. Плюс EWMA-отклонение new-conn/conntrack от нормы ноды и fill-триггер как backstop.
- **Ответ:** агрегатный кап new-conn на защищаемые порты (глобальный, **не** per-IP → безопасно для CDN/CGNAT) + эвикт источников-фантомов (nft-блок + `conntrack -D`, опц. CrowdSec-бан).
- **CGNAT-safe by design:** эвикт срабатывает **только в attack-mode**, и источник щадится при любом из условий — живых сокетов > порога (shared-front/CGNAT), live-доля выше порога, или IP в whitelist. Здоровая нода в attack-mode не входит → не выселяет вообще.
- **sysctl:** `nf_conntrack_tcp_timeout_established=1800` (брошенные фантомы дохнут за 30 мин вместо 5 суток; живые сессии с keepalive переживают).
- **Производительность:** дешёвый коарс-гейт — дорогой полный дамп `conntrack -L` запускается только если `conntrack ≫ ss_total` (фантом-тяжело) или мы уже в attack-mode. Здоровая busy-нода не платит за дамп каждый тик.

**Раскат — observe → enforce.** По умолчанию `SHIELD_CTG_ENFORCE=1`, но для осторожного ввода на новой ноде поставь `0` (только лог), убедись по `journalctl -t shieldnode-ctguard`, что в кандидатах только атакеры (live=0), затем включи:

```bash
sudo sed -i 's/^SHIELD_CTG_ENFORCE=.*/SHIELD_CTG_ENFORCE=0/' /etc/shieldnode/shieldnode.conf
# наблюдаешь журнал… кандидаты = только атакеры? тогда:
sudo sed -i 's/^SHIELD_CTG_ENFORCE=0/SHIELD_CTG_ENFORCE=1/' /etc/shieldnode/shieldnode.conf
sudo systemctl restart shieldnode-ctguard
```

---

## SYNPROXY

Когда флуд незавершённых SYN забивает conntrack — нода превращается в чёрную дыру (`nf_conntrack: table full`). SYNPROXY это закрывает: SYN перехватывается **до** conntrack, проходит syncookie-хендшейк, запись создаётся только после полного 3-way.

- Модуль `shieldnode-synproxy.sh`, таблица `inet shield_synproxy`. Включён по умолчанию (`SHIELD_SYNPROXY=1`).
- Безопасно: ядро не поддерживает → авто-fallback на `ddos_protect`; на стоковых ядрах авто-доустановка `linux-modules-extra-$(uname -r)` (на XanMod встроен); verify mss/wscale живого бэкенда + авто-откат при несовпадении.
- Требует ядро **≥5.14** + модуль `nf_synproxy`. Переживает ребут. Выключить: `SHIELD_SYNPROXY=0` или `sudo shieldnode-synproxy.sh off`.
- Порты синхронятся с фаерволом (ports-watcher держит `sp_ports` в актуальном состоянии).

---

## Лимиты

Рассчитаны на ноду с **500–1000 VPN-клиентами**. Тюнятся в `/etc/shieldnode/limits.conf`.

| Параметр              | Значение               | Обоснование                                  |
| --------------------- | ---------------------- | -------------------------------------------- |
| conn-flood (per-IP)   | ct > 15000             | высокий backstop; точность отдана phantom-слою |
| newconn               | 40000/min, burst 60000 | масс-reconnect 200 юзеров × 50 retry          |
| SYN                   | 2000/sec, burst 3000   | CGNAT 200 юзеров × 1–2 SYN/sec                |
| UDP                   | 10000/sec, burst 20000 | Hysteria2/QUIC 4K + cloud gaming              |
| SSH (per-IP)          | ct=5 + 8/min           | CGNAT-админ + ansible на ≤5 нод               |

Реальные атаки (50k+ SYN/sec, 100k+ соединений) дропаются на уровне ядра. Архитектура **ban-once**: первое нарушение → `suspect` (30 мин наблюдения, без drop), второе → `confirmed` (15 мин drop). Снижает ложные баны CGNAT/мобильных.

> Per-IP `conn-flood` намеренно высокий (15000) — он лишь грубый backstop для одиночных экстремальных холдеров. Распределённый флуд ловит liveness-aware ctguard, а не per-IP-порог.

---

## Блоклисты

- **scanner** — Shodan / Censys / госсканеры РФ.
- **threat** — Spamhaus DROP + FireHOL Level 1 + Feodotracker (high-confidence, ~7–8k IP, bogon-фильтр min /16).
- **tor** — Tor exit nodes (опционально, `BLOCK_TOR=1`).
- **custom** — личный список оператора.

**custom** собирается из трёх источников: `lists/custom.txt` (синк с GitHub каждые 6 ч) + `custom-local.txt` (локальные дополнения, не перезаписываются) + auto-promote.

**Auto-promote:** IP с count ≥ 800 за 24 ч (conn/syn/udp-escalate) попадает в `custom-local.txt` навсегда. TTL 90 дней — запись удаляется, если IP не атакует > 30 дней. Перед каждым промоутом — cross-check с CrowdSec whitelist.

---

## PCAP-форензика

Always-on rolling capture (SYN-only, 128 байт/пакет) — нумерованный ring-buffer на 1 GB в `/var/log/pcap/`. При скачке > 10k drops/min текущий ring архивируется в `/var/lib/shieldnode/pcap-archive/attack-<TS>/`. Последние ~1 GB трафика всегда на диске — есть что отправить хостеру при DDoS, в том числе по атакам, не задевшим пороги.

---

## CrowdSec

SSH brute-force + community blocklist (~28k IP, stream mode), nftables-bouncer на prerouting (`priority -200`, раньше всех слоёв shieldnode). `TRUSTED_IPS` применяются на parser-level (postoverflow whitelist) — trusted-IP не банятся даже сценариями; поддерживается CIDR. Чужой (foreign) CrowdSec корректно детектится и не патчится.

---

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

Дашборд показывает **реальные дропы всех слоёв**, включая `ctguard phantom-evict` и `cap` (отдельная таблица), режим ctguard (normal/**attack**) и `phantom-ratio`, статус SYNPROXY, conntrack %, блоклисты, top-attackers. `self-test` проверяет в т.ч. heartbeat ctguard (детект залипшего таймера).

Интерактивное меню: `[2]` CrowdSec bans, `[3]` whitelist, `[6]` recent history, `[7]` top attackers (all-time), `[8]` unban all, `[s]` settings.

---

## Конфигурация

- `/etc/shieldnode/limits.conf` — все лимиты + ручки ctguard (`SHIELD_CTG_ENFORCE`, `SHIELD_CTG_LIVE_FRAC`, `SHIELD_CTG_PHANTOM_RATIO`, `SHIELD_CTG_PHANTOM_MIN`, `SHIELD_CTG_ACTIVE_FLOOR`, `SHIELD_CTG_CT_MAX_CEIL`, `SHIELD_CTG_COARSE_MULT`). Файл sourced'ится с проверкой прав (root:root, 0640).
- `/etc/shieldnode/shieldnode.conf` — фичи: `SHIELD_SYNPROXY`, `SHIELD_CTGUARD`, `BLOCK_TOR`, `TRUSTED_IPS` (single IP и CIDR), и др.

После изменения лимитов: `sudo systemctl restart shieldnode-nftables.service` (для nft) и `sudo systemctl restart shieldnode-ctguard` (для ctguard), либо `sudo guard upgrade`.

---

## Удаление

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash -s -- --uninstall
```

Удаляет все таблицы (`ddos_protect`, `shield_synproxy`, `shield_ctguard`), юниты, таймеры, state и sysctl-drop-in.

---

## Совместимость

- **UFW** — открытые порты читаются автоматически (inotify path-watcher + catch-all timer).
- **Любой VPN-стек** — терминируется отдельно, shieldnode только фильтрует.
- **Другие nft-таблицы** — мирно сосуществует (свои изолированные таблицы, без `flush ruleset`, UFW не ломается).
- **`vpn-node-setup`** — парный скрипт для kernel-tuning (XanMod/BBRv3); зоны ответственности не пересекаются.

---

## Изменения (последние)

- **v3.26.3** — perf: дешёвый коарс-гейт в ctguard (полный `conntrack -L` дамп только при `conntrack ≫ ss` или attack-mode). Наблюдаемость: guard «Total blocked» + разбивка включают дропы ctguard-слоя; `self-test` проверяет heartbeat ctguard. Конфиг: ручки `SHIELD_CTG_*` выведены в `limits.conf`.
- **v3.26.x** — phantom-детект по **живым сокетам** (`ss` vs conntrack, acct-free) + `ss-phantom-ratio` триггер + conntrack-exhaustion guard. Заменил байтовый детектор (тот при `acct=0` мог масс-эвиктить CGNAT — критфикс). `is_protected` v4/v6, synproxy `sp_ports` auto-merge + синк портов. per-IP conn-flood = высокий backstop 15000.
- **v3.24.0** — SYNPROXY включён по умолчанию; первый модуль conntrack-guard (тогда — только fill-триггер + per-IP-порог; в v3.26 переписан на liveness).
- **v3.23.19** — CRIT FIX агрегатора (lock под `ProtectSystem=strict` падал → статистика замерзала).
- **v3.23.16** — SYNPROXY как изолированный модуль (защита от conntrack-exhaustion).
- **v3.23.15** — security hardening: SQL-inj через journald, bogon-фильтр фидов, оживление auto-promote, RAM-cap агрегатора, SSH/IPv6.
- **v3.23.3** — post-incident (2026-05-24): conn-flood 50k→15k, pcap-capture, auto-promote, CrowdSec scenario.

Полная история: <https://github.com/SpofyJet/shield/commits/main>

---

## Поддержка

Вопросы по установке, тюнингу под нагрузку и кастомные настройки — Telegram **[@SpofySup](https://t.me/SpofySup)**.

---

## Лицензия

MIT — см. [LICENSE](LICENSE).
