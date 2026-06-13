# shieldnode

Коммерческий слой DDoS-защиты для VPN-нод на базе **nftables + CrowdSec**. Заточен под Remnawave / Xray (VLESS Reality, Hysteria2, Shadowsocks) и российский рынок: CGNAT-aware, без ложных банов за NAT, дружелюбен к DPI-evasion-топологиям.

Работает в `prerouting` (до conntrack-логики), не конфликтует с UFW и Docker (фильтрация форварда остаётся в `DOCKER-USER`).

## Установка

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash
```

Установка идемпотентна: повторный запуск/`guard upgrade` безопасно перенакатывает правила и подтягивает свежую версию.

## Требования

- Debian 12/13 (bookworm/trixie) или Ubuntu 24.04+
- root
- ядро с поддержкой nftables (штатно во всех поддерживаемых дистрибутивах)

## Что делает

Многослойная защита, каждый слой независим:

- **nftables prerouting** — rate-limit на SYN / UDP / новые соединения, per-IP conntrack-лимиты, дроп пакетов с невалидными комбинациями флагов (NULL / XMAS / SYN+FIN / SYN+RST / FIN+RST), пре-аутентификационная защита SSH от флуда.
- **Блоклисты** (v4 + v6) — scanner / tor-exit / threat / custom, с курируемыми CIDR из реальных атак.
- **ctguard** — страж исчерпания conntrack: следит за заполнением таблицы, в attack-mode поднимает лимиты и эвиктит, **CGNAT-aware** (не банит хосты за общим NAT). Порог конн-флуда per-IP по умолчанию 15000.
- **auto-promote** — повторно атакующие IP автоматически уезжают в локальный блоклист с TTL.
- **pcap-форензика** — при всплеске дропов (порог) снимается дамп для разбора, с ротацией.
- **CrowdSec** — интеграция через bouncer.
- **Remnawave node-sync** — IP нод панели автоматически держатся в whitelist (режим `auto`).
- **SYNPROXY** — анти-спуф-SYN через notrack. **С v3.30.2 — opt-in (по умолчанию выключен)**: на VPN-туннеле несёт seqadj/window-риски и убивает TFO, а его пользу на нодах без conntrack-давления дублируют syncookies + per-IP ct-лимиты. Включается под реальный спуфнутый SYN-флуд: `SHIELD_SYNPROXY=1`.
- **Единый реапер устаревшего** — при каждом install/upgrade сам находит и снимает артефакты прошлых версий (старые таймеры/скрипты/sysctl, выключенный SYNPROXY и т.д.) по курируемому списку.

## Управление: `guard`

После установки доступна команда `guard`:

```bash
sudo guard            # снимок состояния + интерактивное меню
sudo guard --json     # JSON для интеграций (Zabbix / Prometheus / боты)
sudo watch -n 5 guard # live-режим
```

Подкоманды:

| Команда | Назначение |
|---|---|
| `guard self-test` | самопроверка правил и сервисов |
| `guard upgrade` | обновление до свежей версии (snapshot + re-exec; раскатка на флот) |
| `guard rollback` | откат на предыдущий snapshot |
| `guard sync` | подтяжка блоклистов/нод вручную |
| `guard check` | проверка целостности/доступности обновления |
| `guard status` | краткий статус |

## Ключевые параметры (env при установке)

Передаются перед запуском, например `SHIELD_SYNPROXY=1 SHIELD_RATE_SYN=3000/second sudo bash shieldnode.sh`.

| Переменная | Дефолт | Назначение |
|---|---|---|
| `SHIELD_SYNPROXY` | `0` | SYNPROXY (opt-in; 1 — включить под спуф-SYN-флуд) |
| `SHIELD_CTGUARD` | `1` | страж conntrack-exhaustion |
| `SHIELD_CGNAT_SAFE` | `1` | не банить хосты за общим NAT |
| `SHIELD_CT_CONN_FLOOD` | `15000` | потолок коннектов на один IP |
| `SHIELD_RATE_SYN` | `2000/second` | лимит новых SYN (burst `3000`) |
| `SHIELD_RATE_UDP` | `10000/second` | лимит UDP (burst `20000`) |
| `SHIELD_RATE_NEWCONN` | `40000/minute` | лимит новых соединений (burst `60000`) |
| `SHIELD_SSH_NEWCONN_RATE` | `8/minute` | анти-флуд SSH (burst `20`, ct-лимит `5`) |
| `SHIELD_AUTOPROMOTE_THRESHOLD` | `800` | порог авто-промоушна IP в блоклист (окно 24ч) |
| `SHIELD_REMNAWAVE_SYNC` | `auto` | автоподтяжка IP нод Remnawave |
| `SHIELD_PCAP_TRIGGER_DROPS` | `10000` | порог дропов для снятия pcap |
| `SHIELD_EVENTS_DB_RETENTION_DAYS` | `90` | хранение БД событий |

Полный список — в шапке скрипта.

## Удаление

```bash
sudo bash shieldnode.sh --uninstall
```

Сносит правила, сервисы, таймеры, sysctl-оверрайды и сопутствующие артефакты.

## Версия

Текущая: **v3.30.2**. История изменений — в шапке `shieldnode.sh` и в разделе Releases.
