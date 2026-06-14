# shieldnode

Защита VPN-нод от DDoS и сетевого абуза на базе **nftables**. Один скрипт ставит многослойную фильтрацию в `prerouting`, держит conntrack под контролем и переживает перезагрузки. Заточен под высоконагруженные релеи (VLESS/Reality, Hysteria2, Shadowsocks) и CGNAT-реалии: не банит абонентов за общим NAT.

---

## Быстрый старт

```bash
curl -fL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh | sudo bash
```

Повторный запуск безопасен — правила и сервисы перенакатываются идемпотентно, версия подтягивается свежая.

## Требования

| | |
|---|---|
| ОС | Debian 12/13 · Ubuntu 24.04+ |
| Права | root |
| Ядро | с поддержкой nftables (штатно) |

## Возможности

- **Rate-limiting в nftables** — пороги на SYN, UDP и новые соединения с burst-окнами.
- **Per-IP conntrack-лимиты** — потолок одновременных коннектов с одного адреса (анти connect-and-hold).
- **Дроп невалидных пакетов** — NULL / XMAS / SYN+FIN / SYN+RST / FIN+RST сканы режутся по флагам.
- **Блоклисты v4/v6** — scanner / tor-exit / threat / custom, с курируемыми CIDR из боевых данных.
- **ctguard** — страж исчерпания conntrack: следит за заполнением таблицы, в режиме атаки поднимает лимиты и эвиктит. CGNAT-aware.
- **Авто-промоушн** — повторно атакующие адреса уезжают в локальный блоклист с TTL.
- **Pcap-форензика** — при всплеске дропов снимается дамп для разбора, с ротацией.
- **CrowdSec** — интеграция через bouncer.
- **SYNPROXY (opt-in)** — анти-спуф-SYN через notrack. По умолчанию выключен; включается под реальный спуфнутый SYN-флуд переменной `SHIELD_SYNPROXY=1`.
- **Авто-очистка устаревшего** — при каждой установке/обновлении снимаются артефакты прошлых версий по курируемому списку.
- **Переживает ребут** — модуль conntrack форсится при загрузке до применения sysctl, ключевые параметры не теряются.

## Управление

После установки доступна команда `guard`:

```bash
sudo guard            # снимок состояния + интерактивное меню
sudo guard --json     # JSON для Zabbix / Prometheus / ботов
sudo watch -n 5 guard # live-режим
```

| Подкоманда | Действие |
|---|---|
| `guard self-test` | самопроверка правил и сервисов |
| `guard upgrade`   | обновление до свежей версии (snapshot + перезапуск) |
| `guard rollback`  | откат на предыдущий snapshot |
| `guard sync`      | ручная подтяжка блоклистов |
| `guard check`     | проверка целостности и доступности обновления |
| `guard status`    | краткий статус |

## Параметры (env при установке)

Передаются перед запуском:
`SHIELD_SYNPROXY=1 SHIELD_RATE_SYN=3000/second sudo bash shieldnode.sh`

| Переменная | Дефолт | Назначение |
|---|---|---|
| `SHIELD_SYNPROXY` | `0` | SYNPROXY (1 — включить под спуф-SYN-флуд) |
| `SHIELD_CTGUARD` | `1` | страж conntrack-exhaustion |
| `SHIELD_CGNAT_SAFE` | `1` | не банить хосты за общим NAT |
| `SHIELD_CT_CONN_FLOOD` | `15000` | потолок коннектов на один IP |
| `SHIELD_RATE_SYN` | `2000/second` | лимит SYN (burst `3000`) |
| `SHIELD_RATE_UDP` | `10000/second` | лимит UDP (burst `20000`) |
| `SHIELD_RATE_NEWCONN` | `40000/minute` | лимит новых соединений (burst `60000`) |
| `SHIELD_SSH_NEWCONN_RATE` | `8/minute` | анти-флуд SSH (burst `20`, ct-лимит `5`) |
| `SHIELD_AUTOPROMOTE_THRESHOLD` | `800` | порог авто-промоушна IP (окно 24ч) |
| `SHIELD_PCAP_TRIGGER_DROPS` | `10000` | порог дропов для снятия pcap |
| `SHIELD_EVENTS_DB_RETENTION_DAYS` | `90` | хранение БД событий |

Полный список — в шапке скрипта.

## Удаление

```bash
sudo bash shieldnode.sh --uninstall
```

Снимает правила, сервисы, таймеры, sysctl-оверрайды и сопутствующие артефакты.

## Версия

**v3.30.4** · история изменений — в шапке `shieldnode.sh` и в разделе Releases.
