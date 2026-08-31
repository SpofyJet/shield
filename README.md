# 🛡️ shieldnode

Комплексная DDoS-защита VPN-нод **Remnawave / Xray** (Ubuntu 24.04+, XanMod).
Один скрипт: nftables-фильтрация на prerouting, CrowdSec + firewall-bouncer,
динамические blocklist-фиды, автовосстановление после инцидентов и TUI-панель `guard`.

![version](https://img.shields.io/badge/version-v4.0.0-blue)
![platform](https://img.shields.io/badge/platform-Ubuntu%2024.04%2B-orange)
![shell](https://img.shields.io/badge/lang-bash-lightgrey)

## Установка — одна команда

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh)
```

Пиннинг на конкретный релиз:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/v4.0.0/shieldnode.sh)
```

Зеркало для РФ-нод (DPI может резать raw.githubusercontent.com):

```bash
SHIELD_FEED_MIRROR=https://your.mirror/ sudo bash <(curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh)
```

## Что внутри

- **nftables** `inet ddos_protect`: prerouting priority **-150** (раньше docker dstnat),
  атомарная загрузка `nft -f`, named counters, динамические set'ы с timeout
- **Rate-limit**: syn/udp/icmp-метры, drop `ct state invalid`, connlimit
- **CrowdSec + firewall-bouncer** (priority -200): поведенческие сценарии поверх сетевых метров
- **Blocklist-фиды**: Spamhaus DROP/EDROP, Firehol, Tor exit, анти-сканер листы;
  авто-зеркало для РФ (`SHIELD_FEED_MIRROR`)
- **Whitelist** с timer-реапплаем (OnBootSec=45s) и hash-guard v2
- **Conntrack**: tier-aware тюнинг `nf_conntrack_max`/hashsize по RAM ноды
- **Живучесть**: boot-repair юнит, snapshot + атомарный rollback, notify-алерты,
  watchdog за CrowdSec/bouncer/портами
- **guard** — TUI-панель: `[1]` Баны CrowdSec `[2]` Whitelist `[3]` Разбанить всех
  `[s]` Настройки `[r]` Обновить `[0]` Выход
- **Self-upgrade** с проверкой `bash -n` + маркера версии скачанного

## Управление

| Команда | Действие |
|---|---|
| `shieldnode --status` | сводка защиты (также `--json`) |
| `guard` | интерактивная TUI-панель |
| `guard --once` | одноразовый снапшот дашборда |
| `shieldnode --help` | полный список команд |
| `shieldnode uninstall` | полное удаление (откат всех артефактов) |

## Требования

- Ubuntu 24.04+ (x86_64), root
- Ядро XanMod — рекомендуется (ставится [vpn-node-setup](https://github.com/SpofyJet/node))
- Remnawave panel + remnanode/Xray в Docker

## Changelog v4.0.0

Полный аудит (39 находок) + S-оптимизации. Ключевое:

- tarpit/endlessh **удалён полностью** (не чинился — вырезан)
- drop `ct state invalid` перенесён **после** whitelist-accept'ов
- priority -150 безусловно; атомарная запись `ddos-protect.conf` (tmp + `nft -c` + mv)
- whitelist.timer + hash-guard v2, строгая валидация CIDR (отклонение /0–/7)
- uninstall закрывает 100% артефактов (юниты, sysctl, ufw, notify, rollback)
- boot-repair + маркер `.install-in-progress`, SMOKE_FAIL → exit 2
- guard: переработанное меню, чистый дашборд, защита от busy-loop не-TTY
- docker: daemon.json log-opts 50m×3, восстановление `ip nat`, healthcheck
- logrotate 10-мин тик; staleness-алерты фидов; snapshot → atomic rollback

Полная история изменений — в шапке скрипта `shieldnode.sh`.

---

*Деплой этого релиза: [`deploy-github.sh`](https://github.com/SpofyJet/shield) · classic PAT, одна команда.*
