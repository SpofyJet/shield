# 🛡️ shieldnode

Комплексная DDoS-защита VPN-нод **Remnawave / Xray** (Ubuntu 24.04+, XanMod).
Один скрипт: nftables-фильтрация на prerouting, CrowdSec + firewall-bouncer,
динамические blocklist-фиды, автовосстановление после инцидентов и TUI-панель `guard`.

![version](https://img.shields.io/badge/version-v4.1.0-blue)
![platform](https://img.shields.io/badge/platform-Ubuntu%2024.04%2B-orange)
![shell](https://img.shields.io/badge/lang-bash-lightgrey)

## Установка — одна команда

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh)
```

Пиннинг на конкретный релиз:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/v4.1.0/shieldnode.sh)
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

## Changelog v4.1.0

FEEDS-релиз: ссылки-фиды прямо в lists/scanner.txt.

- **inline-URL в list-файлах**: строки `https://...` в `/etc/shieldnode/lists/*.txt`
  качаются как полноценные фиды (plain + JSON). Добавить фид = вставить ссылку
  в `lists/scanner.txt` на github — shieldnode.sh трогать не нужно
- **github-sync** теперь синкает `custom.txt` И `scanner.txt` каждые 6ч
  (+ мгновенный рестарт updater'а после синка, без ожидания timer'а)
- **lists/scanner.txt пересобран**: 12 фидов-ссылок (RIPEstat AS61280/AS213853
  ГРЧЦ + AS197571 НКЦКИ — живые BGP из RIPE RIS; ShadowWhisperer 60k + maltrail +
  OpenFilters binaryedge/strechoid — 99.9% union'а 15 фидов по overlap-анализу)
  + 1 343 сети RKN-статики (ГРЧЦ LIR, Roskomnadzor-net, СКИПА, APN-RKN)
  — валидировано боевыми хитами на 8 нодах (17.9M хитов, 14 809 IP)
- дедуп URL'ов, закомментированный `# http...` фид не качается

Полная история изменений — в шапке скрипта `shieldnode.sh`.

---

*Деплой этого релиза: [`deploy-github.sh`](https://github.com/SpofyJet/shield) · classic PAT, одна команда.*
