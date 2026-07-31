# shield — защита VPN-ноды от сканеров и DDoS (shieldnode)

**v3.37.7** · Debian 12/13 · Ubuntu 24.04+

nftables + CrowdSec: отсекает сканеров, брутфорс и флуд до того, как они
дойдут до Xray. Управление — через интерактивный `guard`.

## Быстрый старт

```bash
curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh -o shieldnode.sh
sudo bash shieldnode.sh
```

После установки:

```bash
sudo guard          # дашборд: угрозы, дропы, whitelist, сервисы
sudo guard --json   # то же в JSON (для мониторинга)
```

## Что внутри

| Компонент | Роль |
|---|---|
| **nftables ddos_protect** | rate-limits (syn/udp/newconn), conn-flood per-IP, dynamic sets с timeout |
| **CrowdSec + bouncer** | сценарии комьюнити + собственные (VPN-специфика), решения о банах |
| **Блоклисты** | Spamhaus DROP, FireHOL L1, scanner/threat/tor/custom — обновление по таймерам |
| **Whitelist single-writer** | один писатель `manual_whitelist_v4` (file ∪ mgmt) — нет race |
| **Tarpit (endlessh)** | SSH-сканеры висят бесконечно |
| **Auto-promote** | повторные нарушители → постоянный бан в custom blocklist |
| **Rollback (node-rollback)** | snapshot перед изменениями, восстановление в 1 команду |
| **API (unix-socket)** | `guard --json` по HTTP, socket-activated (0 в idle) |
| **Metrics / notify** | node_exporter textfile + Telegram-уведомления (отключаемые) |
| **Fleet-sync** | авто-whitelist нод Remnawave-флота |
| **chrony NTS** | шифрованное время (анти-подделка NTP) |
| **earlyoom** | OOM не тронет xray/sshd/crowdsec |

## Управление trusted IP

`sudo guard` → **Trusted IPs** — полный whitelist в 1 действие
(nft + UFW + CrowdSec decision + postoverflow). Изменения применяются
мгновенно (явный sync, не path-watcher).

## Удаление

```bash
sudo bash shieldnode.sh --uninstall
```

Changelog — в шапке `shieldnode.sh` (newest-first).
Парный проект: [SpofyJet/node](https://github.com/SpofyJet/node) — оптимизация ноды.
