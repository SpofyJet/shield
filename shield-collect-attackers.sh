#!/bin/bash
# shield-collect-attackers.sh
# Собирает 100%-кандидатов в бан из events.db.
# БЕЗОПАСНО для VPN: берёт только flood-сигнатуры (ddos/syn/conn/udp escalate)
# с высоким count, отсекает residential/mobile ISP (там живые клиенты),
# отсекает уже забаненные и whitelisted IP. Ничего не банит сам —
# пишет в /tmp/shield-candidates.txt для ревью, бан делаешь руками.
set -euo pipefail

DB=/var/lib/shieldnode/events.db
LISTS=/etc/shieldnode/lists
OUT=/tmp/shield-candidates.txt
MINCOUNT="${MINCOUNT:-200}"     # порог пакетов/событий
WINDOW="${WINDOW:-86400}"       # окно, сек (24ч)

[ -r "$DB" ] || { echo "нет $DB"; exit 1; }

# residential/mobile keywords → НЕ банить (там реальные юзеры)
RESI='broadband|residential|telecom|mobile|cellular|gpon|fiber|dsl|cable|retail|household|rostelecom|mts|beeline|megafon|dom\.ru|er-telecom|tele2|ufanet|sktel|comcast|spectrum|vodafone|orange|telefonica|t-mobile|at&t|verizon'

# уже забанено (exact IP) + whitelisted
known=$(cat "$LISTS"/custom.txt "$LISTS"/custom-local.txt "$LISTS"/whitelist-local.txt 2>/dev/null \
        | grep -oE '^[0-9.]+' | sort -u)

# flood-сигнатуры = 100% атака, обычный клиент их не триггерит
cands=$(sqlite3 "$DB" "
  SELECT ip FROM events
  WHERE type IN ('ddos','syn_escalate','conn_flood','newconn_flood','udp_escalate')
    AND count >= $MINCOUNT
    AND last_seen > strftime('%s','now')-$WINDOW
  GROUP BY ip
  ORDER BY MAX(count) DESC;")

: > "$OUT"
echo "# shieldnode attacker candidates $(date '+%F %T')" >> "$OUT"
echo "# MINCOUNT=$MINCOUNT WINDOW=${WINDOW}s — review, потом: guard sync" >> "$OUT"

added=0 skipped=0
for ip in $cands; do
    grep -qxF "$ip" <<<"$known" && { skipped=$((skipped+1)); continue; }
    info=$(whois "$ip" 2>/dev/null | grep -iE 'netname|org-name|descr|country' | head -4 | tr '\n' ' ')
    if grep -qiE "$RESI" <<<"$info"; then
        echo "# SKIP residential: $ip | $info"
        skipped=$((skipped+1)); sleep 1; continue
    fi
    echo "$ip   # $info" >> "$OUT"
    added=$((added+1)); sleep 1
done

echo
echo "=== candidates: $added | skipped: $skipped ==="
echo "файл: $OUT"
echo "проверь глазами, потом применить:"
echo "  grep -oE '^[0-9.]+' $OUT | tee -a $LISTS/custom-local.txt && guard sync"
