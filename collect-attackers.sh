#!/usr/bin/env bash
#
# collect-attackers.sh — сбор IP сканеров и атакующих с VPN-ноды для custom-списка
# Version: 2.0.0
#
# Работает с обоими стеками: старым shieldnode (таблица inet ddos_protect, events.db, логи [shield:*])
# и новым vpn-node-stack (inet shieldnode). ТОЛЬКО ЧТЕНИЕ, кроме --apply.
#
#   sudo bash collect-attackers.sh                     # отчёт по ноде: ./attackers-<нода>-<дата>.tsv + сводка
#   sudo bash collect-attackers.sh --days 30 --known custom.txt
#   sudo bash collect-attackers.sh --apply             # дописать новые IP в локальный список этой ноды
#   bash collect-attackers.sh merge *.tsv --min-nodes 2 --known custom.txt -o new-ips.txt
#                                                      # объединить отчёты нескольких нод (root не нужен)
#
# Что считается доказательством (по умолчанию):
#   ufw        — UFW BLOCK: стук в ЗАКРЫТЫЕ порты (клиенты VPN ходят только на открытые)
#   ssh        — неудачные входы sshd (подбор пароля; VPN-клиентам SSH не нужен)
#   tcp_invalid, tarpit, confirmed/ddos — старый shield: сканы флагами, ловушка, подтверждённая атака
#   ssh_flood, abuse_journal, flood_ban — новый стек: наборы ssh/tcp/udp_abusers и их история
#   crowdsec   — решения, найденные ЭТОЙ нодой (общий список сообщества CAPI не берётся)
# НЕ берётся без --include-rate-limited: syn/udp_escalate, conn_flood, newconn_flood, suspect — это
# превышения частоты, под них попадают активные клиенты и общие IP мобильных операторов (CGNAT).
#
# Исключаются: частные/служебные адреса, IP ноды, белые списки обоих стеков и TRUSTED_IPS, IP с
# успешным входом по SSH (админ), IP, подключённые к ноде как клиенты VPN прямо сейчас.
# Уже заблокированные (живые блок-листы ноды, локальные списки, --known) — считаются отдельно,
# сравнение с учётом подсетей (IP внутри CIDR списка = уже есть).
#
# Опции collect:
#   --days N               глубина журналов (по умолчанию 7)
#   --min-score N          порог веса (по умолчанию 50)
#   --min-ssh N            неудачных входов SSH для учёта (по умолчанию 5)
#   --min-ufw-ports N      разных закрытых портов для учёта UFW (по умолчанию 2)
#   --min-ufw-hits N       учитывать и ОДИН закрытый порт, если хитов >= N (по умолчанию выкл.: клиент со
#                          старой подпиской после смены порта в панели стучится в теперь закрытый порт)
#   --known FILE           ваш итоговый список (IP/CIDR) — уже внесённые не предлагать (можно несколько раз)
#   --include-rate-limited брать и превышения частоты (осторожно: клиенты за CGNAT)
#   --no-crowdsec          без CrowdSec
#   --apply                дописать новые IP в /etc/shieldnode/lists/custom.txt (новый стек) или
#                          custom-local.txt (старый); резервная копия, без дублей
#   -o FILE                куда записать отчёт TSV (по умолчанию ./attackers-<нода>-<дата>.tsv)
#   -q                     тише
# Опции merge:
#   merge FILE...          отчёты TSV с нод; --min-nodes N (1), --min-score N (50), --known FILE,
#                          --aggregate24 N — свернуть в /24, если из подсети >= N IP (осторожно: CGNAT),
#                          -o FILE — итоговый список (по умолчанию stdout)
#
# Формат отчёта TSV: ip<TAB>вес<TAB>доказательства<TAB>нода — строки с # — комментарии.
set -u
case " $* " in *" -h "*|*" --help "*) sed -n '2,/^set -u/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;; esac
command -v python3 >/dev/null 2>&1 || { echo "нужен python3" >&2; exit 1; }
exec python3 - "$@" <<'PYEOF'
import ipaddress, json, os, re, socket, subprocess, sys, time, collections, shutil

VERSION = "2.0.0"
FIX = os.environ.get("COLLECT_FIXTURE_DIR", "")      # тесты: вывод команд из файлов
ROOT = os.environ.get("COLLECT_ROOT", "")            # тесты: префикс для /etc, /var, /run
args = sys.argv[1:]
QUIET = "-q" in args

def say(*a):
    if not QUIET:
        print(*a, file=sys.stderr)

def die(msg, code=1):
    print("ОШИБКА: " + msg, file=sys.stderr); sys.exit(code)

def opt(name, default=None, conv=str):
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args): die("нет значения для " + name, 64)
        v = args[i + 1]; del args[i:i + 2]
        try: return conv(v)
        except ValueError: die("неверное значение %s: %s" % (name, v), 64)
    return default

def opts_multi(name):
    out = []
    while name in args:
        out.append(opt(name))
    return out

def flag(name):
    if name in args:
        args.remove(name); return True
    return False

def run(key, cmd):
    """Вывод команды (или фикстуры COLLECT_FIXTURE_DIR/<key>); ошибка/нет команды -> ''."""
    if FIX:
        p = os.path.join(FIX, key)
        return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""
    if not shutil.which(cmd[0]):
        return ""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=300).stdout
    except Exception:
        return ""

def path(p):
    return ROOT + p

def read(p):
    try:
        return open(path(p), encoding="utf-8", errors="replace").read()
    except OSError:
        return ""

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
def ip_ok(s):
    try:
        a = ipaddress.IPv4Address(s)
    except ValueError:
        return None
    return a if a.is_global else None

def parse_nets(text):
    """IP, CIDR и диапазоны a-b из произвольного текста списка/набора -> список IPv4Network."""
    nets = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        for m in re.finditer(r"(%s)\s*-\s*(%s)|(%s/\d{1,2})|(%s)" % (IPV4, IPV4, IPV4, IPV4), line):
            try:
                if m.group(1):
                    nets.extend(ipaddress.summarize_address_range(ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))))
                elif m.group(3):
                    nets.append(ipaddress.IPv4Network(m.group(3), strict=False))
                else:
                    nets.append(ipaddress.IPv4Network(m.group(4) + "/32"))
            except ValueError:
                pass
    return nets

class NetSet:
    """Быстрая проверка «IP внутри одной из сетей»: слияние интервалов + бинарный поиск."""
    def __init__(self, nets=()):
        self.iv = []
        self.add(nets)
    def add(self, nets):
        iv = self.iv + [(int(n.network_address), int(n.broadcast_address)) for n in nets]
        iv.sort(); merged = []
        for a, b in iv:
            if merged and a <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], b))
            else:
                merged.append((a, b))
        self.iv = merged; self.starts = [a for a, _ in merged]
    def __contains__(self, ip):
        import bisect
        x = int(ipaddress.IPv4Address(ip)); i = bisect.bisect_right(self.starts, x) - 1
        return i >= 0 and self.iv[i][0] <= x <= self.iv[i][1]
    def size(self):
        return sum(b - a + 1 for a, b in self.iv)

def nft_tables():
    return set(re.findall(r"table inet (\w+)", run("nft_tables", ["nft", "list", "tables"])))

def nft_set_nets(table, name):
    """Элементы набора nft (JSON): IP, префиксы, диапазоны, элементы с таймаутом."""
    raw = run("nft_%s_%s" % (table, name), ["nft", "-j", "list", "set", "inet", table, name])
    if not raw.strip():
        return []
    if not raw.lstrip().startswith("{"):
        return parse_nets(raw)
    nets = []
    try:
        d = json.loads(raw)
    except ValueError:
        return parse_nets(raw)
    def one(e):
        if isinstance(e, dict) and "elem" in e: e = e["elem"].get("val", e["elem"])
        try:
            if isinstance(e, str): nets.append(ipaddress.IPv4Network(e + ("" if "/" in e else "/32"), strict=False))
            elif isinstance(e, dict) and "prefix" in e: nets.append(ipaddress.IPv4Network("%s/%s" % (e["prefix"]["addr"], e["prefix"]["len"]), strict=False))
            elif isinstance(e, dict) and "range" in e:
                nets.extend(ipaddress.summarize_address_range(ipaddress.IPv4Address(e["range"][0]), ipaddress.IPv4Address(e["range"][1])))
        except (ValueError, KeyError, TypeError):
            pass
    for x in d.get("nftables", []):
        for e in (x.get("set", {}).get("elem") or []):
            one(e)
    return nets

def nft_set_names(table):
    raw = run("nft_sets_" + table, ["nft", "list", "table", "inet", table])
    return re.findall(r"^\s*set (\S+) \{", raw, re.M)

# ═══════════════════════════════ merge ═══════════════════════════════
if args and args[0] == "merge":
    args.pop(0)
    min_nodes = opt("--min-nodes", 1, int); min_score = opt("--min-score", 50, int)
    agg = opt("--aggregate24", 0, int); out = opt("-o", "")
    known = NetSet()
    for f in opts_multi("--known"):
        known.add(parse_nets(open(f, encoding="utf-8", errors="replace").read()))
    flag("-q")
    files = [a for a in args if not a.startswith("-")]
    if not files: die("merge: укажите отчёты TSV", 64)
    ips = {}
    for f in files:
        for line in open(f, encoding="utf-8", errors="replace"):
            if line.startswith("#") or not line.strip(): continue
            p = line.rstrip("\n").split("\t")
            if len(p) < 3 or not ip_ok(p[0]): continue
            r = ips.setdefault(p[0], {"score": 0, "nodes": set(), "ev": set()})
            r["score"] += int(p[1]) if p[1].isdigit() else 0
            r["nodes"].add(p[3] if len(p) > 3 and p[3] else f)
            r["ev"].update(e.split(":")[0] for e in p[2].split(";") if e)
    sel = {ip: r for ip, r in ips.items() if len(r["nodes"]) >= min_nodes and r["score"] >= min_score}
    already = [ip for ip in sel if ip in known]
    new = sorted((ip for ip in sel if ip not in known), key=lambda x: int(ipaddress.IPv4Address(x)))
    lines = []
    if agg > 0:
        by24 = collections.defaultdict(list)
        for ip in new: by24[ip.rsplit(".", 1)[0]].append(ip)
        for net, members in sorted(by24.items(), key=lambda x: int(ipaddress.IPv4Address(x[0] + ".0"))):
            if len(members) >= agg:
                lines.append("%s.0/24" % net)
            else:
                lines.extend(members)
    else:
        lines = new
    hdr = ["# collect-attackers %s merge %s: отчётов %d, IP всего %d, прошли порог (нод >= %d, вес >= %d) %d, уже в --known %d, новых %d" %
           (VERSION, time.strftime("%Y-%m-%d"), len(files), len(ips), min_nodes, min_score, len(sel), len(already), len(new))]
    top = sorted(((len(r["nodes"]), r["score"], ip, ",".join(sorted(r["ev"]))) for ip, r in sel.items() if ip not in known), reverse=True)[:15]
    say(hdr[0][2:])
    for n, s, ip, ev in top:
        say("  %-15s нод %-3d вес %-6d %s" % (ip, n, s, ev))
    text = "\n".join(hdr + lines) + "\n"
    if out:
        open(out, "w").write(text); say("записано: %s (%d строк)" % (out, len(lines)))
    else:
        sys.stdout.write(text)
    sys.exit(0)

# ═══════════════════════════════ collect ═══════════════════════════════
if not FIX and os.geteuid() != 0:
    die("нужен root: sudo bash collect-attackers.sh")
DAYS = opt("--days", 7, int); MIN_SCORE = opt("--min-score", 50, int); MIN_SSH = opt("--min-ssh", 5, int)
MIN_UFW_PORTS = opt("--min-ufw-ports", 2, int); MIN_UFW_HITS = opt("--min-ufw-hits", 0, int)
KNOWN = opts_multi("--known"); OUT = opt("-o", ""); APPLY = flag("--apply")
RATE = flag("--include-rate-limited"); NO_CS = flag("--no-crowdsec"); flag("-q")
if args: die("неизвестные аргументы: %s (см. --help)" % " ".join(args), 64)

node = os.environ.get("COLLECT_NODE") or socket.gethostname()
tables = nft_tables()
OLD = "ddos_protect" in tables; NEW = "shieldnode" in tables
say("[*] нода %s · стек: %s" % (node, " + ".join(x for x, y in (("старый shield (ddos_protect)", OLD), ("новый (shieldnode)", NEW)) if y) or "shieldnode не найден"))

score = collections.Counter(); ev = collections.defaultdict(list)
def add(ip, pts, what):
    if ip_ok(ip):
        score[ip] += pts; ev[ip].append(what)

# ── 1. старый shield ────────────────────────────────────────────────────
if OLD:
    db = path("/var/lib/shieldnode/events.db")
    if os.path.exists(db):
        import sqlite3
        strong = {"tcp_invalid": 20, "ddos": 1}
        weak = {"syn_escalate": 1, "udp_escalate": 1, "conn_flood": 1, "newconn_flood": 1}
        since = int(time.time()) - DAYS * 86400
        try:
            con = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
            for typ, ip, cnt in con.execute("SELECT type, ip, SUM(count) FROM events WHERE last_seen >= ? GROUP BY type, ip", (since,)):
                if typ in strong:
                    add(ip, min(500, cnt * strong[typ]) if typ == "tcp_invalid" else min(500, 100 + cnt), "%s:%d" % (typ, cnt))
                elif RATE and typ in weak:
                    add(ip, min(100, cnt), "rate_%s:%d" % (typ, cnt))
            con.close()
        except Exception as e:
            say("    events.db не читается: %s" % e)
    for s, pts, name in (("confirmed_attack_v4", 300, "confirmed"), ("tarpit_caught", 500, "tarpit")) + ((("suspect_v4", 50, "rate_suspect"),) if RATE else ()):
        for n in nft_set_nets("ddos_protect", s):
            if n.prefixlen == 32: add(str(n.network_address), pts, name)

# ── 2. новый стек ───────────────────────────────────────────────────────
if NEW:
    for s, pts, name in (("ssh_abusers", 300, "ssh_flood"), ("tcp_abusers", 200, "flood_ban"), ("udp_abusers", 200, "flood_ban"), ("temporary_blocklist", 200, "manual_ban")):
        for n in nft_set_nets("shieldnode", s):
            if n.prefixlen == 32: add(str(n.network_address), pts, name)
    sect = None; seen = collections.Counter()
    for line in read("/var/lib/shieldnode/abuse.journal").splitlines():
        m = re.match(r"^## (\w+)", line)
        if m: sect = m.group(1); continue
        if line.startswith("#"): sect = None; continue
        if sect in ("ssh_abusers", "tcp_abusers", "udp_abusers") and line.strip():
            seen[(line.split()[0], sect)] += 1
    for (ip, sect), n in seen.items():
        add(ip, min(300, 50 * n), "abuse_journal_%s:%d" % (sect, n))

# ── 3. журналы: UFW BLOCK (закрытые порты), [shield:*] старого shield, sshd ────
since = "%d days ago" % DAYS
kern = run("journal_kernel", ["journalctl", "-k", "--since", since, "--no-pager", "-q", "-o", "cat"])
ufw_ports = collections.defaultdict(set); ufw_hits = collections.Counter()
shield_log = collections.Counter()
for line in kern.splitlines():
    src = re.search(r"SRC=(%s)" % IPV4, line)
    if not src: continue
    ip = src.group(1)
    if "[UFW BLOCK]" in line:
        dpt = re.search(r"DPT=(\d+)", line); pr = re.search(r"PROTO=(\w+)", line)
        ufw_hits[ip] += 1
        if dpt: ufw_ports[ip].add("%s/%s" % (dpt.group(1), pr.group(1) if pr else "?"))
    else:
        m = re.search(r"\[shield:(\w+)\]", line)
        if m: shield_log[(ip, m.group(1))] += 1
for ip, hits in ufw_hits.items():
    ports = len(ufw_ports[ip])
    if ports >= MIN_UFW_PORTS or (MIN_UFW_HITS > 0 and hits >= MIN_UFW_HITS):
        add(ip, min(500, 30 * ports + 2 * hits), "ufw:ports=%d,hits=%d" % (ports, hits))
for (ip, kind), n in shield_log.items():
    if kind == "tcp_invalid":
        add(ip, min(500, 20 * n), "log_tcp_invalid:%d" % n)
    elif kind in ("syn_escalate", "udp_escalate") and RATE:
        add(ip, min(100, n), "rate_log_%s:%d" % (kind, n))
    # [shield:scanner|threat|tor|custom|ddos] — IP уже в блок-листах: не новые кандидаты

# по идентификатору программы, а не юниту: при socket-активации / sshd-session юнит бывает другим
ssh = run("journal_ssh", ["journalctl", "-t", "sshd", "-t", "sshd-session", "--since", since, "--no-pager", "-q", "-o", "cat"])
ssh_fail = collections.Counter(); ssh_ok = set()
for line in ssh.splitlines():
    m = re.search(r"Accepted \S+ for \S+ from (%s)" % IPV4, line)
    if m: ssh_ok.add(m.group(1)); continue
    m = re.search(r"(?:Failed \S+ for (?:invalid user )?\S* ?from|Invalid user \S* ?from|authenticating user \S+|invalid user \S+|maximum authentication attempts exceeded for .* from|Did not receive identification string from|banner exchange: Connection from) ?(%s)" % IPV4, line)
    if m: ssh_fail[m.group(1)] += 1
for ip, n in ssh_fail.items():
    if n >= MIN_SSH and ip not in ssh_ok:
        add(ip, min(500, 10 * n), "ssh:fail=%d" % n)

# ── 4. CrowdSec: решения, найденные ЭТОЙ нодой ─────────────────────────────
if not NO_CS:
    raw = run("cscli", ["cscli", "decisions", "list", "-o", "json"])
    try:
        for alert in (json.loads(raw) if raw.strip() else []) or []:
            for d in alert.get("decisions") or []:
                if d.get("origin") in ("crowdsec", "cscli") and d.get("scope", "").lower() == "ip":
                    add(d.get("value", ""), 300, "crowdsec:%s" % (d.get("scenario") or "?").split("/")[-1])
    except ValueError:
        pass

# ── 5. исключения ─────────────────────────────────────────────────────────
excl = NetSet(); why = {}
own = run("own_ips", ["hostname", "-I"])
excl.add(parse_nets(own))
wl = []
for t, sets in (("ddos_protect", ("manual_whitelist_v4", "infrastructure_v4", "remnawave_nodes_v4")), ("shieldnode", ("whitelist_v4", "node_api_allow_v4"))):
    if t in tables:
        for s in sets: wl += nft_set_nets(t, s)
for f in ("/etc/shieldnode/lists/whitelist-local.txt", "/etc/shieldnode/lists/whitelist.txt", "/run/shieldnode/mgmt-auto-v4.txt"):
    wl += parse_nets(read(f))
for f in ("/etc/shieldnode/shieldnode.conf", "/etc/shieldnode/config.conf"):
    for m in re.finditer(r'^TRUSTED_IPS="?([^"\n]*)', read(f), re.M):
        wl += parse_nets(m.group(1).replace(",", " "))
excl.add(wl); excl.add(parse_nets("\n".join(ssh_ok)))
# клиенты VPN прямо сейчас: установленные TCP-сессии и UDP-потоки (conntrack) на слушающие порты ноды
listen = set(re.findall(r":(\d+)\s", run("ss_listen", ["ss", "-Htuln"])))
clients = set()
for line in run("ss_est", ["ss", "-Htn", "state", "established"]).splitlines():
    p = line.split()
    if len(p) >= 4 and p[2].rsplit(":", 1)[-1] in listen:
        clients.add(p[3].rsplit(":", 1)[0].strip("[]").replace("::ffff:", ""))
for line in run("conntrack_udp", ["conntrack", "-L", "-p", "udp"]).splitlines():
    m = re.search(r"src=(%s) dst=\S+ sport=\d+ dport=(\d+)" % IPV4, line)
    if m and m.group(2) in listen and "ASSURED" in line: clients.add(m.group(1))

# уже заблокировано: живые блок-листы ноды, локальные списки, --known
listed = NetSet(); lst = []
for t in ("ddos_protect", "shieldnode"):
    if t in tables:
        # только постоянные блок-листы; confirmed_attack/temporary_blocklist/*_abusers — временные баны
        # этой ноды, их как раз и переносим в список
        for s in nft_set_names(t):
            if "blocklist" in s and not s.endswith("_v6") and not s.startswith("temporary"):
                lst += nft_set_nets(t, s)
for f in ("/etc/shieldnode/lists/custom.txt", "/etc/shieldnode/lists/custom-local.txt"):
    lst += parse_nets(read(f))
for f in KNOWN:
    try: lst += parse_nets(open(f, encoding="utf-8", errors="replace").read())
    except OSError: die("нет файла --known: " + f)
listed.add(lst)

res = []; n_client = n_excl = n_listed = n_low = 0; client_ex = []
for ip, sc in score.most_common():
    if ip in excl: n_excl += 1; continue
    if ip in clients: n_client += 1; client_ex.append(ip); continue
    if sc < MIN_SCORE: n_low += 1; continue
    if ip in listed: n_listed += 1; continue
    res.append((ip, sc, ";".join(sorted(set(ev[ip])))))

say("[*] кандидатов %d · исключено: белые/свои/админ %d, клиенты VPN сейчас %d, ниже порога %d, уже в списках %d · НОВЫХ %d"
    % (len(score), n_excl, n_client, n_low, n_listed, len(res)))
if client_ex:
    say("    как клиенты исключены (есть сессия к ноде): %s%s" % (" ".join(client_ex[:10]), " …" if len(client_ex) > 10 else ""))
for ip, sc, e in res[:15]:
    say("    %-15s вес %-5d %s" % (ip, sc, e))

stamp = time.strftime("%Y-%m-%d")
out = OUT or "attackers-%s-%s.tsv" % (re.sub(r"[^A-Za-z0-9._-]", "_", node), stamp)
with open(out, "w") as f:
    f.write("# collect-attackers %s · нода %s · %s · дней %d · порог %d · rate-limited: %s\n" % (VERSION, node, time.strftime("%Y-%m-%d %H:%M"), DAYS, MIN_SCORE, "да" if RATE else "нет"))
    f.write("# ip\tвес\tдоказательства\tнода\n")
    for ip, sc, e in res:
        f.write("%s\t%d\t%s\t%s\n" % (ip, sc, e, node))
say("[✔] отчёт: %s (%d IP) — объединить с другими нодами: bash collect-attackers.sh merge *.tsv" % (out, len(res)))

if APPLY:
    if not res:
        say("[*] новых IP нет — список не тронут"); sys.exit(0)
    target = path("/etc/shieldnode/lists/custom.txt" if NEW else "/etc/shieldnode/lists/custom-local.txt")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    cur = read(target[len(ROOT):]) if os.path.exists(target) else "# shieldnode custom list: один IP или CIDR на строку\n"
    have = NetSet(parse_nets(cur))
    add_ips = [ip for ip, _, _ in res if ip not in have]
    if not add_ips:
        say("[*] все новые IP уже есть в %s" % target); sys.exit(0)
    if os.path.exists(target):
        bak = "%s.bak-collect-%s" % (target, time.strftime("%Y%m%d-%H%M%S")); shutil.copy2(target, bak)
        baks = sorted(p for p in os.listdir(os.path.dirname(target)) if p.startswith(os.path.basename(target) + ".bak-collect-"))
        for old in baks[:-5]: os.remove(os.path.join(os.path.dirname(target), old))
    tmp = target + ".tmp-collect"
    with open(tmp, "w") as f:
        f.write(cur if cur.endswith("\n") else cur + "\n")
        f.write("# ─── collect-attackers %s %s: +%d ───\n" % (VERSION, time.strftime("%Y-%m-%d %H:%M"), len(add_ips)))
        f.write("\n".join(add_ips) + "\n")
    os.chmod(tmp, 0o644); os.replace(tmp, target)
    say("[✔] в %s добавлено %d IP (служба shieldnode подхватит файл сама)" % (target, len(add_ips)))
PYEOF
