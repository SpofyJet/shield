#!/bin/bash

# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.9 — закрытие остатков из саморевью (2 фикса)
#
#  Мелкие, но реальные дыры робастности, найденные при аудите:
#  (1) modprobe в shieldnode-synproxy.service был хардкодом /sbin/modprobe с '-'.
#      На системах, где modprobe в /usr/sbin, шаг молча пропускался → модуль
#      nf_synproxy не грузился при boot и SYNPROXY-фикс v3.28.7 не срабатывал.
#      Теперь modprobe ищется через PATH (sh -c 'modprobe …').
#  (2) Интерактивный chooser whitelist (v3.28.3) читал /dev/tty без таймаута —
#      если терминал есть, но ввода нет (полу-автомат/CI с tty), `read` мог
#      зависнуть навечно. Добавлен `read -t 300` на все 4 чтения → по таймауту
#      пусто → дефолт «пропустить», установка едет дальше.
#  Про #3 из саморевью (gateless main prerouting): СОЗНАТЕЛЬНО не трогаю —
#  см. разбор. Гейт `fib daddr type local` на всей цепочке ddos_protect опасен
#  (на хостах с DNAT-публикацией портов мог бы СНЯТЬ защиту с опубликованных
#  портов), а реального вреда от форвардного трафика основная цепочка не несёт
#  (rate-limit'ы пропускают под лимитом; единственный «ломатель» — synproxy
#  notrack — уже закрыт в v3.28.4 через fib-гейт ТОЛЬКО на synproxy).
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.8 — FIX полноты `guard rollback`
#
#  Аудит install/upgrade выявил: snapshot для rollback был НЕПОЛНЫМ. Сохранялось
#  7 скриптов из 15 и НИ ОДНОГО systemd-юнита. После `guard rollback` компоненты
#  synproxy/ctguard/remnawave-sync/auto-promote/cleanup/pcap/mobile-ru и все юниты
#  оставались на НОВОЙ версии, остальное откатывалось → рассинхрон (хуже любой из
#  версий). Плюс nft-restore флашил только ddos_protect → shield_synproxy/
#  shield_ctguard из снапшота конфликтовали с живыми при nft -f.
#  Фиксы: (1) snapshot теперь глобит ВСЕ /usr/local/sbin/shieldnode-*.sh + guard;
#  (2) snapshot'ятся и восстанавливаются systemd-юниты; (3) перед nft -f флашатся
#  все три наши таблицы; (4) на rollback перезапускаются и synproxy/ctguard.
#  Касается только пути upgrade/rollback — на сам runtime защиты не влияет.
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.7 — НАДЁЖНОСТЬ включения SYNPROXY (3 фикса)
#
#  Симптом: SYNPROXY не включился при install/boot (DEGRADED, synproxy_enable_
#  failed), но вручную (shieldnode-synproxy.sh on) включается. Непостоянство =
#  гонки. Найдено и исправлено три места:
#
#  1) verify_untracked_reaches давал ЛОЖНЫЙ откат. Проба смотрела ОДНО окно:
#     "входящие SYN есть, а счётчик synproxy не растёт" → сразу disable+exit3.
#     Но synproxy считает только UNTRACKED-new SYN; ретрансмиты/уже-tracked он
#     законно не считает. При install (фоновые сканеры) одно окно ложно
#     срабатывало → откат → DEGRADED. Теперь откат ТОЛЬКО при ДВУХ подтверждённых
#     окнах; успех на любом окне = ок; неоднозначность = synproxy оставляем.
#
#  2) systemd-сервис не грузил модуль при ребуте. shieldnode-synproxy.service
#     делал голый `nft -f synproxy.nft`. На ядрах где nf_synproxy — загружаемый
#     модуль (стоковые + часть XanMod), при boot он мог быть не подгружен → nft
#     падал → SYNPROXY не вставал после ребута. Добавлен ExecStartPre=modprobe.
#
#  3) enable() не снимал degraded-маркер при успехе (это делал только install-
#     блок) → ручной `on` оставлял залежавшийся .synproxy-degraded. Теперь
#     снимается и в enable().
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.6 — FIX отображения "All-time history (since —)"
#
#  Дата "since" бралась как MIN(first_seen) из events.db. На ноде, где событий
#  ещё не было (пустая таблица), MIN возвращал NULL → печаталось "since —".
#  Теперь при пустой БД since = время создания файла events.db (birth-time, с
#  фолбэком на mtime) — т.е. реальная дата старта трекинга. Только отображение.
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.5 — FIX отображения подсказки synproxy DEGRADED
#
#  В guard (и в install-варнинге) строка "fix:" при DEGRADED печаталась с
#  экранированным "\$(uname -r)" → пользователь видел буквально "$(uname -r)"
#  вместо реальной версии ядра. Плюс совет "apt install linux-modules-extra-…"
#  НЕВЕРЕН для XanMod: там nf_synproxy встроен в ядро и такого пакета не
#  существует. Теперь подсказка kernel-aware: на XanMod говорит, что модуль
#  встроен (ставить нечего) и направляет на 'shieldnode-synproxy.sh on' + dmesg;
#  на стоковом ядре показывает РЕАЛЬНУЮ версию ядра в имени пакета. Только текст
#  подсказки — на саму защиту не влияет.
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.4 — FIX: SYNPROXY ломал форвардный трафик
#
#  Симптом: на сервере с ПАНЕЛЬЮ (Remnawave в Docker) после апгрейда shieldnode
#  одна нода ушла в offline. Та нода использовала control-порт 2223, и 2223 попал
#  в защищаемые порты панели → SYNPROXY его покрыл.
#  Причина: правило `notrack` в pre_raw (хук prerouting, prio -300) матчило
#  `tcp dport @sp_ports` для ЛЮБОГО трафика, включая ТРАНЗИТНЫЙ — исходящее
#  соединение контейнера панели к удалённой ноде (panel→node:2223) форвардится
#  через хост, проходит prerouting, цепляет notrack → conntrack/NAT для этого
#  коннекта ломается → ответ ноды не возвращается в контейнер → timeout.
#  Хост-локальный `nc` работал (OUTPUT минует prerouting), а контейнер — нет.
#  Фикс: notrack теперь только для трафика К САМОМУ ХОСТУ (`fib daddr type local`).
#  Транзит (Docker/панель/роутер/VPN-exit) больше не трогается — SYNPROXY как и
#  прежде защищает локальные сервисы хоста. На обычных нодах поведение не меняется
#  (Xray проксирует через OUTPUT, не форвардит). Откат прост: модуль изолирован.
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.3 — FIX интерактивного выбора (объединение)
#
#  Баг (репорт): при `guard upgrade` показывался СТАРЫЙ вопрос про bridge-IP, а
#  выбора «токен или IP» (v3.28.1) не было.
#  Причины:
#    1) Выбор v3.28.1 и существующий с v3.18 промпт «Bridge/Upstream nodes» — это
#       были ДВА РАЗНЫХ вопроса. На настроенной/обычной ноде они дублировались бы
#       (спросили бы дважды). Теперь это ОДИН вопрос: старый bridge-промпт заменён
#       на выбор 1) Remnawave токен / 2) вручную IP бриджей / 3) пропустить.
#    2) Старый промпт читал stdin и был завязан на `[ -t 0 ]` → в pipe-режиме
#       (curl|bash) он пропускался. Теперь интерактивность определяется по наличию
#       /dev/tty, а чтение идёт с /dev/tty → вопрос работает И в `guard upgrade`,
#       И в `curl|bash`. Headless/CI (нет /dev/tty) — тихо пропуск (env), как было.
#    3) Опрос пропускается, если whitelist нод уже настроен (BRIDGE_IPS, TRUSTED_IPS,
#       remnawave.env или REMNAWAVE_URL+TOKEN) → апгрейды настроенных нод не
#       переспрашивают. Вариант (2) кормит прежнюю логику BRIDGE_IPS; вариант (1) —
#       fleet-sync (токен пишется в remnawave.env на ШАГ 5.6).
#
#  ВАЖНО про деплой: `guard upgrade` тянет shieldnode.sh с GitHub (ветка main).
#  Чтобы выбор появился на нодах — сначала задеплой эту версию (deploy-shield.sh),
#  потом `guard upgrade` на ноде.
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.2 — FIX отображения v6 в guard
#
#  В строке "blocklists" дашборда вокруг счётчика v6 печатался сырой
#  "\033[0;36m...\033[0m" вместо цвета. Причина: цветовые коды (${C}/${N})
#  встраивались в переменную bl_summary, а она выводилась через printf "%s" —
#  в %s-аргументе printf escape-последовательности НЕ интерпретируются (в отличие
#  от формат-строки). Фикс: вывод через %b (как echo -e). Косметика, на защиту
#  не влияет. Баг существовал с v3.27.0 (когда добавили суммарный v6-счётчик).
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.1 — ИНТЕРАКТИВНЫЙ ВЫБОР WHITELIST'А НОД
#
#  При установке (ДО долгих apt-операций) скрипт теперь СПРАШИВАЕТ, как
#  whitelist'ить ноды флота:
#    1) Remnawave токен — авто-дискавери всех нод (рекомендуется);
#    2) Вручную IP нод/бриджей (TRUSTED_IPS);
#    3) Пропустить (настроить позже).
#  Раньше токен/IP надо было знать заранее и передавать через env/conf — теперь
#  достаточно запустить установку и ответить на вопрос.
#
#  Детали:
#    - Спрашиваем ТОЛЬКО на свежей ноде: если уже сконфигурено (REMNAWAVE_URL+TOKEN
#      в env/conf, или есть /etc/shieldnode/remnawave.env, или задан TRUSTED_IPS) —
#      промпт пропускается (апгрейды не переспрашивают).
#    - В pipe-режиме (curl|bash) stdin=pipe, поэтому читаем с /dev/tty; токен —
#      скрытым вводом (read -rs). URL валидируется (http(s)://…).
#    - Headless/CI (нет управляющего терминала) → тихо пропускаем, работает env
#      (поведение прежнее). Отключить промпт: SHIELD_WL_PROMPT=0.
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.28.0 — REMNAWAVE FLEET AUTO-SYNC
#
#  Боль: при ручном whitelist'е (TRUSTED_IPS/BRIDGE_IPS) добавление новой ноды
#  требовало идти и обновлять список IP на КАЖДОЙ ноде флота. Теперь — авто.
#
#  Что добавлено:
#    - Даёшь токен Remnawave-панели (REMNAWAVE_URL + REMNAWAVE_TOKEN) → shieldnode
#      в фоне (systemd-таймер, дефолт 5 мин) тянет GET /api/nodes по Bearer-токену,
#      резолвит address каждой ноды (IP или hostname → getent A/AAAA) и держит
#      nft-сеты remnawave_nodes_v4/v6 в актуальном виде. Новую ноду добавил в
#      панель → ВСЕ ноды подхватят её на следующем тике, без ручной правки.
#    - Эти сеты accept'ятся сразу после manual_whitelist (bypass всех лимитов) —
#      это СВОИ серверы, не CGNAT → CGNAT-safe. Логическое завершение FIX#10.
#    - Включается авто, если заданы URL+TOKEN (SHIELD_REMNAWAVE_SYNC=auto|1|0).
#      Передать при install:  REMNAWAVE_URL=... REMNAWAVE_TOKEN=... curl ... | sudo bash
#    - Токен НЕ в shieldnode.conf (0640) — в /etc/shieldnode/remnawave.env (root:root
#      0600). На re-install/upgrade восстанавливается из него (env заново не нужен).
#    - FAIL-SAFE: панель недоступна / кривой ответ / 0 валидных IP → текущий whitelist
#      нод НЕ трогаем (last-known-good). Иначе сбой панели «разбанил» бы весь флот и
#      ноды начали бы лимитировать друг друга. Применение — ОТДЕЛЬНОЙ nft-транзакцией
#      (битые данные не ломают ddos_protect) и только если сет существует.
#    - guard показывает статус fleet-sync + число нод (v4/v6) + время последнего синка.
#    - uninstall чистит юнит/скрипт/токен-файл.
#
#  Зависимости: curl + jq (уже требуются). Резолв hostname — getent (без новых пакетов).
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.27.2 — DEPENDENCY/FEED CURRENCY
#
#  Внешние фиды/API дрейфанули в 2024–2025 (сам код свежий, но третьи стороны
#  поменялись) — приведено к актуальному:
#    FEED#1 abuse.ch Feodo УБРАН из threat: датасет сейчас пустой + abuse.ch ввёл
#           обязательный Auth-Key (30 июня 2025) и мигрирует под Spamhaus → отдавал
#           ~0 IP и ломался бы на 401. Убран мёртвый груз.
#    FEED#2 Spamhaus DROP: drop.txt → drop_v4.json + drop_v6.json. Текстовые файлы
#           Spamhaus на пути к deprecation, рекомендован JSON (+jq). JSON парсится
#           существующей jq-веткой апдейтера (расширена на v6); drop_v6.json теперь
#           КОРМИТ threat_blocklist_v6 (раньше пустой). eDROP уже влит в DROP — ок.
#    FEED#3 ASN-lookup в guard: ipinfo.io (legacy free API) → Team Cymru whois.
#           ipinfo без токена = 1000 req/день ОБЩИЕ на исходящий IP + deprecation +
#           утечка IP атакующих коммерческому geoIP. Cymru: без ключа, поддерживается,
#           ASN+owner одним запросом. Пакет 'whois' ставится best-effort (нет → "?"
#           в дашборде, без лагов). Кэш/offline-fallback сохранены.
#    CLEAN#6 удалён мёртвый knob SHIELD_CT_EVICT_MIN (DEPRECATED с v3.26, не читался).
#
#  Аудит рантайм-зависимостей (всё актуально): nftables, conntrack, iproute2,
#  systemd, curl, sqlite3, jq, gawk/coreutils, python3 — текущие поддерживаемые
#  инструменты, версий-проблем нет. CrowdSec ставится официальным инсталлятором
#  (всегда latest). Дрейф был ТОЛЬКО во внешних data-feeds/API (выше), не в тулчейне.
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.27.1 — RED-TEAM ROUND 2 (CGNAT-safe closes)
#
#  Закрыто без риска для CGNAT (две дыры, которые открыли патчи v3.27.0 / остались):
#    FIX#1  (pulsing обходил дебаунс #9): счётчик аномалий заменён на СКОЛЬЗЯЩЕЕ ОКНО.
#           Раньше STREAK сбрасывался в 0 на любом чистом тике → атака «вкл/выкл»
#           держала STREAK=1, кап не включался никогда. Теперь sustained, если в окне
#           SHIELD_CTG_ANOM_WINDOW (4 тика) накопилось >= ATTACK_MIN_TICKS (2) аномалий
#           (не обязательно подряд). Одиночный/редкий всплеск кап НЕ включает → анти-FP
#           сохранён (CGNAT-safe, поведение как было). Побочно усиливает #4: infra-
#           фронтовый флуд теперь надёжно ловится ctguard-капом (capnew до infra-accept),
#           т.к. пульсацией от него больше не уйти. EWMA не учится при ANOM_CNT>0.
#    FIX#6  (спуф-SYN на SSH-порт тёк conntrack): SYNPROXY теперь покрывает и SSH
#           (SHIELD_SYNPROXY_SSH=1, дефолт). SSH не в protected_ports_tcp → раньше не
#           покрыт ни synproxy, ни ctguard-капом → спуф-SYN с уник. src создавал
#           SYN_RECV-conntrack. Модуль детектит sshd-listener'ы в рантайме; ports-updater
#           сохраняет SSH в sp_ports при смене портов. SSH≠CGNAT → нулевой CGNAT-риск;
#           прозрачно для легит-хендшейков, established SSH не рвётся.
#
#  НЕ закрыто — нельзя без риска CGNAT/CDN (осознанно оставлено):
#    #2  live connect-and-hold: эвикт живых сокетов = масс-эвикт тяжёлых CGNAT-юзеров
#        (байтовый детект уже пробовали в <v3.26 → критфикс-откат). Держим live==0.
#    #3-side (CGNAT-safe убрал быстрый бан одиночного src): быстрый confirmed_attack
#        вернул бы 15-мин бан общих CGNAT-IP. Покрывается auto-promote (syn/udp_escalate).
#    #4  infrastructure-bypass: сужение = ложные баны CDN-fronted легита (Private Relay
#        и т.п.). Оставлено по решению оператора; #1-фикс закрыл худший infra+pulsing кейс.
#    #9-UDP CPU-burn под капом / RAM-clamp ceiling: понижение порогов = риск легит-QUIC
#        и CGNAT-conntrack. Оставлено (OOM уже закрыт #1/#13 v3.27.0).
#    Volumetric / насыщение канала: архитектурно нелечимо на хосте (нужен upstream-scrub).
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.27.0 (Commercial Edition) — SECURITY HARDENING
#
#  v3.27.0 (red-team batch 1 — анти-takedown / анти-self-DoS):
#    FIX#1  (spoofed/distributed UDP-флуд): ctguard apply_cap теперь капает И UDP
#           new-flow на protected-портах в attack-mode (раньше TCP-only). Spoofed-UDP
#           обходит per-saddr meter ddos_protect и течёт conntrack → теперь приток
#           новых flow режется глобально (established QUIC не трогается). Пол
#           SHIELD_CTG_UDP_FLOOR (3000/с). Детект — через существующий conntrack-fill.
#    FIX#13 (анти-OOM): авто-рост nf_conntrack_max ограничен SHIELD_CTG_CT_RAM_PCT
#           (25%) от MemAvailable. Раньше рост до 1М (~384МБ) OOM-killил Xray —
#           защита сама конвертила conntrack-fill в RAM-exhaustion. Если RAM-потолок
#           ниже текущего max — НЕ поднимаем (дроп переживаемее OOM).
#    FIX#8  (CGNAT collateral): SHIELD_CGNAT_SAFE=1 (дефолт) — превышение per-IP
#           new-conn/SYN/UDP режет только избыточные пакеты (rate-shape) + логирует,
#           но НЕ заносит общий CGNAT-IP в confirmed_attack (15-мин blackhole новых
#           конн на ~200 абонентов за одним IP). =0 → прежний escalate.
#    FIX#12 (ctguard как усилитель): Nice -5 → 10 + CPUWeight=20 + IOSchedulingClass=
#           idle. Guard под атакой (дорогой conntrack -L каждые 15с) больше не
#           отбирает CPU у Xray → частичная атака не перерастает в полный аутаж.
#    FIX#14 (агрегатор OOM): per-tick journal cap 200k → 50k строк (nft-дропы идут
#           независимо). Наблюдаемость деградирует плавно, не падает.
#    --- batch 2 ---
#    FIX#2  (distributed connect-and-hold): 2-й проход эвикта phantom_evict_distributed —
#           много IP по чуть-чуть. Порог ниже (PH_MIN_DIST=800), но условие СТРОЖЕ:
#           эвикт ТОЛЬКО при live==0 (чистый abandon) → CGNAT с активными юзерами
#           щадится. Только в sustained-attack и если 1-й (концентрированный) проход пуст.
#    FIX#9  (ложный attack-mode): дебаунс — глобальный кап включается лишь при
#           ATTACK_MIN_TICKS=2 тиках подряд (≈30с), КРОМЕ PCT>=HIGH (капаем сразу).
#           Один tick всплеска (легит reconnect/утренний ramp) больше не душит ноду и
#           не отравляет EWMA-базлайн (учёба только на чистом тике). Отдельный
#           CAP_FLOOR=1000 (был общий FLOOR_RATE=200 — слишком низкий потолок капа).
#    FIX#5  (тихая деградация SYNPROXY): fail-loud — при неудаче enable пишем
#           /var/lib/shieldnode/.synproxy-degraded, громкий ALERT в установке, journald
#           и индикатор DEGRADED в 'guard'. Подсказка как починить (modules-extra/ядро).
#    FIX#3  (distributed handshake-флуд): opt-in глобальный new-conn ceiling на
#           protected-TCP (SHIELD_GLOBAL_NEWCONN_CEIL, ДЕФОЛТ 0=off — глоб. потолки
#           опасны для CGNAT). Не-CGNAT ноды могут включить жёсткий backstop. В
#           attack-mode аггрегатный кап ctguard и так покрывает (через PassiveOpens).
#    FIX#11 (v6 UX): SHIELD_V6_REJECT (дефолт 0=drop/стелс). 1 → RST новым v6-TCP на
#           VPN-портах → мгновенный happy-eyeballs fallback на v4 (без SYN-timeout).
#    FIX#10 (bridge/whitelist drift): read-only advisory в 'guard' — TRUSTED_IPS из conf,
#           которых нет в живом nft manual_whitelist_v4 (их трафик идёт через лимиты →
#           мост/upstream рискует баном и аутажом downstream). O(1) проверка, без conntrack.
#    --- batch 3 ---
#    FIX#7  (IPv6 нет threat-feeds): добавлены v6-параллели blocklist-сетов
#           (scanner/threat/custom/tor _v6) + v6 drop-правила ПЕРЕД остальным v6
#           (бьют и SSH-over-v6). Updater теперь параллельно парсит v6 из того же фида:
#           префикс-флор (threat /29 [v3.27.2], прочие /24 — анти-::/0), фильтр bogon/ULA/
#           link-local/multicast/doc/v4-mapped/NAT64, структурная валидация против
#           обрезков greedy-grep. v6 применяется ОТДЕЛЬНОЙ nft-транзакцией (битый v6
#           НЕ ломает v4) и только если v6-set существует (backward-compat со старой
#           таблицей). v6==0 в фиде — норма (min-check к v6 не применяется). guard
#           показывает суммарный v6-счётчик; toggle Tor чистит и v6-сет.
#    Решения по остатку:
#      #6 (ban обходится ротацией) — НЕ чиним subnet-баном НАМЕРЕННО: на RU-мобайл
#         CGNAT целый /24 = тысячи легит-юзеров, авто-/24-бан = массовый аутаж. Ротацию
#         закрывает CrowdSec CAPI (community blocklist). Оставляем как осознанный trade-off.
#      #4 (infrastructure-bypass) — НАМЕРЕННО не трогаем (по решению оператора).
#
# ==============================================================================
#  VPN NODE DDoS PROTECTION v3.26.5 (Commercial Edition) — SECURITY HARDENING
#
#  v3.26.5 (dependency auto-upgrade):
#    - install/upgrade держит управляемые apt-зависимости на последней версии репо
#      (nftables, conntrack, iproute2, tcpdump, sqlite3, jq, curl, zstd, xz-utils,
#      crowdsec + firewall-bouncer). Апгрейд только если репо-версия строго новее
#      (downgrade исключён --only-upgrade). Foreign-CrowdSec не трогаем (подсказка).
#      Knob SHIELD_UPGRADE_DEPS=0 замораживает версии.
#
#  v3.26.4 (CGNAT/mobile false-positive fix):
#    - phantom attack-mode входит ТОЛЬКО при реальном per-source холдере (≥PH_MIN);
#      мобильный CGNAT-churn (conntrack≫live и у ЛЕГИТА из-за est_to) больше НЕ = атака.
#    - PH_MIN дефолт 500→4000 (выше легит-CGNAT-churn ~2200, ниже атаки 7000+) →
#      ENFORCE=1 снова безопасен на мобильных нодах.
#    - агрегатный кап теперь opt-in: SHIELD_CTG_AGG_CAP (0=прямые ноды, 1=CDN/мост).
#      Настоящий rate/fill-флуд капается всегда; чистый churn — нет (не вредит легиту).
#    - ensure_table пересоздаёт устаревшую таблицу без chain capnew (фикс WARN-спама
#      "не наложил агрегатный кап" при апгрейде поверх <v3.26).
#    - убран per-tick лог "фантом-холдеров не найдено".
#
#  v3.26.3: (perf) дешёвый коарс-гейт в ctguard — дорогой conntrack-L дамп только
#    если conntrack >> ss_total (фантом-тяжело) или attack-mode; здоровая busy-нода
#    не платит за полный дамп каждый тик. (наблюдаемость) guard «Total blocked» +
#    разбивка включают дропы ctguard-слоя (своя таблица); self-test проверяет heartbeat
#    ctguard (детект залипшего таймера). (конфиг) ручки SHIELD_CTG_* выведены в limits.conf.
#
#  v3.26.2: guard-дашборд теперь показывает РЕАЛЬНЫЕ дропы нового ctguard-слоя
#    (счётчики shield_ctguard: ctguard_drops/ctguard_capdrop) + режим и phantom-ratio;
#    раньше guard читал счётчики только из ddos_protect → дропы фантом-эвикта были
#    не видны (на connect-and-hold атаке conn_flood_v4≈0). + индикатор synproxy active.
#
#  v3.26.1: per-IP conn_flood возвращён на высокий backstop 15000 (в v3.26.0 был
#    ошибочно понижен до 4000 — близко к замеренному легит-CGNAT-потолку ~2216/IP,
#    риск ложных дропов в reconnect-шторме). Точность распределёнки — у ctguard
#    phantom-evict (liveness-aware, CGNAT-safe), per-IP лишь грубый backstop.
#    Ports-watcher теперь синхронит и synproxy sp_ports при смене портов фаервола.
#    Уточнён sysctl-коммент про acct (ctguard меряет живые сокеты, не байты).
#
#  v3.26.0: phantom-детект по ЖИВЫМ СОКЕТАМ (ss vs conntrack, acct-free) + ss-phantom-
#    ratio триггер + conntrack-exhaustion guard. Заменяет байтовый phantom_evict (тот при
#    nf_conntrack_acct=0 видел ВСЕ флоу как «фантом» → масс-эвикт CGNAT — критфикс).
#    is_protected теперь v4/v6. synproxy sp_ports: auto-merge (фикс пересечения портов с
#    protected_ports_tcp). SHIELD_CTG_ENFORCE (1=эвикт, 0=наблюдение). Новые conf:
#    SHIELD_CTG_LIVE_FRAC/_PHANTOM_RATIO/_CT_MAX_CEIL.
#
#  v3.25.0: защита от РАСПРЕДЕЛЁННОГО connection-exhaustion (connect-and-hold)
#    флуда — универсально для прямых / CDN / мост-нод (без per-node порогов).
#    Корень проблемы: статический per-IP порог нерешаем (легит-пик от ~127 на
#    прямой ноде до десятков тысяч за CDN). Новый сигнал = ОТКЛОНЕНИЕ от
#    собственной нормы ноды + КАЧЕСТВО флоу (фантом vs живой), не счётчик.
#    (1) ctguard переписан: EWMA-базлайн new-conn/с (TcpPassiveOpens) и
#        concurrent (conntrack) per-node; attack-mode при ×4 от нормы (выход
#        ×2), плюс fill-триггер сохранён. Отвязан от гейта 90% (app падал при
#        7% заполнения).
#    (2) Ответ в attack-mode: агрегатный кап new-conn на protected-порты
#        (глобальный limit rate, НЕ per-IP → safe для CDN/моста/CGNAT;
#        существующие сессии не трогаются) + phantom-эвикт: выселяет ТОЛЬКО
#        источники с многими handshake-only флоу (acct-байты < порога) И почти
#        без живых флоу — shared-фронты/CGNAT (с живым трафиком) не трогаются.
#    (3) sysctl: nf_conntrack_tcp_timeout_established 5д→1800с (брошенные
#        фантомы дохнут, живые с keepalive живут), acct=1 (для phantom-детекта),
#        tcp_loose=0, срезаны close_wait/fin_wait/time_wait/last_ack.
#    (4) Опц. crowdsec-бан выселенных фантом-источников (SHIELD_CTG_CSCLI=1).
#    Legacy per-IP conn_flood оставлен как высокий backstop (per-node в conf),
#    больше не основная защита.
#
#  v3.24.2: (1) conn_flood log-правило стало per-IP (отдельный set connwatch_v4
#    с 'ip saddr ct count over X-1') вместо глобального 'ct count over X-1' —
#    раньше на здоровой ноде суммарный conntrack по всем клиентам штатно >порог,
#    и лог [shield:conn_flood] сыпался почти непрерывно (дропа не было, только
#    шум в journald). Теперь логируется только реальный per-IP near-threshold.
#    (2) SYNPROXY: анонсируемый клиентам MSS теперь кэпится SHIELD_SYNPROXY_MSS_CAP
#    (default 1400) — фикс PMTU-blackhole для RU-мобайла/PPPoE/DSL с низким
#    path-MTU при default-on SYNPROXY. Кэп только понижает MSS (всегда безопасно).
#
#  v3.24.1: bouncer flap guard — релоады crowdsec при установке рвут decision-
#    стрим firewall-bouncer'а ("stream halted" → systemd рестарт по кругу).
#    Финальная проверка ловила bouncer в момент флапа (restart; sleep 3) и
#    печатала ложное "НЕ active". Теперь: ждём готовности LAPI → reset-failed →
#    рестарт → проверка active С РЕТРАЯМИ (8×2с) вместо одного снимка.
#
#  v3.24.0: SYNPROXY включён по умолчанию (SHIELD_SYNPROXY=1) — безопасно (авто-
#    fallback на ddos_protect если ядро не тянет; verify mss/wscale + авто-откат;
#    авто-доустановка linux-modules-extra на стоковых ядрах). + НОВЫЙ модуль
#    anti-conntrack-exhaustion (shieldnode-ctguard): изолированная таблица
#    inet shield_ctguard (priority -160), мониторит nf_conntrack_count и при
#    >=90% заполнения эвиктит ТОЛЬКО IP с аномальной долей соединений
#    (>=SHIELD_CT_EVICT_MIN, дефолт 10000 — много выше легита), nft-блок + conntrack -D,
#    авто-recovery при <=70%. conntrack% выведен в дашборд guard. Renumber меню 1..5.
#
#  v3.23.19: CRIT FIX агрегатора — shieldnode-aggregator.service под
#    ProtectSystem=strict не объявлял /run/shieldnode как writable → lock
#    /run/shieldnode/agg-state.lock падал "Read-only file system" → агрегатор
#    скипал КАЖДЫЙ тик → events.db замораживалась → guard-статистика стояла,
#    защита выглядела "не реагирующей" (а nft при этом дропал нормально).
#    Добавлены RuntimeDirectory=shieldnode + ReadWritePaths=/run/shieldnode
#    (как в ports-update unit). + агрегатор при невозможности открыть lock пишет
#    CRITICAL и exit 1 (раньше молча "skip" — баг прятался незаметно).
#
#  v3.23.18: synproxy теперь показывает причину невключения (фикс молчаливого
#    set -e + grep в verify_backend; явный die на nft -f при отсутствии nf_synproxy).
#    custom-счётчик виден в guard всегда. Чистка меню: [1] active-attacks,
#    [4] scanner-samples, [9] full-log и settings [f]/[v] удалены из кода + функции.
#
#  v3.23.17: FIX переполнения диска — rolling pcap (/var/log/pcap) рос до десятков
#    GB: strftime-имя ломало -W ring (ring удаляет только нумерованные файлы).
#    Теперь нумерованный ring 1GB (без -G/strftime) + size-cap + авто-очистка
#    legacy в archiver/install/FATAL. all-time history даты: LC_ALL=C + fallback.
#
#  v3.23.16: SYNPROXY (default-on с v3.24.0, SHIELD_SYNPROXY=1) — conntrack-exhaustion
#    защита. SYN перехватывается до conntrack (syncookies). Отдельный модуль
#    shieldnode-synproxy.sh / table inet shield_synproxy (ddos_protect не трогает).
#    На enable: verify mss/wscale + проверка untracked с авто-откатом. Boot-unit.
#    Ядро >=5.14. SSH не трогается. Включать на ноду после своей проверки.
#
#  v3.23.15 (security audit fixes):
#    P0-2 SSH-блок выше infra-accept; IaaS убран из infra baseline (CDN/edge only).
#    P0-1 базовая IPv6-защита (new-conn DROP на VPN-портах, SSH/v6 rate-limit).
#    P1-1 auto-promote 2000->800; источники conn_flood/syn_escalate/udp_escalate.
#    P2-1 octet<=255 в blocklist-updater. P2-2 ADMIN_IP -> whitelist (anti-lockout).
#
#  Что нового vs v3.23.12 (results of static security audit):
#
#  === P0 SECURITY FIXES ===
#    - BUG-002 FIX: SQL injection через journald. Aggregator теперь фильтрует
#      journalctl по `_TRANSPORT=kernel + SYSLOG_IDENTIFIER=kernel + crowdsec`,
#      применяет gsub очистку SRC= для ВСЕХ handlers (раньше [shield:ddos] и
#      [UFW BLOCK] не чистили IP), валидирует IPv4 format перед SQL INSERT.
#      Любой непривилегированный пользователь раньше мог через `logger` инжектить
#      строки с фейковым [shield:ddos] SRC=... и засорять / SQL injection events.db.
#
#    - BUG-003 FIX: Bogon-фильтр threat-feeds. min prefix /16 для threat (был /8 —
#      compromised feed мог затолкать 1.0.0.0/8 и забанить Cloudflare). Добавлены
#      CGNAT (100.64/10), TEST-NET-1/2/3, benchmark (198.18/19). MAX_FEED_ENTRIES
#      cap (200k threat / 100k scanner / 10k tor / 50k custom). Alert при >20%
#      росте от peak.
#      FAIL_THRESHOLD больше НЕ flush'ит set — stale data > no protection.
#
#    - BUG-006 FIX: shield_safe_source убрал 0644 из allowed perms. Все
#      shieldnode.conf теперь chmod 0640 (root:root). Files с 0644 auto-fixed.
#
#  === P0 FUNCTIONAL REGRESSION FIXES ===
#    - BUG-004 CRIT FIX: auto-promote был мёртв.
#      a) [shield:conn_flood] log prefix вообще не генерился в nft template —
#         aggregator awk парсил /\[shield:conn_flood\]/ впустую. Добавлен с
#         rate-limit 1/sec.
#      b) auto-promote query искал `type='syn_flood'` — но aggregator пишет
#         только `syn_escalate` (typo с рефакторинга v3.15.x). Исправлено на
#         `IN ('conn_flood','syn_escalate','newconn_flood')`.
#      c) Threat/custom/scanner/tor/ddos/syn_escalate/udp_escalate log prefix
#         теперь ВСЕГДА активны с rate-limit (не зависят от VERBOSE_LOGS).
#         events.db, auto-promote, guard top attackers — работают по default.
#
#  === P0 RESOURCE PROTECTION ===
#    - BUG-007 FIX: aggregator RAM blow-up. MAX_UNIQUE_IPS_PER_TYPE=50000 hash
#      cap. MemoryMax=512M MemoryHigh=384M TasksMax=20 CPUQuota=80% на systemd
#      unit. Storm-mode warning через logger при превышении cap'а.
#
#  === P1 ROBUSTNESS ===
#    - BUG-010 FIX: pcap-archiver. tar.zst compression >7d, retention 30d
#      теперь реально работает в archiver runtime (раньше жил только в
#      install-time disk cleanup, почти не срабатывал).
#    - BUG-012 FIX: conntrack snapshot полный + gzip (раньше head -10000
#      без compress, 5-15MB/archive). Через conntrack -L -o save (netlink).
#    - BUG-014 FIX: state-file cap LOG_STATE_MAX_ENTRIES=30000 keep-top-by-recency.
#    - BUG-015 FIX: VACUUM → VACUUM INTO + atomic mv + integrity_check + rollback.
#      Non-blocking, aggregator берёт shared flock на /run/shieldnode/db.lock.
#    - BUG-019 FIX: /etc/shieldnode/limits.conf с 17 настраиваемыми параметрами.
#      Embedded scripts через __PLACEHOLDER__ sed-substitution.
#    - BUG-020 FIX: journalctl фильтр (см. BUG-002), --lines=200000.
#    - BUG-021 FIX: финальный stale ct=5000 в guard CLI dashboard → ct=15000.
#
#  === LEGACY CLEANUP ===
#    - Удалены deprecated переменные mobile_ru/broadband_ru, MAXMIND.
#    - Удалён install-time cs-ssh-whitelist cleanup (≤v3.4 EOL 2 года).
#    - Удалён subnet-aggregator (v3.23.3-rc never released stable).
#
#  Что НЕ пофиксили (вне scope этого hardening release):
#    - BUG-001 (IPv6 не защищён) — архитектурный, требует full v6 ruleset.
#    - BUG-005 (upgrade без crypto verify) — требует GPG/Sigstore signing.
#    - Полный legacy cleanup mobile_ru/broadband_ru uninstall units (50 строк).
#
#  Что нового vs v3.23.11:
#    - FIX: финальное сообщение установщика и Settings меню показывали
#      ct=50000 (legacy hardcoded text). Реальный лимит в nft = 15000
#      с v3.23.3+, но текст в выводе не был обновлён. Поправлено.
#
#  Что нового vs v3.23.10:
#    - CRIT FIX: pcap-service не работал в v3.23.10. systemd unit использует
#      `%` как СВОИ specifiers (%H=hostname, %m=machineid, %Y=hash). Когда
#      я писал `%Y%m%d-%H%M%S` для strftime tcpdump — systemd подставлял
#      свои значения, и tcpdump получал имя файла типа
#      `syn-/etc/systemd/system07397.../run/credentials/.../sweden2.../var/lib.pcap`.
#      ОК что я первоначально делал в v3.23.9 (`%%Y%%m%%d`) — это правильно
#      для systemd escape. В саморевью v3.23.10 я ошибочно решил что %%
#      это баг и убрал их → сломал pcap полностью.
#      Fix: вернуть `%%Y%%m%%d-%%H%%M%%S` в unit-файле. Внутри single-quote
#      heredoc `%%` сохраняется literal → systemd получает `%%` → даёт
#      tcpdump один `%` для strftime → правильное имя файла.
#    - FIX: guard self-test "integer expression expected" — была пустая
#      переменная в `[ $X -gt N ]`. Защита через `${X:-0}` дефолт.
#
#  Что нового vs v3.23.9:
#    - CRIT FIX: в v3.23.9 heredoc для shieldnode-pcap.service использовал
#      `<<PCAP_UNIT_EOF` без quotes (для подстановки $TCPDUMP_BIN). Это
#      привело к двойному %% в фильтре tcpdump (`%%Y%%m%%d-%%H%%M%%S`) —
#      tcpdump получал буквальное имя файла "syn-%%Y%%m%%d-..." вместо
#      рабочего timestamp. PCAP записи были бы сломаны на v3.23.9.
#      Fix: переход на single-quote heredoc (literal) + sed замена ровно
#      одного placeholder __TCPDUMP_BIN__ после создания файла. Никакого
#      expand'а $VAR/%, всё literal до явной замены.
#
#  Что нового vs v3.23.8:
#    - PERF FIX: shieldnode-whitelist-updater использовал 6 nft delete команд
#      per-IP — каждая отдельный fork+exec+nft init. При 3 IP в TRUSTED_IPS
#      это 18 nft процессов на каждый sync. На слабых VPS вызывало CPU spike
#      до 90% при каждом запуске updater'а (path-watcher на whitelist-local.txt
#      или N раз/час). Видно как `nft delete element ... { 213.165.55.166 }`
#      висящие в top с 80-90% CPU.
#      Fix: переход на batch `nft -f -` (один процесс для всех delete операций).
#      Снижение CPU usage в 18x на nodes с whitelist'ом.
#    - FIX: pcap.service status=203/EXEC на некоторых нодах (tcpdump не
#      установлен или путь к binary неверный). Установщик теперь проверяет
#      `command -v tcpdump` ПЕРЕД enable сервиса. Если tcpdump отсутствует —
#      apt install с retry, log warning если не установился.
#
#  Что нового vs v3.23.7:
#    - FIX: фоновый gzip в aggregator теперь логирует ошибки в syslog
#      (раньше 2>/dev/null проглатывал "no space"/"permission denied").
#      Plus retry: если на старте aggregator находит несжатый archive
#      events.log.YYYYMMDD-* — пробует сжать его ещё раз.
#    - FIX: cleanup при upgrade теперь fallback на truncate если диск
#      критически забит (>95%) и gzip может не уместиться. Защита от
#      "висим 10 минут на 37GB gzip когда нет свободного места".
#      При >95% — truncate (быстро, теряем данные). При <95% — gzip
#      (медленно, сохраняем). Промежуточно: при 90-95% диск показывает
#      progress через nohup wrapper.
#    - FIX: PCAP archive теперь СЖИМАЕТСЯ в tar.zst перед удалением
#      (не теряем forensics для хостера). Старше 7 дней → tar.zst.
#      Старше 30 дней → удалить.
#    - FIX: xz -9 → xz -6 в cleanup'е (втрое быстрее, ratio 95% от -9).
#    - FIX: системные logs cleanup — whitelist известных паттернов
#      (syslog.*.gz, kern.log.*.gz, etc), не broad-match всех .gz в
#      /var/log. Защита от случайного удаления docker logs.
#
#  Что нового vs v3.23.6:
#    - CRIT FIX: events.log при заполнении теперь СЖИМАЕТСЯ (gzip), а не truncate.
#      Раньше: events.log >500MB → tail -c 100MB → ТЕРЯЛИ 400MB истории.
#      Теперь: events.log >100MB → mv в events.log.<TS> → gzip в фоне → новый
#      пустой events.log. На диске 37GB → ~2GB (95% компрессии на текстовых
#      логах). История полностью сохранена, читается через `zless`.
#    - FEATURE: автоматическая ретенция архивов:
#       * .gz архивы старше 14 дней → пересжимаются xz -9 (50% доп. экономии)
#       * .xz архивы старше 90 дней → удаляются
#    - FIX: cleanup при upgrade теперь сжимает существующие большие events.log
#      вместо truncate (не теряет данные). Удаляет только архивы старее 30
#      дней (раньше 1 день — слишком агрессивно).
#    - FIX: logrotate config: maxsize 50M → 100M (меньше частых ротаций),
#      rotate 30 дней (история атак сохраняется).
#
#  Что нового vs v3.23.5:
#    - CRIT FIX: should_log() в aggregator использовал `grep -F "^${key}|"` —
#      это fixed-string mode, где `^` ищется буквально, не как anchor.
#      Эффект: state lookup ВСЕГДА возвращал empty → каждое событие писалось
#      как "впервые видим" → дедуп НЕ РАБОТАЛ. Главная фича v3.23.5 была сломана.
#      Fix: переход на in-memory bash associative array (load state на старте,
#      atomic dump в конце). Plus: flock на скрипт против concurrent runs.
#    - CRIT FIX: race condition в aggregator. Timer запускается каждую минуту,
#      тики могли пересекаться при долгой обработке. Теперь flock защищает.
#    - PERF FIX: state-операции были O(N×12) grep/sed на каждом тике. Теперь O(1)
#      bash hash lookup. На крупных нодах (4000+ unique IP) разница в 100-1000x
#      по CPU за тик.
#    - INFRA: state-файл пишется atomically (tmp + mv), не повреждается при kill.
#    - FEATURE: автоматическая чистка диска при upgrade (ШАГ 12.6).
#      Если /var/log >80% — установщик truncate'ит events.log до 100MB,
#      удаляет ротированные *.gz/*.1 в /var/log/{shieldnode,}/, vacuums
#      journald, чистит apt cache, truncate'ит syslog/kern.log >200MB.
#      Решает кейс spofyltd (37GB в /var/log от длительной атаки на старой
#      версии) — после upgrade диск свободен для нормальной работы.
#
#  Что нового vs v3.23.4:
#    - CRIT FIX: events.log больше не заполняет диск при длительных атаках.
#      Раньше aggregator писал каждый активный IP при каждом тике (30s) — при
#      атаке 4000 уникальных IP × 2 тика/мин × 100 байт = 800 KB/min = 1.2 GB/день.
#      Теперь state-based logging: пишется только если IP новый, или count
#      вырос на >=1000, или прошёл час с последнего лога этого IP. Сокращение
#      throughput'а в 100-1000 раз без потери информации (events.db всё пишет).
#    - CRIT FIX: hard cap 500MB на events.log. Если writer перерос лимит —
#      auto-rotate (tail 100MB last). Защита даже если logrotate broken.
#    - FIX: logrotate config теперь с copytruncate (раньше падал с status=1
#      потому что shieldnode-aggregator держал fd на events.log).
#    - FIX: systemd Restart=on-failure для shieldnode-nftables/events/pcap —
#      авто-recovery при крэшах вместо тихого падения защиты.
#    - FIX: aggregator detect MY_IP в suspect_v4 → log WARNING + skip
#      (вместо busy-loop удаления). Self-flood случаи (loopback через
#      public_ip в nginx/proxy_pass) больше не зацикливают CPU.
#    - FEATURE: `guard self-test` — диагностика готовности ноды:
#      conntrack_max vs RAM, диск, MY_IP в suspect, services, nft tables.
#      Запускать после upgrade или при подозрениях.
#
#  Что нового vs v3.23.3:
#    - REMOVED: /24 subnet aggregator + whois install.
#      Был добавлен в v3.23.3-rc, удалён до stable релиза.
#      Причина: дополнительная сложность (whois package + кэш + dry-run logic)
#      vs незначительный профит (CrowdSec community + threat-feeds уже покрывают
#      90% datacenter ботнетов). Auto-promote + ручной custom.txt — достаточно.
#      Cleanup: установщик автоматически удалит legacy unit'ы при upgrade.
#    - FIX: CrowdSec scenario shieldnode/conn-flood filter более не включает
#      UFW-BLOCK события (это port scan, не DDoS, не должен попадать в
#      community blocklist под labels.type='ddos').
#    - FIX: degraded feed warning теперь со скользящим peak (auto-reset если
#      current >= 80% от peak — источник восстановился).
#    - FIX: TTL cleanup в auto-promote логирует warning если date-parsing
#      не сработал (silent failure removed).
#    - INFRA: idempotent cleanup в начале установщика — корректно удаляет
#      legacy systemd unit'ы и nft set'ы от предыдущих версий (включая
#      subnet-aggregator от v3.23.3-rc если был установлен).
#
#  Что нового vs v3.23.1 (на основе DDoS-инцидента 2026-05-24 + долгосрочное усиление):
#    1. CRIT: ct count over 50000 → 15000.
#       Инцидент показал атаку где боты держали 5k-128k conn/IP, проходили
#       под старый лимит 50000. Замер легитимных пиков: 700-750 conn/IP.
#       Новый порог 15000 = запас 20x от пика, режет все известные ботнеты.
#    2. FEATURE: rolling pcap-capture с attack-detect archiver.
#       Базовый ring buffer 1GB заполняется за 80 сек при 100k pps атаке.
#       Поэтому добавлен shieldnode-pcap-archiver.timer: каждую минуту проверяет
#       drop-counters, при скачке >10k drops/min архивирует current ring в
#       /var/lib/shieldnode/pcap-archive/attack-<TS>/ — сохраняется навсегда
#       (cleanup только через 7 дней).
#    3. FEATURE: auto-promote из events.db с TTL 90 дней.
#       Каждые 6ч IP с count>=2000/24ч → custom-local.txt.
#       Раз в сутки cleanup: записи старше 90 дней удаляются если IP не
#       появлялся в events.db последние 30 дней. Защита от unbounded growth.
#    4. FEATURE: CrowdSec scenario с правильным parser pattern.
#       Filter: SYN-ESCALATE, UDP-ESCALATE, CONN-FLOOD, SYN-FLOOD.
#       Grok pattern покрывает форматы с/без dpt=.
#       Acquisition пишется только если events.log существует.
#    5. FEATURE: degraded feed health warning.
#       Updater сохраняет peak entries в /var/lib/shieldnode/.peak-<name>.
#       Если current <50% от peak — WARN в syslog (детект "тихих" поломок
#       источников типа смена URL формата или удаление repo).
#    6. FEATURE: CrowdSec whitelist cross-check в auto-promote.
#       Перед триггером update — удаляем из custom-local любые IP помеченные
#       whitelist'ом в CrowdSec. Защита от конфликта приоритетов.
#    7. FEATURE: threat blocklist расширен до 5 источников (v3.23.2 cumulative):
#       + blocklist.de (~30k IP fail2ban-агрегатор), + Feodotracker abuse.ch,
#       + IPSum level 3. DEFAULT_MIN_ENTRIES_THREAT 500 → 5000.
#    8. INFRA: динамический whitelist DNS из /etc/resolv.conf / resolvectl
#       / systemd-resolved (вместо hardcoded 1.1.1.1, 8.8.8.8).
#    9. INFRA: MY_IP detection без внешних сервисов — через ip route get
#       и фильтр public IP в hostname fallback.
#   10. INFRA: /run/shieldnode/ для locks и transient state (вместо устаревшего
#       /var/run и хрупкого /var/lib/shieldnode/.*-hash).
#   11. INFRA: PCAP restart только если конфиг изменился (sha256 sequence)
#       или сервис не запущен — не обрывать активный capture зря.
#
#  TODO (v3.24+, не критично сейчас):
#    - Adaptive ct count threshold: раз в неделю замерять p99 conn/IP среди
#      легитимных, устанавливать лимит = max(15000, p99*5).
#    - JSON API для shieldnode-archive metrics (для Grafana/Prometheus).
#    - Encrypt-at-rest для /var/lib/shieldnode/pcap-archive/ (privacy).
#
#  Из v3.23.0/v3.23.1 (сохранены):
#    - TRUSTED_IPS через postoverflow whitelist (parser-level)
#    - guard Trusted IPs Delete экранирует точки в IP
#    - TRUSTED_IPS поддерживает CIDR
#    - guard NFT_SINCE читает shieldnode-nftables.service
#    - убрана невалидная "17::/32" из IPv6 baseline
#
#  Что нового vs v3.22.0:
#    1. CRIT-2: log_martians = 0 (was 1).
#       На VPN forwarder с rp_filter=2 (loose) martians — нормальный шум
#       маршрутизации, не сигнал атаки. Логирование martians грузило
#       rsyslog/journald disk-writes, косвенно влияя на softirq scheduling.
#       Mitigation (rsyslog dedup, journald limit, hourly logrotate) оставлены
#       как defense-in-depth, но первопричина теперь убрана.
#    2. IMPR: nf_conntrack_udp_timeout_stream = 600 (was 300).
#       Hysteria2 mobile клиенты в background (Android Doze, iOS suspended)
#       могут не слать пакеты дольше 5 минут. Старый timeout = принудительный
#       reconnect → user видит "freeze on resume from background".
#       10 минут — sweet spot между state bloat и UX.
#    3. IMPR: tcp_synack_retries = 3 (was 2).
#       2 retry = ~3 сек до отказа handshake. Для intercontinental клиентов
#       (RU/Asia → DE/SE) с RTT 200-400ms и пакетлоссом этого мало.
#       SYN cookies продолжают защищать от SYN-flood независимо от этого.
#    4. IMPR: SHIELDNODE_VERBOSE_LOGS=0 по умолчанию.
#       Раньше: все drop-rules имели `log prefix [shield:*]` → ~3000 log
#       events/hour на проде. Теперь: только counter-based metrics (видны
#       через guard), без log prefix. Aggregator работает только при =1.
#       Operator может включить =1 для debug сессий.
#       Уменьшает disk write rate и journald CPU usage.
#
#  Архитектура pipeline (inet ddos_protect, prerouting priority -100/-150):
#    ct established/related accept
#      → manual_whitelist_v4 accept
#      → fib_spoof drop (single-homed only)
#      → tcp_invalid drop (NULL/XMAS/SYN+FIN/SYN+RST/FIN+RST scans)
#      → threat_blocklist_v4 drop  (~1900 IP — Spamhaus/FireHOL)
#      → custom_blocklist_v4 drop  (operator personal, github sync 6h)
#      → scanner_blocklist_v4 drop (~1100 IP — Shodan/Censys/CyberOK)
#      → SSH per-IP rate-limit (ct>5 + 8/min burst 20)
#      → tor_exit_blocklist_v4 drop (~840 IP, only if BLOCK_TOR=1)
#      → infrastructure_v4 accept  (~220 CIDR — CF/Google/AWS/Azure/Apple/...)
#      → confirmed_attack_v4 drop  (banned 15min after 2nd offence)
#      → conn_flood (ct>15000) → suspect_v4 → confirmed
#      → newconn_rate (40000/min burst 60000) → suspect → confirmed
#      → syn_flood (2000/sec burst 3000) → suspect → confirmed
#      → udp_flood (10000/sec burst 20000) → suspect → confirmed
#
#  Лимиты рассчитаны на ноду с 500-1000 VPN-клиентами. CGNAT-провайдеры
#  (МТС/T2/Beeline/Tele2) держат ~200 абонентов за одним public IPv4 через
#  PAT — на peak это до 30k conntrack entries и 75k UDP pkt/sec per CGNAT IP.
#  Лимиты пропускают это, ловят атаки (>100k SYN/sec, >500k connections).
#
#  Hook priorities:
#    prerouting -200: CrowdSec bouncer (table ip crowdsec, CAPI ~28k IPs)
#    prerouting -150: shieldnode (when panel mode active)
#    prerouting -100: shieldnode (standalone) / conntrack (system)
#    input -10:       legacy bouncer hook (migrated to prerouting in v3.10.3)
#    input  0:        UFW + user filter chains
#
#  Файлы:
#    /usr/local/sbin/shieldnode-*.sh   — updater'ы (blocklists, github, version)
#    /etc/shieldnode/shieldnode.conf   — config (PANEL_TYPE, TRUSTED_IPS, ...)
#    /etc/shieldnode/lists/            — blocklists и whitelist-local.txt
#    /etc/nftables.d/ddos-protect.conf — сгенерированный nft ruleset
#    /var/lib/shieldnode/events.db     — sqlite (WAL mode)
#    /var/log/shieldnode/events.log    — human-readable события
#
#  Команды:
#    sudo guard                — дашборд + interactive menu
#    sudo guard --json         — JSON для Zabbix/Prometheus
#    sudo guard upgrade        — re-install с github (auto-snapshot для rollback)
#    sudo guard rollback       — откатиться к предыдущему snapshot'у
#    sudo guard sync           — синк custom.txt прямо сейчас
#
#  Удаление: sudo bash shieldnode.sh --uninstall
#
#  РЕКОМЕНДАЦИЯ: для максимальной защиты после установки:
#    1. ssh-keygen -t ed25519 на локальной машине
#    2. ssh-copy-id root@<server>
#    3. Зайди по ключу, проверь
#    4. sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' \
#         /etc/ssh/sshd_config && systemctl reload ssh
# ==============================================================================


set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${BOLD}$1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}
print_status() { echo -e "${YELLOW}➤${NC} $1"; }
print_ok()     { echo -e "${GREEN}✔${NC} $1"; }
print_error()  { echo -e "${RED}✖${NC} $1"; }
print_info()   { echo -e "${MAGENTA}ℹ${NC} $1"; }
print_warn()   { echo -e "${YELLOW}⚠${NC} $1"; }

# v3.11.1 BUG-CSCLI-FMT FIX: устойчивая проверка установлена ли коллекция
# в CrowdSec независимо от формата вывода cscli (table в 1.7+, plain в 1.6).
# Используем `-o raw` который даёт CSV-like формат, стабильный между версиями.
# Header: первая строка "name", далее "name,status,version,description"
cscli_collection_installed() {
    local name="$1"
    [ -z "$name" ] && return 1
    command -v cscli >/dev/null 2>&1 || return 1
    cscli collections list -o raw 2>/dev/null | \
        awk -F, -v target="$name" 'NR > 1 && $1 == target { found=1; exit } END { exit !found }'
}

# ==============================================================================
# v3.12.0 GLOBAL CONFIG (paths, repo URL, defaults)
# ==============================================================================

# Github repo для скачивания дефолтных lists/*.txt при pipe-mode установке.
# Можно переопределить через env (для тестинга на форке).
SHIELD_REPO_URL="${SHIELD_REPO_URL:-https://raw.githubusercontent.com/SpofyJet/shield/main}"

# v3.18.3: версия для self-check
SHIELDNODE_VERSION="3.28.9"

# Каталоги (объявлены РАНЬШЕ дефолтов — нужны для подгрузки conf на строке ниже)
SHIELD_ETC_DIR="/etc/shieldnode"
SHIELD_LISTS_DIR="$SHIELD_ETC_DIR/lists"
SHIELD_CONF_FILE="$SHIELD_ETC_DIR/shieldnode.conf"
SHIELD_DEFAULTS_FILE="/usr/local/sbin/shieldnode-defaults.sh"
SHIELD_UPDATER_SCRIPT="/usr/local/sbin/shieldnode-update-blocklist.sh"
SHIELD_STATE_DIR="/var/lib/shieldnode"

# v3.14.1: ПРИОРИТЕТНАЯ ПОДГРУЗКА USER CONFIG.
# Если оператор настроил что-либо через guard CLI settings menu — это записалось
# в /etc/shieldnode/shieldnode.conf. При reinstall (apply новой версии) мы должны
# уважать его выбор, а не сбрасывать на дефолты. Подгружаем СЕЙЧАС, до объявления
# дефолтов: env var или conf-значение получает приоритет над встроенным дефолтом.
#
# v3.18.11 SH-NEW-1: source выполняется ТОЛЬКО если файл принадлежит root и
# имеет безопасные права. Защищает от privilege-escalation если /etc/shieldnode/
# был случайно расшарен (chmod 777), либо если non-root юзер получил запись
# через bug в другом сервисе.
shield_safe_source() {
    local f="$1"
    [ -f "$f" ] || return 0
    local owner perms
    owner=$(stat -c "%u:%g" "$f" 2>/dev/null)
    perms=$(stat -c "%a" "$f" 2>/dev/null)
    if [ "$owner" != "0:0" ]; then
        echo "WARN: $f не принадлежит root (owner=$owner) — пропускаю source" >&2
        return 1
    fi
    # v3.23.13 BUG-006 FIX: 0644 убран из разрешённых. TRUSTED_IPS, BRIDGE_IPS,
    # CrowdSec settings — sensitive infrastructure data, не должны быть
    # world-readable. Поддерживается только 600 (owner-only) или 640
    # (root + adm group для logreader). Files с 0644 — auto-chmod в 0640
    # с warning'ом (миграция со старых установок).
    if [ "$perms" = "644" ]; then
        echo "INFO: $f имеет 0644 (legacy) — фиксим в 0640 для безопасности" >&2
        chmod 0640 "$f" 2>/dev/null
        perms="640"
    fi
    case "$perms" in
        600|640) ;;
        *)
            echo "WARN: $f имеет небезопасные права ($perms) — пропускаю source" >&2
            return 1
            ;;
    esac
    # shellcheck source=/dev/null
    . "$f" 2>/dev/null || true
    return 0
}

# v3.23.13 SR-FIX-4: проверка после sed-подстановки placeholders.
# Если в embedded скрипте остался незаменённый `__SHIELD_*__` placeholder —
# значит соответствующая SHIELD_* переменная была пустая, или sed выпал.
# Fail loud, не silent — иначе скрипт упадёт при первом запуске с криптичной
# ошибкой ('cannot parse "__SHIELD_..._DAYS__" as integer').
verify_no_placeholders() {
    local file="$1"
    local residuals
    residuals=$(grep -oE '__SHIELD_[A-Z_]+__' "$file" 2>/dev/null | sort -u | tr '\n' ' ')
    if [ -n "$residuals" ]; then
        print_error "FATAL: placeholder substitution failed in $file"
        print_error "  Unresolved placeholders: $residuals"
        print_error "  Возможные причины: SHIELD_* env vars не заданы, или sed выпал."
        return 1
    fi
    return 0
}

if [ -f "$SHIELD_CONF_FILE" ]; then
    shield_safe_source "$SHIELD_CONF_FILE"
fi

# v3.18.11 SH-NEW-10: строгая валидация IPv4/CIDR.
# Отклоняет:
#   - 0.0.0.0/x  (whitelist всего интернета — частая ошибка оператора)
#   - 224-255    (multicast/reserved)
#   - 255.255.255.255 (broadcast)
#   - оctets > 255
#   - prefix < 8 или > 32
# Принимает:
#   - 1.2.3.4
#   - 10.0.0.0/8 (RFC1918 ok)
#   - 127.0.0.0/8 (loopback ok — может быть legitimate в test setups)
# Возвращает 0 если valid, 1 если нет.
validate_ipv4_or_cidr() {
    local input="$1"
    local ip cidr o1 o2 o3 o4
    if [[ "$input" == */* ]]; then
        cidr="${input#*/}"
        ip="${input%/*}"
        case "$cidr" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "$cidr" -ge 8 ] && [ "$cidr" -le 32 ] || return 1
    else
        ip="$input"
    fi
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [ -z "$o4" ] && return 1
    [ -n "$extra" ] && return 1
    for o in "$o1" "$o2" "$o3" "$o4"; do
        case "$o" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
    done
    # Reject 0.0.0.0/x, multicast, broadcast
    [ "$o1" -eq 0 ] && return 1
    [ "$o1" -ge 224 ] && return 1
    [ "$o1" -eq 255 ] && [ "$o2" -eq 255 ] && [ "$o3" -eq 255 ] && [ "$o4" -eq 255 ] && return 1
    return 0
}

# v3.14.0: настройки auto-sync (можно переопределить в shieldnode.conf или env).
# Приоритет: env var → shieldnode.conf → дефолт здесь.
ENABLE_GITHUB_SYNC="${ENABLE_GITHUB_SYNC:-1}"
ENABLE_VERSION_CHECK="${ENABLE_VERSION_CHECK:-1}"
DEFAULT_GITHUB_SYNC_INTERVAL="6h"
DEFAULT_VERSION_CHECK_INTERVAL="1d"

# v3.23.0/v3.23.13: SHIELDNODE_VERBOSE_LOGS — toggle для HIGH-VOLUME per-packet
# log правил (tcp_invalid, fib_spoof). Эти срабатывают на КАЖДОМ packet с
# bad-flag комбинацией — могут давать тысячи log lines/sec под scan'ом.
#
# v3.23.13 ВАЖНОЕ ИЗМЕНЕНИЕ: события для events.db attribution
# (threat/custom/scanner/tor/conn_flood/syn_escalate/udp_escalate/ddos)
# теперь логируются ВСЕГДА с агрессивным rate-limit (1/sec burst 5).
# Это max 3600 строк/час × 8 типов = ~28k строк/час, что << 37GB inцидент
# (тот был БЕЗ rate-limit). Без этих log'ов events.db и auto-promote мёртвы
# (см. v3.23.13 BUG-004 fix).
#
#   SHIELDNODE_VERBOSE_LOGS=0 (default): только critical events с rate-limit.
#   SHIELDNODE_VERBOSE_LOGS=1: + tcp_invalid + fib_spoof + ssh per-packet (debug).
SHIELDNODE_VERBOSE_LOGS="${SHIELDNODE_VERBOSE_LOGS:-0}"

# v3.12.0: detect pipe-mode (curl | bash) vs git-clone-mode (./shieldnode.sh)
# Pipe-mode → BASH_SOURCE[0] = /dev/fd/* или похожее → нет ./lists рядом со скриптом
# Git-mode → BASH_SOURCE[0] — реальный файл, рядом может лежать ./lists/
SHIELD_SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SHIELD_PIPE_MODE=0
case "$SHIELD_SCRIPT_PATH" in
    /dev/fd/*|/proc/*|bash|-bash|sh|-sh|"")
        SHIELD_PIPE_MODE=1
        SHIELD_SCRIPT_DIR=""
        ;;
    *)
        if [ -f "$SHIELD_SCRIPT_PATH" ]; then
            SHIELD_SCRIPT_DIR="$(cd "$(dirname "$SHIELD_SCRIPT_PATH")" && pwd)"
        else
            SHIELD_PIPE_MODE=1
            SHIELD_SCRIPT_DIR=""
        fi
        ;;
esac

# v3.23.14 PIPE-DEADLOCK FIX: при `curl | bash` скрипт читается из НЕ-seekable
# pipe. Этот файл ~480KB — он НЕ влезает в pipe-буфер ядра (64KB). Как только
# bash блокируется на долгой операции (ожидание apt-lock, apt-get install
# crowdsec на минуты), он перестаёт вычитывать stdin → curl упирается в полный
# pipe → через таймаут отдаёт `curl: (23) Failure writing output to destination`,
# а bash получает ОБРЕЗАННЫЙ скрипт и ведёт себя непредсказуемо
# (это и есть симптом "apt lock 300s + curl 23 + не остановить процесс").
#
# РЕШЕНИЕ: в pipe-режиме скачиваем полную копию во временный файл и exec'аем её.
# После exec stdin больше не pipe → дедлок невозможен в принципе, даже если
# apt-операции идут минуты. Guard SHIELD_REEXEC=1 защищает от петли.
if [ "$SHIELD_PIPE_MODE" = "1" ] && [ "${SHIELD_REEXEC:-0}" != "1" ] && [ "${1:-}" != "--uninstall" ]; then
    _SHIELD_SELF="$(mktemp /tmp/shieldnode.XXXXXX.sh 2>/dev/null)"
    if [ -n "$_SHIELD_SELF" ] && \
       command -v curl >/dev/null 2>&1 && \
       curl -fsSL --max-time 60 --retry 3 "$SHIELD_REPO_URL/shieldnode.sh" -o "$_SHIELD_SELF" 2>/dev/null && \
       [ -s "$_SHIELD_SELF" ] && head -1 "$_SHIELD_SELF" | grep -q '^#!'; then
        chmod 0755 "$_SHIELD_SELF" 2>/dev/null
        echo "ℹ Pipe-режим: перезапускаюсь из $_SHIELD_SELF (защита от curl-обрыва на 484KB)" >&2
        export SHIELD_REEXEC=1
        # shellcheck disable=SC2093
        exec bash "$_SHIELD_SELF" "$@"
        # exec не вернётся; если вдруг вернулся — продолжаем на pipe (best-effort)
    else
        [ -n "$_SHIELD_SELF" ] && rm -f "$_SHIELD_SELF" 2>/dev/null
        echo "⚠ Не смог перекачать копию для re-exec — продолжаю на pipe (возможен обрыв на больших паузах)" >&2
    fi
fi

# v3.12.0: дефолтные blocklist sources. Если /etc/shieldnode/shieldnode.conf
# существует — он переопределит эти массивы (через source).
DEFAULT_LOCAL_BLOCKLISTS=(
    "scanner=$SHIELD_LISTS_DIR/scanner.txt"
    "threat=$SHIELD_LISTS_DIR/threat.txt"
    "tor=$SHIELD_LISTS_DIR/tor.txt"
    "custom=$SHIELD_LISTS_DIR/custom.txt,$SHIELD_LISTS_DIR/custom-local.txt"
    # v3.20.0: mobile_ru + broadband_ru entries УБРАНЫ. Whitelist'ы заменены
    # на единый глобальный лимит ct=3000 (см. changelog).
)

# Объединение URL'ов через запятую → один set
DEFAULT_REMOTE_BLOCKLISTS=(
    "scanner=https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list,https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list,https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
    "threat=https://www.spamhaus.org/drop/drop_v4.json,https://www.spamhaus.org/drop/drop_v6.json,https://iplists.firehol.org/files/firehol_level1.netset"
    # v3.23.14 FALSE-POSITIVE FIX: убраны blocklist.de/all и stamparm/ipsum L3 —
    # это АГРЕГАТОРЫ abuse-репортов. Они часто содержат публичные CGNAT/PAT-адреса
    # мобильных операторов и переиспользованные IP, за которыми сидят ОБЫЧНЫЕ
    # клиенты VPN. Эти IP попадали в threat_blocklist_v4 → drop NEW-соединений →
    # юзер не может подключиться / не грузятся сайты. Оставлены только
    # high-confidence источники: Spamhaus DROP (угнанные/криминальные блоки),
    # FireHOL Level1 (bogon + dshield top, курируется как safe).
    # v3.27.2: Spamhaus drop.txt → drop_v4.json + drop_v6.json (txt на пути к
    #   deprecation; JSON парсится существующей jq-веткой; v6 кормит threat_v6-сет).
    #   Feodo abuse.ch УБРАН — датасет сейчас пустой + abuse.ch требует Auth-Key
    #   (июнь 2025) и мигрирует под Spamhaus → мёртвый груз + будущие 401.
    # Вернуть шумные фиды (НЕ рекомендуется для user-facing ноды) можно через
    # REMOTE_BLOCKLISTS в /etc/shieldnode/shieldnode.conf.
    "tor=https://check.torproject.org/torbulkexitlist"
    # custom: только локальный файл, без URL
    "custom="
    # v3.20.0: mobile_ru + broadband_ru URLs УБРАНЫ
)


DEFAULT_SCANNER_UPDATE_INTERVAL="6h"
DEFAULT_THREAT_UPDATE_INTERVAL="1d"
DEFAULT_TOR_UPDATE_INTERVAL="1h"
DEFAULT_CUSTOM_UPDATE_INTERVAL="6h"   # для custom: timer редкий, основной trigger — path-watcher

# v3.23.13 LEGACY CLEANUP: DEFAULT_MOBILE_RU_UPDATE_INTERVAL и
# DEFAULT_BROADBAND_RU_UPDATE_INTERVAL удалены (DEPRECATED с v3.20.0).

DEFAULT_MIN_ENTRIES_SCANNER=100
# v3.23.14: было 5000 (под blocklist.de+ipsum ~50k). После удаления шумных
# агрегаторов остаётся Spamhaus(~1100)+FireHOL1(~6800)+Feodo(~300)≈8200 — порог
# 3000 даёт запас, чтобы временная просадка одного источника не отменяла apply.
DEFAULT_MIN_ENTRIES_THREAT=3000
DEFAULT_MIN_ENTRIES_TOR=100
DEFAULT_MIN_ENTRIES_CUSTOM=0

DEFAULT_FAIL_THRESHOLD=3

# === v3.23.13 BUG-019 FIX: TUNABLE LIMITS ===
# Все hardcoded thresholds которые могут потребовать tuning под разные
# профили нагрузки (50 клиентов vs 2000 клиентов на ноде). Дефолты подходят
# для 100-200 клиентов на 4-8GB ноде. Оператор может переопределить через
# /etc/shieldnode/limits.conf (генерируется при установке).
SHIELD_CT_CONN_FLOOD="${SHIELD_CT_CONN_FLOOD:-15000}"
SHIELD_RATE_NEWCONN="${SHIELD_RATE_NEWCONN:-40000/minute}"
SHIELD_RATE_NEWCONN_BURST="${SHIELD_RATE_NEWCONN_BURST:-60000}"
SHIELD_RATE_SYN="${SHIELD_RATE_SYN:-2000/second}"
SHIELD_RATE_SYN_BURST="${SHIELD_RATE_SYN_BURST:-3000}"
SHIELD_RATE_UDP="${SHIELD_RATE_UDP:-10000/second}"
SHIELD_RATE_UDP_BURST="${SHIELD_RATE_UDP_BURST:-20000}"
SHIELD_SSH_CT_LIMIT="${SHIELD_SSH_CT_LIMIT:-5}"
SHIELD_SSH_NEWCONN_RATE="${SHIELD_SSH_NEWCONN_RATE:-8/minute}"
SHIELD_SSH_NEWCONN_BURST="${SHIELD_SSH_NEWCONN_BURST:-20}"
# v3.27.0 FIX(#8): 1=rate-shape per-IP-превышений new-conn/SYN/UDP (дроп только избыточных
# пакетов, НЕ заносить общий CGNAT-IP в confirmed_attack/15-мин blackhole); 0=старый escalate.
SHIELD_CGNAT_SAFE="${SHIELD_CGNAT_SAFE:-1}"
# v3.27.0 FIX(#3): глобальный backstop new-conn/с на protected-TCP. 0=off (CGNAT-safe дефолт).
SHIELD_GLOBAL_NEWCONN_CEIL="${SHIELD_GLOBAL_NEWCONN_CEIL:-0}"
# v3.27.0 FIX(#11): 1=RST новым v6-TCP на VPN-портах (быстрый happy-eyeballs fallback), 0=drop (стелс).
SHIELD_V6_REJECT="${SHIELD_V6_REJECT:-0}"
SHIELD_AUTOPROMOTE_THRESHOLD="${SHIELD_AUTOPROMOTE_THRESHOLD:-800}"
# v3.24.0: SYNPROXY (conntrack-exhaustion защита). 1=вкл (дефолт), 0=выкл.
SHIELD_SYNPROXY="${SHIELD_SYNPROXY:-1}"
# v3.27.1 FIX(#6): покрывать ли SSH-порт SYNPROXY (анти-спуф-SYN на SSH). 1=да (дефолт), 0=нет.
SHIELD_SYNPROXY_SSH="${SHIELD_SYNPROXY_SSH:-1}"
# v3.24.0: conntrack-pressure guard (anti-exhaustion backstop)
SHIELD_CTGUARD="${SHIELD_CTGUARD:-1}"
SHIELD_CT_WARN_PCT="${SHIELD_CT_WARN_PCT:-80}"
SHIELD_CT_HIGH_PCT="${SHIELD_CT_HIGH_PCT:-90}"
SHIELD_CT_RECOVER_PCT="${SHIELD_CT_RECOVER_PCT:-70}"
SHIELD_AUTOPROMOTE_WINDOW_HOURS="${SHIELD_AUTOPROMOTE_WINDOW_HOURS:-24}"
SHIELD_CUSTOM_LOCAL_TTL_DAYS="${SHIELD_CUSTOM_LOCAL_TTL_DAYS:-90}"
SHIELD_EVENTS_DB_RETENTION_DAYS="${SHIELD_EVENTS_DB_RETENTION_DAYS:-90}"
SHIELD_PCAP_TRIGGER_DROPS="${SHIELD_PCAP_TRIGGER_DROPS:-10000}"
SHIELD_PCAP_RETENTION_DAYS="${SHIELD_PCAP_RETENTION_DAYS:-30}"
SHIELD_AGG_JOURNAL_LINES="${SHIELD_AGG_JOURNAL_LINES:-50000}"  # v3.27.0 FIX(#14): 200k→50k per-tick (анти-OOM/CPU агрегатора под лог-штормом; nft-дропы идут независимо)
SHIELD_AGG_MAX_UNIQUE_IPS="${SHIELD_AGG_MAX_UNIQUE_IPS:-50000}"

# Load operator overrides if present
SHIELD_LIMITS_FILE="/etc/shieldnode/limits.conf"
if [ -f "$SHIELD_LIMITS_FILE" ]; then
    # shellcheck source=/dev/null
    if shield_safe_source "$SHIELD_LIMITS_FILE" 2>/dev/null; then
        :
    else
        echo "WARN: limits.conf failed safe-source check, using defaults" >&2
    fi
fi

# v3.23.13 SR-FIX-7: validate SHIELD_* numeric vars before use in nft heredoc.
# Defense-in-depth: если оператор поставил в limits.conf не-число (например,
# случайный пробел или комментарий), используем default вместо silent fail.
shield_ensure_numeric() {
    local varname="$1" default="$2"
    local val="${!varname}"
    if ! [[ "$val" =~ ^[0-9]+$ ]]; then
        echo "WARN: $varname='$val' is not numeric, using default=$default" >&2
        eval "$varname=\"\$default\""
    fi
}
shield_ensure_numeric SHIELD_CT_CONN_FLOOD 15000
shield_ensure_numeric SHIELD_RATE_NEWCONN_BURST 60000
shield_ensure_numeric SHIELD_RATE_SYN_BURST 3000
shield_ensure_numeric SHIELD_RATE_UDP_BURST 20000
shield_ensure_numeric SHIELD_SSH_CT_LIMIT 5
shield_ensure_numeric SHIELD_SSH_NEWCONN_BURST 20
shield_ensure_numeric SHIELD_AUTOPROMOTE_THRESHOLD 800
shield_ensure_numeric SHIELD_CGNAT_SAFE 1
shield_ensure_numeric SHIELD_GLOBAL_NEWCONN_CEIL 0
shield_ensure_numeric SHIELD_V6_REJECT 0
shield_ensure_numeric SHIELD_SYNPROXY 0
shield_ensure_numeric SHIELD_SYNPROXY_SSH 1
shield_ensure_numeric SHIELD_AUTOPROMOTE_WINDOW_HOURS 24
shield_ensure_numeric SHIELD_CUSTOM_LOCAL_TTL_DAYS 90
shield_ensure_numeric SHIELD_EVENTS_DB_RETENTION_DAYS 90
shield_ensure_numeric SHIELD_PCAP_TRIGGER_DROPS 10000
shield_ensure_numeric SHIELD_PCAP_RETENTION_DAYS 30
shield_ensure_numeric SHIELD_AGG_JOURNAL_LINES 50000
shield_ensure_numeric SHIELD_AGG_MAX_UNIQUE_IPS 50000

# Pre-compute derived values to avoid $((...)) inside heredoc (some bash
# versions on certain platforms had issues with arithmetic expansion inside
# unquoted heredoc when var contains unexpected chars).
SHIELD_CT_CONN_FLOOD_MINUS_1=$((SHIELD_CT_CONN_FLOOD - 1))

# v3.13.0: mobile-RU whitelist defaults
# v3.14.1: эти переменные тоже подхватятся из shieldnode.conf если оператор
# v3.18.8: TRUSTED_IPS — comma-separated список доверенных IP'шников твоей
# инфраструктуры (другие ноды, панель, мониторинг). Для каждого IP при установке
# применяется полный trust-stack:
#   1. shieldnode: добавляется в whitelist-local.txt → nft manual_whitelist_v4
#   2. UFW: ufw allow from <ip> comment 'Trusted (TRUSTED_IPS)'
#   3. CrowdSec: cscli decisions add --type whitelist на 1 год
# Применяется в ШАГ 12.5 после установки всех трёх слоёв защиты.
# Пример в shieldnode.conf:
#   TRUSTED_IPS="77.239.107.190,213.165.55.166,138.124.88.15"
# Управление через 'sudo guard' → [s] settings → [t] Trusted IPs.
TRUSTED_IPS="${TRUSTED_IPS:-}"

# v3.28.0: Remnawave fleet auto-sync. Вместо ручного перечисления IP нод/бриджей в
# TRUSTED_IPS на КАЖДОЙ ноде — даёшь токен панели, и shieldnode в фоне (таймер)
# тянет GET /api/nodes и держит nft-сет remnawave_nodes_v4/v6 в актуальном виде.
# Новую ноду добавил в панель → все ноды подхватят её сами. Это СВОИ серверы →
# whitelist безопасен (не CGNAT). Токен НЕ кладётся в shieldnode.conf (0640) —
# хранится в /etc/shieldnode/remnawave.env (root:root 0600). Передать при install:
#   REMNAWAVE_URL="https://panel.example.com" REMNAWAVE_TOKEN="ey..." curl ... | sudo bash
# SHIELD_REMNAWAVE_SYNC: auto (вкл, если есть URL+TOKEN) | 1 (форс) | 0 (выкл).
REMNAWAVE_URL="${REMNAWAVE_URL:-}"
REMNAWAVE_TOKEN="${REMNAWAVE_TOKEN:-}"
SHIELD_REMNAWAVE_SYNC="${SHIELD_REMNAWAVE_SYNC:-auto}"
SHIELD_REMNAWAVE_INTERVAL="${SHIELD_REMNAWAVE_INTERVAL:-5min}"

# v3.23.13 LEGACY CLEANUP:
# Удалены deprecated переменные (v3.20.0):
#   ENABLE_RU_MOBILE_WHITELIST, ENABLE_RU_BROADBAND_WHITELIST,
#   DEFAULT_MIN_ENTRIES_MOBILE_RU, DEFAULT_MIN_ENTRIES_BROADBAND_RU,
#   MAXMIND_LICENSE_KEY (deprecated v3.15.0).
# Эти переменные больше нигде не читаются. uninstall очищает legacy unit'ы.

# ==============================================================================
# UNINSTALL MODE
# ==============================================================================

if [ "${1:-}" = "--uninstall" ]; then
    if [[ $EUID -ne 0 ]]; then
        print_error "FATAL: Запустите через sudo"
        exit 1
    fi

    print_header "UNINSTALL: vpn-node-ddos-protect"

    print_warn "Это удалит:"
    echo "  - nft table inet ddos_protect (rate-limit + scanner-blocklist)"
    echo "  - /etc/nftables.d/ddos-protect.conf"
    echo "  - scanner-blocklist updater + timer"
    echo ""
    echo "  НЕ удалит:"
    echo "  - сам CrowdSec и bouncer (apt purge crowdsec вручную)"
    echo "  - sshd-конфиг (PasswordAuthentication)"
    echo "  - бэкапы в /root/vpn-ddos-backup-*"
    echo ""
    read -r -p "Продолжить? [y/N] " ANSWER
    case "$ANSWER" in
        y|Y|yes|YES) ;;
        *) echo "Отмена."; exit 0 ;;
    esac

    # Systemd units
    for unit in scanner-blocklist-update.timer scanner-blocklist-update.service \
                tor-blocklist-update.timer tor-blocklist-update.service \
                protected-ports-update.timer protected-ports-update.service \
                protected-ports-update.path \
                shieldnode-aggregator.timer shieldnode-aggregator.service \
                shieldnode-ctguard.timer shieldnode-ctguard.service \
                shieldnode-nftables.service \
                shieldnode-update@scanner.timer shieldnode-update@scanner.service \
                shieldnode-update@threat.timer  shieldnode-update@threat.service \
                shieldnode-update@tor.timer     shieldnode-update@tor.service \
                shieldnode-update@custom.timer  shieldnode-update@custom.service \
                shieldnode-update@custom.path \
                shieldnode-update@mobile_ru.timer shieldnode-update@mobile_ru.service \
                shieldnode-update@broadband_ru.timer shieldnode-update@broadband_ru.service \
                shieldnode-github-sync.timer shieldnode-github-sync.service \
                shieldnode-version-check.timer shieldnode-version-check.service \
                shieldnode-logrotate.timer shieldnode-logrotate.service \
                shieldnode-cleanup.timer shieldnode-cleanup.service \
                shieldnode-whitelist.path shieldnode-whitelist.service \
                shieldnode-remnawave-sync.timer shieldnode-remnawave-sync.service \
                shieldnode-synproxy.service; do
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f "/etc/systemd/system/$unit"
    done
    # v3.12.0: убираем templated unit-файлы (если timer'ы создавались из шаблона)
    rm -f /etc/systemd/system/shieldnode-update@.service
    rm -f /etc/systemd/system/shieldnode-update@.timer
    # v3.5: legacy unit от ≤v3.4 — удаляем если осталось от старой установки
    systemctl disable --now cs-ssh-whitelist 2>/dev/null || true
    rm -f /etc/systemd/system/cs-ssh-whitelist.service
    systemctl daemon-reload
    print_ok "Systemd units удалены"

    # Scripts
    rm -f /usr/local/sbin/cs-ssh-key-whitelist.sh
    rm -f /usr/local/sbin/update-scanner-blocklist.sh
    rm -f /usr/local/sbin/update-tor-blocklist.sh
    rm -f /usr/local/sbin/update-protected-ports.sh
    rm -f /usr/local/sbin/shieldnode-aggregator.sh
    rm -f /usr/local/sbin/shieldnode-update-blocklist.sh
    rm -f /usr/local/sbin/shieldnode-update-mobile-ru.sh
    rm -f /usr/local/sbin/shieldnode-github-sync.sh
    rm -f /usr/local/sbin/shieldnode-version-check.sh
    rm -f /usr/local/sbin/shieldnode-whitelist-updater.sh
    rm -f /usr/local/sbin/shieldnode-synproxy.sh /etc/shieldnode/synproxy.nft /etc/sysctl.d/99-shieldnode-synproxy.conf  # v3.23.16
    rm -f /usr/local/sbin/shieldnode-ctguard.sh  # v3.24.0
    rm -f /usr/local/sbin/shieldnode-remnawave-sync.sh /etc/shieldnode/remnawave.env /var/lib/shieldnode/remnawave-nodes.list  # v3.28.0
    rm -f /etc/systemd/system/shieldnode-ctguard.service /etc/systemd/system/shieldnode-ctguard.timer  # v3.24.0
    nft delete table inet shield_ctguard 2>/dev/null || true  # v3.24.0
    rm -f /usr/local/sbin/shieldnode-defaults.sh
    rm -f /usr/local/sbin/shieldnode-cleanup.sh  # v3.20.3
    rm -f /usr/local/bin/guard
    print_ok "Скрипты удалены (включая команду guard)"

    # v3.11: BLOCK_TOR marker
    rm -f /etc/shieldnode/block_tor
    # v3.12.0: lists и опциональный config
    rm -rf /etc/shieldnode/lists
    rm -f /etc/shieldnode/shieldnode.conf
    rmdir /etc/shieldnode 2>/dev/null || true

    # БД истории событий (v2.9), включая ASN cache (v3.12.0) и fail counters
    rm -rf /var/lib/shieldnode

    # v3.5: human-readable логи + logrotate
    rm -rf /var/log/shieldnode
    rm -f /etc/logrotate.d/shieldnode
    rm -f /etc/logrotate.d/shieldnode-syslog-aggressive  # v3.20.3 legacy
    # v3.23.13 SR-FIX-8: убираем наш patch (маркер + maxsize 100M) из rsyslog conf
    if [ -f /etc/logrotate.d/rsyslog ]; then
        sed -i -E '/^\s*# shieldnode-aggressive-marker\s*$/{N;d;}' /etc/logrotate.d/rsyslog 2>/dev/null || true
    fi
    # Cleanup нашего state файла
    rm -f /var/lib/shieldnode/logrotate-hourly.state /var/lib/shieldnode/logrotate.state /var/lib/shieldnode/logrotate-syslog.state 2>/dev/null
    print_ok "Логи и logrotate-конфиг удалены"

    # v3.21.3: rsyslog kern.* dedup (restore from backup) и journald limit drop-in
    RSYSLOG_RELOAD=0
    # Сначала чистим старый drop-in от первой версии v3.21.3 (если он остался
    # на хосте от broken-первой-итерации фикса — drop-in не работал, но мог
    # быть создан в /etc/rsyslog.d/).
    if [ -f /etc/rsyslog.d/49-shieldnode-kern-dedup.conf ]; then
        rm -f /etc/rsyslog.d/49-shieldnode-kern-dedup.conf
        RSYSLOG_RELOAD=1
    fi
    # Восстанавливаем 50-default.conf из backup'а (создан in-place edit'ом).
    if [ -f /etc/rsyslog.d/50-default.conf.shieldnode.bak ]; then
        # Проверяем что текущий 50-default.conf ещё содержит наш kern.none
        # (если оператор сам его перередактировал — не трогаем).
        if grep -qE '^\*\.\*;auth,authpriv\.none;kern\.none[[:space:]]+-?/var/log/syslog' \
              /etc/rsyslog.d/50-default.conf 2>/dev/null; then
            mv /etc/rsyslog.d/50-default.conf.shieldnode.bak /etc/rsyslog.d/50-default.conf
            print_ok "Восстановлен оригинальный /etc/rsyslog.d/50-default.conf из backup'а"
            RSYSLOG_RELOAD=1
        else
            print_info "50-default.conf изменён вручную после установки — backup сохранён в .shieldnode.bak"
        fi
    fi
    if [ "$RSYSLOG_RELOAD" = "1" ] && command -v systemctl >/dev/null 2>&1; then
        # reload (SIGHUP) — без обрыва приёма логов
        systemctl reload rsyslog 2>/dev/null || systemctl restart rsyslog 2>/dev/null || true
        print_ok "Rsyslog перечитал конфигурацию (kern.* снова дублируется в syslog)"
    fi
    JOURNALD_RESTART=0
    if [ -f /etc/systemd/journald.conf.d/shieldnode.conf ]; then
        rm -f /etc/systemd/journald.conf.d/shieldnode.conf
        # Если папка пуста — удаляем (вернули полный дефолт)
        rmdir /etc/systemd/journald.conf.d 2>/dev/null || true
        JOURNALD_RESTART=1
    fi
    if [ "$JOURNALD_RESTART" = "1" ] && command -v systemctl >/dev/null 2>&1; then
        # journald не поддерживает reload — нужен restart
        systemctl restart systemd-journald 2>/dev/null || true
        print_ok "Journald limit drop-in удалён (дефолтная квота восстановлена)"
    fi

    # Sysctl hardening (v3.3+, оба имени файла — старое 99 и новое 90 из v3.7)
    REMOVED_SYSCTL=0
    for f in /etc/sysctl.d/99-shieldnode.conf /etc/sysctl.d/90-shieldnode.conf; do
        if [ -f "$f" ]; then
            rm -f "$f"
            REMOVED_SYSCTL=1
        fi
    done
    if [ "$REMOVED_SYSCTL" = "1" ]; then
        # v3.18.9: sysctl --system НЕ сбрасывает значения которые писал ТОЛЬКО
        # удалённый файл — они "залипают" в памяти ядра до ребута. Явно сбрасываем
        # ключи которые shieldnode писал (на kernel defaults). Если оператор
        # установил vpn-node-setup.sh v5.1.0+ — он перезапишет своими значениями
        # через 80-vpn-node-tuning.conf при sysctl --system ниже.
        # Если его нет — сбросим явно.
        sysctl -w net.ipv4.tcp_synack_retries=5 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.tcp_syn_retries=6 >/dev/null 2>&1 || true
        sysctl -w net.netfilter.nf_conntrack_udp_timeout=30 >/dev/null 2>&1 || true
        sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=0 >/dev/null 2>&1 || true
        # v3.23.0: log_martians теперь = 0 в установщике, всё равно сбрасываем явно
        # (на случай если оператор включал вручную)
        sysctl -w net.ipv4.conf.all.log_martians=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.default.log_martians=0 >/dev/null 2>&1 || true
        # Остальные ключи (rp_filter, syncookies, accept_redirects, send_redirects,
        # accept_source_route, icmp_echo_ignore_broadcasts, tcp_rfc1337) обычно
        # дублируются vpn-node-setup.sh с теми же значениями — sysctl --system
        # их применит из 80-vpn-node-tuning.conf. Если setup не установлен —
        # оператор вернёт defaults вручную или ребутом.
        sysctl --system >/dev/null 2>&1 || true
        print_ok "Sysctl hardening удалён (UDP-timeout/synack/martians сброшены на defaults)"
    fi

    # CrowdSec parser
    rm -f /etc/crowdsec/postoverflows/s01-whitelist/ssh-key-whitelist.yaml
    # Старая UFW acquisition (от v1.1-1.3)
    if [ -f /etc/crowdsec/acquis.d/ufw.yaml ] && \
       grep -q "vpn-node-ddos-protect" /etc/crowdsec/acquis.d/ufw.yaml 2>/dev/null; then
        rm -f /etc/crowdsec/acquis.d/ufw.yaml
    fi
    systemctl reload crowdsec 2>/dev/null || true
    print_ok "Postoverflow parser удалён"

    # nft table
    nft delete table inet shield_synproxy 2>/dev/null || true   # v3.23.16 SYNPROXY
    nft delete table inet ddos_protect 2>/dev/null || true
    rm -f /etc/nftables.d/ddos-protect.conf
    # Убираем include из /etc/nftables.conf
    if [ -f /etc/nftables.conf ]; then
        sed -i '/# DDoS protection (vpn-node-ddos-protect)/d' /etc/nftables.conf
        sed -i '\|include "/etc/nftables.d/ddos-protect.conf"|d' /etc/nftables.conf
    fi
    print_ok "nft правила удалены"

    # cscli whitelist decisions (только наши — v3.18.11 SH-NEW-148: фильтр
    # по reason. Раньше удаляли ВСЕ whitelist'ы оператора (от других сервисов).)
    if command -v cscli >/dev/null 2>&1; then
        cscli decisions delete --type whitelist --reason "shieldnode mgmt IP whitelist" >/dev/null 2>&1 || true
        cscli decisions delete --type whitelist --reason "Trusted (TRUSTED_IPS)" >/dev/null 2>&1 || true
        cscli decisions delete --type whitelist --reason "Trusted infrastructure (TRUSTED_IPS)" >/dev/null 2>&1 || true
        print_ok "Whitelist decisions shieldnode'а очищены (чужие whitelist'ы сохранены)"
    fi

    # v3.10.3: убираем cron-job hub upgrade
    rm -f /etc/cron.daily/cscli-hub-upgrade

    # v3.10.4: убираем postoverflow whitelist
    rm -f /etc/crowdsec/postoverflows/s01-whitelist/shieldnode-mgmt.yaml
    # v3.23.1: убираем postoverflow whitelist для TRUSTED_IPS
    rm -f /etc/crowdsec/postoverflows/s01-whitelist/shieldnode-trusted.yaml

    # v3.10.4: убираем journalctl SSH acquisition если он от нас
    if [ -f /etc/crowdsec/acquis.d/sshd.yaml ] && \
       grep -q "v3.10.4" /etc/crowdsec/acquis.d/sshd.yaml 2>/dev/null; then
        rm -f /etc/crowdsec/acquis.d/sshd.yaml
        print_ok "Удалён shieldnode SSH acquisition"
    fi
    systemctl reload crowdsec >/dev/null 2>&1 || true

    # v3.10.3: восстанавливаем оригинальный bouncer config если есть бэкап
    # v3.18.11 SH-NEW-149: ищем последний backup автоматически.
    # Раньше использовался $BACKUP_DIR который undefined в --uninstall блоке
    # (создаётся в начале install run, не uninstall) → restore никогда не работал.
    LAST_BACKUP=$(ls -1dt /root/vpn-ddos-backup-* 2>/dev/null | head -1)
    if [ -n "$LAST_BACKUP" ] && [ -f "$LAST_BACKUP/crowdsec-firewall-bouncer.yaml.before" ]; then
        cp -a "$LAST_BACKUP/crowdsec-firewall-bouncer.yaml.before" \
              /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
        print_ok "Bouncer config восстановлен из бэкапа: $LAST_BACKUP"
    fi

    print_header "UNINSTALL ЗАВЕРШЁН"
    echo "Бэкапы остались в /root/vpn-ddos-backup-*"
    exit 0
fi

# ==============================================================================
# v3.5: install.log — все шаги установки в /var/log/shieldnode/install.log
# ==============================================================================
# Поднимаем тут (до ШАГ 1), чтобы покрыть проверки и весь output установки.
# Используем tee + process substitution: stdout и stderr идут И на терминал,
# И в файл. Если tee недоступен или /var/log не пишется — продолжаем без лога.
INSTALL_LOG_DIR="/var/log/shieldnode"
INSTALL_LOG="$INSTALL_LOG_DIR/install.log"
if mkdir -p "$INSTALL_LOG_DIR" 2>/dev/null && touch "$INSTALL_LOG" 2>/dev/null; then
    chmod 0750 "$INSTALL_LOG_DIR" 2>/dev/null || true
    chmod 0640 "$INSTALL_LOG" 2>/dev/null || true
    {
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "shieldnode install run — $(date '+%Y-%m-%d %H:%M:%S %z')"
        echo "  host: $(hostname)"
        echo "  user: $(id -un) (uid=$EUID)"
        echo "  args: $*"
        echo "═══════════════════════════════════════════════════════════════"
    } >> "$INSTALL_LOG"
    # Перенаправляем stdout И stderr в tee (видим на экране + пишем в лог).
    # Это ставится ДО первого print_* — все шаги установки попадут в файл.
    exec > >(tee -a "$INSTALL_LOG") 2>&1
fi

# ==============================================================================
# v3.7: LEGACY CLEANUP (миграция со старых версий)
# ==============================================================================
# Точечно убираем артефакты старых версий, чтобы не висели orphan-файлы.
# Делаем тихо — если ничего нет, ничего не происходит.
# Полная зачистка остаётся в --uninstall блоке.

# v3.23.13 LEGACY CLEANUP: блок удаления cs-ssh-whitelist (≤v3.4 EOL ~2 года
# назад) убран отсюда. Аналогичный cleanup остаётся в uninstall и в
# explicit legacy-cleanup секции — для оператора который мигрирует с очень
# старой версии.

# ==============================================================================
# v3.18.0: PRE-INSTALL CONFIGURATION
# ==============================================================================
# Спрашиваем у оператора критичные настройки ДО начала установки чтобы избежать
# случайного бана bridge-нод и legacy-партнёров. Ответы сохраняются в conf-файл
# и при reinstall переиспользуются автоматически (без повторного опроса).
#
# Можно пропустить опрос: SHIELDNODE_NONINTERACTIVE=1 sudo bash shieldnode.sh

PREINSTALL_CONF="/etc/shieldnode/shieldnode.conf"
mkdir -p /etc/shieldnode 2>/dev/null

# Загружаем существующие настройки (если есть)
# v3.18.11 SH-NEW-1: используем shield_safe_source (определена выше).
if [ -r "$PREINSTALL_CONF" ]; then
    shield_safe_source "$PREINSTALL_CONF"
fi

# v3.28.3: helper — есть ли управляющий терминал (работает и в curl|bash через /dev/tty).
shield_have_tty(){ { true >/dev/tty; } 2>/dev/null && [ -r /dev/tty ]; }

# v3.20.5: panel auto-detect через docker ps удалён.
# Раньше priorities менялись динамически на основе detected panel:
#   • panel detected → prerouting -150, forward -50
#   • no panel       → prerouting -100, forward filter (=0)
# Это создавало неконсистентное состояние: одна нода с docker панелью
# имела одни priorities, другая (та же конфигурация, но docker остановлен) —
# другие. После update панели (новые контейнеры/имена) детект ломался,
# priorities перестраивались → race condition в netfilter.
# Теперь ВСЕГДА standalone-режим. Если нужен panel-compat (-150 prerouting) —
# выставить вручную в /etc/shieldnode/pre-install.conf:
#   PANEL_TYPE="remnawave"
# либо как env var перед запуском.
if [ -z "${PANEL_TYPE:-}" ]; then
    PANEL_TYPE="none"
fi

# Не интерактивный режим — пропускаем опрос (но auto-detect выше уже отработал)
# v3.28.3: интерактивность определяем по /dev/tty (а не stdin -t 0), чтобы вопрос
# работал и в pipe-режиме (curl|bash), где stdin занят пайпом. Жёстко выключить
# опрос: SHIELDNODE_NONINTERACTIVE=1 или SHIELD_WL_PROMPT=0.
if [ "${SHIELDNODE_NONINTERACTIVE:-0}" = "1" ] || [ "${SHIELD_WL_PROMPT:-1}" = "0" ] || ! shield_have_tty; then
    PREINSTALL_SKIP=1
    print_info "Non-interactive mode — pre-install опрос пропущен (PANEL_TYPE=$PANEL_TYPE)"
fi

# Если whitelist нод уже сконфигурён — пропускаем интерактивный опрос.
# v3.28.3: учитываем не только BRIDGE_IPS, но и Remnawave-токен (env или
# сохранённый remnawave.env) и TRUSTED_IPS → апгрейды настроенных нод не
# переспрашивают.
if [ -n "${BRIDGE_IPS:-}" ] || [ -n "${TRUSTED_IPS:-}" ] || [ -r /etc/shieldnode/remnawave.env ] || \
   { [ -n "${REMNAWAVE_URL:-}" ] && [ -n "${REMNAWAVE_TOKEN:-}" ]; }; then
    PREINSTALL_SKIP=1
    print_status "Используем существующие настройки whitelist'а нод:"
    [ -n "${BRIDGE_IPS:-}" ]   && print_info "  Bridge IPs: $BRIDGE_IPS"
    [ -n "${TRUSTED_IPS:-}" ]  && print_info "  Trusted IPs: $TRUSTED_IPS"
    { [ -r /etc/shieldnode/remnawave.env ] || [ -n "${REMNAWAVE_TOKEN:-}" ]; } && print_info "  Remnawave fleet-sync: настроен (токен сохранён)"
    print_info "  Panel type: ${PANEL_TYPE:-none}"
fi

# v3.18.8: merge-aware write — сохраняем все настройки оператора (BLOCK_TOR,
# ENABLE_GITHUB_SYNC, ENABLE_VERSION_CHECK, ENABLE_RU_MOBILE_WHITELIST и пр.,
# выставленные через `guard settings`), переписываем только BRIDGE_IPS / PANEL_TYPE.
write_preinstall_conf() {
    local tmp
    tmp=$(mktemp "${PREINSTALL_CONF}.XXXXXX") || return 1
    {
        echo "# shieldnode pre-install configuration"
        echo "# Обновлено: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        echo "# При reinstall эти значения переиспользуются автоматически."
        echo "# Настройки оператора (BLOCK_TOR, ENABLE_*) сохраняются."
        echo ""
        echo "BRIDGE_IPS=\"${BRIDGE_IPS:-}\""
        echo "PANEL_TYPE=\"${PANEL_TYPE:-none}\""
        # Переносим все остальные строки из старого conf (кроме перезаписываемых
        # и кроме комментариев/пустых строк с шапки)
        if [ -f "$PREINSTALL_CONF" ]; then
            grep -vE '^[[:space:]]*(#|$|BRIDGE_IPS=|PANEL_TYPE=)' "$PREINSTALL_CONF" 2>/dev/null || true
        fi
    } > "$tmp"
    chmod 0640 "$tmp"
    mv "$tmp" "$PREINSTALL_CONF"   # atomic — same FS
}

# v3.18.3/3.18.7: всегда сохраняем conf после auto-detect (даже в non-interactive),
# чтобы при следующих запусках использовался кэшированный PANEL_TYPE.
if [ ! -e "$PREINSTALL_CONF" ] || ! grep -q "^PANEL_TYPE=" "$PREINSTALL_CONF" 2>/dev/null; then
    write_preinstall_conf
fi

if [ -z "${PREINSTALL_SKIP:-}" ]; then
    print_header "PRE-INSTALL CONFIGURATION"

    echo ""
    echo "  Эти настройки помогут shieldnode'у работать корректно в твоей"
    echo "  конкретной архитектуре. Все настройки сохраняются в:"
    echo "    $PREINSTALL_CONF"
    echo "  и при reinstall переиспользуются автоматически."
    echo ""

    # === Выбор метода whitelist'а нод флота (v3.28.3) ===
    # Единый вопрос вместо старого «только bridge IP»: токен Remnawave
    # (авто-дискавери) ЛИБО ручные IP бриджей. Читаем с /dev/tty (работает и в
    # curl|bash, где stdin = пайп). Вариант 2 кормит существующую логику BRIDGE_IPS,
    # вариант 1 — fleet-sync (ШАГ 5.6 запишет токен в remnawave.env).
    {
        printf '─── Whitelist нод флота (бриджей) ───\n\n'
        printf '  Чтобы ноды/бриджи не резались лимитами, их IP должны быть в whitelist.\n'
        printf '  Как это сделать:\n\n'
        printf '    1) Remnawave токен — авто: тянем IP ВСЕХ нод из панели и держим\n'
        printf '       актуальными. Новую ноду добавил в панель → все ноды подхватят\n'
        printf '       сами, без правки на каждой. (рекомендуется для флота)\n'
        printf '    2) Вручную IP      — перечислить IP нод/бриджей (single-node/простой случай).\n'
        printf '    3) Пропустить      — настрою позже (sudo guard → settings).\n\n'
        printf '  Выбор [1/2/3] (Enter=3): '
    } > /dev/tty
    # v3.28.9 FIX: -t 300 — если /dev/tty есть, но ввода нет (полу-автомат), read
    # не виснет вечно: по таймауту → пусто → дефолт «3 / пропустить».
    read -t 300 -r WL_CHOICE < /dev/tty || WL_CHOICE=""
    case "${WL_CHOICE:-3}" in
        1)
            printf '  URL панели Remnawave (https://panel.example.com): ' > /dev/tty
            read -t 300 -r RW_URL_IN < /dev/tty || RW_URL_IN=""
            printf '  API-токен (Remnawave Settings → API Tokens; ввод скрыт): ' > /dev/tty
            read -t 300 -rs RW_TOK_IN < /dev/tty || RW_TOK_IN=""
            printf '\n' > /dev/tty
            RW_URL_IN="$(printf '%s' "$RW_URL_IN" | tr -d '[:space:]')"
            if printf '%s' "$RW_URL_IN" | grep -qiE '^https?://[^/]' && [ -n "$RW_TOK_IN" ]; then
                REMNAWAVE_URL="$RW_URL_IN"; REMNAWAVE_TOKEN="$RW_TOK_IN"
                export REMNAWAVE_URL REMNAWAVE_TOKEN
                print_ok "Remnawave fleet-sync будет включён — IP нод панели подтянутся в whitelist автоматически"
            else
                print_warn "URL должен быть http(s)://… и токен не пустым — пропускаю токен. Включить позже: env REMNAWAVE_URL/REMNAWAVE_TOKEN при reinstall, либо sudo guard."
            fi
            ;;
        2)
            printf '  IP-адрес(а) нод/бриджей через запятую (1.2.3.4,5.6.7.8), Enter если нет: ' > /dev/tty
            read -t 300 -r BRIDGE_INPUT < /dev/tty || BRIDGE_INPUT=""
            BRIDGE_IPS=$(echo "$BRIDGE_INPUT" | tr -d ' ')
            if [ -n "$BRIDGE_IPS" ]; then
                VALID_IPS=""
                IFS=',' read -ra IP_ARR <<< "$BRIDGE_IPS"
                for ip in "${IP_ARR[@]}"; do
                    # v3.18.11 SH-NEW-10: строгая валидация (отклоняет 0.0.0.0/0 etc)
                    if validate_ipv4_or_cidr "$ip"; then
                        VALID_IPS="${VALID_IPS:+$VALID_IPS,}$ip"
                    else
                        print_warn "Пропускаю невалидный IP: $ip (запрещены 0.0.0.0/x, multicast, prefix<8)"
                    fi
                done
                BRIDGE_IPS="$VALID_IPS"
                [ -n "$BRIDGE_IPS" ] && print_ok "Bridge/node IPs будут добавлены в whitelist: $BRIDGE_IPS"
                print_info "Подсказка: вариант (1) с токеном избавил бы от ручного обновления IP на каждой ноде при расширении флота"
            else
                print_info "IP не введены (стандартная single-node установка)"
            fi
            ;;
        *)
            print_info "Whitelist нод пропущен — настроишь позже (sudo guard → settings, либо env REMNAWAVE_TOKEN при reinstall)"
            ;;
    esac
    echo ""

    # v3.20.5: показываем PANEL_TYPE только если оператор явно установил его
    # в pre-install.conf или env var. Auto-detect через docker удалён.
    if [ "${PANEL_TYPE:-none}" != "none" ]; then
        print_info "Panel mode: $PANEL_TYPE (compat priority -150 для prerouting)"
    else
        print_info "Standalone mode (PANEL_TYPE=none, default)"
    fi
    echo ""

    # Обновляем conf с актуальными BRIDGE_IPS (PANEL_TYPE уже сохранён выше)
    # v3.18.8: используем merge-aware write — сохраняем настройки оператора.
    write_preinstall_conf
    print_ok "Сохранено: $PREINSTALL_CONF"
    echo ""
fi

# Если bridge IPs заданы — добавляем их в whitelist-local.txt + TRUSTED_IPS
# (полный whitelist через все 3 слоя: shieldnode + UFW + CrowdSec)
# v3.18.3: добавлена валидация формата IP/CIDR
# v3.20.7: BRIDGE_IPS теперь также попадают в TRUSTED_IPS → видны в
# 'guard → Trusted IPs', применяются через ШАГ 12.5 (UFW comment + CrowdSec).
# Раньше только в whitelist-local.txt → защищены от rate-limit, но не от
# CrowdSec community CAPI бана (если bridge IP в community blocklist).
if [ -n "${BRIDGE_IPS:-}" ]; then
    WL_LOCAL="/etc/shieldnode/lists/whitelist-local.txt"
    mkdir -p /etc/shieldnode/lists
    if [ ! -e "$WL_LOCAL" ]; then
        echo "# shieldnode whitelist (auto-populated from BRIDGE_IPS)" > "$WL_LOCAL"
    fi
    BRIDGE_TRUSTED_ADDED=""
    IFS=',' read -ra BR_ARR <<< "$BRIDGE_IPS"
    for ip in "${BR_ARR[@]}"; do
        # v3.18.11 SH-NEW-10: строгая валидация (отклоняет 0.0.0.0/0 etc)
        ip=$(echo "$ip" | tr -d ' ')
        if ! validate_ipv4_or_cidr "$ip"; then
            print_warn "Пропускаю невалидный bridge IP: '$ip' (запрещены 0.0.0.0/x, multicast, prefix<8)"
            continue
        fi
        if ! grep -qxF "$ip" "$WL_LOCAL" 2>/dev/null; then
            echo "$ip" >> "$WL_LOCAL"
            print_ok "Добавлен в whitelist: $ip"
        fi
        # v3.23.1: и single IPs, и CIDR идут в TRUSTED_IPS чтобы guard UI их показывал
        # и ШАГ 12.5 применил UFW + CrowdSec whitelist (для CIDR — через --range).
        if [ -z "$BRIDGE_TRUSTED_ADDED" ]; then
            BRIDGE_TRUSTED_ADDED="$ip"
        else
            BRIDGE_TRUSTED_ADDED="${BRIDGE_TRUSTED_ADDED},${ip}"
        fi
    done

    # v3.20.7: мержим BRIDGE_IPS (single IPs) в TRUSTED_IPS conf и переменную
    if [ -n "$BRIDGE_TRUSTED_ADDED" ]; then
        SHIELD_CONF="/etc/shieldnode/shieldnode.conf"
        mkdir -p /etc/shieldnode
        if [ ! -e "$SHIELD_CONF" ]; then
            touch "$SHIELD_CONF"
            chmod 0640 "$SHIELD_CONF"
        fi
        EXISTING_TRUSTED=$(grep -E '^TRUSTED_IPS=' "$SHIELD_CONF" 2>/dev/null | head -1 | \
            sed -E 's/^TRUSTED_IPS="?([^"]*)"?.*/\1/')
        # Merge BRIDGE_IPS в EXISTING_TRUSTED
        ALL_TRUSTED="$EXISTING_TRUSTED"
        IFS=',' read -ra NEW_ARR <<< "$BRIDGE_TRUSTED_ADDED"
        for new_ip in "${NEW_ARR[@]}"; do
            if ! echo "$ALL_TRUSTED" | tr ',' '\n' | grep -qxF "$new_ip"; then
                if [ -z "$ALL_TRUSTED" ]; then
                    ALL_TRUSTED="$new_ip"
                else
                    ALL_TRUSTED="${ALL_TRUSTED},${new_ip}"
                fi
            fi
        done
        if [ -n "$ALL_TRUSTED" ] && [ "$ALL_TRUSTED" != "$EXISTING_TRUSTED" ]; then
            if grep -qE '^TRUSTED_IPS=' "$SHIELD_CONF" 2>/dev/null; then
                sed -i "s|^TRUSTED_IPS=.*|TRUSTED_IPS=\"${ALL_TRUSTED}\"|" "$SHIELD_CONF"
            else
                echo "TRUSTED_IPS=\"${ALL_TRUSTED}\"" >> "$SHIELD_CONF"
            fi
            export TRUSTED_IPS="$ALL_TRUSTED"
            print_ok "BRIDGE_IPS добавлены в TRUSTED_IPS (видимо в guard → Trusted IPs)"
        fi
    fi
fi

# v3.20.7: импорт существующих UFW "ALLOW from <IP>" правил в whitelist-local.txt
# на первой установке.
#
# КОНТЕКСТ: shieldnode-nftables.service запускает port-syncer, который читает
# UFW status и заполняет nft set manual_whitelist_v4 IP'шниками из правил
# "ALLOW from <IP>" (это admin IPs, mgmt IPs, инфраструктура).
#
# ПРОБЛЕМА (до v3.20.7): IP попадают в nft set, но не в whitelist-local.txt.
# UI "guard → Trusted IPs" читает только файл → показывает «пусто» хотя
# IP whitelisted. Юзер не понимает где IP, как ими управлять.
#
# РЕШЕНИЕ: на первой установке импортируем UFW "ALLOW from X" → файл.
# Дальше управление унифицировано через файл + UI.
# Re-install НЕ перетирает существующий файл (только дополняет).
WL_LOCAL="/etc/shieldnode/lists/whitelist-local.txt"
if command -v ufw >/dev/null 2>&1 && \
   LANG=C ufw status 2>/dev/null | grep -q "Status: active"; then
    mkdir -p /etc/shieldnode/lists

    # Создаём файл если нет
    if [ ! -e "$WL_LOCAL" ]; then
        echo "# shieldnode whitelist (auto-populated from UFW ALLOW rules)" > "$WL_LOCAL"
        echo "# Управление через: sudo guard → Trusted IPs" >> "$WL_LOCAL"
        echo "" >> "$WL_LOCAL"
    fi

    # Извлекаем IP из правил вида "PORT/proto  ALLOW  IP" (только IPv4, не Anywhere)
    UFW_MGMT_IPS=$(LANG=C ufw status 2>/dev/null | awk '
        $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 != "Anywhere" {
            if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $3
        }
    ' | sort -u)

    IMPORTED=0
    if [ -n "$UFW_MGMT_IPS" ]; then
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            # Валидация (защита от 0.0.0.0/x, multicast, broken)
            if ! validate_ipv4_or_cidr "$ip" 2>/dev/null; then
                continue
            fi
            # Добавляем только если ещё нет (idempotent)
            if ! grep -qxF "$ip" "$WL_LOCAL" 2>/dev/null; then
                echo "$ip" >> "$WL_LOCAL"
                IMPORTED=$((IMPORTED + 1))
            fi
        done <<< "$UFW_MGMT_IPS"
    fi

    if [ "$IMPORTED" -gt 0 ]; then
        print_ok "Импортировано $IMPORTED IP из UFW ALLOW rules в $WL_LOCAL"

        # Также записать в TRUSTED_IPS в shieldnode.conf — чтобы guard → Trusted IPs
        # UI их показывал. Иначе IP лежат в файле + nft set, но menu пустое.
        SHIELD_CONF="/etc/shieldnode/shieldnode.conf"
        mkdir -p /etc/shieldnode
        if [ ! -e "$SHIELD_CONF" ]; then
            touch "$SHIELD_CONF"
            chmod 0640 "$SHIELD_CONF"
        fi

        # Текущий TRUSTED_IPS (может быть пустой)
        EXISTING_TRUSTED=$(grep -E '^TRUSTED_IPS=' "$SHIELD_CONF" 2>/dev/null | head -1 | \
            sed -E 's/^TRUSTED_IPS="?([^"]*)"?.*/\1/')

        # Merge: existing + новые из UFW (только single IPs, без CIDR — TRUSTED_IPS
        # формат это single IPs для UFW/CrowdSec consistency)
        ALL_TRUSTED=""
        if [ -n "$EXISTING_TRUSTED" ]; then
            ALL_TRUSTED="$EXISTING_TRUSTED"
        fi
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            # Только single IPs для TRUSTED_IPS (CIDR'ы остаются только в whitelist-local.txt)
            if [[ "$ip" == */* ]]; then
                continue
            fi
            if ! echo "$ALL_TRUSTED" | tr ',' '\n' | grep -qxF "$ip"; then
                if [ -z "$ALL_TRUSTED" ]; then
                    ALL_TRUSTED="$ip"
                else
                    ALL_TRUSTED="${ALL_TRUSTED},${ip}"
                fi
            fi
        done <<< "$UFW_MGMT_IPS"

        # Записать обновлённый TRUSTED_IPS в conf (idempotent — добавляет или обновляет)
        if [ -n "$ALL_TRUSTED" ]; then
            if grep -qE '^TRUSTED_IPS=' "$SHIELD_CONF" 2>/dev/null; then
                # Обновить существующую строку
                sed -i "s|^TRUSTED_IPS=.*|TRUSTED_IPS=\"${ALL_TRUSTED}\"|" "$SHIELD_CONF"
            else
                # Добавить новую строку
                echo "TRUSTED_IPS=\"${ALL_TRUSTED}\"" >> "$SHIELD_CONF"
            fi
            print_ok "TRUSTED_IPS в $SHIELD_CONF обновлён (видимо в guard → Trusted IPs)"
            # Экспортируем в текущую среду — чтобы apply_trusted_ip в ШАГ 12.5
            # подхватил эти IP и применил CrowdSec whitelist + UFW comment
            export TRUSTED_IPS="$ALL_TRUSTED"
        fi
        print_info "  Управление: sudo guard → Trusted IPs"
    fi
fi

# ==============================================================================
# ШАГ 1: ПРОВЕРКИ
# ==============================================================================

print_header "ШАГ 1: ПРОВЕРКИ"

if [[ $EUID -ne 0 ]]; then
    print_error "FATAL: Запустите через sudo"
    exit 1
fi
print_ok "Запущен от root"

# v3.18.8: проверка свободного места ДО любых установок и записей.
# Без этого на full disk: apt падает посреди dpkg, sqlite events.db не создаётся
# (но 2>/dev/null глушит ошибку), aggregator уходит в restart-loop, защита
# выглядит "успешно установленной" но events не пишутся.
check_disk_space() {
    local mp need_mb avail
    # Минимумы подобраны под: crowdsec ~120MB + bouncer ~30MB + lists/db ~50MB + запас.
    for mp_need in "/var:500" "/etc:50" "/tmp:50"; do
        mp="${mp_need%%:*}"
        need_mb="${mp_need##*:}"
        # df -BM выдаёт колонку Available с суффиксом 'M'
        avail=$(df -BM "$mp" 2>/dev/null | awk 'NR==2 {gsub("M","",$4); print $4+0}')
        if [ -z "$avail" ] || [ "$avail" -lt "$need_mb" ]; then
            # v3.23.17: частая причина переполнения /var — старый pcap-ring в /var/log/pcap
            # (strftime-имена + -W не удалял файлы). Чистим legacy и пере-меряем.
            if [ "$mp" = "/var" ]; then
                find /var/log/pcap -maxdepth 1 -type f -name 'syn-*.pcap' -delete 2>/dev/null || true
                avail=$(df -BM "$mp" 2>/dev/null | awk 'NR==2 {gsub("M","",$4); print $4+0}')
            fi
        fi
        if [ -z "$avail" ] || [ "$avail" -lt "$need_mb" ]; then
            print_error "FATAL: $mp имеет ${avail:-0} MB свободно, нужно >= ${need_mb} MB"
            print_info "Очисти: sudo find /var/log/pcap -name 'syn-*.pcap' -delete   # частая причина (старый pcap-ring)"
            print_info "       sudo du -sh /var/log/pcap /var/lib/shieldnode/* 2>/dev/null | sort -h"
            print_info "       sudo journalctl --vacuum-size=100M"
            print_info "       sudo apt-get clean && sudo apt-get autoremove -y"
            return 1
        fi
    done
    print_ok "Disk space: /var=$(df -BM /var 2>/dev/null | awk 'NR==2{print $4}'), /etc=$(df -BM /etc 2>/dev/null | awk 'NR==2{print $4}'), /tmp=$(df -BM /tmp 2>/dev/null | awk 'NR==2{print $4}')"
    return 0
}
check_disk_space || exit 1

# v2.8: ждём пока apt освободится (unattended-upgrades на свежих VPS)
wait_for_apt_lock() {
    local max_wait="${SHIELDNODE_APT_WAIT:-300}"
    local elapsed=0
    local first_msg=1

    # v3.23.14 APT-LOCK FIX: авторитетный сигнал — fuser по реальным lock-файлам.
    # Старый `pgrep -f "apt-get|apt |dpkg|unattended-upgr"` ловил ФАНТОМЫ:
    # apt-daily.service / apt.systemd.daily / dpkg-query от других процессов —
    # которые НЕ держат lock. Отсюда "300s ожидания" при свободном apt.
    apt_lock_held() {
        if command -v fuser >/dev/null 2>&1; then
            fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
            fuser /var/lib/dpkg/lock         >/dev/null 2>&1 || \
            fuser /var/lib/apt/lists/lock    >/dev/null 2>&1
        else
            # Fallback без psmisc: точное совпадение ИМЕНИ процесса (-x), не cmdline.
            pgrep -x dpkg >/dev/null 2>&1 || \
            pgrep -x apt-get >/dev/null 2>&1 || \
            pgrep -x unattended-upgr >/dev/null 2>&1
        fi
    }

    while apt_lock_held; do
        if [ $first_msg -eq 1 ]; then
            print_status "Ждём пока освободится apt (unattended-upgrades в процессе)..."
            print_info "Это может занять 2-5 минут на свежем VPS"
            if command -v fuser >/dev/null 2>&1; then
                HOLDER=$(fuser -v /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock 2>&1 | tail -n +2)
                [ -n "$HOLDER" ] && print_info "Lock держит: $HOLDER"
            fi
            first_msg=0
        fi

        if [ $elapsed -ge $max_wait ]; then
            print_warn "apt всё ещё занят после $((max_wait))s"
            if [ "${SHIELDNODE_FORCE_APT:-0}" = "1" ]; then
                print_status "SHIELDNODE_FORCE_APT=1 — останавливаю apt-таймеры и снимаю lock..."
                # Глушим то, что перезапускает apt-get/unattended (источник "не остановить процесс")
                systemctl stop unattended-upgrades.service apt-daily.service \
                              apt-daily-upgrade.service apt-daily.timer \
                              apt-daily-upgrade.timer >/dev/null 2>&1 || true
                if command -v fuser >/dev/null 2>&1; then
                    fuser -k /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1 || true
                else
                    pkill -x unattended-upgr 2>/dev/null || true
                    pkill -x apt-get 2>/dev/null || true
                fi
                sleep 3
                # Снимаем stale lock-файлы ТОЛЬКО если их уже никто не держит
                if ! apt_lock_held; then
                    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock 2>/dev/null
                    dpkg --configure -a >/dev/null 2>&1 || true
                    print_ok "apt lock снят принудительно"
                    return 0
                fi
                print_error "Lock всё ещё держится после force — апни вручную и перезапусти"
                return 1
            fi
            print_info "Останови источник и повтори:"
            print_info "  sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer unattended-upgrades"
            print_info "Или запусти со снятием lock автоматически:"
            print_info "  SHIELDNODE_FORCE_APT=1 sudo bash shieldnode.sh"
            return 1
        fi

        sleep 5
        elapsed=$((elapsed + 5))
        printf "\r  ${YELLOW}⏳${NC} Ждём apt lock... ${BOLD}${elapsed}s${NC}    "
    done

    if [ $first_msg -eq 0 ]; then
        printf "\r"
        print_ok "apt освободился (ждали ${elapsed}s)"
    fi
    return 0
}

# v3.26.5: держим УЖЕ УСТАНОВЛЕННЫЕ управляемые apt-зависимости на последней версии репо.
# Не доустанавливает лишнее, апгрейдит только если candidate строго новее (--only-upgrade
# никогда не делает downgrade). Заморозить версии: SHIELD_UPGRADE_DEPS=0.
SHIELD_UPGRADE_DEPS="${SHIELD_UPGRADE_DEPS:-1}"
_SHIELD_APT_REFRESHED=0
shield_apt_refresh_once(){ [ "$_SHIELD_APT_REFRESHED" = "1" ] && return 0; wait_for_apt_lock; apt-get update -qq >/dev/null 2>&1 || true; _SHIELD_APT_REFRESHED=1; }
ensure_latest_apt(){   # $1=пакет, $2=опц. сервис для рестарта после апгрейда
    [ "$SHIELD_UPGRADE_DEPS" = "1" ] || return 0
    local pkg="$1" svc="${2:-}" inst cand
    dpkg -l "$pkg" 2>/dev/null | grep -qE '^ii' || return 0          # не установлен → не трогаем
    shield_apt_refresh_once
    inst=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
    cand=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/{print $2}')
    [ -n "$cand" ] && [ "$cand" != "(none)" ] || return 0
    dpkg --compare-versions "$cand" gt "$inst" 2>/dev/null || return 0   # candidate новее?
    wait_for_apt_lock
    print_status "Обновляю $pkg: $inst → $cand..."
    if timeout --kill-after=30s 300s env DEBIAN_FRONTEND=noninteractive \
         CSCLI_UNATTENDED_SKIP=1 CROWDSEC_SKIP_HUB_UPDATE=1 \
         apt-get install --only-upgrade -y "$pkg" </dev/null >/dev/null 2>&1; then
        print_ok "$pkg → $(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
        [ -n "$svc" ] && systemctl restart "$svc" >/dev/null 2>&1 || true
    else
        DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
        print_warn "$pkg: апгрейд не завершился — остаётся $inst (вручную: sudo apt install --only-upgrade $pkg)"
    fi
}

# Проверяем apt lock перед любыми установками
wait_for_apt_lock || exit 1

if ! command -v nft >/dev/null 2>&1; then
    print_status "Устанавливаю nftables..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y nftables; then
        print_error "Не удалось установить nftables"
        exit 1
    fi
    # v3.18.8 UFW-FIX: пакет nftables кладёт /etc/nftables.conf с `flush ruleset`.
    # Если nftables.service запустится (ребут / unattended-upgrades / другой пакет
    # с try-restart) — он выполнит flush ruleset и снесёт UFW цепочки в kernel
    # (на Ubuntu 24 UFW работает через iptables-nft → таблицы видны в nftables).
    # Симптом: после ребута `ufw status` → inactive, хотя ENABLED=yes в ufw.conf.
    # FIX: stop/disable/mask. У нас свой shieldnode-nftables.service который
    # загружает только наши таблицы БЕЗ flush.
    systemctl stop nftables.service >/dev/null 2>&1 || true
    systemctl disable nftables.service >/dev/null 2>&1 || true
    systemctl mask nftables.service >/dev/null 2>&1 || true
    print_ok "nftables.service masked (защита UFW от flush ruleset при ребуте)"
fi
print_ok "nftables: $(nft --version 2>&1 | head -1)"

# v1.9: sqlite3 для быстрого чтения crowdsec БД в guard'е
# (опционально — fallback на cscli если не установится)
if ! command -v sqlite3 >/dev/null 2>&1; then
    wait_for_apt_lock
    print_status "Устанавливаю sqlite3 (для оптимизации guard)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3 >/dev/null 2>&1 || \
        print_warn "sqlite3 не установлен — guard будет использовать cscli (медленнее)"
fi

# v2.4: jq для парсинга nft -j вывода в guard
if ! command -v jq >/dev/null 2>&1; then
    wait_for_apt_lock
    print_status "Устанавливаю jq (для парсинга nft JSON в guard)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y jq >/dev/null 2>&1 || \
        print_warn "jq не установлен — guard будет использовать text-парсинг (хрупко)"
fi

# v3.27.2 FIX(#3): whois для ASN/owner top-attackers через Team Cymru (заменил ipinfo).
# Опционально — нет → дашборд покажет IP без владельца ("?"), без лагов.
if ! command -v whois >/dev/null 2>&1; then
    wait_for_apt_lock
    print_status "Устанавливаю whois (ASN/owner в guard через Team Cymru)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y whois >/dev/null 2>&1 || \
        print_warn "whois не установлен — в guard top-attackers без ASN-владельца (не критично)"
fi

# v3.22.0: conntrack — для unban_all с очисткой conntrack entries разбаненного IP.
# Без этого пакета unban_all удаляет IP из nft sets, но conntrack table сохраняет
# до 5 дней старые ESTABLISHED записи. При extreme-CGNAT (5000+ conn) юзер
# остаётся фактически забаненным через ct count check.
if ! command -v conntrack >/dev/null 2>&1; then
    wait_for_apt_lock
    print_status "Устанавливаю conntrack (для unban_all очистки conntrack entries)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y conntrack >/dev/null 2>&1 || \
        print_warn "conntrack не установлен — unban_all не сможет полностью разбанить IP с активными соединениями"
fi

# v3.26.5: подтягиваем уже установленные управляемые зависимости до последней версии репо
# (security-патчи дистрибутива). Только установленные пакеты; gated SHIELD_UPGRADE_DEPS.
for _dep in nftables conntrack iproute2 tcpdump sqlite3 jq curl zstd xz-utils psmisc; do
    ensure_latest_apt "$_dep"
done

if ! nft list ruleset >/dev/null 2>&1; then
    print_error "nft list ruleset не работает — нет ядерных модулей nftables"
    print_error "Это бывает на OpenVZ/LXC. На KVM не должно встречаться."
    exit 1
fi
print_ok "nftables ядерные модули работают"

# v3.3: SECURITY HARDENING
# Закрытие свежих CVE 2025-2026 + sysctl kernel hardening.

# 1) Апгрейд OpenSSH (закрывает CVE-2025-26465/26466, CVE-2026-35414)
SSH_VERSION=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?' | head -1)
if [ -n "$SSH_VERSION" ]; then
    print_info "OpenSSH: $SSH_VERSION"

    # v3.11.1: Ubuntu/Debian backport-aware check.
    # Проблема: upstream OpenSSH 9.6p1 уязвим к CVE-2025-26466, но Ubuntu 24.04
    # имеет backport (1:9.6p1-3ubuntu13.8+) который УЖЕ ИСПРАВЛЕН. Старая
    # проверка `[ ssh_version < 9.9p2 ]` ругалась на patched 9.6p1 ложно.
    #
    # FIX: смотрим dpkg-version openssh-server и сверяем с известными
    # patched-версиями для конкретного дистрибутива.
    SSH_VULNERABLE=0
    OS_ID=$(. /etc/os-release 2>/dev/null && echo "$ID")
    OS_VER=$(. /etc/os-release 2>/dev/null && echo "$VERSION_ID")
    DPKG_SSH_VER=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null)

    if [ -n "$DPKG_SSH_VER" ]; then
        # Известные patched-версии (USN-7270-1, Feb 2025):
        case "$OS_ID:$OS_VER" in
            ubuntu:24.04|ubuntu:24.10)
                # Ubuntu 24.04: patched в 1:9.6p1-3ubuntu13.8 и выше
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:9.6p1-3ubuntu13.8" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            ubuntu:22.04)
                # Ubuntu 22.04: 8.9p1, не affected by CVE-2025-26466 (introduced in 9.5p1)
                # Но проверим CVE-2025-26465 — patched в 1:8.9p1-3ubuntu0.11
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:8.9p1-3ubuntu0.11" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            ubuntu:20.04)
                # 8.2p1 — не affected by CVE-2025-26466
                # CVE-2025-26465 patched в 1:8.2p1-4ubuntu0.12
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:8.2p1-4ubuntu0.12" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            debian:12)
                # Bookworm: 9.2p1 — не affected by CVE-2025-26466 (introduced 9.5p1)
                # CVE-2025-26465 patched в 1:9.2p1-2+deb12u4
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:9.2p1-2+deb12u4" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            debian:11)
                # Bullseye: 8.4p1 — не affected by CVE-2025-26466
                if dpkg --compare-versions "$DPKG_SSH_VER" "lt" "1:8.4p1-5+deb11u4" 2>/dev/null; then
                    SSH_VULNERABLE=1
                fi
                ;;
            *)
                # Неизвестный дистрибутив — fallback на upstream-версию
                SSH_MAJOR=$(echo "$SSH_VERSION" | grep -oE '[0-9]+\.[0-9]+' | head -1)
                if dpkg --compare-versions "$SSH_MAJOR" "lt" "9.9" 2>/dev/null; then
                    SSH_VULNERABLE=1
                    print_info "Неизвестный дистрибутив ($OS_ID:$OS_VER) — fallback на upstream-проверку"
                fi
                ;;
        esac
    fi

    if [ "$SSH_VULNERABLE" = "1" ]; then
        print_warn "Версия OpenSSH потенциально уязвима ($DPKG_SSH_VER)"
        print_status "Обновляю openssh-server (apt upgrade)..."
        wait_for_apt_lock
        if DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y openssh-server openssh-client >/dev/null 2>&1; then
            NEW_DPKG_VER=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null)
            if [ "$NEW_DPKG_VER" != "$DPKG_SSH_VER" ]; then
                print_ok "OpenSSH обновлён: $DPKG_SSH_VER → $NEW_DPKG_VER"
                print_info "Перезагрузи ssh: systemctl restart ssh (или ребут)"
            else
                print_info "OpenSSH уже последней версии в репо ($DPKG_SSH_VER)"
                print_info "Если репо старый — обнови дистрибутив или через backports"
            fi
        else
            print_warn "Не удалось обновить openssh — продолжаю установку"
        fi
    else
        # Известная patched-версия для этого дистрибутива
        if [ -n "$DPKG_SSH_VER" ]; then
            print_ok "OpenSSH защищён (patched в $OS_ID:$OS_VER backport: $DPKG_SSH_VER)"
        else
            print_ok "OpenSSH версия не уязвима к известным CVE"
        fi
    fi
fi

# 2) Sysctl kernel hardening
print_status "Применяю sysctl kernel hardening..."

# v3.7: миграция со старого имени 99-shieldnode.conf → 90-shieldnode.conf.
# v5.1.0/v3.23.0 порядок: 80-vpn-node-tuning.conf (база) → 90-shieldnode.conf
# (security overrides) → 99-z-* (ad-hoc operator fixes).
# Лексикографически 80 < 90 < 99 → каждый следующий перетирает предыдущий.
if [ -f /etc/sysctl.d/99-shieldnode.conf ]; then
    rm -f /etc/sysctl.d/99-shieldnode.conf
    print_info "Удалён старый /etc/sysctl.d/99-shieldnode.conf (миграция v3.7)"
fi

SYSCTL_FILE="/etc/sysctl.d/90-shieldnode.conf"
cat > "$SYSCTL_FILE" <<'SYSCTL_EOF'
# Shieldnode kernel hardening v3.23.0
# Префикс 90 — security-полка поверх базы (80-vpn-node-tuning.conf).
# vpn-node-setup v5.1.0+ пишет базу в 80-, мы перетираем нужные ключи
# поверх. Любые ad-hoc operator fixes (99-z-*) перетирают и нас.
#
# v3.7: shieldnode стал standalone. Раньше критичные security-ключи
# (rp_filter, syncookies, redirects, ...) ставил только vpn-node-setup.sh,
# из-за чего без него shieldnode работал на дефолтах ядра (rp_filter=1
# strict — ломал VPN-форвардинг). Теперь shieldnode сам пишет минимум,
# нужный для своей работы. Значения скопированы из vpn-node-setup.sh
# один-в-один — конфликта не будет.
#
# Зону ответственности setup'а (BBRv3, qdisc=fq, conntrack tuning, buffer
# sizes, file-max, swappiness, ip_forward, ephemeral ports, keepalives,
# tcp_max_syn_backlog, tcp_tw_reuse) shieldnode НЕ трогает.

# === SYN-flood mitigation ===
# SYN cookies (kernel сам активирует когда backlog переполнен)
net.ipv4.tcp_syncookies = 1
# Сколько раз отправлять SYN+ACK перед сдачей.
# v3.23.0: 2 → 3. Default kernel = 5. 2 было слишком агрессивно для
# intercontinental клиентов (RU/Asia → DE/SE) с RTT 200-400ms и пакетлоссом:
# 2 retry = ~3 сек до отказа handshake → user видит timeout вместо connect.
# SYN cookies продолжают защищать от SYN-flood независимо от этого retry.
net.ipv4.tcp_synack_retries = 3
# Сколько раз ретраить SYN при исходящих (по умолчанию 6)
net.ipv4.tcp_syn_retries = 3

# === IP-spoofing mitigation ===
# Reverse path filter (RFC 3704), режим 2 = loose.
# КРИТИЧНО для VPN: режим 1 (strict) дропает asymmetric routing
# (пакет приходит на eth0, ответ через tun0 — нормально для VPN).
# Режим 2 защищает от spoofing и при этом не ломает форвардинг.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# Source routing — древняя угроза, отключаем
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# ICMP redirects — могут использоваться для атак (man-in-the-middle)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
# VPN-нода — forwarding-роутер, ICMP redirects слать не должна
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# === ICMP hardening ===
# Игнорировать broadcast ping (smurf-атаки)
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Игнорировать bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# === TCP hardening ===
# Защита от TIME_WAIT assassination (RFC 1337)
net.ipv4.tcp_rfc1337 = 1

# === Logging ===
# v3.23.0: log_martians = 0 (was 1).
# На VPN forwarder с rp_filter=2 (loose) martians — нормальный шум
# маршрутизации (asymmetric paths, Docker host-mode, multiple ifaces),
# не сигнал атаки. Логирование martian каждого пакета:
#   - грузит kernel printk() → rsyslog → /var/log disk writes
#   - дублируется в systemd-journald (третья копия)
#   - на 1000+ юзеров может дать сотни/час log lines
# Если нужен martian-логирование для debug — выставить вручную:
#   sysctl -w net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0

# === v3.16.4: UDP conntrack timeout для VPN keepalive ===
# Default UDP timeout 30 сек слишком короткий для VPN-протоколов с
# keepalive каждые 60-120 сек (WireGuard, мост-связки, Hysteria/Tuic).
# Без этого — UFW дропает каждый второй keepalive ответ как "новый пакет
# на закрытый порт", т.к. conntrack теряет state между keepalive'ами.
#
# 180 сек охватывает все VPN-сценарии для unidirectional UDP. По алфавиту
# 80-vpn-node-tuning.conf применяется ПЕРВЫМ (база), затем
# 90-shieldnode.conf (security overrides) перетирает нужные ключи.
# Раньше у setup'а было 99-vpn-node-tuning → setup побеждал shieldnode,
# что было багом. С v5.1.0 / v3.23.0 порядок правильный.
#
# v3.23.0: stream 300 → 600. Bidirectional UDP "stream" state (Hysteria2
# established session) теперь живёт 10 минут. Mobile клиенты в background
# (Android Doze, iOS suspended) могут не слать пакеты дольше 5 минут.
# 5 мин timeout = принудительный reconnect → user видит "freeze on resume".
# 10 мин — sweet spot между state bloat и UX.
#
# TCP timeout'ы НАМЕРЕННО не трогаем — это зона ответственности
# vpn-node-setup.sh.
net.netfilter.nf_conntrack_udp_timeout = 180
net.netfilter.nf_conntrack_udp_timeout_stream = 600

# === v3.25.0: anti-connection-exhaustion (conntrack table) ===
# Распределённый connect-and-hold флуд оставляет "фантомные" ESTABLISHED-
# записи (handshake прошёл → клиент бросил → запись висит по дефолту 5 суток,
# nf_conntrack_tcp_timeout_established=432000). На атаке копятся десятки тысяч
# мёртвых записей (наблюдалось 72000 при 2270 живых сокетах) → давление на
# conntrack и память. Срезаем idle-таймауты: брошенные дохнут за ~30 мин,
# живые сессии с трафиком/keepalive сбрасывают таймер и переживают. acct=1
# оставлен для диагностики (per-flow байты в conntrack); ctguard v3.26 отделяет
# фантом-холдеров по ЖИВЫМ сокетам (ss vs conntrack), не по байтам. Это
# nf_conntrack-зона, НЕ tcp_*-сокеты (их по-прежнему ведёт setup).
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_tcp_loose = 0
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 30
SYSCTL_EOF

# Применяем
if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
    print_ok "Sysctl hardening применён ($SYSCTL_FILE)"
else
    print_warn "Не все sysctl применились (некоторые модули могут отсутствовать)"
    print_info "Проверь: sysctl -p $SYSCTL_FILE"
fi

# v1.5: проверим какой метод auth — но НЕ блокируем установку.
# Скрипт работает с любым типом, просто на разных уровнях защиты.
# Используется глобальная переменная USES_KEY_AUTH в шагах 3 и 7.
USES_KEY_AUTH=0
CURRENT_AUTH_METHOD=""
if [ -n "${SSH_CONNECTION:-}" ] && [ -n "${PPID:-}" ]; then
    SSH_PID=$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -d ' ')
    if [ -n "$SSH_PID" ]; then
        CURRENT_AUTH_METHOD=$(journalctl _PID="$SSH_PID" --no-pager 2>/dev/null | \
            grep -oE "Accepted (publickey|password|keyboard-interactive)" | \
            head -1 | awk '{print $2}')
    fi
fi

if [ "$CURRENT_AUTH_METHOD" = "publickey" ]; then
    print_ok "Текущая SSH-сессия по ключу — максимальная защита будет включена"
    USES_KEY_AUTH=1
elif [ "$CURRENT_AUTH_METHOD" = "password" ] || [ "$CURRENT_AUTH_METHOD" = "keyboard-interactive" ]; then
    print_warn "Текущая SSH-сессия по ПАРОЛЮ"
    print_info "Скрипт продолжит установку. Защита будет работать, но НЕ на максимуме."
    print_info "После установки рекомендую перейти на SSH-ключи (см. итоги в конце)."
elif [ -n "${SSH_CONNECTION:-}" ]; then
    print_info "Метод аутентификации не определён, продолжаю"
else
    print_info "Запуск с локальной консоли — продолжаю"
fi

# v1.7: ПРОВЕРКА ФАЕРВОЛА — обязательное требование
# Логика: скрипт работает поверх существующего фаервола, защищая порты
# которые юзер УЖЕ открыл. Без активного фаервола сервер открыт всему миру,
# и наш скрипт это не исправит — нужен базовый layer.
#
# Поддерживаются: UFW (приоритет), firewalld, iptables/nftables-rules.
# Тип фаервола сохраняется в FIREWALL_TYPE для шага 2.

FIREWALL_TYPE=""

# Проверка UFW
if command -v ufw >/dev/null 2>&1; then
    # v3.10.2 BUG-8 FIX: LANG=C — иначе локализованный "Состояние: активен"
    # на ru_RU/uk_UA/etc сломает grep "Status: active".
    if LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_TYPE="ufw"
        UFW_RULES_COUNT=$(LANG=C LC_ALL=C ufw status numbered 2>/dev/null | grep -cE "^\[ ?[0-9]+\]")
        print_ok "Фаервол: ${BOLD}UFW активен${NC} (${UFW_RULES_COUNT} правил)"

        # v3.16.0 (Variant C): включаем UFW logging если выключен.
        # UFW дропы (на закрытые порты) тогда станут видимы в kernel.log,
        # aggregator парсит их в events.db с type='ufw_block' → видно в
        # guard CLI top-attackers все атаки, а не только наши shieldnode.
        UFW_LOG_LEVEL=$(LANG=C LC_ALL=C ufw status verbose 2>/dev/null | grep -oE "^Logging: (on|off)( \([a-z]+\))?" | head -1)
        if echo "$UFW_LOG_LEVEL" | grep -q "off"; then
            print_info "UFW logging выключен — включаю 'low' для observability"
            ufw logging low >/dev/null 2>&1 && print_ok "UFW logging: low (atypical packets)"
        elif [ -z "$UFW_LOG_LEVEL" ]; then
            # На некоторых дистрах ufw верх. case или новый формат — не парсим, оставляем
            true
        else
            print_info "UFW logging уже включён ($UFW_LOG_LEVEL) — оставляю как есть"
        fi
    fi
fi

# Проверка firewalld
if [ -z "$FIREWALL_TYPE" ] && command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        FIREWALL_TYPE="firewalld"
        FW_PORTS_COUNT=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
        print_ok "Фаервол: ${BOLD}firewalld активен${NC} (${FW_PORTS_COUNT} портов)"
    fi
fi

# Проверка iptables (если правила есть и они не дефолтные ACCEPT)
if [ -z "$FIREWALL_TYPE" ] && command -v iptables >/dev/null 2>&1; then
    # Считаем правила в INPUT chain. Если только дефолт — это не защита.
    IPT_RULES=$(iptables -L INPUT --line-numbers 2>/dev/null | grep -cE "^[0-9]+")
    IPT_POLICY=$(iptables -L INPUT 2>/dev/null | head -1 | grep -oE "policy [A-Z]+" | awk '{print $2}')
    if [ "$IPT_RULES" -gt 0 ] || [ "$IPT_POLICY" = "DROP" ] || [ "$IPT_POLICY" = "REJECT" ]; then
        FIREWALL_TYPE="iptables"
        print_ok "Фаервол: ${BOLD}iptables активен${NC} ($IPT_RULES правил, policy=$IPT_POLICY)"
    fi
fi

# Проверка nftables (кастомные filter chains, не наш ddos_protect)
if [ -z "$FIREWALL_TYPE" ]; then
    NFT_FILTER=$(nft list ruleset 2>/dev/null | \
        awk '/^table inet filter|^table ip filter|^table ip6 filter/{found=1} END{print found}')
    if [ "$NFT_FILTER" = "1" ]; then
        FIREWALL_TYPE="nftables"
        print_ok "Фаервол: ${BOLD}nftables filter table активен${NC}"
    fi
fi

# Если ни одного фаервола не найдено — отказываемся ставиться
if [ -z "$FIREWALL_TYPE" ]; then
    print_error ""
    print_error "ФАЕРВОЛ НЕ НАСТРОЕН — установка невозможна"
    print_error ""
    print_warn "Этот скрипт защищает порты которые ты ОТКРЫЛ в фаерволе."
    print_warn "Без фаервола сервер открыт всему интернету, и DDoS-защита не поможет."
    print_warn ""
    print_warn "Сначала настрой фаервол. Самый простой вариант — UFW:"
    print_info "  ${BOLD}apt install ufw${NC}"
    print_info "  ${BOLD}ufw allow 22/tcp comment 'SSH'${NC}      # порт SSH (важно!)"
    print_info "  ${BOLD}ufw allow 443${NC}                     # порт VPN (Reality/etc)"
    print_info "  ${BOLD}ufw allow 8443${NC}                    # резервный VPN-порт (опционально)"
    print_info "  ${BOLD}ufw --force enable${NC}                # активировать"
    print_info "  ${BOLD}ufw status${NC}                        # проверить"
    print_warn ""
    print_warn "Когда UFW активен, запусти этот скрипт повторно."
    print_warn "Скрипт защитит ВСЕ порты которые ты открыл (кроме SSH)."
    exit 1
fi

BACKUP_DIR="/root/vpn-ddos-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
nft list ruleset > "$BACKUP_DIR/nft-ruleset.before" 2>/dev/null || true
print_ok "Бэкап текущих nft-правил: $BACKUP_DIR/nft-ruleset.before"

# ==============================================================================
# ШАГ 1.5: МИГРАЦИЯ С ЛЕГАСИ-ВЕРСИЙ (v3.13.2+)
# ==============================================================================
# При обновлении ≤v3.11.x → v3.12.x → v3.13.x на тех же серверах оставались
# мёртвые артефакты от старых scanner-blocklist-update.* и tor-blocklist-update.*
# unit'ов, заменённых единым shieldnode-update@<name>.* templated unit'ом.
# Чистим их сейчас (идемпотентно — на свежей установке no-op).

LEGACY_FOUND=0

# 1) Legacy systemd unit'ы (v3.11.x scanner/tor отдельные timer'ы)
for unit in scanner-blocklist-update.timer scanner-blocklist-update.service \
            tor-blocklist-update.timer tor-blocklist-update.service \
            cs-ssh-whitelist.service; do
    if [ -f "/etc/systemd/system/$unit" ]; then
        LEGACY_FOUND=1
        systemctl disable --now "$unit" 2>/dev/null || true
        rm -f "/etc/systemd/system/$unit"
    fi
done

# 2) Legacy updater-скрипты (v3.11.x — заменены единым shieldnode-update-blocklist.sh)
for script in /usr/local/sbin/update-scanner-blocklist.sh \
              /usr/local/sbin/update-tor-blocklist.sh \
              /usr/local/sbin/cs-ssh-key-whitelist.sh; do
    if [ -f "$script" ]; then
        LEGACY_FOUND=1
        rm -f "$script"
    fi
done

# 3) Legacy postoverflow whitelist parser (≤v3.4)
if [ -f /etc/crowdsec/postoverflows/s01-whitelist/ssh-key-whitelist.yaml ]; then
    LEGACY_FOUND=1
    rm -f /etc/crowdsec/postoverflows/s01-whitelist/ssh-key-whitelist.yaml
fi

# 4) Legacy UFW acquisition (v1.1-1.3)
if [ -f /etc/crowdsec/acquis.d/ufw.yaml ] && \
   grep -q "vpn-node-ddos-protect" /etc/crowdsec/acquis.d/ufw.yaml 2>/dev/null; then
    LEGACY_FOUND=1
    rm -f /etc/crowdsec/acquis.d/ufw.yaml
fi

# 5) Legacy sysctl имя (v3.7 переехал 99-shieldnode.conf → 90-shieldnode.conf)
if [ -f /etc/sysctl.d/99-shieldnode.conf ]; then
    LEGACY_FOUND=1
    rm -f /etc/sysctl.d/99-shieldnode.conf
fi

# 6) v3.15.0: удаляем старый MaxMind-based mobile-RU updater (заменён унифицированным).
#    timer/service оставляем — они переустановятся под новый updater автоматом.
if [ -f /usr/local/sbin/shieldnode-update-mobile-ru.sh ]; then
    LEGACY_FOUND=1
    rm -f /usr/local/sbin/shieldnode-update-mobile-ru.sh
fi

# 7) v3.20.0+: mobile_ru и broadband_ru timer'ы УДАЛЕНЫ из shieldnode (whitelist'ы убраны).
#    Если ранее были установлены (v3.13.0+/v3.19.0+) — отключить и удалить.
for legacy_timer in shieldnode-update@mobile_ru.timer shieldnode-update@mobile_ru.service \
                    shieldnode-update@broadband_ru.timer shieldnode-update@broadband_ru.service; do
    if systemctl list-unit-files "$legacy_timer" 2>/dev/null | grep -q "$legacy_timer"; then
        LEGACY_FOUND=1
        systemctl disable --now "$legacy_timer" 2>/dev/null || true
    fi
done

# v3.20.0+: удалить старые seed-файлы whitelist'ов
if [ -f /etc/shieldnode/lists/mobile-ru.txt ]; then
    LEGACY_FOUND=1
    rm -f /etc/shieldnode/lists/mobile-ru.txt
fi
if [ -f /etc/shieldnode/lists/broadband-ru.txt ]; then
    LEGACY_FOUND=1
    rm -f /etc/shieldnode/lists/broadband-ru.txt
fi

# v3.20.0+: удалить старые fail counter'ы
rm -f /var/lib/shieldnode/mobile_ru_fail_count 2>/dev/null
rm -f /var/lib/shieldnode/broadband_ru_fail_count 2>/dev/null

if [ "$LEGACY_FOUND" = "1" ]; then
    systemctl daemon-reload
    print_ok "Legacy-артефакты удалены"
else
    print_info "Legacy-артефактов не обнаружено (свежая установка)"
fi

# ==============================================================================
# ШАГ 2: AUTO-DETECT (порты из фаервола, SSH порт, IP)
# ==============================================================================

print_header "ШАГ 2: AUTO-DETECT"

# v1.7: порты берутся из ПРАВИЛ ФАЕРВОЛА. Юзер сам решил что открыть —
# это и защищаем. SSH-порт исключаем (он защищается CrowdSec'ом и не
# должен попадать под rate-limit для VPN-клиентов).

# Функция возвращает порты из UFW в формате "tcp,tcp,udp..." парами через |
# Stdout: две строки
#   1. TCP-порты через запятую
#   2. UDP-порты через запятую
detect_firewall_ports() {
    local fw="$1"
    local tcp_list=""
    local udp_list=""
    local mgmt_ipv4=""

    case "$fw" in
        ufw)
            # ufw status: "443/tcp ALLOW IN Anywhere", "443 ALLOW IN ..." (без proto = TCP+UDP),
            # multi-port: "80,443/tcp ALLOW Anywhere", range: "4000:5000/tcp ALLOW Anywhere"
            local ufw_out
            # v3.10.2 BUG-8 FIX: LANG=C — иначе ru/uk/it/etc локали ломают парсер.
            ufw_out=$(LANG=C LC_ALL=C ufw status 2>/dev/null)
            # v3.10.2 BUG-1+3 FIX: regex теперь принимает port-range (N:M)
            # и multi-port (N,M,...) форматы UFW. Двоеточие нормализуется в дефис
            # (UFW: 4000:5000, nft: 4000-5000). Comma-list разворачивается в
            # отдельные порты.
            tcp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "tcp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')

            udp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "udp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')

            # v2.2: management IPs из правил "ALLOW from <IP>" (только IPv4, v3.6)
            # Формат: "2222/tcp  ALLOW  213.165.55.166" (3й колонкой идёт IP вместо Anywhere)
            mgmt_ipv4=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 != "Anywhere" {
                    if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $3
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;

        firewalld)
            # firewall-cmd --list-ports выдаёт "443/tcp 8443/tcp 36789/udp"
            local fw_out
            fw_out=$(firewall-cmd --list-ports 2>/dev/null)
            tcp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="tcp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="udp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')

            # Также добавим порты из --list-services (ssh=22, http=80, https=443 и т.д.)
            local services
            services=$(firewall-cmd --list-services 2>/dev/null)
            for svc in $services; do
                local svc_ports
                svc_ports=$(firewall-cmd --info-service="$svc" 2>/dev/null | awk '/ports:/{$1="";print}' | xargs)
                for sp in $svc_ports; do
                    local p="${sp%/*}"
                    local pr="${sp#*/}"
                    if [ "$pr" = "tcp" ]; then
                        tcp_list="${tcp_list:+$tcp_list,}$p"
                    elif [ "$pr" = "udp" ]; then
                        udp_list="${udp_list:+$udp_list,}$p"
                    fi
                done
            done
            tcp_list=$(echo "$tcp_list" | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$udp_list" | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            ;;

        iptables)
            # iptables -S INPUT: ищем "-A INPUT -p tcp --dport 443 -j ACCEPT"
            # v3.18.11 SH-NEW-25: gsub :->-  (UFW: 4000:5000, nft требует 4000-5000)
            tcp_list=$(iptables -S INPUT 2>/dev/null | \
                awk '/-j ACCEPT/ && /-p tcp/ {
                    for (i=1; i<=NF; i++) {
                        if ($i == "--dport" || $i == "--dports") {
                            p=$(i+1); gsub(/:/,"-",p); print p
                        }
                    }
                }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')

            udp_list=$(iptables -S INPUT 2>/dev/null | \
                awk '/-j ACCEPT/ && /-p udp/ {
                    for (i=1; i<=NF; i++) {
                        if ($i == "--dport" || $i == "--dports") {
                            p=$(i+1); gsub(/:/,"-",p); print p
                        }
                    }
                }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            ;;

        nftables)
            # nft -j: ищем accept-правила с tcp/udp dport (jq mandatory, см. ШАГ 1)
            local nft_json
            nft_json=$(nft -j list ruleset 2>/dev/null)
            if [ -n "$nft_json" ]; then
                tcp_list=$(echo "$nft_json" | jq -r '
                    .nftables[] | select(.rule?) | .rule
                    | select(any(.expr[]?; .accept))
                    | .expr[] | select(.match?)
                    | select(.match.left.payload.protocol == "tcp")
                    | .match.right
                    | if type == "object" and .set then .set[] elif type == "array" then .[] else . end
                    | tostring
                ' 2>/dev/null | grep -E '^[0-9]+$' | sort -un | tr '\n' ',' | sed 's/,$//')

                udp_list=$(echo "$nft_json" | jq -r '
                    .nftables[] | select(.rule?) | .rule
                    | select(any(.expr[]?; .accept))
                    | .expr[] | select(.match?)
                    | select(.match.left.payload.protocol == "udp")
                    | .match.right
                    | if type == "object" and .set then .set[] elif type == "array" then .[] else . end
                    | tostring
                ' 2>/dev/null | grep -E '^[0-9]+$' | sort -un | tr '\n' ',' | sed 's/,$//')
            fi
            ;;
    esac

    echo "$tcp_list"
    echo "$udp_list"
    echo "$mgmt_ipv4"
}

# Получаем сырые списки портов из фаервола
FW_OUTPUT=$(detect_firewall_ports "$FIREWALL_TYPE")
RAW_TCP=$(echo "$FW_OUTPUT" | sed -n '1p')
RAW_UDP=$(echo "$FW_OUTPUT" | sed -n '2p')
MGMT_IPV4=$(echo "$FW_OUTPUT" | sed -n '3p')

# v3.10.2 BUG-7 FIX: убран `exit` после первого совпадения — все sshd-listener
# порты собираются. SSH_PORT (для display) — первый, остальные тоже исключаются
# из списков защищаемых портов.
SSH_PORTS=$(ss -tlnpH 2>/dev/null | awk '
    /users:\(.*"sshd"/ {
        split($4, a, ":")
        port = a[length(a)]
        if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next
        print port
    }
' | sort -un | tr '\n' ',' | sed 's/,$//')
SSH_PORTS="${SSH_PORTS:-22}"
SSH_PORT=$(echo "$SSH_PORTS" | cut -d, -f1)

# Исключаем SSH (все ssh-порты) из списков защищаемых портов
exclude_port() {
    local list="$1" exclude="$2"
    echo ",$list," | sed "s/,$exclude,/,/g; s/^,//; s/,$//"
}

# v3.10.2: исключаем все SSH-порты, не только первый
exclude_ports_list() {
    local list="$1" excludes="$2"
    local IFS=','
    for e in $excludes; do
        list=$(exclude_port "$list" "$e")
    done
    echo "$list"
}

PROTECTED_TCP=$(exclude_ports_list "$RAW_TCP" "$SSH_PORTS")
PROTECTED_UDP="$RAW_UDP"  # UDP SSH не использует, исключать не нужно

# v3.10.2: формируем nft-set синтаксис для SSH-портов: "22, 2222"
SSH_PORTS_NFT=$(echo "$SSH_PORTS" | sed 's/,/, /g')

# Печать результатов
if [ "$SSH_PORTS" = "$SSH_PORT" ]; then
    print_ok "SSH порт: ${BOLD}$SSH_PORT${NC} (pre-auth flood защита: 5 conn / 10 newconn-min)"
else
    print_ok "SSH порты: ${BOLD}$SSH_PORTS${NC} (pre-auth flood защита: 5 conn / 10 newconn-min)"
fi

if [ -n "$PROTECTED_TCP" ]; then
    print_ok "Защищаемые TCP-порты: ${BOLD}$PROTECTED_TCP${NC}"
else
    print_warn "В фаерволе нет открытых TCP-портов кроме SSH"
fi

if [ -n "$PROTECTED_UDP" ]; then
    print_ok "Защищаемые UDP-порты: ${BOLD}$PROTECTED_UDP${NC}"
else
    print_info "В фаерволе нет открытых UDP-портов (Hysteria/TUIC/QUIC будет нечего защищать)"
fi

# v2.2: manual whitelist для management-IP (правила UFW "ALLOW from <IP>")
if [ -n "$MGMT_IPV4" ]; then
    print_ok "Management IPv4 (manual whitelist): ${BOLD}$MGMT_IPV4${NC}"
fi

if [ -z "$PROTECTED_TCP" ] && [ -z "$PROTECTED_UDP" ]; then
    print_error ""
    print_error "В фаерволе нет открытых портов (кроме SSH)."
    print_error "Скрипту нечего защищать. Открой VPN-порт в фаерволе и запусти повторно."
    print_info "Пример: ${BOLD}ufw allow 443${NC}"
    exit 1
fi

# Объединяем для совместимости (старые места в скрипте)
XRAY_PORTS_TCP="$PROTECTED_TCP"
XRAY_PORTS_UDP="$PROTECTED_UDP"
XRAY_PORTS=$(echo "${XRAY_PORTS_TCP},${XRAY_PORTS_UDP}" | tr ',' '\n' | grep -v '^$' | sort -un | tr '\n' ',' | sed 's/,$//')

# v2.2: management IPs для nft set (только IPv4, v3.6)
MANUAL_WHITELIST_V4_INIT=""
if [ -n "$MGMT_IPV4" ]; then
    MANUAL_WHITELIST_V4_INIT="        elements = { $(echo "$MGMT_IPV4" | sed 's/,/, /g') }"
fi

# v3.21.5: Embedded infrastructure baseline — крупные CDN/cloud CIDR-блоки.
# Загружаются ВСЕГДА на установке. Опциональный updater (см. ниже) может
# заменить их актуальными списками из официальных API, но если updater
# не работает (нет интернета / лёг сервис) — baseline продолжает защищать.
#
# Источники (даты на момент составления — май 2026):
# - Cloudflare:  https://www.cloudflare.com/ips-v4 (официальный, стабильный)
# - Google:      крупные supernets из Google AS15169 (BGP feed)
# - AWS:         крупные supernets AS16509 (consolidated /8 блоки)
# - Azure:       Microsoft AS8075 крупные supernets
# - Apple:       AS714 — весь 17.0.0.0/8 (исторически только Apple)
# - Meta/FB:     AS32934 — известные блоки
# - Akamai:      AS20940, AS16625 — supernets
# - Fastly:      AS54113 — основные блоки
# - GitHub:      AS36459 (внутри Microsoft AS8075, но отдельные диапазоны)
# - Telegram:    AS62041, AS44907 — официальные
# - Yandex:      AS13238 — основные supernets
# - VK:          AS47541, AS28709 — основные
# - Selectel:    AS50340 — основные
#
# ВАЖНО: список консервативный, использует крупные supernets. Это значит
# overscoping (некоторые субдиапазоны могут быть переделегированы), но
# для нашей цели (НЕ банить случайно) это безопаснее. Точные диапазоны
# подтягивает dynamic updater из официальных endpoint'ов.
INFRASTRUCTURE_V4_CIDR=$(cat <<'INFRA_V4_EOF'
# v3.23.15 P0-2: ТОЛЬКО CDN/edge провайдеры (контент-сети, IP арендовать нельзя).
# IaaS-compute (AWS EC2 / Azure / GCP-compute 34-35 / Selectel / Yandex Cloud /
# VK Cloud) УБРАНЫ из bypass — это типовой источник стресс/брут-ботов.
# Bridge/upstream/mgmt ноды (даже на Selectel/Yandex) защищены manual_whitelist_v4
# (проверяется ПЕРВЫМ) + TRUSTED_IPS — их этот trim не затрагивает.
# Вернуть конкретный IaaS-блок при необходимости — добавь его в нижнюю секцию.
# === Cloudflare (AS13335) ===
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
104.16.0.0/13
104.24.0.0/14
108.162.192.0/18
131.0.72.0/22
141.101.64.0/18
162.158.0.0/15
172.64.0.0/13
173.245.48.0/20
188.114.96.0/20
190.93.240.0/20
197.234.240.0/22
198.41.128.0/17
# === Google EDGE/DNS (AS15169) — GCP-compute 34.x/35.x НАМЕРЕННО исключены ===
8.8.4.0/24
8.8.8.0/24
8.34.208.0/20
8.35.192.0/20
64.18.0.0/20
64.233.160.0/19
66.102.0.0/20
66.249.64.0/19
72.14.192.0/18
74.125.0.0/16
108.177.0.0/17
142.250.0.0/15
172.217.0.0/16
173.194.0.0/16
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
192.178.0.0/16
# === Apple (AS714) ===
17.0.0.0/8
# === Meta/Facebook (AS32934) ===
31.13.24.0/21
31.13.64.0/18
66.220.144.0/20
69.63.176.0/20
69.171.224.0/19
74.119.76.0/22
102.132.96.0/20
129.134.0.0/16
157.240.0.0/16
163.70.128.0/17
173.252.64.0/18
185.60.216.0/22
204.15.20.0/22
# === Akamai (AS20940, AS16625) ===
23.32.0.0/11
23.64.0.0/14
23.192.0.0/11
72.246.0.0/15
95.100.0.0/15
96.6.0.0/15
104.64.0.0/10
184.24.0.0/13
204.245.32.0/20
# === Fastly (AS54113) ===
23.235.32.0/20
43.249.72.0/22
103.244.50.0/24
146.75.0.0/16
151.101.0.0/16
157.52.64.0/18
167.82.0.0/17
199.27.72.0/21
199.232.0.0/16
# === GitHub (AS36459) ===
140.82.112.0/20
143.55.64.0/20
185.199.108.0/22
192.30.252.0/22
# === Telegram (AS62041, AS44907) ===
91.108.4.0/22
91.108.8.0/22
91.108.12.0/22
91.108.16.0/22
91.108.56.0/22
149.154.160.0/20
#
# IaaS-compute УБРАНО из auto-bypass (P0-2): AWS/Azure/GCP-compute(34-35)/Selectel/
# Yandex Cloud/VK Cloud — там тривиально арендуют ботов. Bridge/mgmt на этих сетях
# защищены manual_whitelist_v4 (проверяется первым). Нужен конкретный блок — добавь
# его CIDR'ы сюда вручную (из официальных ranges провайдера).
INFRA_V4_EOF
)

INFRASTRUCTURE_V6_CIDR=$(cat <<'INFRA_V6_EOF'
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
2001:4860::/32
2607:f8b0::/32
2800:3f0::/32
2a00:1450::/32
2402:9800::/32
2404:6800::/32
2620:107:300f::/48
2620:1ec::/36
2a03:2880::/29
2620:0:1c00::/40
2620:0:1cff::/48
2a01:111::/32
2620:1ec:c::/48
2a01:b740::/32
2620:11c::/32
2606:4700:90::/44
INFRA_V6_EOF
)

INFRASTRUCTURE_V4_INIT=""
INFRASTRUCTURE_V6_INIT=""
if [ -n "$INFRASTRUCTURE_V4_CIDR" ]; then
    INFRASTRUCTURE_V4_INIT="        elements = { $(echo "$INFRASTRUCTURE_V4_CIDR" | grep -v '^$' | grep -v '^#' | paste -sd',' | sed 's/,/, /g') }"
fi
if [ -n "$INFRASTRUCTURE_V6_CIDR" ]; then
    INFRASTRUCTURE_V6_INIT="        elements = { $(echo "$INFRASTRUCTURE_V6_CIDR" | grep -v '^$' | grep -v '^#' | paste -sd',' | sed 's/,/, /g') }"
fi

# Инициализирующие elements для nft-set
nft_set_init() {
    local list="$1"
    if [ -z "$list" ]; then
        echo ""
    else
        echo "        elements = { $(echo "$list" | sed 's/,/, /g') }"
    fi
}

XRAY_PORTS_TCP_INIT=$(nft_set_init "$XRAY_PORTS_TCP")
XRAY_PORTS_UDP_INIT=$(nft_set_init "$XRAY_PORTS_UDP")

# --- Текущий админский IP (для bootstrap-whitelist) ---
ADMIN_IP=""
if [ -n "${SSH_CLIENT:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
elif [ -n "${SSH_CONNECTION:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
else
    ADMIN_IP=$(who -m 2>/dev/null | grep -oE '\([^)]+\)' | tr -d '()' | head -1)
fi

case "$ADMIN_IP" in
    ""|localhost|127.0.0.1|::1) ADMIN_IP="" ;;
    *[!0-9.:]*) ADMIN_IP="" ;;
esac

if [ -n "$ADMIN_IP" ]; then
    print_ok "Текущий админский IP: ${BOLD}$ADMIN_IP${NC}"
    print_info "Если хочешь добавить в manual whitelist: sudo ufw allow from $ADMIN_IP"
else
    print_info "Админский IP не определён (запуск с локальной консоли — это ок)"
fi

# v3.8: детект upstream-интерфейсов для anti-spoofing (fib saddr).
# Считаем интерфейсы в основной таблице маршрутизации, исключая виртуальные.
# Если интерфейсов больше 1 — multi-homed VPS, fib может дать false-positive
# из-за asymmetric routing → отключаем правило.
UPSTREAM_IFACES=$(ip -o -4 route show default 2>/dev/null | awk '{print $5}' | sort -u)
UPSTREAM_COUNT=$(echo "$UPSTREAM_IFACES" | grep -cE '^[a-z]')
if [ "$UPSTREAM_COUNT" = "1" ] && [ -n "$UPSTREAM_IFACES" ]; then
    ENABLE_FIB_ANTISPOOF=1
    print_ok "Single-homed VPS (uplink: ${BOLD}$UPSTREAM_IFACES${NC}) — fib anti-spoofing будет включён"
else
    ENABLE_FIB_ANTISPOOF=0
    print_warn "Multi-homed VPS (${UPSTREAM_COUNT} default routes) — fib anti-spoofing ОТКЛЮЧЁН"
    print_info "На multi-homed asymmetric routing нормален; fib может дать false-positive."
    print_info "rp_filter=2 (loose) от vpn-node-setup.sh продолжает защищать от spoofing."
fi

# v3.11: Tor exit blocklist (опционально). Активируется через:
#   - переменную окружения BLOCK_TOR=1 при запуске
#   - либо файл-маркер /etc/shieldnode/block_tor (для повторных запусков)
# По умолчанию ОТКЛЮЧЕНО — операторы которые хостят Tor → VPN bridge для
# параноиков должны оставлять выключенным.
BLOCK_TOR="${BLOCK_TOR:-0}"
if [ -f /etc/shieldnode/block_tor ]; then
    BLOCK_TOR=1
fi
if [ "$BLOCK_TOR" = "1" ]; then
    print_ok "Tor exit blocklist: ${BOLD}ВКЛЮЧЁН${NC} (BLOCK_TOR=1)"
    print_info "Для отключения: rm /etc/shieldnode/block_tor && перезапустить скрипт"
else
    print_info "Tor exit blocklist: отключён (включить: BLOCK_TOR=1 sudo ./shieldnode.sh)"
fi

# ==============================================================================
# ШАГ 3: ПРОВЕРКА КОНФИГА SSH (информационная, не блокирует установку)
# ==============================================================================

print_header "ШАГ 3: ПРОВЕРКА КОНФИГА SSH"

# v1.5: проверка SSH-конфига больше не интерактивная и не блокирующая.
# Просто показываем текущее состояние и рекомендации в конце скрипта.
# Юзер сам решит когда и как переходить на ключи.

# Глобальные переменные для использования в шагах 7 и 12 (summary)
SSHD_PASSWORD_AUTH_ENABLED=0
SSHD_PUBKEY_AUTH_ENABLED=1

SSHD_EFFECTIVE=$(sshd -T 2>/dev/null)

if [ -z "$SSHD_EFFECTIVE" ]; then
    print_warn "sshd -T не работает — пропускаю проверку"
else
    PASSWORD_AUTH=$(echo "$SSHD_EFFECTIVE" | awk '/^passwordauthentication/ {print $2}')
    PUBKEY_AUTH=$(echo "$SSHD_EFFECTIVE" | awk '/^pubkeyauthentication/ {print $2}')
    KBD_INT_AUTH=$(echo "$SSHD_EFFECTIVE" | awk '/^kbdinteractiveauthentication/ {print $2}')

    if [ "$PUBKEY_AUTH" = "yes" ]; then
        print_ok "PubkeyAuthentication: yes"
        SSHD_PUBKEY_AUTH_ENABLED=1
    else
        print_warn "PubkeyAuthentication: $PUBKEY_AUTH (отключено)"
        print_info "Без него SSH-key auto-whitelist работать не будет"
        SSHD_PUBKEY_AUTH_ENABLED=0
    fi

    if [ "$PASSWORD_AUTH" = "yes" ] || [ "$KBD_INT_AUTH" = "yes" ]; then
        print_warn "PasswordAuthentication=$PASSWORD_AUTH, KbdInteractive=$KBD_INT_AUTH"
        print_info "Защита установится. Для МАКСИМАЛЬНОЙ безопасности:"
        print_info "  1. Настрой вход по SSH-ключу"
        print_info "  2. Отключи password-auth: см. инструкцию в конце скрипта"
        SSHD_PASSWORD_AUTH_ENABLED=1
    else
        print_ok "PasswordAuthentication: no — максимальная защита"
        SSHD_PASSWORD_AUTH_ENABLED=0
    fi
fi

# ==============================================================================
# ШАГ 4: NFTABLES RATE-LIMIT
# ==============================================================================

print_header "ШАГ 4: NFTABLES RATE-LIMIT (kernel-level SYN flood protection)"

NFT_CONF_DIR="/etc/nftables.d"
NFT_DDOS_CONF="$NFT_CONF_DIR/ddos-protect.conf"
mkdir -p "$NFT_CONF_DIR"

# v3.23.13 BUG-019 FIX: создание /etc/shieldnode/limits.conf при первом install.
# Файл создаётся только если его НЕТ — повторная установка не затирает
# оператор-кастомизации.
if [ ! -f "$SHIELD_LIMITS_FILE" ]; then
    mkdir -p /etc/shieldnode
    cat > "$SHIELD_LIMITS_FILE" <<'LIMITS_EOF'
# /etc/shieldnode/limits.conf — настраиваемые лимиты shieldnode.
#
# Файл sourced'ится из shieldnode.sh при install/upgrade И при запуске
# embedded скриптов через placeholders. Перезагрузка nft после изменения:
#   sudo systemctl restart shieldnode-nftables.service
# Для применения к auto-promote/aggregator/cleanup — запустить
#   sudo bash $(curl -fsSL https://raw.githubusercontent.com/SpofyJet/shield/main/shieldnode.sh -o /tmp/sn.sh && echo /tmp/sn.sh)
# или просто \`guard upgrade\`.
#
# Дефолты подходят для 100-200 клиентов на 4-8GB ноде. Тuning:
#   - Маленькая нода (<50 клиентов): SHIELD_CT_CONN_FLOOD=3000
#   - Большая нода (>1000 клиентов): SHIELD_CT_CONN_FLOOD=50000
#
# Безопасность: файл должен быть owned root:root, perms 0640.
# shield_safe_source проверяет это при загрузке.

# ─── Авто-апгрейд зависимостей (v3.26.5) ───
# 1 = при install/upgrade держать УЖЕ установленные управляемые пакеты (nftables,
# conntrack, iproute2, tcpdump, sqlite3, jq, curl, zstd, xz-utils, crowdsec + баунсер)
# на последней версии из репо (security-патчи). Апгрейд только если репо-версия новее
# (downgrade исключён). 0 = заморозить версии. Можно и разово: SHIELD_UPGRADE_DEPS=0 bash shieldnode.sh
SHIELD_UPGRADE_DEPS=1

# ─── Per-IP conntrack лимит (защита от conn-flood/slowloris) ───
# 15000 = baseline 20× от пика реальных юзеров. Срезает все известные ботнеты.
SHIELD_CT_CONN_FLOOD=15000

# ─── Per-IP new connection rate-limit ───
# 40000/min = baseline для 500-1000 клиентов с CGNAT.
SHIELD_RATE_NEWCONN="40000/minute"
SHIELD_RATE_NEWCONN_BURST=60000

# ─── Per-IP SYN rate-limit ───
SHIELD_RATE_SYN="2000/second"
SHIELD_RATE_SYN_BURST=3000

# ─── Per-IP UDP rate-limit ───
SHIELD_RATE_UDP="10000/second"
SHIELD_RATE_UDP_BURST=20000

# ─── SSH защита (защита от bruteforce + SYN flood на 22) ───
SHIELD_SSH_CT_LIMIT=5
SHIELD_SSH_NEWCONN_RATE="8/minute"
SHIELD_SSH_NEWCONN_BURST=20

# ─── CGNAT-safe overflow (v3.27.0 FIX#8) ───
# 1 = превышение per-IP new-conn/SYN/UDP режет только избыточные пакеты, НЕ банит
# общий CGNAT-IP в confirmed_attack (15-мин blackhole новых конн). 0 = старый escalate.
SHIELD_CGNAT_SAFE=1

# ─── Опц. backstop'ы (v3.27.0) ───
# Глобальный new-conn/с ceiling на protected-TCP (анти-distributed-handshake). 0=off.
# ВКЛЮЧАТЬ ТОЛЬКО на НЕ-CGNAT нодах и много выше суммарного легит-пика new-conn/с.
SHIELD_GLOBAL_NEWCONN_CEIL=0
# v6-TCP на VPN-портах: 1=reject(RST) для быстрого happy-eyeballs fallback, 0=drop (стелс).
SHIELD_V6_REJECT=0

# ─── Auto-promote (events.db → custom-local.txt permanent ban) ───
# IP с >=THRESHOLD hits за WINDOW_HOURS попадает в local blocklist на TTL_DAYS.
# v3.23.15 P1-1: 800 (раньше 2000 — недостижимо за 24ч под log-meter 1/min).
# Heavy-CGNAT нода? Подними обратно (conn_flood ложно срабатывает на CGNAT-пиках).
SHIELD_AUTOPROMOTE_THRESHOLD=800
SHIELD_AUTOPROMOTE_WINDOW_HOURS=24
# v3.24.0: SYNPROXY (conntrack-exhaustion). 1=вкл (дефолт), 0=выкл.
# Безопасно: ядро не тянет → авто-fallback на ddos_protect; verify mss/wscale + авто-откат.
SHIELD_SYNPROXY=1
# v3.27.1 FIX(#6): SYNPROXY покрывает и SSH-порт (анти-спуф-SYN→conntrack). 0=выключить.
SHIELD_SYNPROXY_SSH=1
# v3.27.1 FIX(#1): анти-pulsing — sustained если >= SHIELD_CTG_ATTACK_MIN_TICKS аномалий
# в скользящем окне из SHIELD_CTG_ANOM_WINDOW тиков (не обязательно подряд).
SHIELD_CTG_ANOM_WINDOW=4

# v3.26: conntrack-guard — основная защита от connect-and-hold (фантом) флуда + backstop
# против conntrack-exhaustion. Изолированная таблица shield_ctguard. Эвиктит источники,
# у которых conntrack ≫ ЖИВЫХ сокетов (ss) — handshake-and-abandon; легит с live>0 щадит.
# v3.26.4: attack-mode по фантому входит ТОЛЬКО при наличии реального per-source холдера
# (≥SHIELD_CTG_PHANTOM_MIN) — мобильный CGNAT-churn (conntrack≫live и у легита) больше НЕ
# триггерит ложную атаку/кап/эвикт. 1=вкл, 0=выкл.
SHIELD_CTGUARD=1
SHIELD_CTG_ENFORCE=1         # 1=выселять; 0=ТОЛЬКО лог (наблюдение) — для осторожного раската
SHIELD_CTG_LIVE_FRAC=10      # выселять источник, если живых сокетов < этого %% от его conntrack
SHIELD_CTG_PHANTOM_RATIO=60  # %% ss-phantom-ratio (сигнал; attack-mode лишь при реальном холдере)
SHIELD_CTG_PHANTOM_MIN=4000  # мин. conntrack с источника, чтобы считать его холдером. Выше потолка
                             # легит-CGNAT-churn (~2200), ниже connect-and-hold атаки (7000+).
                             # Не-CGNAT нода со стабильными конн-ами: можно понизить для чувствительности.
SHIELD_CTG_AGG_CAP=0         # агрегатный кап new-conn по фантому. 0=off (прямые ноды: эвикт сам справляется,
                             # кап на CGNAT-пиках вреден). 1=on для CDN/мост-нод, где per-IP эвикт невозможен.
SHIELD_CTG_ACTIVE_FLOOR=20   # > стольких ЖИВЫХ сокетов у источника => shared-front/CGNAT => НЕ трогаем
SHIELD_CTG_CT_MAX_CEIL=1048576  # авто-поднимать nf_conntrack_max до этого потолка при заполнении
SHIELD_CTG_COARSE_MULT=3     # perf: полный conntrack-дамп только если conntrack > ss_total×это
SHIELD_CTG_UDP_FLOOR=3000    # v3.27.0 FIX#1: пол агрегатного UDP-капа new-flow/с в attack-mode (анти-spoofed-UDP)
SHIELD_CTG_CT_RAM_PCT=25     # v3.27.0 FIX#13: conntrack ≤ этого %% MemAvailable при авто-росте max (анти-OOM)
SHIELD_CT_WARN_PCT=80        # %% заполнения conntrack → WARN-алерт
SHIELD_CT_HIGH_PCT=90        # %% → fill-триггер attack-mode + авто-подъём nf_conntrack_max
SHIELD_CT_RECOVER_PCT=70     # %% → выход из attack-mode (auto-recovery)
SHIELD_CUSTOM_LOCAL_TTL_DAYS=90

# ─── Retention ───
SHIELD_EVENTS_DB_RETENTION_DAYS=90
SHIELD_PCAP_RETENTION_DAYS=30
SHIELD_PCAP_TRIGGER_DROPS=10000

# ─── Aggregator (защита от RAM blow-up при rotating-IP storm) ───
# JOURNAL_LINES — лимит на journalctl --lines (cap per-tick).
# MAX_UNIQUE_IPS — hard cap на bash hash size per-type. После cap'а новые IP
# дропаются (но nft drops продолжают работать независимо).
SHIELD_AGG_JOURNAL_LINES=50000
SHIELD_AGG_MAX_UNIQUE_IPS=50000
LIMITS_EOF
    chmod 0640 "$SHIELD_LIMITS_FILE"
    chown root:root "$SHIELD_LIMITS_FILE"
    print_ok "Created $SHIELD_LIMITS_FILE (limits.conf)"

    # Re-source чтобы overrides из только что созданного файла применились
    if shield_safe_source "$SHIELD_LIMITS_FILE" 2>/dev/null; then
        :
    fi
else
    print_info "Using existing $SHIELD_LIMITS_FILE"
fi

# v3.23.13 SR-FIX-7: re-validate numerics after limits.conf re-source
# (на случай если оператор положил мусор в файл).
shield_ensure_numeric SHIELD_CT_CONN_FLOOD 15000
shield_ensure_numeric SHIELD_RATE_NEWCONN_BURST 60000
shield_ensure_numeric SHIELD_RATE_SYN_BURST 3000
shield_ensure_numeric SHIELD_RATE_UDP_BURST 20000
shield_ensure_numeric SHIELD_SSH_CT_LIMIT 5
shield_ensure_numeric SHIELD_SSH_NEWCONN_BURST 20
# Re-compute derived (после возможной правки SHIELD_CT_CONN_FLOOD)
SHIELD_CT_CONN_FLOOD_MINUS_1=$((SHIELD_CT_CONN_FLOOD - 1))

# v3.8: подготовка conditional-правил для nft template.
# fib anti-spoofing — только на single-homed VPS.
# v3.23.0: log prefix в правиле fib_spoof тоже опционален (SHIELDNODE_VERBOSE_LOGS=1).
if [ "${ENABLE_FIB_ANTISPOOF:-0}" = "1" ]; then
    if [ "$SHIELDNODE_VERBOSE_LOGS" = "1" ]; then
        FIB_ANTISPOOF_RULE="        # === v3.8: ANTI-SPOOFING (fib reverse-path) ===
        # Стронгер чем rp_filter loose — ловит spoofed src из соседних сетей,
        # для которых kernel'у не известен обратный маршрут.
        # v3.15.3: log prefix '[shield:fib_spoof]' для observability (verbose mode).
        iif \"lo\" accept
        fib saddr . iif oif missing limit rate 1/second burst 5 packets log prefix \"[shield:fib_spoof] \" level info flags ip options counter name tcp_invalid drop
        fib saddr . iif oif missing counter name tcp_invalid drop"
    else
        FIB_ANTISPOOF_RULE="        # === v3.8: ANTI-SPOOFING (fib reverse-path) ===
        # Стронгер чем rp_filter loose — ловит spoofed src из соседних сетей.
        # v3.23.0: counter-only mode (no log, SHIELDNODE_VERBOSE_LOGS=0 default).
        iif \"lo\" accept
        fib saddr . iif oif missing counter name tcp_invalid drop"
    fi
else
    FIB_ANTISPOOF_RULE="        # fib anti-spoofing отключён (multi-homed VPS — может дать false-positive)"
fi

# v3.20.5: priorities захардкожены под standalone-режим.
# Forward chain удалён (см. Patch S1 ниже — MSS clamp принадлежит vpn-node-setup),
# поэтому SHIELD_FORWARD_PRIO больше не используется в nft-конфиге.
# Prerouting priority -100 применяется ко всем нодам одинаково.
# Если оператор явно поставил PANEL_TYPE != "none" в pre-install.conf или
# через env var — используем compat priority -150 для prerouting.
if [ "${PANEL_TYPE:-none}" != "none" ]; then
    SHIELD_PREROUTING_PRIO="-150"
    print_info "PANEL_TYPE=$PANEL_TYPE — compat prerouting priority -150 (manual override)"
else
    SHIELD_PREROUTING_PRIO="-100"
    print_info "Standalone — prerouting priority -100"
fi

# v3.23.0: generation of log prefix blocks based on SHIELDNODE_VERBOSE_LOGS.
# При =0 (default) — лог-правила НЕ генерируются. Counter+drop остаются на своих
# местах, поэтому guard CLI продолжает работать как раньше (counters обновляются
# независимо от log).
# При =1 — лог-правила добавляются как в v3.22.x для aggregator/events.db.
#
# Хитрость: ВЕСЬ блок генерируется одной переменной (включая все строки правила
# с обратными слэшами для line-continuation). При =0 переменная пустая → блок
# полностью отсутствует в nft conf, синтаксис не ломается.
# При =1 — лог-правила добавляются как в v3.22.x для aggregator/events.db.
#
# Хитрость: ВЕСЬ блок генерируется одной переменной (включая все строки правила
# с обратными слэшами для line-continuation). При =0 переменная пустая → блок
# полностью отсутствует в nft conf, синтаксис не ломается.
#
# v3.23.13 BUG-004 FIX: SHIELD_LOG_*_FULL переменные для blocklist/escalation
# УБРАНЫ — соответствующие log правила теперь hardcoded в template с
# rate-limit 1/sec (всегда активны). Без них events.db никогда не получала
# attribution events → auto-promote был полностью мёртв.
# Только SHIELD_LOG_TCP_INVALID остался под toggle — это high-volume per-packet
# rule (nmap сканеры), действительно может дать тысячи строк/sec без burst-rate.
if [ "$SHIELDNODE_VERBOSE_LOGS" = "1" ]; then
    print_info "Verbose logs ENABLED (SHIELDNODE_VERBOSE_LOGS=1) — + tcp_invalid + fib_spoof per-packet log"
    SHIELD_LOG_TCP_INVALID=$'\n        tcp flags & (fin|syn) == (fin|syn) limit rate 1/second burst 5 packets \\\n            log prefix "[shield:tcp_invalid] " level info flags ip options\n        tcp flags & (syn|rst) == (syn|rst) limit rate 1/second burst 5 packets \\\n            log prefix "[shield:tcp_invalid] " level info flags ip options\n        tcp flags & (fin|rst) == (fin|rst) limit rate 1/second burst 5 packets \\\n            log prefix "[shield:tcp_invalid] " level info flags ip options\n        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 limit rate 1/second burst 5 packets \\\n            log prefix "[shield:tcp_invalid] " level info flags ip options\n        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) limit rate 1/second burst 5 packets \\\n            log prefix "[shield:tcp_invalid] " level info flags ip options'
else
    print_info "Verbose logs DISABLED (default) — blocklist/escalation attribution still active (always-on)"
    print_info "  Включить tcp_invalid + fib_spoof debug:  SHIELDNODE_VERBOSE_LOGS=1 sudo bash shieldnode.sh"
    SHIELD_LOG_TCP_INVALID=""
fi

# === v3.23.15 P0-1: базовая IPv6-защита (дешёвый вариант; полный v6-ruleset — 2-я волна) ===
# v3.27.0 FIX(#11): SHIELD_V6_REJECT=1 → новые v6-TCP на VPN-порты получают RST вместо
# тихого DROP. Dual-stack клиент по happy-eyeballs мгновенно фейловерит на v4 (без
# SYN-timeout-задержки). Дефолт 0 (drop = стелс). UDP/QUIC всегда drop (RST невозможен).
SHIELD_V6_REJECT="${SHIELD_V6_REJECT:-0}"
if [ "$SHIELD_V6_REJECT" = "1" ]; then
    V6_TCP_VERDICT='counter name conn6_blocked reject with tcp reset'
else
    V6_TCP_VERDICT='counter name conn6_blocked drop'
fi
SHIELD_V6_SETS=""
SHIELD_V6_RULES=""
if ip -6 addr show scope global 2>/dev/null | grep -qE 'inet6 (2[0-9a-f]|3[0-9a-f])'; then
    print_warn "Публичный IPv6 обнаружен — включаю базовую v6-защиту (P0-1)"
    print_info "  VPN-порты: новые v6-соединения $([ "$SHIELD_V6_REJECT" = "1" ] && echo "REJECT(reset)" || echo "DROP") (клиенты идут по v4/CGNAT)"
    print_info "  SSH over v6: rate-limit как v4 (без hard-deny → без lockout)"
    print_info "  Полноценный v6 rate-limit на VPN-портах — следующий релиз"
    SHIELD_V6_SETS="    set ssh_connlimit_v6 {
        type ipv6_addr
        flags dynamic
        size 16384
    }
    set ssh_newconn_v6 {
        type ipv6_addr
        flags dynamic, timeout
        timeout 5m
        size 16384
    }
    counter conn6_blocked { }
    counter ssh6_flood { }"
    SHIELD_V6_RULES="        # === v3.23.15 P0-1: базовая IPv6-защита (established уже принят выше) ===
        # v3.28.0: ноды флота (v6) из Remnawave — bypass как whitelist. Пустой сет = no-op.
        meta nfproto ipv6 ip6 saddr @remnawave_nodes_v6 counter name remnawave_nodes_pass_v6 accept
        # v3.27.0 FIX(#7): v6 blocklist-drops ПЕРЕД остальным (бьют и SSH-over-v6).
        meta nfproto ipv6 ip6 saddr @threat_blocklist_v6 counter drop
        meta nfproto ipv6 ip6 saddr @custom_blocklist_v6 counter drop
        meta nfproto ipv6 ip6 saddr @scanner_blocklist_v6 counter drop
        meta nfproto ipv6 ip6 saddr @tor_exit_blocklist_v6 counter drop
        meta nfproto ipv6 tcp dport @protected_ports_tcp ct state new $V6_TCP_VERDICT
        meta nfproto ipv6 udp dport @protected_ports_udp ct state new counter name conn6_blocked drop
        meta nfproto ipv6 tcp dport { $SSH_PORTS_NFT } ct state new add @ssh_connlimit_v6 { ip6 saddr ct count over $SHIELD_SSH_CT_LIMIT } counter name ssh6_flood drop
        meta nfproto ipv6 tcp dport { $SSH_PORTS_NFT } ct state new add @ssh_newconn_v6 { ip6 saddr limit rate over $SHIELD_SSH_NEWCONN_RATE burst $SHIELD_SSH_NEWCONN_BURST packets } counter name ssh6_flood drop"
fi

# === v3.27.0 FIX(#3): опц. ГЛОБАЛЬНЫЙ new-conn ceiling на protected-TCP (backstop против
# распределённого handshake-флуда, который проходит per-IP лимиты). ДЕФОЛТ 0 (off) —
# глобальные потолки опасны для CGNAT (память: исключены намеренно). Включать ТОЛЬКО на
# не-CGNAT нодах: SHIELD_GLOBAL_NEWCONN_CEIL=<pps>. Значение должно быть много выше
# суммарного легит-пика new-conn/с ноды. ctguard уже даёт аггрегатный кап в attack-mode;
# это статический backstop для тех, кто хочет жёсткий потолок. ===
SHIELD_GLOBAL_NEWCONN_CEIL="${SHIELD_GLOBAL_NEWCONN_CEIL:-0}"
SHIELD_GLOBAL_NEWCONN_RULE=""
if [ "${SHIELD_GLOBAL_NEWCONN_CEIL:-0}" -gt 0 ] 2>/dev/null; then
    _gnc_burst=$(( SHIELD_GLOBAL_NEWCONN_CEIL * 2 ))
    SHIELD_GLOBAL_NEWCONN_RULE="        # v3.27.0 FIX(#3): глобальный backstop new-conn/с на protected-TCP (opt-in)
        tcp dport @protected_ports_tcp ct state new limit rate over ${SHIELD_GLOBAL_NEWCONN_CEIL}/second burst ${_gnc_burst} packets counter name global_newconn_drop drop"
fi

# v3.27.0 FIX(#8): тела overflow-цепочек генерируются здесь по SHIELD_CGNAT_SAFE.
# CGNAT-safe (=1, дефолт): превышение per-IP лимита РЕЖЕТ только избыточные пакеты
# (rate-shaping) и логирует для events.db, но НЕ заносит source-IP в confirmed_attack
# (что блэкхолило ВСЕ новые конны с IP на 15 мин). На общем CGNAT-IP оператора
# (до ~200 абонентов) старый escalate клал всех при reconnect-шторме/стриминг-пике.
# confirmed_attack по-прежнему дропается (set и правило живы) — просто эти три rate-
# сигнала больше не банят IP целиком. SYN/UDP сохраняют [shield:*_escalate] лог
# (attribution/auto-promote не теряются). =0 → прежнее поведение (escalate→confirmed).
if [ "${SHIELD_CGNAT_SAFE:-1}" = "1" ]; then
    NEWCONN_OVERFLOW_BODY='counter name newconn_flood_v4 drop'
    SYN_OVERFLOW_BODY='meter shield_syn_escalate_log { ip saddr limit rate 1/minute burst 5 packets } log prefix "[shield:syn_escalate] " level info flags ip options
        counter name syn_confirmed_v4 drop'
    UDP_OVERFLOW_BODY='meter shield_udp_escalate_log { ip saddr limit rate 1/minute burst 5 packets } log prefix "[shield:udp_escalate] " level info flags ip options
        counter name udp_confirmed_v4 drop'
else
    NEWCONN_OVERFLOW_BODY='ip saddr @suspect_v4 add @confirmed_attack_v4 { ip saddr } counter name newconn_flood_v4 drop
        add @suspect_v4 { ip saddr } counter name newconn_flood_v4'
    SYN_OVERFLOW_BODY='ip saddr @suspect_v4 meter shield_syn_escalate_log { ip saddr limit rate 1/minute burst 5 packets } log prefix "[shield:syn_escalate] " level info flags ip options
        ip saddr @suspect_v4 add @confirmed_attack_v4 { ip saddr } counter name syn_confirmed_v4 drop
        add @suspect_v4 { ip saddr }'
    UDP_OVERFLOW_BODY='ip saddr @suspect_v4 meter shield_udp_escalate_log { ip saddr limit rate 1/minute burst 5 packets } log prefix "[shield:udp_escalate] " level info flags ip options
        ip saddr @suspect_v4 add @confirmed_attack_v4 { ip saddr } counter name udp_confirmed_v4 drop
        add @suspect_v4 { ip saddr }'
fi

cat > "$NFT_DDOS_CONF" <<EOF
#!/usr/sbin/nft -f
# Generated by vpn-node-ddos-protect.sh v1.4
# Kernel-level SYN flood protection on Xray ports: $XRAY_PORTS
# SSH port $SSH_PORT excluded from rate-limit.
#
# v1.4: rate-limit 60/sec burst 100 — даёт запас для CGNAT-юзеров мобильных
# операторов, где сотни легитимных пользователей могут сидеть за одним IP.
# Реальный SYN-flood делает тысячи SYN/sec — лимит 60 их режет, но
# обычных юзеров не трогает.
#
# v1.3: scanner_blocklist drop'ает известных сканеров (Shodan, Censys,
# госсканеры) ДО rate-limit. Они даже не доходят до handshake.
# Списки обновляются каждые 6 часов через scanner-blocklist-update.timer.
#
# Whitelist в ЭТОЙ таблице — только runtime-добавленные IP (для ручного
# исключения). Manual whitelist управляется через UFW (ALLOW from <IP>):
# скрипт update-protected-ports.sh синхронит management-IP из UFW в nft.
#
# Test:    hping3 -S -p ${XRAY_PORTS%%,*} -i u100 <YOUR_VPN_IP>
# Monitor: nft list set inet ddos_protect syn_flood_v4
#          nft list set inet ddos_protect scanner_blocklist_v4 | wc -l
# Remove:  bash vpn-node-ddos-protect-v3_5.sh --uninstall

# Идемпотентность
table inet ddos_protect
delete table inet ddos_protect

table inet ddos_protect {
    # --- Защищаемые порты (named sets, обновляются watcher'ом из фаервола) ---
    # Заполняются скриптом /usr/local/sbin/update-protected-ports.sh из правил
    # фаервола (UFW/firewalld/iptables). При изменении правил фаервола эти
    # сеты обновляются автоматически в течение 30 секунд через systemd timer.
    set protected_ports_tcp {
        type inet_service
        flags interval
        auto-merge
$XRAY_PORTS_TCP_INIT
    }
    set protected_ports_udp {
        type inet_service
        flags interval
        auto-merge
$XRAY_PORTS_UDP_INIT
    }

    # --- Pre-emptive blocklist (известные сканеры) ---
    # Заполняется скриптом /usr/local/sbin/shieldnode-update-blocklist.sh scanner
    set scanner_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        # Размер для ~50k подсетей с запасом
        size 131072
    }

    # --- v3.12.0: Threat blocklist (Spamhaus DROP, FireHOL Level 1) ---
    # Заполняется /usr/local/sbin/shieldnode-update-blocklist.sh threat
    # Spamhaus DROP — известные criminally-controlled сети (low false-positive).
    # FireHOL Level 1 — агрегатор RBL'ов (high-confidence атакующие).
    set threat_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 65536
    }

    # --- v3.12.0: Custom blocklist (operator personal IPs) ---
    # Заполняется /usr/local/sbin/shieldnode-update-blocklist.sh custom
    # Источник: /etc/shieldnode/lists/custom.txt + опциональные URL'ы из конфига.
    # Path-watcher inotify-триггерит обновление сразу при изменении файла.
    set custom_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 32768
    }

    # v3.20.0: nft sets mobile_ru_whitelist_v4 + broadband_ru_whitelist_v4 УБРАНЫ.
    # Whitelist-логика заменена на единый глобальный лимит ct=3000 для всех IP.
    # Это упрощает архитектуру и гарантирует что 99.5% юзеров не страдают
    # (предыдущий whitelist'ный подход требовал поддержки списков подсетей через
    # github sync, что давало риск устаревания + complexity).

    # --- v3.11: Tor exit blocklist ---
    # Заполняется /usr/local/sbin/shieldnode-update-blocklist.sh tor (v3.12.0)
    # из check.torproject.org/torbulkexitlist (~1500 IPs, individual /32).
    # Активен только если оператор включил BLOCK_TOR=1 при установке.
    # Если выключен — set пустой, правило 'ip saddr @... drop' no-op.
    set tor_exit_blocklist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 8192
    }
    # --- v3.27.0 FIX(#7): IPv6-параллели blocklist-сетов ---
    # Заполняются тем же shieldnode-update-blocklist.sh (v6-парсинг фидов). Пустые,
    # пока фид не отдал v6 — правила 'ip6 saddr @..._v6 drop' тогда no-op. Type ipv6_addr.
    set scanner_blocklist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        size 65536
    }
    set threat_blocklist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        size 65536
    }
    set custom_blocklist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        size 16384
    }
    set tor_exit_blocklist_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        size 8192
    }
    # --- v2.5: STAGE 1 — SUSPECT (наблюдение 5 минут) ---
    # IP попадает сюда при первом превышении лимита.
    # Трафик НЕ дропается. Если за 5 минут IP опять превышает — переводим в confirmed.
    # Если не превышает — таймер истекает, забываем про IP (false positive).
    # v3.9: timeout поднят с 5m до 30m. Причина: 5m слишком коротко для
    # реальной защиты — клиент с retry (Reality mux, mobile reconnect) мог
    # залезть в suspect, через 6 мин попробовать снова, и таймер сбрасывался.
    # Ban-once не работал по сути. 30m даёт окно определить atакующего vs CGNAT.
    set suspect_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 30m
        size 65536
    }

    # v3.9: connlimit_v4 — отслеживает concurrent connections per source IP
    # для ct count. ВАЖНО: НЕ должен иметь timeout (по docs nftables wiki:
    # "ct count statement can only be used with add set statement, if you
    # define timeout, you will hit Operation is not supported error").
    # Conntrack table timers сами cleanup элементы при истечении соединений.
    set connlimit_v4 {
        type ipv4_addr
        flags dynamic
        size 65536
    }

    # v3.24.2: connwatch_v4 — отдельный per-source-IP ct-count для LOG-правила
    # near-threshold (X-1), чтобы лог НЕ матчился глобально. Без timeout (как
    # connlimit_v4 — conntrack timers cleanup'ят сами). Не дропает, не банит.
    set connwatch_v4 {
        type ipv4_addr
        flags dynamic
        size 65536
    }

    # v3.21.0: SSH-СПЕЦИФИЧНЫЕ сеты для pre-auth flood защиты.
    # ПРОБЛЕМА: SSH-порт ранее был полностью исключён из prerouting
    # ("tcp dport SSH accept"), а защита делегировалась CrowdSec'у через
    # auth.log. Это создавало дыру: атакующий мог открыть 100 параллельных
    # TCP-соединений до sshd, упереться в MaxStartups (sshd dropping pre-auth),
    # но softirq уже сожрал CPU на handshake. CrowdSec не видел повода банить
    # (нет failed login events — только pre-auth drop).
    # ФИКС: отдельный rate-limit на SSH с relaxed-лимитами (юзер коннектится
    # 1-3 раза за сессию, атакующий — 50+). Параметры намного мягче основных
    # protected_ports, чтобы НЕ забанить легитимного админа.
    set ssh_connlimit_v4 {
        type ipv4_addr
        flags dynamic
        size 16384
    }
    set ssh_newconn_rate_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 5m
        size 16384
    }
$SHIELD_V6_SETS

    # --- v2.5: STAGE 2 — CONFIRMED ATTACK (бан 1 час) ---
    # Сюда IP попадает если уже сидел в suspect и опять превысил лимит.
    # Это значит — точно атака, баним всерьёз.
    # v3.12.0 CGNAT FIX: timeout 1h → 15min. Если CGNAT IP попал false-positive,
    # быстро разблочится. Реальная атака возобновится — снова попадёт в бан.
    set confirmed_attack_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 15m
        size 65536
    }

    # --- LEGACY: syn_flood/udp_flood (для совместимости с guard и rate-limit) ---
    # Используются как rate-counter — IP попадает сюда при превышении.
    # Сами по себе не дропают трафик — это делают вышестоящие правила
    # на основе наличия IP в suspect/confirmed.
    set syn_flood_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }
    set udp_flood_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }

    # v3.5: rate-limit новых TCP-соединений (отдельно от SYN-flood — SYN считает ВСЕ
    # SYN-пакеты включая retry, а это считает уникальные new-conn по conntrack).
    # Дополняет SYN-rate-limit для случаев когда атакующий шлёт мало SYN, но
    # быстро открывает/закрывает много соединений (HTTP-flood через TLS).
    set newconn_rate_v4 {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1m
        size 65536
    }

    # --- Manual whitelist ---
    # Авто-заполняется management-IP из правил UFW "ALLOW from <IP>".
    # Также можно добавить вручную:
    #   nft add element inet ddos_protect manual_whitelist_v4 { 1.2.3.4 }
    set manual_whitelist_v4 {
        type ipv4_addr
        flags interval
        auto-merge
$MANUAL_WHITELIST_V4_INIT
    }

    # v3.28.0: авто-дискавери нод флота через Remnawave-панель. Заполняется
    # shieldnode-remnawave-sync.sh (GET /api/nodes по Bearer-токену) → IP всех нод
    # флота. Это СВОИ серверы (бриджи/ноды), не CGNAT-юзеры → whitelist безопасен.
    # Пусто, пока синк не отработал/выключен → accept по пустому сету = no-op.
    # Новую ноду добавил в панель — все ноды подхватят её на следующем тике, без
    # ручного редактирования TRUSTED_IPS на каждой.
    set remnawave_nodes_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        size 4096
    }
    set remnawave_nodes_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        size 4096
    }

    # v3.21.5: Infrastructure bypass — крупные CDN/cloud провайдеры
    # обходят rate-limit и conn_flood/newconn_rate, не попадая в events.db
    # как "атакующие". См. блок 3) Embedded CIDR baseline ниже.
    # Этот set заполняется через инициализацию (\$INFRASTRUCTURE_V4_INIT),
    # обновляется опционально через shieldnode-update@infrastructure.timer.
    # tcp_invalid и fib_spoof проверки работают для ВСЕХ включая инфра.
    set infrastructure_v4 {
        type ipv4_addr
        flags interval
        auto-merge
$INFRASTRUCTURE_V4_INIT
    }
    set infrastructure_v6 {
        type ipv6_addr
        flags interval
        auto-merge
$INFRASTRUCTURE_V6_INIT
    }
    # v2.7: Named counters для статистики "всего заблокировано".
    # Каждый counter сохраняет packets и bytes с момента старта nft.
    # Сбрасываются при ребуте/перезагрузке правил.
    counter scanner_drops_v4 { }
    counter confirmed_drops_v4 { }
    counter syn_confirmed_v4 { }
    counter udp_confirmed_v4 { }
    counter tor_drops_v4 { }      # v3.11: Tor exit nodes dropped
    counter threat_drops_v4 { }   # v3.12.0: Spamhaus/FireHOL drops
    counter custom_drops_v4 { }   # v3.12.0: operator personal blocklist drops
    # v3.22.0: counters mobile_ru_* и broadband_ru_* удалены (deprecated с v3.20.0).
    # v3.5: counters для HTTP/connection-flood защиты
    counter conn_flood_v4 { }     # ct count > 400 на src (v3.12.0: CGNAT-friendly)
    counter newconn_flood_v4 { }  # >50 new conn/min на src
    counter global_newconn_drop { } # v3.27.0 FIX(#3): глобальный new-conn backstop (opt-in SHIELD_GLOBAL_NEWCONN_CEIL)
    counter tcp_invalid { }       # invalid TCP flag combos
    # v3.21.0: SSH pre-auth flood counters (v3.21.4: лимиты ужесточены)
    counter ssh_conn_flood_v4 { }     # ct count > 3 на src для SSH-порта (было 5 до v3.21.4)
    counter ssh_newconn_flood_v4 { }  # > 5 new conn/min на src для SSH-порта (было 10 до v3.21.4)
    # v3.21.5: пакеты прошедшие через infrastructure bypass (Cloudflare/Google/AWS/etc).
    # Без log prefix — слишком много трафика. Только counter для observability.
    counter infrastructure_passes_v4 { }
    counter infrastructure_passes_v6 { }
    counter remnawave_nodes_pass_v4 { } # v3.28.0: трафик от нод флота (auto-whitelist)
    counter remnawave_nodes_pass_v6 { }

    chain prerouting {
        # v3.18.1: priority динамический ($SHIELD_PREROUTING_PRIO).
        # Если есть VPN-панель (Remnawave/Marzban/3x-ui) — используем -150
        # чтобы не конфликтовать с её 'priority dstnat' (=-100) для DSTNAT
        # маршрутизации клиентов VLESS. Если панели нет — -100 (стандарт).
        type filter hook prerouting priority $SHIELD_PREROUTING_PRIO; policy accept;

        # Established/related — пропускаем без проверок.
        ct state established,related accept

        # Manual whitelist (всегда первым приоритетом)
        ip saddr @manual_whitelist_v4 accept

        # v3.28.0: ноды флота из Remnawave-панели (auto-discovery) — свои серверы,
        # bypass всех лимитов как whitelist. Пустой сет = no-op.
        ip saddr @remnawave_nodes_v4 counter name remnawave_nodes_pass_v4 accept

        # SSH защита перенесена ниже scanner_blocklist для эффективности
        # (см. блок === SSH PRE-AUTH FLOOD PROTECTION ===).

$FIB_ANTISPOOF_RULE

        # === v3.5: TCP FLAG SANITY ===
        # Дропаем пакеты с невозможными комбинациями TCP-флагов.
        # Используются port-сканерами (nmap -sN/-sF/-sX), evasion-сценариями,
        # и stateless-атаками. Легитимный трафик их не использует.
        # tcp flags syn,fin    → SYN+FIN одновременно (XMAS-вариант)
        # tcp flags syn,rst    → SYN+RST одновременно (невозможно в TCP)
        # tcp flags fin,rst    → FIN+RST одновременно (нет смысла)
        # tcp flags == 0x0     → null scan (все флаги выключены)
        # tcp flags == fin,psh,urg → XMAS scan (nmap -sX)
        #
        # v3.15.3: добавлено логирование (rate 1/sec burst 5) — видно SRC
        # сканеров nmap -sN/-sF/-sX. Сами drop-правила ниже остались без
        # логов для производительности (большинство атак тут rate-limited
        # уже по факту, но первый пакет залогируется этим правилом).
        # v3.23.0: log-блок генерится опционально (SHIELDNODE_VERBOSE_LOGS=1).
        # Counter+drop правила ниже всегда активны.
$SHIELD_LOG_TCP_INVALID

        tcp flags & (fin|syn) == (fin|syn) counter name tcp_invalid drop
        tcp flags & (syn|rst) == (syn|rst) counter name tcp_invalid drop
        tcp flags & (fin|rst) == (fin|rst) counter name tcp_invalid drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter name tcp_invalid drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|psh|urg) counter name tcp_invalid drop

        # v3.20.0: блоки mobile-RU и broadband-RU whitelist'ов УБРАНЫ.
        # Теперь все IP идут через единые лимиты (см. ниже: conn_flood, newconn,
        # syn_flood, udp_flood). Whitelist'ы дополнительно не нужны потому что
        # глобальный лимит ct=3000 уже покрывает 99.5% RU broadband + mobile
        # юзеров. Для defense in depth остаются blocklist'ы и CrowdSec.

        # === v3.12.0: THREAT BLOCKLIST (Spamhaus DROP, FireHOL Level 1) ===
        # High-confidence криминальные сети. Идёт ПЕРВЫМ — самый дорогой
        # источник нежелательного трафика, отсекаем сразу.
        # v3.23.13 BUG-004 FIX: log ВСЕГДА активен.
        # v3.23.13 SR-FIX-1: meter (per-IP rate-limit) вместо global limit.
        # Раньше 'limit rate 1/sec' был GLOBAL — под массивной атакой
        # залогировался бы только один IP в секунду. С meter — 1/min per IP,
        # каждый атакующий получит attribution хотя бы раз в минуту.
        # Лимит per-IP × timeout 1h автоматически собирает только активных.
        ip saddr @threat_blocklist_v4 \\
            meter shield_threat_log { ip saddr limit rate 1/minute burst 5 packets } \\
            log prefix "[shield:threat] " level info flags ip options
        ip saddr @threat_blocklist_v4 counter name threat_drops_v4 drop

        # === v3.12.0: CUSTOM BLOCKLIST (operator personal IPs) ===
        # Источник: /etc/shieldnode/lists/custom.txt (+ опциональные URL'ы).
        # Идёт после threat но до scanner — оператор может явно перехватить
        # любой IP даже если других списков его пока нет.
        ip saddr @custom_blocklist_v4 \\
            meter shield_custom_log { ip saddr limit rate 1/minute burst 5 packets } \\
            log prefix "[shield:custom] " level info flags ip options
        ip saddr @custom_blocklist_v4 counter name custom_drops_v4 drop

        # Pre-emptive drop известных сканеров (с counter v2.7).
        # Стоит ПЕРЕД rate-limit — экономит conntrack-слоты и CPU.
        # v3.23.13 BUG-004 + SR-FIX-1: log ВСЕГДА с per-IP rate-limit.
        ip saddr @scanner_blocklist_v4 \\
            meter shield_scanner_log { ip saddr limit rate 1/minute burst 5 packets } \\
            log prefix "[shield:scanner] " level info flags ip options
        ip saddr @scanner_blocklist_v4 counter name scanner_drops_v4 drop

        # SSH защита перемещена ниже tor_blocklist drop (v3.21.1)
        # См. блок === SSH PRE-AUTH FLOOD PROTECTION ===

        # === v3.11: Tor exit blocklist drop ===
        # Set заполняется только если оператор активировал BLOCK_TOR=1.
        # Иначе set пустой, эти 2 правила — no-op (overhead близок к нулю,
        # nft проверка пустого set'а — O(1)).
        ip saddr @tor_exit_blocklist_v4 \\
            meter shield_tor_log { ip saddr limit rate 1/minute burst 5 packets } \\
            log prefix "[shield:tor] " level info flags ip options
        ip saddr @tor_exit_blocklist_v4 counter name tor_drops_v4 drop

        # === v3.21.5: INFRASTRUCTURE BYPASS ===
        # Крупные CDN/cloud (Cloudflare, Google, AWS, Azure, Apple, Meta,
        # Akamai, Fastly, GitHub, Telegram, Yandex, VK, Selectel) — accept
        # БЕЗ прохождения SSH rate-limit и conn_flood/newconn_rate проверок.
        # Решает проблему ложных банов: их IP попадали в events.db как
        # "топ атакующие" из-за TCP retransmits/conntrack quirks, оператор
        # копировал в custom.txt → блокировал половину интернета у VPN-клиентов.
        # Set заполняется embedded baseline на установке + dynamic updater.
        # Этот accept ПОСЛЕ blocklists (scanner/threat/tor) — если инфра-IP
        # каким-то чудом окажется в blocklist'е, всё равно дропнется раньше.
        # tcp_invalid и fib_spoof ВЫШЕ — работают для всех включая инфра.
        # v3.23.15 P0-2: infra-accept ПЕРЕМЕЩЁН НИЖЕ SSH-блока (см. ниже) +
        # IaaS убран из baseline — облако не обходит SSH-лимит/rate-limit.

        # === SSH PRE-AUTH FLOOD PROTECTION (v3.21.0, перемещён в v3.21.1) ===
        # v3.10.2: поддержка нескольких SSH-портов (e.g. миграция 22 → 2222)
        # До v3.21.0: SSH-порт полностью accept'ился, защита делегировалась
        # CrowdSec'у (парсит auth.log → банит за failed login). Дыра: pre-auth
        # TCP flood (100+ соединений до stage auth) проходил мимо защиты.
        # v3.21.0: добавлены rate-limits на SSH с RELAXED-лимитами:
        #   - max 5 одновременных соединений с одного IP
        #   - max 10 новых соединений за минуту с одного IP
        # Легитимный админ: 1-3 коннекта на сессию (далеко от лимитов).
        # Атакующий: 50+ pre-auth handshake → дропается на kernel-level.
        # Whitelist (manual_whitelist_v4 в начале) обходит ВСЁ — mgmt IP
        # точно не пострадают. CrowdSec продолжает работать поверх для
        # auth-level банов.
        # ВАЖНО для CI/CD: если используешь ansible (50+ хостов), GitLab runner,
        # массовый deploy через ssh из одного IP — добавь этот IP в whitelist:
        #   nft add element inet ddos_protect manual_whitelist_v4 { 1.2.3.4 }
        # Иначе массовое переподключение может попасть под лимит.
        # v3.21.1: блок ПЕРЕМЕЩЁН после scanner/tor/threat blocklist drops.
        # Причина: до v3.21.1 'tcp dport SSH accept' стоял после whitelist,
        # но до tor_blocklist → Tor exit nodes могли подключаться к SSH
        # даже при BLOCK_TOR=1. Теперь все blocklist'ы дропают раньше,
        # SSH-rate-limit работает только на оставшийся "чистый" трафик.
        # NB: ssh_connlimit_v4 без timeout — conntrack чистит сам (как у connlimit_v4).
        # ВАЖНО: правила в одну строку. Многострочный синтаксис с \\ ломается
        # в bash heredoc без кавычек — открывающий { трактуется как brace expansion.
        # v3.22.0: лимиты relaxed для CGNAT-админов + CI/CD.
        # Было (v3.21.4): ct=3, 5/min burst 15.
        # Стало (v3.22.0): ct=5, 8/min burst 20.
        # Обоснование: SSH-админы из офисов с CGNAT (роуминг, аэропорт WiFi)
        # делят public IP с другими людьми и CI/CD runners. tmux/screen +
        # параллельный SCP/rsync + ansible на ~8 нод требуют запаса.
        # Slowloris защита: атакующий делает 100+ концертных, всё равно
        # ловится (ct=5 << 100). 5 vs 3 — почти не меняет защиту от brute,
        # сильно снижает FP админов.
        # Параллельные действия что покрываются ct=5:
        #   - tmux/screen main session
        #   - второе SSH окно для tail -f
        #   - SCP/rsync для копирования
        #   - ansible parallel deploy (4 ноды одновременно)
        #   - случайно ушедший zombie SSH (timeout не закрылся)
        # CrowdSec + scanner_blocklist дают defence in depth поверх этих лимитов.
        tcp dport { $SSH_PORTS_NFT } ct state new add @ssh_connlimit_v4 { ip saddr ct count over $SHIELD_SSH_CT_LIMIT } counter name ssh_conn_flood_v4 drop
        tcp dport { $SSH_PORTS_NFT } ct state new add @ssh_newconn_rate_v4 { ip saddr limit rate over $SHIELD_SSH_NEWCONN_RATE burst $SHIELD_SSH_NEWCONN_BURST packets } counter name ssh_newconn_flood_v4 drop
        # Прошёл все blocklist'ы и оба лимита — пропускаем дальше к sshd.
        tcp dport { $SSH_PORTS_NFT } accept

        # === INFRASTRUCTURE BYPASS (v3.23.15 P0-2: перемещён сюда, ПОСЛЕ SSH) ===
        # CDN/edge accept без conn_flood/newconn/syn/udp (у них легит burst).
        # SSH обработан ВЫШЕ → облачные источники не обходят SSH-лимит.
        ip saddr @infrastructure_v4 counter name infrastructure_passes_v4 accept
        ip6 saddr @infrastructure_v6 counter name infrastructure_passes_v6 accept
$SHIELD_V6_RULES

        # === v2.5: BAN-ONCE АРХИТЕКТУРА ===
        # Двухэтапная проверка перед баном — снижает ложные баны CGNAT/мобильных.
        #
        # Этап 0: Если IP в confirmed_attack — он уже подтверждённый атакующий, дропаем.
        # v3.23.13 BUG-004 + SR-FIX-1: log ВСЕГДА активен с per-IP rate-limit
        # (1/min per IP через meter — каждый confirmed attacker получает
        # хотя бы один log per minute даже под массивным штормом).
        ip saddr @confirmed_attack_v4 \\
            meter shield_ddos_log { ip saddr limit rate 1/minute burst 5 packets } \\
            log prefix "[shield:ddos] " level info flags ip options
        ip saddr @confirmed_attack_v4 counter name confirmed_drops_v4 drop

        # === v3.5+v3.9: CONNECTION-FLOOD / SLOWLORIS ЗАЩИТА ===
        # Защищает от: тысяч одновременных TCP-соединений с одного IP,
        # медленного TLS handshake (slowloris), HTTP-flood через established TCP.
        # Применяется только к защищаемым TCP-портам (Xray/Reality/sing-box).
        # manual_whitelist уже пропущен выше.
        #
        # v3.9 CRITICAL FIX: правильный синтаксис per-source-IP.
        # Старый синтаксис "ct count over N" БЕЗ "ip saddr" в add-statement
        # был ГЛОБАЛЬНЫМ счётчиком conntrack. На VPN-нодах с >100 conntrack
        # это банило ВСЕХ клиентов. Правильный синтаксис (Red Hat docs +
        # nftables wiki Meters):
        #   add @set { ip saddr ct count over N }
        # Set ОБЯЗАТЕЛЬНО без timeout (иначе "Operation is not supported").
        # Conntrack timers сами cleanup элементы.
        #
        # v3.13.1: правила mobile_ru_whitelist перенесены ВЫШЕ blocklist drop'ов
        # (см. секцию 'MOBILE-RU AS WHITELIST' между TCP-flag-sanity и threat).
        # Здесь остаются только обычные conn-flood / newconn / SYN / UDP правила
        # которые применяются к НЕ-mobile трафику (mobile-RU уже accept выше).

        # === v3.5+v3.9+v3.10.2: CONNECTION-FLOOD / SLOWLORIS ЗАЩИТА ===
        # Защищает от: тысяч одновременных TCP-соединений с одного IP,
        # медленного TLS handshake (slowloris), HTTP-flood через established TCP.
        # Применяется только к защищаемым TCP-портам (Xray/Reality/sing-box).
        # manual_whitelist уже пропущен выше.
        #
        # === CONNECTION-FLOOD / SLOWLORIS ЗАЩИТА ===
        # v3.22.0: лимит поднят 5000 → 50000 для VPN-нод с 500-1000 клиентами.
        # Расчёт: CGNAT-провайдеры РФ (МТС, T2, Beeline, Tele2) держат до
        # 200 абонентов за одним public IPv4 через PAT. 200 юзеров × 150
        # conntrack entries/юзер (multi-tab браузер + WebSocket + streaming)
        # = 30000 concurrent connections per CGNAT IP — нормальный baseline.
        # При power-users (gaming + streaming + IDE) пиковые ~40000.
        # Лимит 50000 даёт запас 25% для extreme cases.
        # Slowloris атака — 100k-500k параллельных connections, всё равно
        # ловится. Реальные ботнет-атаки используют тысячи IP с 10-50 conn
        # на каждом — наш лимит per-source-IP их не ловит, но их ловят
        # threat_blocklist (Spamhaus) и CrowdSec CAPI community list.
        # ВАЖНО: требует net.netfilter.nf_conntrack_max >= 262144 (Ubuntu
        # default). На малых нодах (1GB RAM) — проверь sysctl.
        # История: v3.0=150 → v3.12.0=400 → v3.18.13=1500 → v3.20.0=3000 →
        #          v3.20.1=5000 → v3.22.0=50000 → v3.23.3=15000.
        # v3.23.3: снижение 50000→15000 после DDoS-инцидента 2026-05-24
        # где атакующие держали по 5k-128k conn/IP, проходили под лимит 50k.
        # Замер легитимных пиков на работающих нодах: 700-750 conn/IP.
        # 15000 = запас 20x от пика, при этом срезает все известные ботнеты
        # (топ атакующих в инциденте были >11k conn/IP).
        # v3.20.3: log УБРАН с этого правила (lograte 10000 строк/sec).
        # v3.23.13 BUG-004a + SR-FIX-1 FIX: добавлено ОТДЕЛЬНОЕ log правило
        # с per-IP meter — не trigger'ит add @set, не дропает.
        # Семантика: log срабатывает когда IP достиг threshold-1 (на грани),
        # meter rate-limit 1/min per-IP даёт fair attribution даже при
        # massive ботнете (каждый атакующий хоть раз логируется в минуту).
        #
        # Архитектура:
        #   (1) Log-rule: per-IP 'add @connwatch_v4 { ip saddr ct count over X-1 }'
        #       — match ТОЛЬКО когда у конкретного src >X-1 conns (v3.24.2;
        #       раньше был глобальный 'ct count over X-1' → лог-шум на busy-ноде).
        #       meter per-IP rate-limit (1/min). Counter+drop НЕТ — пакет идёт
        #       дальше в правило (2).
        #   (2) Drop rule (как в v3.23.12): atomic match-add-counter-drop.
        #       Counter показывает реальные дропы.
        tcp dport @protected_ports_tcp ct state new \\
            add @connwatch_v4 { ip saddr ct count over $SHIELD_CT_CONN_FLOOD_MINUS_1 } \\
            meter shield_conn_flood_log { ip saddr limit rate 1/minute burst 5 packets } \\
            log prefix "[shield:conn_flood] " level info flags ip options
        tcp dport @protected_ports_tcp ct state new \\
            add @connlimit_v4 { ip saddr ct count over $SHIELD_CT_CONN_FLOOD } \\
            counter name conn_flood_v4 drop

        # === NEW CONNECTION RATE-LIMIT ===
        # v3.22.0: лимит 5000/min → 40000/min для 500-1000 клиентов на ноде.
        # Базовый rate: CGNAT 200 юзеров × 3-5 reconnect/min = 600-1000/min.
        # Storm reconnect (упала WiFi у вышки): 200 юзеров × 50 retry/min
        # = 10000/min sustained. Burst 60000 покрывает 3-минутный шторм.
        # Реальные new-conn flood атаки = 100k-500k/min, ловятся.
        # История: v3.0=200/min → v3.12.0=500/min → v3.18.13=1500/min →
        #          v3.20.0=3000/min → v3.20.1=5000/min → v3.22.0=40000/min.
        tcp dport @protected_ports_tcp ct state new \\
            add @newconn_rate_v4 { ip saddr limit rate over $SHIELD_RATE_NEWCONN burst $SHIELD_RATE_NEWCONN_BURST packets } \\
            jump newconn_overflow

        # === TCP SYN rate-limit ===
        # v3.22.0: 300/sec → 2000/sec для 500-1000 клиентов на ноде.
        # CGNAT 200 юзеров × 1-2 SYN/sec base = 200-400/sec. При reconnect
        # storm (network blip) 200 × 10 SYN/sec retry = 2000/sec.
        # Реальный SYN-flood атака = 50k-500k SYN/sec, отлично ловится.
        # Reality scanner делает 50-200 SYN/sec — проходит (был никогда не
        # ловился даже на 300/sec). Это приемлемо: scanner не вредит сам
        # по себе, нас защищает Reality SNI fingerprint validation.
        # Burst 3000 покрывает мгновенные пики (рестарт серверной стороны
        # → все клиенты одновременно retry).
        # История: v3.0=60/sec → ... → v3.20.0=300/sec → v3.22.0=2000/sec.
        tcp dport @protected_ports_tcp ct state new \\
            add @syn_flood_v4 { ip saddr limit rate over $SHIELD_RATE_SYN burst $SHIELD_RATE_SYN_BURST packets } \\
            jump syn_overflow

        # === UDP rate-limit ===
        # v3.22.0: 1500/sec → 10000/sec для 500-1000 клиентов на ноде.
        # Контекст: Hysteria2/AmneziaWG/WireGuard через QUIC активно used.
        # Per-user: 4K stream ~600 pkt/sec, 8K ~1500, cloud gaming ~2500,
        # VR streaming до 3000. Базовый non-streaming юзер ~50-100/sec.
        # CGNAT 200 юзеров mix: 50% idle (50 pkt/sec) + 30% browsing
        # (200 pkt/sec) + 20% streaming/gaming (1500 pkt/sec) = ~75000/sec.
        # На практике одновременно стримит ~10-20% = 10-30k/sec sustained.
        # Лимит 10000/sec ловит реальные UDP-flood атаки (>100k pkt/sec),
        # но дропает экстремальные CGNAT peaks. Trade-off: 1% CGNAT-юзеров
        # с stable 4K на 50+ устройствах за одним IP могут видеть drop —
        # whitelist их через TRUSTED_IPS.
        # Burst 20000 покрывает мгновенные spikes (всех reconnect одновременно).
        # Реальный UDP-flood атака — 100k-1M pkt/sec, гарантированно ловится.
        # История: v3.20.0/v3.20.1=1500/sec → v3.22.0=10000/sec.
        udp dport @protected_ports_udp \\
            add @udp_flood_v4 { ip saddr limit rate over $SHIELD_RATE_UDP burst $SHIELD_RATE_UDP_BURST packets } \\
            jump udp_overflow
$SHIELD_GLOBAL_NEWCONN_RULE
    }

    # === v3.10.2: подцепочки overflow-обработки ===
    # Эти цепочки вызываются ИЗ prerouting через jump, ТОЛЬКО когда meter
    # уже обнаружил overflow (rate over limit). Решают: confirm-vs-suspect.
    # Не трогают meter-set'ы → не могут вызвать double-charge.
    chain newconn_overflow {
        # v3.27.0 FIX(#8): тело из \$NEWCONN_OVERFLOW_BODY (CGNAT-safe rate-shape vs escalate).
        $NEWCONN_OVERFLOW_BODY
    }

    chain syn_overflow {
        # v3.27.0 FIX(#8): тело из \$SYN_OVERFLOW_BODY. CGNAT-safe: shape+log без escalate.
        $SYN_OVERFLOW_BODY
    }

    chain udp_overflow {
        # v3.27.0 FIX(#8): тело из \$UDP_OVERFLOW_BODY. CGNAT-safe: shape+log без escalate.
        $UDP_OVERFLOW_BODY
    }

    # === v3.20.5: MSS clamping moved to vpn-node-setup (ШАГ 7.8) ===
    # Раньше shieldnode делал MSS clamp на forward hook ("tcp option maxseg
    # size set rt mtu"). Теперь этим владеет vpn-node-setup
    # (table inet vpn_node_mss_clamp, hook forward priority -150).
    # Удалено отсюда чтобы избежать двойного clamp'а в netfilter pipeline.
    # Если vpn-node-setup на ноде НЕ установлен — MSS clamp не делается
    # вообще, клиенты с PMTU<1500 (мобильные, PPPoE) могут видеть blackhole.
}
EOF

# v3.23.13 SR-FIX-3: ДВУХФАЗНАЯ загрузка nft правил.
# Раньше `nft -f` сразу применял ruleset — если ошибка, защита упала на
# время до фикса.
# Теперь:
#   (1) `nft -c -f` parse-only check (НЕ применяет). Если syntax error
#       выловит здесь и НЕ тронет работающий ruleset.
#   (2) `nft -f` apply только после успешного parse.
# `-c` (--check) флаг доступен с nftables 0.9.0+.
if nft -c -f "$NFT_DDOS_CONF" 2>&1; then
    print_ok "nft conf parse-check OK"
else
    print_error "nft parse-check FAILED — конфиг содержит синтаксические ошибки"
    print_error "Старый ruleset (если был) ОСТАЁТСЯ активен. Исправь $NFT_DDOS_CONF и retry."
    exit 1
fi

# Загружаем правила
if nft -f "$NFT_DDOS_CONF" 2>&1; then
    print_ok "nft rate-limit активен"
else
    print_error "Ошибка загрузки nft-правил — смотри вывод выше"
    exit 1
fi

# ============================================================================
# v3.23.16: SYNPROXY модуль (opt-in, conntrack-exhaustion защита)
# ============================================================================
# Изолированный модуль (отдельная nft table inet shield_synproxy, отдельный
# процесс). Управляется флагом SHIELD_SYNPROXY (default 1, v3.24.0). ddos_protect не
# трогается. Запускаем ПОСЛЕ загрузки основной таблицы — модуль детектит
# protected_ports_tcp из живого ruleset'а.
cat > /usr/local/sbin/shieldnode-synproxy.sh <<'SYNPROXY_MODULE_EOF'
#!/bin/bash
# shieldnode-synproxy v0.2 — opt-in SYNPROXY (защита от conntrack-exhaustion).
# SYN перехватывается ДО conntrack (syncookies); запись в conntrack только после
# завершённого 3-way → SYN-флуд не течёт таблицу. Изолированная table
# inet shield_synproxy (ddos_protect не трогает, откат = удаление). v3.27.1: SSH ТОЖЕ
# покрыт по умолчанию (анти-спуф-SYN на SSH-порт; SHIELD_SYNPROXY_SSH=0 чтобы выключить).
# enable: verify mss/wscale против бэкенда + проверка untracked с авто-откатом
# (если другой фаервол дропает untracked — иначе оборвало бы клиентов).
set -euo pipefail

TABLE="inet shield_synproxy"
NFT_FILE="/etc/shieldnode/synproxy.nft"
SYSCTL_FILE="/etc/sysctl.d/99-shieldnode-synproxy.conf"
DDOS_TABLE="inet ddos_protect"
VERIFY_SECS="${SHIELD_SYNPROXY_VERIFY_SECS:-6}"
PROBE_SECS="${SHIELD_SYNPROXY_PROBE_SECS:-8}"

log(){ printf '%s\n' "$*" >&2; }
die(){ log "ERROR: $*"; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

detect_dev(){
    local d
    d=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    [ -n "${d:-}" ] || d=$(ip -o link show up 2>/dev/null | awk -F': ' '$2!="lo"{print $2;exit}')
    echo "${d:-eth0}"
}

detect_ports(){
    local raw
    raw=$(nft list set $DDOS_TABLE protected_ports_tcp 2>/dev/null \
          | tr '\n' ' ' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' | tr -d ' \t')
    [ -n "$raw" ] && { echo "$raw"; return; }
    echo "443"
}
# v3.27.1 FIX(#6): SSH-порты для SYNPROXY (спуф-SYN на SSH иначе течёт conntrack —
# SSH не в protected_ports_tcp, значит не покрыт ни synproxy, ни ctguard-капом).
# Детектим listener'ы sshd в рантайме (как установщик). Пусто → ничего не добавляем.
detect_ssh_ports(){
    ss -tlnpH 2>/dev/null | awk '
        /users:\(.*"sshd"/ {
            split($4, a, ":"); port = a[length(a)]
            if ($4 ~ /^127\./ || $4 ~ /^\[::1\]/) next
            print port
        }' | sort -un | tr '\n' ',' | sed 's/,$//'
}
detect_mss(){ local m; m=$(cat "/sys/class/net/$(detect_dev)/mtu" 2>/dev/null || echo 1500); echo $((m-40)); }
detect_wscale(){
    local rmax space=65535 w=0
    rmax=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')
    [ -n "${rmax:-}" ] || rmax=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 6291456)
    while [ "$space" -lt "$rmax" ] && [ "$w" -lt 14 ]; do space=$((space*2)); w=$((w+1)); done
    echo "$w"
}

PORTS="${SHIELD_SYNPROXY_PORTS:-$(detect_ports)}"
# v3.27.1 FIX(#6): по умолчанию покрываем и SSH (спуф-SYN-флуд на SSH иначе течёт
# conntrack). SYNPROXY прозрачен для легитимных хендшейков; established SSH-сессии не
# рвутся (accept по ct established выше). Отключить: SHIELD_SYNPROXY_SSH=0.
if [ "${SHIELD_SYNPROXY_SSH:-1}" = "1" ]; then
    _sshp="$(detect_ssh_ports || true)"
    [ -n "${_sshp:-}" ] && PORTS="${PORTS:+$PORTS,}${_sshp}"
fi
MSS="${SHIELD_SYNPROXY_MSS:-$(detect_mss)}"
WSCALE="${SHIELD_SYNPROXY_WSCALE:-$(detect_wscale)}"
FIRST_PORT="$(echo "$PORTS" | tr ',' '\n' | head -1 | cut -d- -f1)"

synproxy_syn_total(){
    local s=0 syn rest hdr v
    [ -r /proc/net/stat/synproxy ] || { echo 0; return; }
    while read -r hdr syn rest; do
        [ "$hdr" = "entries" ] && continue
        v=$(( 16#${syn:-0} )) 2>/dev/null || v=0
        s=$(( s + v ))
    done < /proc/net/stat/synproxy
    echo "$s"
}

cap_check(){
    modprobe nf_synproxy 2>/dev/null || true
    modprobe nf_conntrack 2>/dev/null || true
    # v3.24.0: на стоковых ядрах nf_synproxy может быть в linux-modules-extra — доустановим
    if ! lsmod 2>/dev/null | grep -qw nf_synproxy && command -v apt-get >/dev/null 2>&1; then
        log "nf_synproxy не загружен — пробую linux-modules-extra-$(uname -r) (на XanMod встроен, пропустится)…"
        DEBIAN_FRONTEND=noninteractive apt-get install -y "linux-modules-extra-$(uname -r)" >/dev/null 2>&1 || true
        modprobe nf_synproxy 2>/dev/null || true
    fi
    nft -c -f - >/dev/null 2>&1 <<'PROBE' || die "ядро/nft без SYNPROXY (нужен CONFIG_NFT_SYNPROXY / kernel >=5.14). Обнови ядро или используй обычную SYN-rate защиту."
table inet __sp_probe {
    chain c {
        type filter hook input priority 0;
        tcp dport 443 ct state invalid,untracked synproxy mss 1460 wscale 7 timestamp sack-perm
    }
}
PROBE
}

verify_backend_mss_wscale(){
    [ "${SHIELD_SYNPROXY_NOVERIFY:-0}" = "1" ] && { log "verify пропущен (NOVERIFY=1)"; return 0; }
    have tcpdump || { log "tcpdump не найден — проверку mss/wscale пропускаю (авто-детект mss=$MSS wscale=$WSCALE)"; return 0; }
    local dev cap mss_seen wscale_seen
    dev=$(detect_dev)
    log "Проверяю нативный SYN-ACK бэкенда на :$FIRST_PORT (${VERIFY_SECS}s, нужен живой трафик)…"
    cap=$(timeout "$VERIFY_SECS" tcpdump -ni "$dev" -c1 -v \
          "tcp src port $FIRST_PORT and tcp[tcpflags]=(tcp-syn|tcp-ack)" 2>/dev/null || true)
    mss_seen=$(echo "$cap"    | grep -oE 'mss [0-9]+'    | head -1 | awk '{print $2}' || true)
    wscale_seen=$(echo "$cap" | grep -oE 'wscale [0-9]+' | head -1 | awk '{print $2}' || true)
    if [ -z "${mss_seen:-}" ]; then
        log "  (живого SYN-ACK за окно нет — оставляю авто-детект mss=$MSS wscale=$WSCALE)"
        return 0
    fi
    log "  нативный бэкенд: mss=$mss_seen wscale=${wscale_seen:-?}"
    if [ "$mss_seen" != "$MSS" ]; then
        log "  ⚠ MSS расходится (synproxy=$MSS, бэкенд=$mss_seen) → выставляю $mss_seen"
        MSS="$mss_seen"
    fi
    if [ -n "${wscale_seen:-}" ] && [ "$wscale_seen" != "$WSCALE" ]; then
        log "  ⚠ wscale расходится (synproxy=$WSCALE, бэкенд=$wscale_seen) → выставляю $wscale_seen"
        WSCALE="$wscale_seen"
    fi
}

verify_untracked_reaches(){
    [ "${SHIELD_SYNPROXY_NOVERIFY:-0}" = "1" ] && return 0
    have tcpdump || { log "tcpdump не найден — проверку доходимости untracked пропускаю"; return 0; }
    local dev before after syn_in i fails=0
    dev=$(detect_dev)
    log "Проверяю что untracked SYN доходит до synproxy (до 3×${PROBE_SECS}s)…"
    # v3.28.7 FIX: откатываем ТОЛЬКО при ДВУХ подтверждённых окнах "SYN есть, а
    # synproxy их не считает". Одиночное окно ложно срабатывает: ретрансмиты и
    # уже-tracked SYN synproxy законно не считает (он видит лишь untracked-new),
    # хотя слой исправен. Раньше одно такое окно → спонтанный disable+exit 3 при
    # install (фоновые сканеры) → ложный synproxy_enable_failed/DEGRADED, хотя
    # вручную позже включалось. Успех на ЛЮБОМ окне = слои уживаются.
    for i in 1 2 3; do
        before=$(synproxy_syn_total)
        syn_in=$(timeout "$PROBE_SECS" tcpdump -ni "$dev" -c1 \
                 "tcp dst port $FIRST_PORT and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0" 2>/dev/null | wc -l)
        after=$(synproxy_syn_total)
        if [ "${syn_in:-0}" -eq 0 ]; then
            [ "$i" = "1" ] && { log "  (входящих SYN на :$FIRST_PORT за окно нет — пропускаю; повтори под нагрузкой/nc)"; return 0; }
            continue
        fi
        if [ "$after" -gt "$before" ]; then
            log "  ✔ untracked SYN доходит (syn_received растёт) — слои уживаются."
            return 0
        fi
        fails=$((fails+1))
        log "  ⚠ окно $i: входящие SYN есть, а synproxy их не считает (${fails}/2)"
        [ "$fails" -ge 2 ] && break
    done
    if [ "${fails:-0}" -ge 2 ]; then
        log "  ✖ ВХОДЯЩИЕ SYN ЕСТЬ, но synproxy их не видит (подтверждено ${fails} окнами)."
        log "    Другой фаервол (UFW/firewalld/кастом) дропает UNTRACKED раньше synproxy."
        log "    АВТО-ОТКАТ во избежание обрыва клиентов. Разбери конфликт слоёв и включи заново."
        disable
        exit 3
    fi
    log "  (проверка неоднозначна — synproxy оставлен активным; повтори под нагрузкой: shieldnode-synproxy.sh on)"
    return 0
}

write_conf(){
    local ports_nft="${PORTS//,/, }"
    # v3.24.2: кэпим анонсируемый клиентам MSS (после verify_backend, который мог
    # выставить большой backend-MSS). Слишком большой MSS = PMTU-blackhole для
    # RU-мобайла/PPPoE/DSL. Кэп ТОЛЬКО понижает → всегда безопасно (клиент шлёт
    # сегменты <= min(свой, анонс)). Поднять: SHIELD_SYNPROXY_MSS_CAP=0 (off).
    local mss_cap="${SHIELD_SYNPROXY_MSS_CAP:-1400}"
    if [ "${mss_cap:-0}" -gt 0 ] 2>/dev/null && [ "${MSS:-0}" -gt "$mss_cap" ] 2>/dev/null; then
        log "  MSS=$MSS > cap $mss_cap → анонсирую $mss_cap (low-path-MTU клиенты; SHIELD_SYNPROXY_MSS_CAP)"
        MSS="$mss_cap"
    fi
    mkdir -p /etc/shieldnode
    cat > "$NFT_FILE" <<EOF
#!/usr/sbin/nft -f
# shieldnode SYNPROXY — изолированная table, НЕ трогает inet ddos_protect.
# mss/wscale подогнаны под бэкенд (verify на enable), MSS кэпится под low-path-MTU
# (SHIELD_SYNPROXY_MSS_CAP, default 1400). При жалобах — понизь SHIELD_SYNPROXY_MSS.
table inet shield_synproxy {
    set sp_ports {
        type inet_service
        flags interval
        auto-merge
        elements = { ${ports_nft} }
    }
    chain pre_raw {
        type filter hook prerouting priority -300; policy accept;
        # v3.28.4: fib daddr type local — notrack ТОЛЬКО для трафика, адресованного
        # самому хосту. Без этого на форвардящем хосте (Docker/панель/роутер) notrack
        # цеплял ТРАНЗИТНЫЙ трафик контейнера к удалённой ноде на том же порту (напр.
        # панель→node:2223) и ломал его conntrack/NAT → нода уходила в offline.
        fib daddr type local tcp dport @sp_ports tcp flags syn / fin,syn,rst,ack notrack
    }
    chain in_synproxy {
        type filter hook input priority -275; policy accept;
        tcp dport @sp_ports ct state invalid,untracked synproxy mss ${MSS} wscale ${WSCALE} timestamp sack-perm
        tcp dport @sp_ports ct state invalid drop
    }
}
EOF
}

enable(){
    cap_check
    nft list table $TABLE >/dev/null 2>&1 && nft delete table $TABLE
    verify_backend_mss_wscale
    sysctl -qw net.netfilter.nf_conntrack_tcp_loose=0 2>/dev/null || true
    sysctl -qw net.ipv4.tcp_syncookies=1 2>/dev/null || true
    cat > "$SYSCTL_FILE" <<SCTL
# shieldnode SYNPROXY requirements
net.netfilter.nf_conntrack_tcp_loose=0
net.ipv4.tcp_syncookies=1
SCTL
    write_conf
    nft -c -f "$NFT_FILE" || die "сгенерированный ruleset не парсится"
    nft -f "$NFT_FILE" || die "применение ruleset не удалось (nft -f) — нет модуля ядра nf_synproxy? см. dmesg"
    log "✔ SYNPROXY включён: порты={${PORTS}} mss=${MSS} wscale=${WSCALE}"
    verify_untracked_reaches
    log "  conntrack_tcp_loose=0, syncookies=1 (persisted ${SYSCTL_FILE})"
    # v3.28.7: enable дошёл до конца (verify не откатил) → снимаем degraded-маркер,
    # как делает install-блок. Раньше ручной `on` оставлял залежавшийся маркер.
    rm -f /var/lib/shieldnode/.synproxy-degraded 2>/dev/null || true
}

disable(){
    nft list table $TABLE >/dev/null 2>&1 && nft delete table $TABLE && log "table $TABLE удалена"
    rm -f "$NFT_FILE" "$SYSCTL_FILE"
    log "✔ SYNPROXY выключен."
}

status(){
    echo "ports = {${PORTS}}   mss = ${MSS}   wscale = ${WSCALE}"
    echo "loose = $(sysctl -n net.netfilter.nf_conntrack_tcp_loose 2>/dev/null || echo '?')"
    echo ""
    if nft list table $TABLE >/dev/null 2>&1; then
        echo "SYNPROXY: ACTIVE"
        echo "--- conntrack count ---"
        conntrack -C 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true
        echo "--- synproxy cookie stats ---"
        cat /proc/net/stat/synproxy 2>/dev/null || echo "(нет статы)"
    else
        echo "SYNPROXY: inactive"
    fi
}

dryrun(){
    cap_check && log "✔ ядро/nft поддерживают SYNPROXY"
    write_conf
    nft -c -f "$NFT_FILE" && log "✔ ruleset валиден (порты={${PORTS}} mss=${MSS} wscale=${WSCALE})"
    log "(ничего не применено)"
}

case "${1:-status}" in
    on|enable|start)  enable ;;
    off|disable|stop) disable ;;
    status)           status ;;
    dryrun|check)     dryrun ;;
    *) echo "usage: $0 {on|off|status|dryrun}"; exit 1 ;;
esac
SYNPROXY_MODULE_EOF
chmod 0755 /usr/local/sbin/shieldnode-synproxy.sh

if [ "$SHIELD_SYNPROXY" = "1" ]; then
    print_status "SHIELD_SYNPROXY=1 → включаю SYNPROXY-слой"
    # enable применяет слой + verify mss/wscale + проверка untracked (авто-откат)
    if /usr/local/sbin/shieldnode-synproxy.sh on; then
        # boot-persistence: грузим зафиксированный synproxy.nft при старте (без verify)
        cat > /etc/systemd/system/shieldnode-synproxy.service <<'SPUNIT'
[Unit]
Description=Shieldnode SYNPROXY ruleset
After=shieldnode-nftables.service
Wants=shieldnode-nftables.service
ConditionPathExists=/etc/shieldnode/synproxy.nft
[Service]
Type=oneshot
RemainAfterExit=yes
# v3.28.7 FIX: на ядрах где nf_synproxy — загружаемый МОДУЛЬ (стоковые + часть
# XanMod-сборок) при boot он может быть не подгружен → голый `nft -f` с synproxy-
# правилом падал и SYNPROXY не вставал после ребута. Грузим модуль ДО применения.
# v3.28.9 FIX: modprobe ищется через PATH (sh -c), а не хардкодом /sbin/modprobe —
# на части систем он в /usr/sbin, и хардкод+'-' молча пропускал загрузку → баг
# возвращался. 'true' в конце = шаг никогда не фейлит старт сервиса.
ExecStartPre=-/bin/sh -c 'modprobe nf_synproxy 2>/dev/null; modprobe nf_conntrack 2>/dev/null; true'
ExecStart=/usr/sbin/nft -f /etc/shieldnode/synproxy.nft
[Install]
WantedBy=multi-user.target
SPUNIT
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable shieldnode-synproxy.service >/dev/null 2>&1 || true
        rm -f /var/lib/shieldnode/.synproxy-degraded 2>/dev/null || true   # v3.27.0 FIX(#5): снимаем degraded-маркер
        print_ok "SYNPROXY активен и переживёт ребут"
    else
        # v3.27.0 FIX(#5): fail-loud. Раньше тихо падали на ddos_protect rate-limit —
        # на стоковом ядре без nf_synproxy (и без интернета для modules-extra) это
        # СЛАБЕЕ: SYN под per-src лимитом проходит → создаёт SYN_RECV-conntrack →
        # таблица течёт → conntrack-exhaustion при SYN-флуде. Оператор должен ЗНАТЬ.
        mkdir -p /var/lib/shieldnode 2>/dev/null || true
        {
            echo "degraded_at=$(date -u +%FT%TZ)"
            echo "reason=synproxy_enable_failed"
            echo "kernel=$(uname -r)"
            echo "note=ddos_protect rate-limit активен, но conntrack-exhaustion-защита SYN ослаблена"
        } > /var/lib/shieldnode/.synproxy-degraded 2>/dev/null || true
        logger -t shieldnode "ALERT: SYNPROXY запрошен (SHIELD_SYNPROXY=1), но НЕ включился — нода на ослабленной SYN-защите (см. /var/lib/shieldnode/.synproxy-degraded)"
        print_error "════════════════════════════════════════════════════════════════"
        print_error "⚠ SYNPROXY НЕ ВКЛЮЧИЛСЯ — нода на ОСЛАБЛЕННОЙ защите от SYN-флуда!"
        print_error "  ddos_protect rate-limit работает, но conntrack может переполниться"
        print_error "  при SYN-флуде (SYN под per-src лимитом создаёт conntrack-записи)."
        print_warn  "  Причина обычно: нет модуля ядра nf_synproxy (стоковое ядро без"
        print_warn  "  linux-modules-extra) или ядро < 5.14, либо не было интернета."
        if uname -r | grep -qi xanmod; then
            print_info  "  Ядро XanMod: nf_synproxy встроен — пакет ставить НЕ надо. Запусти"
            print_info  "  'sudo shieldnode-synproxy.sh on' и смотри dmesg | grep -i synproxy."
        else
            print_info  "  Починить:  sudo apt install linux-modules-extra-$(uname -r) && sudo shieldnode-synproxy.sh on"
            print_info  "  Либо обнови ядро (XanMod несёт nf_synproxy встроенным)."
        fi
        print_info  "  Маркер degraded виден в 'sudo guard'. Скрытно деградировать не будем."
        print_error "════════════════════════════════════════════════════════════════"
    fi
else
    print_info "SYNPROXY выключен (SHIELD_SYNPROXY=0). Дефолт — вкл. Включить: sudo shieldnode-synproxy.sh on"
fi

# ════════════════════════════════════════════════════════════════════
# v3.24.0: anti-conntrack-exhaustion guard (shieldnode-ctguard)
# Изолированная таблица inet shield_ctguard (priority -160 → раньше ddos_protect).
# ddos_protect НЕ трогает; откат = удаление таблицы. Эвиктит только аномальные источники.
# ════════════════════════════════════════════════════════════════════
cat > /usr/local/sbin/shieldnode-ctguard.sh <<'CTGUARD_EOF'
#!/bin/bash
# shieldnode conntrack/connection-flood guard v3.26.0. Таймер раз в ~15с.
# v3.26.0: фантом-детект ПО ЖИВЫМ СОКЕТАМ (ss vs conntrack), acct-free; ss-phantom-ratio
# триггер; conntrack-exhaustion guard. Заменяет байтовый детектор (тот при acct=0 видел
# все флоу как «фантом» → масс-эвикт CGNAT). ENFORCE=0 → наблюдение (только лог).
# Изолированная таблица inet shield_ctguard (priority -160). ddos_protect не трогает.
set -uo pipefail
export LC_ALL=C
CONF=/etc/shieldnode/shieldnode.conf
[ -r "$CONF" ] && . "$CONF" 2>/dev/null || true
SHIELD_CTGUARD="${SHIELD_CTGUARD:-1}"
WARN="${SHIELD_CT_WARN_PCT:-80}"; HIGH="${SHIELD_CT_HIGH_PCT:-90}"; RECOVER="${SHIELD_CT_RECOVER_PCT:-70}"
EVICT_TTL="${SHIELD_CT_EVICT_TTL:-30m}"
MULT_IN="${SHIELD_CTG_MULT_IN:-4}"; MULT_OUT="${SHIELD_CTG_MULT_OUT:-2}"
FLOOR_RATE="${SHIELD_CTG_FLOOR_RATE:-200}"
FLOOR_CT="${SHIELD_CTG_FLOOR_CT:-20000}"
# v3.26.0 phantom-eviction ПО ЖИВЫМ СОКЕТАМ (ss), acct-free.
# v3.26.4 PH_MIN дефолт 500→4000: на мобильных/CGNAT-нодах легит-клиенты бросают
# соединения быстрее, чем est_to их реапит → conntrack≫live и у ЛЕГИТА тоже (churn).
# Порог 4000 выше потолка легит-CGNAT-churn (~2200) и ниже connect-and-hold атаки (7000+),
# что делает ENFORCE=1 безопасным на CGNAT. Не-CGNAT ноды могут понизить для чувствительности.
PH_MIN="${SHIELD_CTG_PHANTOM_MIN:-4000}"         # мин. conntrack-флоу с источника, чтобы считать его холдером
LIVE_FRAC="${SHIELD_CTG_LIVE_FRAC:-10}"          # выселять если live/conntrack < этого % (фантом-холдер)
ACTIVE_FLOOR="${SHIELD_CTG_ACTIVE_FLOOR:-20}"    # > стольких ЖИВЫХ сокетов у источника → shared-front/CGNAT → НЕ трогаем
PHR_TRIG="${SHIELD_CTG_PHANTOM_RATIO:-60}"       # % ss-phantom-ratio (сигнал; attack-mode только если есть РЕАЛЬНЫЙ холдер)
AGG_CAP="${SHIELD_CTG_AGG_CAP:-0}"               # v3.26.4: агрегатный кап new-conn по фантому. 0=off (прямые ноды), 1=on (CDN/мост, где per-IP эвикт невозможен)
ENFORCE="${SHIELD_CTG_ENFORCE:-1}"               # 1=выселять; 0=только лог (наблюдение)
CT_MAX_CEIL="${SHIELD_CTG_CT_MAX_CEIL:-1048576}" # до какого потолка авто-поднимать nf_conntrack_max
COARSE_MULT="${SHIELD_CTG_COARSE_MULT:-3}"       # perf: полный conntrack-дамп только если conntrack > ss_total×это (или attack-mode)
UDP_FLOOR="${SHIELD_CTG_UDP_FLOOR:-3000}"        # v3.27.0 FIX(#1): пол агрегатного UDP-капа new-flow/с в attack-mode (QUIC reconnect выше TCP)
CT_RAM_PCT="${SHIELD_CTG_CT_RAM_PCT:-25}"        # v3.27.0 FIX(#13): conntrack не более этого %% от MemAvailable (анти-OOM при авто-росте max)
PH_MIN_DIST="${SHIELD_CTG_PHANTOM_MIN_DIST:-800}" # v3.27.0 FIX(#2): порог 2-го прохода (распределённый connect-and-hold); эвикт ТОЛЬКО при live==0
DISTRIBUTED="${SHIELD_CTG_DISTRIBUTED:-1}"        # v3.27.0 FIX(#2): 2-й проход против распределённого hold (1=вкл, только в sustained-attack)
ATTACK_MIN_TICKS="${SHIELD_CTG_ATTACK_MIN_TICKS:-2}" # v3.27.0 FIX(#9)/v3.27.1: порог аномалий В ОКНЕ для глоб. капа (PCT>=HIGH капает сразу)
ANOM_WINDOW="${SHIELD_CTG_ANOM_WINDOW:-4}"        # v3.27.1 FIX(#1 pulsing): размер скользящего окна тиков (≥ATTACK_MIN_TICKS аномалий в окне → sustained)
CAP_FLOOR="${SHIELD_CTG_CAP_FLOOR:-1000}"         # v3.27.0 FIX(#9): мин. значение глобального TCP-капа new-conn/с (не душить легит reconnect)
CSCLI="${SHIELD_CTG_CSCLI:-1}"; CSCLI_TTL="${SHIELD_CTG_CSCLI_TTL:-6h}"
ALPHA_NUM="${SHIELD_CTG_ALPHA_NUM:-5}"           # EWMA alpha = ALPHA_NUM/100
TAG=shieldnode-ctguard
RUN=/run/shieldnode; ST=/var/lib/shieldnode
mkdir -p "$RUN" "$ST" 2>/dev/null || true
TIER_F="$RUN/ctguard.tier"; EVICT_F="$RUN/ctguard.evicted"; MODE_F="$RUN/ctguard.mode"
PREV_F="$RUN/ctguard.prev"; BASE_F="$ST/ctguard-base"; STREAK_F="$RUN/ctguard.attackstreak"

if [ "$SHIELD_CTGUARD" != "1" ]; then
    nft delete table inet shield_ctguard 2>/dev/null || true
    rm -f "$TIER_F" "$EVICT_F" "$MODE_F" "$PREV_F" "$BASE_F" "$STREAK_F" 2>/dev/null || true
    exit 0
fi

SELF_IPS="$(hostname -I 2>/dev/null) $(ip -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"

ensure_table(){
    # v3.26.4: пересоздаём УСТАРЕВШУЮ таблицу. До v3.26 в shield_ctguard не было chain capnew —
    # при апгрейде поверх старой таблицы apply_cap падал каждый тик. Если таблица есть, но
    # без capnew — удаляем и создаём заново корректную схему.
    if nft list table inet shield_ctguard >/dev/null 2>&1; then
        nft list chain inet shield_ctguard capnew >/dev/null 2>&1 && return 0
        logger -t "$TAG" "ensure_table: устаревшая shield_ctguard (нет capnew) — пересоздаю"
        nft delete table inet shield_ctguard 2>/dev/null || true
    fi
    nft -f - 2>/dev/null <<'NFT'
table inet shield_ctguard {
    set evict4 { type ipv4_addr; flags timeout; }
    set evict6 { type ipv6_addr; flags timeout; }
    counter ctguard_drops { }
    counter ctguard_capdrop { }
    chain pre {
        type filter hook prerouting priority -160; policy accept;
        ip  saddr @evict4 counter name ctguard_drops drop
        ip6 saddr @evict6 counter name ctguard_drops drop
    }
    chain capnew {
        type filter hook prerouting priority -159; policy accept;
    }
}
NFT
}

is_protected(){  # whitelist/infra/loopback/private/self (v4 и v6)
    local ip="$1"
    case "$ip" in
        127.*|10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        ::1|fe80:*|fc*|fd*) return 0 ;;
    esac
    printf '%s\n' $SELF_IPS | grep -qxF "$ip" && return 0
    if printf '%s' "$ip" | grep -q ':'; then
        nft get element inet ddos_protect infrastructure_v6  "{ $ip }" >/dev/null 2>&1 && return 0
        nft get element inet ddos_protect manual_whitelist_v6 "{ $ip }" >/dev/null 2>&1 && return 0
    else
        nft get element inet ddos_protect manual_whitelist_v4 "{ $ip }" >/dev/null 2>&1 && return 0
        nft get element inet ddos_protect infrastructure_v4   "{ $ip }" >/dev/null 2>&1 && return 0
    fi
    return 1
}

protected_ports(){ nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | tr -d '\n' | grep -oE 'elements = \{[^}]*\}' | sed -E 's/.*\{ *//; s/ *\}.*//'; }

SNAP_DONE=0
take_snap(){   # раз за тик: conntrack inbound per-src + ss live per-src на protected tcp портах
    [ "$SNAP_DONE" = "1" ] && return 0
    command -v conntrack >/dev/null 2>&1 || return 1
    local ports; ports="$(protected_ports | tr -d ' ')"
    [ -n "$ports" ] || return 1
    conntrack -L -p tcp 2>/dev/null | awk -v P="$ports" -v S="$SELF_IPS" '
        function inset(p,  i,t){for(i=1;i<=nr;i++)if(rr[i]==p)return 1;for(i=1;i<=ng;i++){split(gr[i],t,"-");if(p>=t[1]&&p<=t[2])return 1}return 0}
        BEGIN{n=split(P,a,",");for(i=1;i<=n;i++){if(a[i]~/-/){ng++;gr[ng]=a[i]}else{nr++;rr[nr]=a[i]}} m=split(S,s," ");for(i=1;i<=m;i++)slf[s[i]]=1}
        /ESTABLISHED/{cip="";did="";dpt="";for(i=1;i<=NF;i++){if(cip==""&&$i~/^src=/){split($i,x,"=");cip=x[2]} if(did==""&&$i~/^dst=/){split($i,x,"=");did=x[2]} if(dpt==""&&$i~/^dport=/){split($i,x,"=");dpt=x[2]}} if(cip!=""&&(did in slf)&&inset(dpt))print cip}' \
        | sort | uniq -c > "$RUN/ctg.ctsrc" 2>/dev/null || : > "$RUN/ctg.ctsrc"
    if command -v ss >/dev/null 2>&1; then
        ss -tnH state established 2>/dev/null | awk -v P="$ports" '
            function inset(p,  i,t){for(i=1;i<=nr;i++)if(rr[i]==p)return 1;for(i=1;i<=ng;i++){split(gr[i],t,"-");if(p>=t[1]&&p<=t[2])return 1}return 0}
            BEGIN{n=split(P,a,",");for(i=1;i<=n;i++){if(a[i]~/-/){ng++;gr[ng]=a[i]}else{nr++;rr[nr]=a[i]}}}
            {m=split($3,L,":");if(inset(L[m])){k=split($4,b,":");print b[1]}}' \
            | sort | uniq -c > "$RUN/ctg.sslive" 2>/dev/null || : > "$RUN/ctg.sslive"
    else
        : > "$RUN/ctg.sslive"
    fi
    SNAP_DONE=1
}

CNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
[ "${MAX:-0}" -gt 0 ] 2>/dev/null || exit 0
PCT=$(( CNT * 100 / MAX ))
echo "$PCT" > "$RUN/ctguard.pct" 2>/dev/null || true
ensure_table || logger -t "$TAG" "WARN: не смог создать shield_ctguard (kernel/nft?)"
date +%s > "$RUN/ctguard.heartbeat" 2>/dev/null || true   # v3.26.3: для детекта залипшего таймера

# v3.26.0 conntrack-exhaustion guard: поднять max при заполнении (легит начинает дропаться)
# v3.27.0 FIX(#13): потолок подъёма ограничен долей MemAvailable. Иначе авто-рост до
# CT_MAX_CEIL (1М × ~384Б ≈ 384МБ) OOM-killил Xray на малых нодах — защита сама
# конвертила conntrack-fill в RAM-exhaustion. Если RAM-потолок ниже текущего max —
# НЕ поднимаем (дроп новых пакетов переживаемее, чем OOM активных сессий).
if [ "$PCT" -ge "$HIGH" ] 2>/dev/null && [ "$MAX" -lt "$CT_MAX_CEIL" ] 2>/dev/null; then
    NEWMAX=$(( MAX * 2 )); [ "$NEWMAX" -gt "$CT_MAX_CEIL" ] && NEWMAX="$CT_MAX_CEIL"
    MEM_KB=$(awk '/^MemAvailable:/{print $2; f=1} END{if(!f)print 0}' /proc/meminfo 2>/dev/null); MEM_KB="${MEM_KB:-0}"
    [ "$MEM_KB" -gt 0 ] 2>/dev/null || MEM_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
    RAM_CAP=0
    [ "${MEM_KB:-0}" -gt 0 ] 2>/dev/null && RAM_CAP=$(( MEM_KB * 1024 / 100 * CT_RAM_PCT / 384 ))
    if [ "$RAM_CAP" -gt 0 ] 2>/dev/null && [ "$NEWMAX" -gt "$RAM_CAP" ]; then
        NEWMAX="$RAM_CAP"
    fi
    if [ "$NEWMAX" -le "$MAX" ] 2>/dev/null; then
        logger -t "$TAG" "WARN: conntrack ${PCT}% но RAM-потолок (${CT_RAM_PCT}% avail ≈ ${NEWMAX}) <= текущего max (${MAX}) — НЕ поднимаю (дроп предпочтительнее OOM Xray)"
    elif [ "$ENFORCE" = "1" ]; then
        sysctl -wq net.netfilter.nf_conntrack_max="$NEWMAX" 2>/dev/null && logger -t "$TAG" "conntrack fill ${PCT}% → nf_conntrack_max ${MAX}→${NEWMAX} (RAM-capped ${CT_RAM_PCT}%)" && MAX="$NEWMAX" && PCT=$(( CNT * 100 / MAX ))
    else
        logger -t "$TAG" "DRY: conntrack fill ${PCT}% → поднял бы nf_conntrack_max ${MAX}→${NEWMAX} (RAM-capped)"
    fi
fi

# new-conn rate via TcpPassiveOpens (дёшево, kernel-wide, топология-агностик)
NOW=$(date +%s)
PASS=$(awk '/^Tcp:/{ if(!seen){for(i=1;i<=NF;i++)col[$i]=i; seen=1; next} print $(col["PassiveOpens"]); exit }' /proc/net/snmp 2>/dev/null); PASS="${PASS:-0}"
PTS=0; PPASS=0
[ -r "$PREV_F" ] && read -r PTS PPASS < "$PREV_F" 2>/dev/null || true
echo "$NOW $PASS" > "$PREV_F" 2>/dev/null || true
DT=$(( NOW - PTS )); [ "$DT" -le 0 ] 2>/dev/null && DT=15
RATE=0
if [ "${PPASS:-0}" -gt 0 ] 2>/dev/null && [ "$PASS" -ge "$PPASS" ] 2>/dev/null; then
    RATE=$(( (PASS - PPASS) / DT ))
fi

# baseline (EWMA), переживает ребут
BASE_RATE=0; BASE_CT=0
[ -r "$BASE_F" ] && read -r BASE_RATE BASE_CT < "$BASE_F" 2>/dev/null || true
if [ "${BASE_RATE:-0}" -le 0 ] 2>/dev/null; then BASE_RATE="$RATE"; fi
if [ "${BASE_CT:-0}" -le 0 ] 2>/dev/null; then BASE_CT="$CNT"; fi

trig_rate=$(( BASE_RATE * MULT_IN )); [ "$trig_rate" -lt "$FLOOR_RATE" ] && trig_rate="$FLOOR_RATE"
trig_ct=$(( BASE_CT * MULT_IN ));     [ "$trig_ct" -lt "$FLOOR_CT" ]     && trig_ct="$FLOOR_CT"
exit_rate=$(( BASE_RATE * MULT_OUT )); [ "$exit_rate" -lt $(( FLOOR_RATE / 2 )) ] && exit_rate=$(( FLOOR_RATE / 2 ))
exit_ct=$(( BASE_CT * MULT_OUT ));     [ "$exit_ct" -lt $(( FLOOR_CT / 2 )) ]     && exit_ct=$(( FLOOR_CT / 2 ))

# v3.26.0 ss-phantom-ratio (acct-free, основной триггер).
# v3.26.3 perf: дешёвый коарс-гейт. Фантомы раздувают conntrack, но НЕ число
# established-сокетов (у connect-and-hold атакеров live=0). Полный (дорогой)
# conntrack -L дамп в take_snap делаем ТОЛЬКО если суммарный conntrack заметно
# больше числа живых сокетов (фантом-тяжело) ИЛИ мы уже в attack-mode. Иначе —
# здоровая busy-нода: дорогой дамп пропускаем (строго меньше работы, детект не теряем).
SNAP_FLOOR=$(( FLOOR_CT / 4 )); [ "$SNAP_FLOOR" -lt 2000 ] && SNAP_FLOOR=2000
CT_INB=0; SS_LIVE=0; PHR=0
PREV_MODE_PEEK=normal; [ -r "$MODE_F" ] && PREV_MODE_PEEK=$(cat "$MODE_F" 2>/dev/null || echo normal)
if [ "$CNT" -ge "$SNAP_FLOOR" ] 2>/dev/null; then
    # дешёвый сигнал: всего established-сокетов (одна лёгкая ss-выборка)
    SS_TOTAL=$(ss -tnH state established 2>/dev/null | wc -l 2>/dev/null); SS_TOTAL="${SS_TOTAL:-0}"
    if [ "$PREV_MODE_PEEK" = "attack" ] 2>/dev/null || [ "$CNT" -gt $(( (SS_TOTAL + 1) * COARSE_MULT )) ] 2>/dev/null; then
        take_snap || true                                 # дорогой per-source conntrack -L + ss
        CT_INB=$(awk '{s+=$1}END{print s+0}' "$RUN/ctg.ctsrc" 2>/dev/null); CT_INB="${CT_INB:-0}"
        SS_LIVE=$(awk '{s+=$1}END{print s+0}' "$RUN/ctg.sslive" 2>/dev/null); SS_LIVE="${SS_LIVE:-0}"
        PHR=$(awk -v t="$CT_INB" -v l="$SS_LIVE" 'BEGIN{printf "%d",(t>0?(t-l)*100/t:0)}')
    else
        # коарс-гейт решил: НЕ фантом-тяжело → дорогой дамп пропущен.
        # PHR=0 для ТРИГГЕРА (мы уже judged not-heavy этим гейтом, грубый ratio
        # на busy-прокси завышен из-за outbound-conntrack и НЕ должен тригерить attack).
        SS_LIVE="$SS_TOTAL"; CT_INB=0; PHR=0
    fi
fi
echo "$PHR" > "$RUN/ctguard.phr" 2>/dev/null || true            # v3.26.1: для дашборда guard
echo "$SS_LIVE $CT_INB" > "$RUN/ctguard.live" 2>/dev/null || true

PREV_MODE=normal; [ -r "$MODE_F" ] && PREV_MODE=$(cat "$MODE_F" 2>/dev/null || echo normal)

# v3.26.4: РАЗДЕЛЯЕМ настоящий флуд от мобильного churn.
# (1) Настоящий L4-флуд new-conn/conntrack (rate/fill) — агрегатный кап здесь правильный инструмент.
FLOOD=0
if [ "$RATE" -gt "$trig_rate" ] 2>/dev/null || [ "$CNT" -gt "$trig_ct" ] 2>/dev/null || [ "$PCT" -ge "$HIGH" ] 2>/dev/null; then
    FLOOD=1
elif [ "$PREV_MODE" = "attack" ] && { [ "$RATE" -gt "$exit_rate" ] 2>/dev/null || [ "$CNT" -gt "$exit_ct" ] 2>/dev/null || [ "$PCT" -gt "$RECOVER" ] 2>/dev/null; }; then
    FLOOD=1
fi
# (2) ss-phantom-сигнал. Высокий ratio даёт И connect-and-hold атака, И легит мобильный
# churn (est_to реапит медленнее, чем клиенты бросают конны → conntrack≫live у легита тоже).
# Различаем их НИЖЕ по наличию реального per-source холдера (≥PH_MIN), а не по самому ratio.
PHANTOM_SIG=0
[ "$PHR" -ge "$PHR_TRIG" ] 2>/dev/null && [ "$CT_INB" -ge "$SNAP_FLOOR" ] 2>/dev/null && PHANTOM_SIG=1

udp_protected_ports(){ nft list set inet ddos_protect protected_ports_udp 2>/dev/null | tr -d '\n' | grep -oE 'elements = \{[^}]*\}' | sed -E 's/.*\{ *//; s/ *\}.*//'; }

apply_cap(){  # глобальный кап new-conn на protected-порты (НЕ per-IP → safe для CDN/моста/CGNAT)
    # v3.27.0 FIX(#1): кап теперь и на UDP. Spoofed/distributed UDP-флуд обходит per-saddr
    # meter ddos_protect (каждый src — свой счётчик → ничего не превышает) и течёт conntrack
    # до OOM. Глобальный UDP-кап в attack-mode останавливает приток НОВЫХ flow; established
    # QUIC (ct state established) не трогается. UDP-пол (UDP_FLOOR) выше TCP — у QUIC больше
    # легит new-flow на reconnect-шторме.
    local cap="$1" tports uports
    tports=$(protected_ports); uports=$(udp_protected_ports)
    nft flush chain inet shield_ctguard capnew 2>/dev/null || true
    if [ -n "$tports" ]; then
        local burst=$(( cap * 2 )); [ "$burst" -lt 100 ] && burst=100
        nft add rule inet shield_ctguard capnew tcp dport "{ $tports }" ct state new \
            limit rate over "${cap}/second" burst "${burst} packets" counter name ctguard_capdrop drop 2>/dev/null \
            || logger -t "$TAG" "WARN: не наложил TCP-кап (${cap}/s)"
    fi
    if [ -n "$uports" ]; then
        local ucap="$cap"; [ "$ucap" -lt "$UDP_FLOOR" ] 2>/dev/null && ucap="$UDP_FLOOR"
        local uburst=$(( ucap * 2 )); [ "$uburst" -lt 200 ] && uburst=200
        nft add rule inet shield_ctguard capnew udp dport "{ $uports }" ct state new \
            limit rate over "${ucap}/second" burst "${uburst} packets" counter name ctguard_capdrop drop 2>/dev/null \
            || logger -t "$TAG" "WARN: не наложил UDP-кап (${ucap}/s)"
    fi
    [ -z "$tports" ] && [ -z "$uports" ] && logger -t "$TAG" "WARN: protected_ports пуст — агрегатный кап не наложен"
}
clear_cap(){ nft flush chain inet shield_ctguard capnew 2>/dev/null || true; }

phantom_evict(){  # v3.26.0: эвикт источников с conntrack ≫ живых сокетов (ss). acct-free, CGNAT-safe.
    FOUND_HOLDER=0
    command -v conntrack >/dev/null 2>&1 || { logger -t "$TAG" "CRITICAL: conntrack-tool нет — эвикт недоступен (apt install conntrack)"; return; }
    take_snap || { logger -t "$TAG" "WARN: snapshot не снят (conntrack/ss/protected_ports) — эвикт пропущен"; return; }
    local ip ct live
    while read -r ct ip; do
        [ -n "${ip:-}" ] || continue
        [ "${ct:-0}" -ge "$PH_MIN" ] 2>/dev/null || continue
        live=$(awk -v ip="$ip" '$2==ip{print $1;exit}' "$RUN/ctg.sslive" 2>/dev/null); live="${live:-0}"
        [ "$live" -gt "$ACTIVE_FLOOR" ] 2>/dev/null && continue           # много живых → shared-front/CGNAT → НЕ трогаем
        awk -v l="$live" -v c="$ct" -v f="$LIVE_FRAC" 'BEGIN{exit !(c>0 && l*100/c < f)}' || continue  # live-доля < порога
        is_protected "$ip" && continue
        FOUND_HOLDER=$((FOUND_HOLDER+1))
        if [ "$ENFORCE" != "1" ]; then
            logger -t "$TAG" "DRY: выселил бы $ip (conntrack=$ct live=$live)"
            echo "$ip conntrack=$ct live=$live DRY $(date '+%F %T')" >> "$EVICT_F" 2>/dev/null || true
            continue
        fi
        if printf '%s' "$ip" | grep -q ':'; then
            nft add element inet shield_ctguard evict6 "{ $ip timeout $EVICT_TTL }" 2>/dev/null || true
        else
            nft add element inet shield_ctguard evict4 "{ $ip timeout $EVICT_TTL }" 2>/dev/null || true
        fi
        conntrack -D -s "$ip" >/dev/null 2>&1 || true
        [ "$CSCLI" = "1" ] && command -v cscli >/dev/null 2>&1 && cscli decisions add -i "$ip" -d "$CSCLI_TTL" -r "shieldnode phantom conn-flood" >/dev/null 2>&1 || true
        echo "$ip conntrack=$ct live=$live $(date '+%F %T')" >> "$EVICT_F" 2>/dev/null || true
        logger -t "$TAG" "EVICT $ip: conntrack=$ct live=$live (phantom-holder) — block ${EVICT_TTL} + conntrack -D"
    done < "$RUN/ctg.ctsrc"
}

phantom_evict_distributed(){  # v3.27.0 FIX(#2): распределённый connect-and-hold — много IP по чуть-чуть,
    # каждый держит abandoned-конны с НУЛЁМ живых сокетов. Порог ниже (PH_MIN_DIST), но условие
    # СТРОЖЕ: эвиктим ТОЛЬКО при live==0 (чистый abandon). CGNAT с любым активным юзером (live>=1)
    # щадится. Запускается лишь в sustained-attack и только если 1-й проход не нашёл холдеров.
    command -v conntrack >/dev/null 2>&1 || return
    take_snap || return
    local ip ct live
    while read -r ct ip; do
        [ -n "${ip:-}" ] || continue
        [ "${ct:-0}" -ge "$PH_MIN_DIST" ] 2>/dev/null || continue
        live=$(awk -v ip="$ip" '$2==ip{print $1;exit}' "$RUN/ctg.sslive" 2>/dev/null); live="${live:-0}"
        [ "$live" -eq 0 ] 2>/dev/null || continue                         # хоть один живой сокет → НЕ трогаем (CGNAT-safe)
        is_protected "$ip" && continue
        FOUND_HOLDER=$((FOUND_HOLDER+1))
        if [ "$ENFORCE" != "1" ]; then
            logger -t "$TAG" "DRY: выселил бы (dist) $ip (conntrack=$ct live=0)"
            echo "$ip conntrack=$ct live=0 DIST-DRY $(date '+%F %T')" >> "$EVICT_F" 2>/dev/null || true
            continue
        fi
        if printf '%s' "$ip" | grep -q ':'; then
            nft add element inet shield_ctguard evict6 "{ $ip timeout $EVICT_TTL }" 2>/dev/null || true
        else
            nft add element inet shield_ctguard evict4 "{ $ip timeout $EVICT_TTL }" 2>/dev/null || true
        fi
        conntrack -D -s "$ip" >/dev/null 2>&1 || true
        [ "$CSCLI" = "1" ] && command -v cscli >/dev/null 2>&1 && cscli decisions add -i "$ip" -d "$CSCLI_TTL" -r "shieldnode distributed conn-hold" >/dev/null 2>&1 || true
        echo "$ip conntrack=$ct live=0 DIST $(date '+%F %T')" >> "$EVICT_F" 2>/dev/null || true
        logger -t "$TAG" "EVICT(dist) $ip: conntrack=$ct live=0 (distributed hold) — block ${EVICT_TTL} + conntrack -D"
    done < "$RUN/ctg.ctsrc"
}

# v3.26.4 решение + v3.27.0 FIX(#9) дебаунс:
#  • эвикт сконцентрированных холдеров — немедленно (abandoned-конны, безопасно).
#  • ГЛОБАЛЬНЫЙ кап (потенциально режет легит) — только при SUSTAINED аномалии
#    (ATTACK_MIN_TICKS тиков подряд), КРОМЕ настоящей переполненности conntrack
#    (PCT>=HIGH → капаем сразу). Один tick всплеска (легит reconnect/утренний ramp
#    после тихого окна) больше НЕ включает кап и НЕ отравляет EWMA-базлайн.
# v3.27.1 FIX(#1 pulsing): СКОЛЬЗЯЩЕЕ ОКНО вместо строго-последовательного счётчика.
# STREAK_F = битстрока последних ANOM_WINDOW тиков; sustained если в окне >= ATTACK_MIN_TICKS
# аномалий (не обязательно подряд). Атака «вкл/выкл» больше НЕ обнуляет счётчик чистым
# тиком → пульсацией от капа не уйти. Одиночный всплеск (1 аномалия в окне) кап НЕ
# включает — анти-FP сохранён (CGNAT-safe, поведение как было). PCT>=HIGH/активная атака — сразу.
ANOM_BIT=0; { [ "$FLOOD" = "1" ] || [ "$PHANTOM_SIG" = "1" ]; } && ANOM_BIT=1
HIST=""; [ -r "$STREAK_F" ] && HIST=$(cat "$STREAK_F" 2>/dev/null | tr -cd '01')
HIST="${HIST}${ANOM_BIT}"
HLEN=${#HIST}; [ "$HLEN" -gt "$ANOM_WINDOW" ] 2>/dev/null && HIST="${HIST:HLEN-ANOM_WINDOW}"
printf '%s' "$HIST" > "$STREAK_F" 2>/dev/null || true
ANOM_CNT=$(printf '%s' "$HIST" | tr -cd '1' | wc -c); ANOM_CNT="${ANOM_CNT:-0}"
SUSTAINED=0
{ [ "$ANOM_CNT" -ge "$ATTACK_MIN_TICKS" ] 2>/dev/null || [ "$PCT" -ge "$HIGH" ] 2>/dev/null || [ "$PREV_MODE" = "attack" ]; } && SUSTAINED=1

FOUND_HOLDER=0
if [ "$PHANTOM_SIG" = "1" ] || { [ "$PREV_MODE" = "attack" ] && [ "$CT_INB" -ge "$SNAP_FLOOR" ] 2>/dev/null; }; then
    phantom_evict
fi
# v3.27.0 FIX(#2): распределённый connect-and-hold — только в sustained-attack и если
# 1-й (сконцентрированный) проход пуст. Эвиктит лишь источники с live==0 → CGNAT щадится.
if [ "$DISTRIBUTED" = "1" ] && [ "${FOUND_HOLDER:-0}" -eq 0 ] 2>/dev/null && [ "$PHANTOM_SIG" = "1" ] && [ "$SUSTAINED" = "1" ]; then
    phantom_evict_distributed
fi
DO_CAP=0
[ "$FLOOD" = "1" ] && [ "$SUSTAINED" = "1" ] && DO_CAP=1                          # настоящий new-conn/conntrack флуд (sustained) → кап
[ "$AGG_CAP" = "1" ] && [ "$PHANTOM_SIG" = "1" ] && [ "$SUSTAINED" = "1" ] && DO_CAP=1  # CDN/мост (opt-in): per-IP эвикт невозможен → кап
ATTACK=0
[ "$FLOOD" = "1" ] && [ "$SUSTAINED" = "1" ] && ATTACK=1
[ "${FOUND_HOLDER:-0}" -gt 0 ] 2>/dev/null && ATTACK=1
[ "$DO_CAP" = "1" ] && ATTACK=1

# Аномалия есть, но ещё не sustained → наблюдаем (без капа). EWMA ниже не обучаем (ANOM_CNT>0).
if [ "$ATTACK" != "1" ] && { [ "$FLOOD" = "1" ] || [ "$PHANTOM_SIG" = "1" ]; }; then
    logger -t "$TAG" "OBSERVE: аномалия ${ANOM_CNT}/${ATTACK_MIN_TICKS} в окне ${ANOM_WINDOW} (rate=${RATE}/s base≈${BASE_RATE} conntrack=${CNT}(${PCT}%) phr=${PHR}%) — глобальный кап отложен (анти-FP)"
fi

if [ "$ATTACK" = "1" ]; then
    echo attack > "$MODE_F" 2>/dev/null || true
    if [ "$DO_CAP" = "1" ]; then
        cap=$(( BASE_RATE * MULT_OUT )); [ "$cap" -lt "$CAP_FLOOR" ] && cap="$CAP_FLOOR"
        apply_cap "$cap"
    else
        clear_cap; cap="off(direct/no-flood)"
    fi
    [ "$PREV_MODE" != "attack" ] && logger -t "$TAG" "ATTACK ON: rate=${RATE}/s (base≈${BASE_RATE}, trig>${trig_rate}) conntrack=${CNT}(${PCT}%) phantom-ratio=${PHR}% (live=${SS_LIVE}/${CT_INB}) holders=${FOUND_HOLDER} flood=${FLOOD} sustained=${SUSTAINED}(anom=${ANOM_CNT}/win${ANOM_WINDOW}) enforce=${ENFORCE} agg_cap=${AGG_CAP} — кап=${cap} + phantom-эвикт"
    echo "$PCT" > "$TIER_F" 2>/dev/null || true
    exit 0
fi

# normal: восстановление + обучение базлайна
if [ "$PREV_MODE" = "attack" ]; then
    clear_cap
    nft flush set inet shield_ctguard evict4 2>/dev/null || true
    nft flush set inet shield_ctguard evict6 2>/dev/null || true
    : > "$EVICT_F" 2>/dev/null || true
    logger -t "$TAG" "RECOVERY: rate=${RATE}/s conntrack=${CNT}(${PCT}%) phantom-ratio=${PHR}% ниже порогов — кап снят, evict очищен"
fi
echo normal > "$MODE_F" 2>/dev/null || true
# EWMA только в normal И только на ЧИСТОМ окне (ANOM_CNT==0). v3.27.0 FIX(#9)/v3.27.1: иначе
# аномалия в окне дебаунса (streak>0, ещё не attack) подняла бы базлайн и сделала
# будущий ×N-триггер недостижимым (атакующий «приучает» норму).
if [ "${ANOM_CNT:-0}" -eq 0 ] 2>/dev/null; then
    NB_RATE=$(awk -v o="$BASE_RATE" -v s="$RATE" -v a="$ALPHA_NUM" 'BEGIN{printf "%.0f", o*(100-a)/100 + s*a/100}')
    NB_CT=$(awk -v o="$BASE_CT" -v s="$CNT" -v a="$ALPHA_NUM" 'BEGIN{printf "%.0f", o*(100-a)/100 + s*a/100}')
    echo "$NB_RATE $NB_CT" > "$BASE_F" 2>/dev/null || true
fi
if [ "$PCT" -ge "$WARN" ] 2>/dev/null && [ "$PCT" -lt "$HIGH" ] 2>/dev/null; then
    logger -t "$TAG" "WARN: conntrack ${PCT}% (${CNT}/${MAX}) — наблюдаю"
fi
echo "$PCT" > "$TIER_F" 2>/dev/null || true
CTGUARD_EOF
chmod 0755 /usr/local/sbin/shieldnode-ctguard.sh

cat > /etc/systemd/system/shieldnode-ctguard.service <<'SPCTU'
[Unit]
Description=Shieldnode conntrack-pressure guard (anti-exhaustion)
After=shieldnode-nftables.service
Wants=shieldnode-nftables.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shieldnode-ctguard.sh
# v3.27.0 FIX(#12): Nice -5 → 10. В attack-mode ctguard делает дорогой conntrack -L
# дамп каждые 15с; с отрицательным nice он отбирал CPU у Xray ИМЕННО когда тот
# критичен → частичная атака превращалась в полный аутаж. Guard теперь уступает
# VPN-сервису (положительный nice + idle-IO + низкий CPUWeight).
Nice=10
CPUWeight=20
IOSchedulingClass=idle
SPCTU

cat > /etc/systemd/system/shieldnode-ctguard.timer <<'SPCTT'
[Unit]
Description=Run shieldnode conntrack-guard every 15s
Requires=shieldnode-ctguard.service
[Timer]
OnBootSec=45s
OnUnitActiveSec=15s
AccuracySec=2s
[Install]
WantedBy=timers.target
SPCTT

systemctl daemon-reload 2>/dev/null || true
if [ "$SHIELD_CTGUARD" = "1" ]; then
    systemctl enable --now shieldnode-ctguard.timer >/dev/null 2>&1 || true
    /usr/local/sbin/shieldnode-ctguard.sh >/dev/null 2>&1 || true
    print_ok "conn-flood guard включён (v3.26.4: phantom-эвикт по ЖИВЫМ сокетам, холдер≥${SHIELD_CTG_PHANTOM_MIN:-4000} conn; attack-mode только при реальном холдере / rate-fill флуде — CGNAT-churn не триггерит; агрегатный кап opt-in SHIELD_CTG_AGG_CAP=${SHIELD_CTG_AGG_CAP:-0}; SHIELD_CTG_ENFORCE=${SHIELD_CTG_ENFORCE:-1})"
else
    systemctl disable --now shieldnode-ctguard.timer >/dev/null 2>&1 || true
    print_info "conntrack-guard выключен (SHIELD_CTGUARD=0)"
fi

# v3.1: НЕ встраиваемся в /etc/nftables.conf!
# Тот файл содержит `flush ruleset` который убивает UFW при ребуте.
# Вместо этого создаём свой systemd-сервис shieldnode-nftables.service
# который загружает только нашу таблицу БЕЗ flush.

# Если предыдущая версия добавила include — удаляем (миграция с v3.0)
NFTABLES_MAIN="/etc/nftables.conf"
if [ -f "$NFTABLES_MAIN" ] && grep -q "$NFT_DDOS_CONF" "$NFTABLES_MAIN"; then
    print_status "Удаляю старый include из $NFTABLES_MAIN (миграция v3.0→v3.1)"
    cp -a "$NFTABLES_MAIN" "$BACKUP_DIR/nftables.conf.before"
    sed -i '/# DDoS protection (vpn-node-ddos-protect)/d' "$NFTABLES_MAIN"
    sed -i "\|include \"$NFT_DDOS_CONF\"|d" "$NFTABLES_MAIN"
    print_ok "Старый include удалён"
fi

# Создаём свой systemd-сервис для загрузки нашей таблицы
cat > /etc/systemd/system/shieldnode-nftables.service <<EOF
[Unit]
Description=Shieldnode DDoS protection nftables ruleset
Documentation=https://github.com/SpofyJet/shield
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=nftables.service
# v3.18.11 SH-NEW-37: убран After=ufw.service (противоречил Before=network-pre.target —
# ufw.service в multi-user.target, который ПОСЛЕ network-pre). UFW работает
# в отдельной таблице (filter chain), наша — inet ddos_protect, не пересекаются.

[Service]
Type=oneshot
RemainAfterExit=yes
# v3.23.13 SR-FIX-3: parse-check ПЕРЕД apply — если conf битый, unit
# не запустится, но старый ruleset продолжит работать (защита не падает).
ExecStartPre=/usr/sbin/nft -c -f $NFT_DDOS_CONF
# Загружаем ТОЛЬКО нашу таблицу БЕЗ flush ruleset
# Это сохраняет UFW и любые другие nft-правила
ExecStart=/usr/sbin/nft -f $NFT_DDOS_CONF
# При остановке/restart удаляем только нашу таблицу.
# v3.18.8: префикс "-" → systemd игнорирует exit code. Если таблицу уже
# флушнул внешний процесс (bouncer post-inst regression и т.п.), unit
# не уйдёт в failed → restart cycle отработает чисто.
ExecStop=-/usr/sbin/nft delete table inet ddos_protect
# v3.23.13 SR-FIX-3: reload тоже parse-check'ит сначала
ExecReload=/usr/sbin/nft -c -f $NFT_DDOS_CONF
ExecReload=/usr/sbin/nft -f $NFT_DDOS_CONF

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shieldnode-nftables.service >/dev/null 2>&1

# Перезапускаем чтобы наш ruleset точно загрузился
if systemctl restart shieldnode-nftables.service 2>/dev/null; then
    print_ok "Сервис shieldnode-nftables.service установлен и активен"
    print_info "Загружает только нашу таблицу — UFW не пересекается"
else
    print_warn "shieldnode-nftables не стартанул — проверь: journalctl -u shieldnode-nftables -n 30"
fi

# v3.18.8 UFW-FIX: УДАЛЕНО `systemctl enable nftables`.
# Прежняя строка реактивировала nftables.service → при ребуте он выполнял
# /etc/nftables.conf с `flush ruleset` → UFW цепочки в kernel удалялись →
# `ufw status` показывал inactive. Свой shieldnode-nftables.service нам
# достаточно (он enabled выше).

# ==============================================================================
# ШАГ 5: PROTECTED PORTS WATCHER (auto-sync с фаерволом)
# ==============================================================================

print_header "ШАГ 5: PROTECTED PORTS WATCHER"

# v1.7: автоматическая синхронизация защищаемых портов с правилами фаервола.
# Каждые 30 секунд скрипт проверяет какие порты открыты в UFW/firewalld/iptables
# и обновляет nft set @protected_ports_tcp/@protected_ports_udp.
#
# Преимущества:
#   - Юзер открыл новый порт `ufw allow 12345` → защита подхватит за 30 сек
#   - Закрыл порт → перестанет защищаться (логично — он больше не нужен)
#   - Не зависит от того какой VPN-стек запущен и под каким именем процесса

PORTS_UPDATER="/usr/local/sbin/update-protected-ports.sh"

cat > "$PORTS_UPDATER" <<UPDATER_EOF
#!/bin/bash
# Sync nft sets @protected_ports_tcp/@protected_ports_udp с правилами фаервола.
# Запускается через protected-ports-update.timer каждые 30 секунд.

set -o pipefail

# v3.10.2 BUG-8 FIX: принудительная C-локаль — ru/uk/it/etc локали ломают
# парсинг "Status: active" (и могут сломать другие строки UFW в будущем).
export LANG=C LC_ALL=C

LOG_TAG="protected-ports"
FIREWALL_TYPE="$FIREWALL_TYPE"
# v3.10.2 BUG-7: SSH_PORTS — все sshd-listener порты (для multi-SSH setup'ов)
SSH_PORTS="$SSH_PORTS"
# v3.27.1 FIX(#6): включать ли SSH-порты в synproxy sp_ports при ресинке портов
SHIELD_SYNPROXY_SSH="${SHIELD_SYNPROXY_SSH}"

# Если nft-таблицы нет — выходим
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    logger -t "\$LOG_TAG" "table inet ddos_protect не существует — пропускаю"
    exit 0
fi

UPDATER_EOF

# Дописываем функцию detect_firewall_ports в updater (та же что в шаге 2)
# Делаем это через подстановку, чтобы юзер мог редактировать тип фаервола без перезапуска скрипта
cat >> "$PORTS_UPDATER" <<'UPDATER_EOF2'
detect_firewall_ports() {
    local fw="$1"
    local tcp_list=""
    local udp_list=""
    local mgmt_ipv4=""

    case "$fw" in
        ufw)
            local ufw_out
            # v3.10.2 BUG-8 FIX: LANG=C уже выставлен глобально, но дублируем
            # на случай если кто-то изменит export.
            ufw_out=$(LANG=C LC_ALL=C ufw status 2>/dev/null)
            # v3.10.2 BUG-1+3 FIX: regex принимает port-range (N:M) и multi-port (N,M).
            # Двоеточие → дефис (UFW: 4000:5000, nft: 4000-5000).
            tcp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "tcp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 == "Anywhere" {
                    pp = $1
                    if (match(pp, /^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*(\/(tcp|udp))?$/)) {
                        n = split(pp, a, "/")
                        ports = a[1]
                        proto = (n > 1) ? a[2] : "any"
                        if (proto == "udp" || proto == "any") {
                            m = split(ports, plist, ",")
                            for (i = 1; i <= m; i++) {
                                p = plist[i]
                                gsub(/:/, "-", p)
                                print p
                            }
                        }
                    }
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            # v2.2: management IPs (только IPv4, v3.6)
            mgmt_ipv4=$(echo "$ufw_out" | awk '
                $2 == "ALLOW" && $0 !~ /\(v6\)/ && $3 != "Anywhere" {
                    if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $3
                }
            ' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;
        firewalld)
            local fw_out
            fw_out=$(firewall-cmd --list-ports 2>/dev/null)
            tcp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="tcp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(echo "$fw_out" | tr ' ' '\n' | awk -F/ '$2=="udp"{print $1}' | sort -un | tr '\n' ',' | sed 's/,$//')
            # firewalld --list-rich-rules может содержать source address
            local rich_rules
            rich_rules=$(firewall-cmd --list-rich-rules 2>/dev/null)
            mgmt_ipv4=$(echo "$rich_rules" | grep -oE 'address="[0-9.]+(/[0-9]+)?"' | \
                grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;
        iptables)
            # v3.18.11 SH-NEW-25: gsub :->- для iptables port-range
            tcp_list=$(iptables -S INPUT 2>/dev/null | awk '/-j ACCEPT/ && /-p tcp/ {
                for (i=1; i<=NF; i++) {
                    if ($i == "--dport" || $i == "--dports") {
                        p=$(i+1); gsub(/:/,"-",p); print p
                    }
                }
            }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            udp_list=$(iptables -S INPUT 2>/dev/null | awk '/-j ACCEPT/ && /-p udp/ {
                for (i=1; i<=NF; i++) {
                    if ($i == "--dport" || $i == "--dports") {
                        p=$(i+1); gsub(/:/,"-",p); print p
                    }
                }
            }' | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
            # iptables: -s <IP>/-s <IP/CIDR> в ACCEPT-правилах
            mgmt_ipv4=$(iptables -S INPUT 2>/dev/null | awk '/-j ACCEPT/ {
                for (i=1; i<=NF; i++) {
                    if ($i == "-s") print $(i+1)
                }
            }' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' | \
                grep -v '^0\.0\.0\.0' | sort -u | tr '\n' ',' | sed 's/,$//')
            ;;
        nftables)
            # v3.5: jq-парсинг (jq mandatory, ставится в ШАГ 1).
            local nft_json
            nft_json=$(nft -j list ruleset 2>/dev/null)
            if [ -n "$nft_json" ]; then
                tcp_list=$(echo "$nft_json" | jq -r '
                    .nftables[] | select(.rule?) | .rule
                    | select(any(.expr[]?; .accept))
                    | .expr[] | select(.match?)
                    | select(.match.left.payload.protocol == "tcp")
                    | .match.right
                    | if type == "object" and .set then .set[] elif type == "array" then .[] else . end
                    | tostring
                ' 2>/dev/null | grep -E '^[0-9]+$' | sort -un | tr '\n' ',' | sed 's/,$//')
                udp_list=$(echo "$nft_json" | jq -r '
                    .nftables[] | select(.rule?) | .rule
                    | select(any(.expr[]?; .accept))
                    | .expr[] | select(.match?)
                    | select(.match.left.payload.protocol == "udp")
                    | .match.right
                    | if type == "object" and .set then .set[] elif type == "array" then .[] else . end
                    | tostring
                ' 2>/dev/null | grep -E '^[0-9]+$' | sort -un | tr '\n' ',' | sed 's/,$//')
            fi
            ;;
    esac

    echo "$tcp_list"
    echo "$udp_list"
    echo "$mgmt_ipv4"
}

exclude_port() {
    local list="$1" exclude="$2"
    echo ",$list," | sed "s/,$exclude,/,/g; s/^,//; s/,$//"
}

# Получаем актуальные данные
FW_OUTPUT=$(detect_firewall_ports "$FIREWALL_TYPE")
NEW_TCP=$(echo "$FW_OUTPUT" | sed -n '1p')
NEW_UDP=$(echo "$FW_OUTPUT" | sed -n '2p')
NEW_MGMT_V4=$(echo "$FW_OUTPUT" | sed -n '3p')

# v3.11.2 RETRY-ON-EMPTY: если ВСЕ результаты пустые — это либо real empty
# фаервол (rare), либо transient parse fail (common). Retry один раз через
# 0.3 сек чтобы дать UFW дописать atomic-rename и stabilize. Если retry
# тоже пустой — оставляем пусто и доверяем safety-guard.
if [ -z "$NEW_TCP" ] && [ -z "$NEW_UDP" ] && [ -z "$NEW_MGMT_V4" ]; then
    sleep 0.3
    FW_OUTPUT=$(detect_firewall_ports "$FIREWALL_TYPE")
    NEW_TCP=$(echo "$FW_OUTPUT" | sed -n '1p')
    NEW_UDP=$(echo "$FW_OUTPUT" | sed -n '2p')
    NEW_MGMT_V4=$(echo "$FW_OUTPUT" | sed -n '3p')
fi

# v3.10.2 BUG-7: исключаем все SSH-порты, не только первый.
exclude_port() {
    local list="$1" exclude="$2"
    echo ",$list," | sed "s/,$exclude,/,/g; s/^,//; s/,$//"
}
exclude_ports_list() {
    local list="$1" excludes="$2"
    local IFS=','
    for e in $excludes; do
        list=$(exclude_port "$list" "$e")
    done
    echo "$list"
}
NEW_TCP=$(exclude_ports_list "$NEW_TCP" "$SSH_PORTS")

# Текущее состояние nft set'ов
# v3.10.2: regex обновлён чтобы захватывать port-range (N-M) после auto-merge
CUR_TCP=$(nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | sort -u | tr '\n' ',' | sed 's/,$//')
CUR_UDP=$(nft list set inet ddos_protect protected_ports_udp 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | sort -u | tr '\n' ',' | sed 's/,$//')
CUR_MGMT_V4=$(nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
    tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | \
    sort -u | tr '\n' ',' | sed 's/,$//')

# v2.4: SAFETY GUARD — не затирать существующие данные пустыми результатами.
# Это случается когда:
#   - UFW в момент опроса делает atomic rename файлов (transient empty output)
#   - path-unit срабатывает несколько раз подряд, и один раз фаервол не отвечает
#   - Кратковременная блокировка ufw lock
#
# Логика: если фаервол активен И мы получили пустой результат, НО предыдущий
# результат был непустой — это скорее всего transient ошибка. Пропускаем
# обновление, не затираем правильные данные.
#
# v3.10.2 BUG-8 FIX: LANG=C для ufw status — иначе "Status: active" не находится
# в локализованных системах (ru_RU, uk_UA, etc.) → FIREWALL_ACTIVE=0 → safety
# guard никогда не срабатывает.
FIREWALL_ACTIVE=0
case "$FIREWALL_TYPE" in
    ufw)       LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active" && FIREWALL_ACTIVE=1 ;;
    firewalld) systemctl is-active --quiet firewalld 2>/dev/null && FIREWALL_ACTIVE=1 ;;
    iptables)  [ "$(iptables -L INPUT 2>/dev/null | wc -l)" -gt 2 ] && FIREWALL_ACTIVE=1 ;;
    nftables)  nft list ruleset 2>/dev/null | grep -q "table inet filter" && FIREWALL_ACTIVE=1 ;;
esac

# v3.10.2 BUG-2 FIX: добавлено CUR_UDP в проверку — иначе UDP-only setup'ы
# (Hysteria/TUIC/WireGuard без admin-IP whitelist) не защищались от transient
# wipe: при пустом NEW_* и непустом только CUR_UDP, safety-guard не срабатывал
# и UDP set обнулялся.
if [ "$FIREWALL_ACTIVE" = "1" ] && [ -z "$NEW_TCP" ] && [ -z "$NEW_UDP" ] && [ -z "$NEW_MGMT_V4" ]; then
    if [ -n "$CUR_TCP" ] || [ -n "$CUR_UDP" ] || [ -n "$CUR_MGMT_V4" ]; then
        logger -t "$LOG_TAG" "SKIP: empty parse result while firewall is active (transient?)"
        exit 0
    fi
fi

# Если ничего не изменилось — выходим
if [ "$NEW_TCP" = "$CUR_TCP" ] && [ "$NEW_UDP" = "$CUR_UDP" ] && [ "$NEW_MGMT_V4" = "$CUR_MGMT_V4" ]; then
    exit 0
fi

# v2.4: Lock-файл — предотвращает одновременный запуск (path-unit + timer).
# flock с -n (non-blocking) — если уже запущен другой instance, выходим.
# v3.5: переехали в /run/shieldnode (cs-ssh-whitelist удалён).
LOCKFILE="/run/shieldnode/.ports-update.lock"
mkdir -p /run/shieldnode 2>/dev/null
exec 200>"$LOCKFILE"
if ! flock -n 200; then
    logger -t "$LOG_TAG" "SKIP: another update already in progress"
    exit 0
fi

# Атомарное обновление через nft -f
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# v3.11.2 PER-SET PROTECTION: don't flush a set if NEW is empty but CUR was
# populated. This protects against transient parser fails that get past the
# global safety-guard (e.g. when UFW returns partial output and FIREWALL_ACTIVE
# detection ALSO returns 0 due to same transient).
#
# Логика: для каждого set'а отдельно решаем — flush+add или keep CUR.
#   NEW=empty, CUR=full   → SKIP (не трогаем set, оставляем CUR)
#   NEW=empty, CUR=empty  → flush (no-op, оба пустые)
#   NEW=full,  CUR=*      → flush + add (apply changes)
{
    if [ -n "$NEW_TCP" ] || [ -z "$CUR_TCP" ]; then
        echo "flush set inet ddos_protect protected_ports_tcp"
        if [ -n "$NEW_TCP" ]; then
            echo "add element inet ddos_protect protected_ports_tcp { $(echo "$NEW_TCP" | sed 's/,/, /g') }"
        fi
    fi
    if [ -n "$NEW_UDP" ] || [ -z "$CUR_UDP" ]; then
        echo "flush set inet ddos_protect protected_ports_udp"
        if [ -n "$NEW_UDP" ]; then
            echo "add element inet ddos_protect protected_ports_udp { $(echo "$NEW_UDP" | sed 's/,/, /g') }"
        fi
    fi
    # v2.2: синхронизируем management whitelist (только IPv4, v3.6)
    if [ -n "$NEW_MGMT_V4" ] || [ -z "$CUR_MGMT_V4" ]; then
        echo "flush set inet ddos_protect manual_whitelist_v4"
        if [ -n "$NEW_MGMT_V4" ]; then
            echo "add element inet ddos_protect manual_whitelist_v4 { $(echo "$NEW_MGMT_V4" | sed 's/,/, /g') }"
        fi
    fi
} > "$TMP"

# v3.11.2: если TMP пустой (всё защищено per-set guard'ом) — ничего не делаем
if [ ! -s "$TMP" ]; then
    logger -t "$LOG_TAG" "SKIP: per-set protection — все NEW пустые, CUR имеют данные"
    exit 0
fi

# v2.4: захватываем stderr из nft для диагностики (раньше >/dev/null глотал ошибки)
NFT_ERR=$(nft -f "$TMP" 2>&1)
if [ $? -eq 0 ]; then
    logger -t "$LOG_TAG" "Updated: TCP={$NEW_TCP} UDP={$NEW_UDP} MGMT={$NEW_MGMT_V4}"
    # v3.26.1: синхронизируем synproxy sp_ports с новыми TCP-портами (если слой активен).
    # sp_ports заполнялся один раз при install — без этого synproxy защищал бы старые
    # порты после смены портов фаервола. Сет не пересоздаём → flags interval+auto-merge
    # сохраняются (add element в существующий set авто-мёрджит пересечения).
    # v3.27.1 FIX(#6): добавляем SSH-порты (если SHIELD_SYNPROXY_SSH=1), иначе ресинк
    # затёр бы SSH-покрытие, добавленное модулем.
    if [ -n "$NEW_TCP" ] && nft list table inet shield_synproxy >/dev/null 2>&1; then
        SP_PORTS_SYNC="$NEW_TCP"
        [ "${SHIELD_SYNPROXY_SSH:-1}" = "1" ] && [ -n "${SSH_PORTS:-}" ] && SP_PORTS_SYNC="${SP_PORTS_SYNC},${SSH_PORTS}"
        SYN_ERR=$(printf 'flush set inet shield_synproxy sp_ports\nadd element inet shield_synproxy sp_ports { %s }\n' "$(echo "$SP_PORTS_SYNC" | sed 's/,/, /g')" | nft -f - 2>&1) \
            && logger -t "$LOG_TAG" "synproxy sp_ports синхронизирован: {$SP_PORTS_SYNC}" \
            || logger -t "$LOG_TAG" "WARN: synproxy sp_ports sync failed: $SYN_ERR"
    fi
else
    logger -t "$LOG_TAG" "ERROR: nft failed: $NFT_ERR"
    exit 1
fi
UPDATER_EOF2

chmod 0755 "$PORTS_UPDATER"
print_ok "Watcher script: $PORTS_UPDATER"

# Systemd service + timer + path-unit
cat > /etc/systemd/system/protected-ports-update.service <<EOF
[Unit]
Description=Sync nft protected_ports sets with firewall rules
After=nftables.service network-online.target
Wants=nftables.service
# Не запускать многократно если несколько триггеров сработали одновременно
StartLimitIntervalSec=10
StartLimitBurst=5

[Service]
Type=oneshot
ExecStart=$PORTS_UPDATER
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# v3.5: lock-файл /run/shieldnode/.ports-update.lock (раньше использовался
# /run/cs-ssh-whitelist, удалён вместе с auto-whitelist).
RuntimeDirectory=shieldnode
RuntimeDirectoryMode=0755
ReadWritePaths=/run/shieldnode
EOF

# v3.22.0: Timer интервал 60s → 5min. path-unit (inotify) ловит изменения
# мгновенно — timer нужен только как catch-all для редких случаев когда
# path-unit пропустил событие (TriggerLimitBurst saturation, daemon-reload).
# 5min даёт worst-case задержку 5 мин для мгновенно-не-замеченных изменений,
# при этом экономит ~15% CPU на 1GB нодах в простое (см. v3.22.0 changelog).
cat > /etc/systemd/system/protected-ports-update.timer <<'EOF'
[Unit]
Description=Sync protected ports every 5min (catch-all for path-unit)
Requires=protected-ports-update.service

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=false

[Install]
WantedBy=timers.target
EOF

# v1.8: Path-unit для МГНОВЕННОЙ реакции на изменения файлов фаервола.
# Использует inotify через systemd для отслеживания изменений в:
#   - UFW: /etc/ufw/user.rules, /etc/ufw/user6.rules
#   - firewalld: /etc/firewalld/zones/, /etc/firewalld/direct.xml
# При срабатывании любого PathChanged триггерит protected-ports-update.service.
#
# Преимущества vs только timer:
#   - Реакция < 1 секунды (kernel-event, без поллинга)
#   - Нулевая нагрузка (не опрашивает фаервол постоянно)
#   - Timer остаётся как safety net (если кто-то меняет nft напрямую)
PATH_UNIT_PATHS=""

# UFW использует /etc/ufw/user*.rules (изменяются при ufw allow/deny)
if [ -d /etc/ufw ]; then
    [ -f /etc/ufw/user.rules ]  && PATH_UNIT_PATHS+="PathChanged=/etc/ufw/user.rules"$'\n'
    [ -f /etc/ufw/user6.rules ] && PATH_UNIT_PATHS+="PathChanged=/etc/ufw/user6.rules"$'\n'
fi

# firewalld использует /etc/firewalld/zones/ (xml-файлы зон)
if [ -d /etc/firewalld/zones ]; then
    PATH_UNIT_PATHS+="PathModified=/etc/firewalld/zones"$'\n'
fi

# Если нашли что отслеживать — создаём path-unit
if [ -n "$PATH_UNIT_PATHS" ]; then
    cat > /etc/systemd/system/protected-ports-update.path <<EOF
[Unit]
Description=Watch firewall config files and trigger protected-ports-update
After=nftables.service

[Path]
$PATH_UNIT_PATHS
# Не дребезжать при нескольких изменениях за короткий период
TriggerLimitIntervalSec=2
TriggerLimitBurst=3
Unit=protected-ports-update.service

[Install]
WantedBy=multi-user.target
EOF
    HAS_PATH_UNIT=1
    print_ok "Path-unit для inotify-watch создан"
else
    HAS_PATH_UNIT=0
    print_info "Path-unit пропущен (файлы фаервола не найдены — только timer)"
fi

systemctl daemon-reload
systemctl enable --now protected-ports-update.timer >/dev/null 2>&1

if [ "$HAS_PATH_UNIT" = "1" ]; then
    systemctl enable --now protected-ports-update.path >/dev/null 2>&1
    print_ok "Auto-sync активен: path-unit (мгновенно) + timer (5min catch-all)"
else
    print_ok "Timer активен (синхронизация каждые 5 минут)"
fi

# ==============================================================================
# ШАГ 5.6: REMNAWAVE FLEET AUTO-SYNC (v3.28.0)
#   Авто-дискавери IP нод флота через Remnawave-панель → nft-whitelist в фоне.
#   Решает боль «завёл новую ноду — иди обнови TRUSTED_IPS на всех нодах руками».
# ==============================================================================
RW_URL="${REMNAWAVE_URL:-}"; RW_TOKEN="${REMNAWAVE_TOKEN:-}"
RW_SYNC="${SHIELD_REMNAWAVE_SYNC:-auto}"; RW_INTERVAL="${SHIELD_REMNAWAVE_INTERVAL:-5min}"
# re-install/upgrade: если заново не передали — восстановим из сохранённого env
if [ -z "$RW_URL" ] && [ -z "$RW_TOKEN" ] && [ -r /etc/shieldnode/remnawave.env ]; then
    # shellcheck source=/dev/null
    . /etc/shieldnode/remnawave.env 2>/dev/null || true
    RW_URL="${REMNAWAVE_URL:-}"; RW_TOKEN="${REMNAWAVE_TOKEN:-}"
fi
RW_ENABLED=0
if [ "$RW_SYNC" = "1" ] || { [ "$RW_SYNC" = "auto" ] && [ -n "$RW_URL" ] && [ -n "$RW_TOKEN" ]; }; then
    RW_ENABLED=1
fi

if [ "$RW_ENABLED" = "1" ] && { [ -z "$RW_URL" ] || [ -z "$RW_TOKEN" ]; }; then
    print_warn "Remnawave fleet-sync запрошен (SHIELD_REMNAWAVE_SYNC=1), но нет REMNAWAVE_URL/REMNAWAVE_TOKEN — пропускаю"
    RW_ENABLED=0
fi

if [ "$RW_ENABLED" = "1" ]; then
    # --- секретный env (токен НЕ в shieldnode.conf 0640) ---
    ( umask 077; cat > /etc/shieldnode/remnawave.env <<EOF
# v3.28.0: доступ к Remnawave-панели для авто-дискавери IP нод флота.
# Токен чувствителен — root:root 0600. Токен: панель → Remnawave Settings → API Tokens.
REMNAWAVE_URL="$RW_URL"
REMNAWAVE_TOKEN="$RW_TOKEN"
EOF
    )
    chown root:root /etc/shieldnode/remnawave.env 2>/dev/null || true
    chmod 0600 /etc/shieldnode/remnawave.env 2>/dev/null || true

    # --- sync-скрипт ---
    cat > /usr/local/sbin/shieldnode-remnawave-sync.sh <<'RWEOF'
#!/usr/bin/env bash
# shieldnode-remnawave-sync.sh — тянет IP нод флота из Remnawave (GET /api/nodes)
# и держит nft-сеты remnawave_nodes_v4/v6 в актуальном виде. Fail-safe: при любой
# ошибке (панель недоступна / кривой ответ / 0 валидных IP) текущий whitelist НЕ
# трогаем (last-known-good) — иначе сбой панели «разбанил» бы весь флот и ноды
# начали бы лимитировать друг друга. -e НЕ ставим намеренно (ошибки обрабатываем).
set -uo pipefail
TAG="shieldnode-remnawave"
ENVFILE="/etc/shieldnode/remnawave.env"
STATE="/var/lib/shieldnode"; LIST="$STATE/remnawave-nodes.list"
TABLE="inet ddos_protect"; SET4="remnawave_nodes_v4"; SET6="remnawave_nodes_v6"

[ -r "$ENVFILE" ] || { logger -t "$TAG" "нет $ENVFILE — синк выключен"; exit 0; }
# shellcheck source=/dev/null
. "$ENVFILE"
URL="${REMNAWAVE_URL:-}"; TOKEN="${REMNAWAVE_TOKEN:-}"
[ -n "$URL" ] && [ -n "$TOKEN" ] || { logger -t "$TAG" "REMNAWAVE_URL/TOKEN пуст — выкл"; exit 0; }
URL="${URL%/}"
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
command -v jq   >/dev/null 2>&1 || { logger -t "$TAG" "нет jq (нужен для /api/nodes)"; exit 1; }
mkdir -p "$STATE" 2>/dev/null || true
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# 1) fetch — fail-safe при недоступности панели
HTTP="$(curl -fsS --max-time 15 -o "$TMP/resp.json" -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" -H "Accept: application/json" \
        "$URL/api/nodes" 2>/dev/null || true)"
if [ "$HTTP" != "200" ] || [ ! -s "$TMP/resp.json" ]; then
    logger -t "$TAG" "панель недоступна (HTTP=$HTTP) — оставляю текущий whitelist нод (last-known-good)"
    exit 0
fi

# 2) address каждой ноды (IP или hostname). Робастно к обёртке {response:[...]}.
jq -r '.. | objects | .address? // empty' "$TMP/resp.json" 2>/dev/null | awk 'NF' | sort -u > "$TMP/addrs.txt"
if [ ! -s "$TMP/addrs.txt" ]; then
    logger -t "$TAG" "в ответе /api/nodes нет address — оставляю текущий whitelist (защита от кривого ответа)"
    exit 0
fi

# 3) hostname → IP (getent: A и AAAA, без доп. зависимостей), разносим v4/v6
: > "$TMP/v4.txt"; : > "$TMP/v6.txt"
while IFS= read -r a; do
    a="$(printf '%s' "$a" | tr -d '[:space:]')"; [ -n "$a" ] || continue
    if printf '%s' "$a" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$a" >> "$TMP/v4.txt"; continue; fi
    if printf '%s' "$a" | grep -qiE '^[0-9a-f]*:[0-9a-f:]+$'; then echo "$a" >> "$TMP/v6.txt"; continue; fi
    getent ahosts "$a" 2>/dev/null | awk '{print $1}' | sort -u | while IFS= read -r ip; do
        if printf '%s' "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$ip" >> "$TMP/v4.txt"
        elif printf '%s' "$ip" | grep -qiE '^[0-9a-f]*:[0-9a-f:]+$'; then echo "$ip" >> "$TMP/v6.txt"; fi
    done
done < "$TMP/addrs.txt"

# 4) финальная валидация + дедуп (октеты ≤255, не loopback/unspecified)
awk -F. 'NF==4 && $1<=255 && $2<=255 && $3<=255 && $4<=255 && $1!=0 && $1!=127' "$TMP/v4.txt" | sort -u > "$TMP/v4.clean"
grep -viE '^(::1|::)$' "$TMP/v6.txt" 2>/dev/null | sort -u > "$TMP/v6.clean"
N4="$(wc -l < "$TMP/v4.clean" 2>/dev/null)"; N4="${N4:-0}"
N6="$(wc -l < "$TMP/v6.clean" 2>/dev/null)"; N6="${N6:-0}"
if [ "$N4" -eq 0 ] && [ "$N6" -eq 0 ]; then
    logger -t "$TAG" "после резолва 0 валидных IP нод — оставляю текущий whitelist (fail-safe)"
    exit 0
fi

# 5) применяем ОТДЕЛЬНОЙ nft-транзакцией (битые данные не ломают ddos_protect),
#    только если сет существует (backward-compat со старой таблицей)
apply_set(){
    local set="$1" lf="$2"
    nft list set "$TABLE" "$set" >/dev/null 2>&1 || return 0
    {
        echo "flush set $TABLE $set"
        if [ -s "$lf" ]; then
            awk -v s="$set" -v t="$TABLE" '
                NR%500==1{ if(NR>1) print "}"; printf "add element %s %s { ", t, s }
                { printf "%s%s", (NR%500==1?"":", "), $0 }
                END{ if(NR>0) print " }" }' "$lf"
        fi
    } | nft -f - 2>"$TMP/nfterr"
}
RC=0
apply_set "$SET4" "$TMP/v4.clean" || { logger -t "$TAG" "WARN: $SET4: $(cat "$TMP/nfterr" 2>/dev/null)"; RC=1; }
apply_set "$SET6" "$TMP/v6.clean" || { logger -t "$TAG" "WARN: $SET6: $(cat "$TMP/nfterr" 2>/dev/null)"; RC=1; }

# 6) persist для guard/visibility
{ echo "# updated $(date -u +%FT%TZ) v4=$N4 v6=$N6 src=$URL/api/nodes"; cat "$TMP/v4.clean" "$TMP/v6.clean" 2>/dev/null; } > "$LIST" 2>/dev/null || true
[ "$RC" = "0" ] && logger -t "$TAG" "whitelist нод обновлён: $N4 IPv4 + $N6 IPv6 (из $URL/api/nodes)"
exit "$RC"
RWEOF
    chmod 0755 /usr/local/sbin/shieldnode-remnawave-sync.sh

    # --- service + timer ---
    cat > /etc/systemd/system/shieldnode-remnawave-sync.service <<EOF
[Unit]
Description=Sync Remnawave fleet node IPs into shieldnode whitelist
After=nftables.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shieldnode-remnawave-sync.sh
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RuntimeDirectory=shieldnode
RuntimeDirectoryMode=0755
ReadWritePaths=/var/lib/shieldnode /run/shieldnode
EOF
    cat > /etc/systemd/system/shieldnode-remnawave-sync.timer <<EOF
[Unit]
Description=Remnawave fleet sync (node IPs → whitelist) every $RW_INTERVAL
Requires=shieldnode-remnawave-sync.service

[Timer]
OnBootSec=45s
OnUnitActiveSec=$RW_INTERVAL
AccuracySec=30s
Persistent=false

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now shieldnode-remnawave-sync.timer >/dev/null 2>&1
    /usr/local/sbin/shieldnode-remnawave-sync.sh >/dev/null 2>&1 || true
    print_ok "Remnawave fleet-sync активен (каждые $RW_INTERVAL): IP нод панели → whitelist авто"
    print_info "  токен в /etc/shieldnode/remnawave.env (root:root 0600); лог: journalctl -t shieldnode-remnawave"
    print_info "  новую ноду добавил в панель → все ноды подхватят её сами, TRUSTED_IPS править не нужно"
else
    print_info "Remnawave fleet-sync выкл — задай REMNAWAVE_URL + REMNAWAVE_TOKEN (env при install), чтобы IP нод подтягивались автоматически (без ручного TRUSTED_IPS на каждой ноде)"
fi

# ==============================================================================
# ШАГ 6: BLOCKLIST UPDATER (universal, v3.12.0)
# ==============================================================================

print_header "ШАГ 6: BLOCKLIST UPDATER"

# v3.12.0: единый универсальный updater для всех blocklist'ов:
#   scanner — Shodan/Censys/government scanners (sources в DEFAULT_REMOTE_BLOCKLISTS)
#   threat  — Spamhaus DROP + FireHOL Level 1 (high-confidence атакующие)
#   tor     — официальный Tor exit list (если BLOCK_TOR=1)
#   custom  — operator personal /etc/shieldnode/lists/custom.txt
#
# Каждый name → один nft set:
#   scanner → scanner_blocklist_v4
#   threat  → threat_blocklist_v4
#   tor     → tor_exit_blocklist_v4   (legacy compat name)
#   custom  → custom_blocklist_v4
#
# Источники для каждого set'а — union: file-based (./lists/*.txt) +
# URL-based (REMOTE_BLOCKLISTS). Минимум: либо файл, либо URL'ы; если ничего —
# set остаётся пустым, drop-rule no-op.
#
# Конфиг /etc/shieldnode/shieldnode.conf опционален. Если есть — переопределяет
# DEFAULT_LOCAL_BLOCKLISTS, DEFAULT_REMOTE_BLOCKLISTS, *_UPDATE_INTERVAL,
# MIN_ENTRIES_*, FAIL_THRESHOLD.

# 1) Дефолты в /usr/local/sbin/shieldnode-defaults.sh — отдельный файл, чтобы
#    updater и установщик использовали один источник истины.
cat > "$SHIELD_DEFAULTS_FILE" <<DEFAULTS_EOF
#!/bin/bash
# shieldnode v3.20.4 — дефолты blocklists (генерится установщиком)
# НЕ редактировать руками — будет перезаписан при следующей установке/обновлении.
# Для переопределения — создай /etc/shieldnode/shieldnode.conf.

DEFAULT_LOCAL_BLOCKLISTS=(
$(for entry in "${DEFAULT_LOCAL_BLOCKLISTS[@]}"; do printf "    %q\n" "$entry"; done)
)

DEFAULT_REMOTE_BLOCKLISTS=(
$(for entry in "${DEFAULT_REMOTE_BLOCKLISTS[@]}"; do printf "    %q\n" "$entry"; done)
)

DEFAULT_SCANNER_UPDATE_INTERVAL="$DEFAULT_SCANNER_UPDATE_INTERVAL"
DEFAULT_THREAT_UPDATE_INTERVAL="$DEFAULT_THREAT_UPDATE_INTERVAL"
DEFAULT_TOR_UPDATE_INTERVAL="$DEFAULT_TOR_UPDATE_INTERVAL"
DEFAULT_CUSTOM_UPDATE_INTERVAL="$DEFAULT_CUSTOM_UPDATE_INTERVAL"

DEFAULT_MIN_ENTRIES_SCANNER=$DEFAULT_MIN_ENTRIES_SCANNER
DEFAULT_MIN_ENTRIES_THREAT=$DEFAULT_MIN_ENTRIES_THREAT
DEFAULT_MIN_ENTRIES_TOR=$DEFAULT_MIN_ENTRIES_TOR
DEFAULT_MIN_ENTRIES_CUSTOM=$DEFAULT_MIN_ENTRIES_CUSTOM

DEFAULT_FAIL_THRESHOLD=$DEFAULT_FAIL_THRESHOLD
DEFAULTS_EOF
chmod 0644 "$SHIELD_DEFAULTS_FILE"
print_ok "Defaults: $SHIELD_DEFAULTS_FILE"

# 2) Универсальный updater
cat > "$SHIELD_UPDATER_SCRIPT" <<'UPDATER_EOF'
#!/bin/bash
# shieldnode v3.12.0 — универсальный blocklist updater.
# Usage: shieldnode-update-blocklist.sh <scanner|threat|tor|custom>

set -o pipefail
export LANG=C LC_ALL=C

NAME="${1:-}"
case "$NAME" in
    scanner|threat|tor|custom) ;;
    # v3.20.0: mobile_ru + broadband_ru УБРАНЫ
    *) echo "Usage: $0 <scanner|threat|tor|custom>" >&2; exit 1 ;;
esac

LOG_TAG="shieldnode-update-$NAME"
STATE_DIR="/var/lib/shieldnode"
mkdir -p "$STATE_DIR"
FAIL_COUNTER="$STATE_DIR/${NAME}_fail_count"

# nft set name (legacy compat для tor → tor_exit_blocklist_v4)
case "$NAME" in
    scanner)   NFT_SET="scanner_blocklist_v4" ; NFT_SET_V6="scanner_blocklist_v6" ;;
    threat)    NFT_SET="threat_blocklist_v4"  ; NFT_SET_V6="threat_blocklist_v6"  ;;
    tor)       NFT_SET="tor_exit_blocklist_v4" ; NFT_SET_V6="tor_exit_blocklist_v6" ;;
    custom)    NFT_SET="custom_blocklist_v4"  ; NFT_SET_V6="custom_blocklist_v6"  ;;
    # v3.20.0: mobile_ru + broadband_ru УБРАНЫ
esac

# Загружаем дефолты + опциональный override
# shellcheck source=/dev/null
. /usr/local/sbin/shieldnode-defaults.sh
if [ -f /etc/shieldnode/shieldnode.conf ]; then
    # shellcheck source=/dev/null
    . /etc/shieldnode/shieldnode.conf
fi

# v3.20.0: ENABLE_RU_MOBILE_WHITELIST / ENABLE_RU_BROADBAND_WHITELIST блоки УБРАНЫ.
# Если старая нода имеет в shieldnode.conf эти переменные — они просто
# игнорируются. При следующем upgrade nft sets mobile_ru/broadband_ru_whitelist_v4
# исчезнут (т.к. их больше нет в новой shield конфигурации).

# Резолвим финальные значения: оператор может задать LOCAL_BLOCKLISTS /
# REMOTE_BLOCKLISTS; иначе берём DEFAULT_*.
[ "${#LOCAL_BLOCKLISTS[@]}"  -gt 0 ] || LOCAL_BLOCKLISTS=("${DEFAULT_LOCAL_BLOCKLISTS[@]}")
[ "${#REMOTE_BLOCKLISTS[@]}" -gt 0 ] || REMOTE_BLOCKLISTS=("${DEFAULT_REMOTE_BLOCKLISTS[@]}")

# Извлекаем для нашего NAME
LOCAL_PATHS=""
for entry in "${LOCAL_BLOCKLISTS[@]}"; do
    case "$entry" in
        "$NAME="*) LOCAL_PATHS="${entry#$NAME=}" ;;
    esac
done
REMOTE_URLS=""
for entry in "${REMOTE_BLOCKLISTS[@]}"; do
    case "$entry" in
        "$NAME="*) REMOTE_URLS="${entry#$NAME=}" ;;
    esac
done

# MIN_ENTRIES + FAIL_THRESHOLD: per-name override → DEFAULT_*
case "$NAME" in
    scanner)      MIN_ENTRIES="${MIN_ENTRIES_SCANNER:-$DEFAULT_MIN_ENTRIES_SCANNER}"     ;;
    threat)       MIN_ENTRIES="${MIN_ENTRIES_THREAT:-$DEFAULT_MIN_ENTRIES_THREAT}"       ;;
    tor)          MIN_ENTRIES="${MIN_ENTRIES_TOR:-$DEFAULT_MIN_ENTRIES_TOR}"             ;;
    custom)       MIN_ENTRIES="${MIN_ENTRIES_CUSTOM:-$DEFAULT_MIN_ENTRIES_CUSTOM}"       ;;
    # v3.20.0: mobile_ru + broadband_ru УБРАНЫ
esac
FAIL_THRESHOLD_VAL="${FAIL_THRESHOLD:-$DEFAULT_FAIL_THRESHOLD}"

# Если nft-таблицы нет — выходим (скрипт может запуститься до первой установки)
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "table inet ddos_protect не существует — пропускаю"
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

REMOTE_DOWNLOADED=0
REMOTE_TRIED=0

# 1) Скачиваем все URL'ы (через запятую в REMOTE_URLS)
if [ -n "$REMOTE_URLS" ]; then
    IFS=',' read -ra URL_ARR <<< "$REMOTE_URLS"
    for url in "${URL_ARR[@]}"; do
        url="${url## }"; url="${url%% }"   # trim spaces
        [ -z "$url" ] && continue
        REMOTE_TRIED=$((REMOTE_TRIED + 1))
        # JSON-формат (MISP/CIRCL/Spamhaus DROP) — отдельная обработка через jq
        if echo "$url" | grep -qE '\.json($|\?)' && command -v jq >/dev/null 2>&1; then
            if curl -fsSL --max-time 30 --retry 2 "$url" -o "$TMP/dl-$REMOTE_TRIED.json" 2>/dev/null; then
                # v3.27.2: эмитим И v4, И v6 CIDR-строки (Spamhaus drop_v6.json → threat_v6).
                # v6-валидация/bogon-фильтр делает v6-парсер ниже; nft валидит при add.
                jq -r '..|strings? | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+(/[0-9]+)?$") or test("^[0-9a-fA-F:]*:[0-9a-fA-F:]*(/[0-9]+)?$"))' \
                    "$TMP/dl-$REMOTE_TRIED.json" 2>/dev/null >> "$TMP/all.raw" && \
                    REMOTE_DOWNLOADED=$((REMOTE_DOWNLOADED + 1))
            else
                logger -t "$LOG_TAG" "WARN: не смог скачать (json) $url"
            fi
        else
            if curl -fsSL --max-time 30 --retry 2 "$url" -o "$TMP/dl-$REMOTE_TRIED.raw" 2>/dev/null; then
                cat "$TMP/dl-$REMOTE_TRIED.raw" >> "$TMP/all.raw"
                REMOTE_DOWNLOADED=$((REMOTE_DOWNLOADED + 1))
            else
                logger -t "$LOG_TAG" "WARN: не смог скачать $url"
            fi
        fi
    done
fi

# 2) Читаем локальные .txt (через запятую в LOCAL_PATHS — обычно один путь)
LOCAL_FOUND=0
if [ -n "$LOCAL_PATHS" ]; then
    IFS=',' read -ra PATH_ARR <<< "$LOCAL_PATHS"
    for p in "${PATH_ARR[@]}"; do
        p="${p## }"; p="${p%% }"
        [ -z "$p" ] && continue
        if [ -r "$p" ]; then
            cat "$p" >> "$TMP/all.raw"
            LOCAL_FOUND=$((LOCAL_FOUND + 1))
        fi
    done
fi

# 3) Если нет ничего — fail handling
if [ "$REMOTE_TRIED" -gt 0 ] && [ "$REMOTE_DOWNLOADED" -eq 0 ] && [ "$LOCAL_FOUND" -eq 0 ]; then
    # Все URL'ы failed AND нет локальных → инкрементируем fail counter
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    CURRENT=$((CURRENT + 1))
    echo "$CURRENT" > "$FAIL_COUNTER"
    logger -t "$LOG_TAG" "ERROR: все URL'ы недоступны и нет local files (fail #$CURRENT/$FAIL_THRESHOLD_VAL)"
    # v3.23.13 BUG-003 FIX: НЕ flush'им set на N подряд провалов.
    # Раньше после 3 fail'ов set обнулялся — это создавало защитный gap.
    # Stale data (например, threat blocklist неделю не обновлялся) — better
    # than no protection (атакующие из stale списка всё равно враждебные).
    # Только alert в syslog.
    if [ "$CURRENT" -ge "$FAIL_THRESHOLD_VAL" ]; then
        logger -t "$LOG_TAG" "ALERT: $CURRENT consecutive fetch failures for $NFT_SET — keeping last-known-good set (stale OK)"
    fi
    exit 1
fi

# 4) Если ничего не скачано и нет local → set остаётся как есть (no-op)
if [ ! -s "$TMP/all.raw" ]; then
    logger -t "$LOG_TAG" "пустой результат, нет источников — пропускаю"
    exit 0
fi

# 5) Парсинг + sanity. Поддерживаем форматы:
#    - plain IP:           8.8.8.8
#    - CIDR:               1.2.3.0/24
#    - Spamhaus:           "1.2.3.0/24 ; SBL12345"
#    - FireHOL:            "# comment\n1.2.3.0/24"
#    - inline комментарий: "8.8.8.8 # google"
#
# Sanity v3.23.13 BUG-003 FIX:
#    - prefix per-feed-type:
#       threat: min /16 (защита от compromised feed с /8 /10 broad blocks).
#       scanner/custom: min /8 (operator-controlled).
#       tor: только /32 (single IPs).
#    - bogons расширены: + CGNAT (100.64/10), + TEST-NET-1/2/3, + benchmark.
#    - multicast/reserved: 224-255/8 (через o1>=224).
case "$NAME" in
    threat) MIN_PREFIX=16 ;;
    *)      MIN_PREFIX=8  ;;
esac
grep -oE '^[[:space:]]*[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]+)?' "$TMP/all.raw" | \
    awk '{ sub(/^[[:space:]]+/, ""); print }' | \
    awk -F'[./]' -v minprefix="$MIN_PREFIX" '
    {
        prefix = (NF >= 5) ? $5 : 32
        if (prefix < minprefix || prefix > 32) next
        o1 = $1 + 0
        o2 = $2 + 0
        o3 = $3 + 0
        o4 = $4 + 0
        if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) next   # v3.23.15 P2-1: невалидный октет (битый фид)
        if (o1 == 0)   next                                      # 0/8
        if (o1 == 10)  next                                      # RFC1918
        if (o1 == 127) next                                      # loopback
        if (o1 >= 224) next                                      # multicast + reserved
        if (o1 == 169 && o2 == 254) next                         # link-local
        if (o1 == 172 && o2 >= 16 && o2 <= 31) next              # RFC1918
        if (o1 == 192 && o2 == 168) next                         # RFC1918
        if (o1 == 100 && o2 >= 64 && o2 <= 127) next             # CGNAT RFC6598
        if (o1 == 192 && o2 == 0 && o3 == 0) next                # IANA reserved
        if (o1 == 192 && o2 == 0 && o3 == 2) next                # TEST-NET-1
        if (o1 == 198 && (o2 == 18 || o2 == 19)) next            # benchmark RFC2544
        if (o1 == 198 && o2 == 51 && o3 == 100) next             # TEST-NET-2
        if (o1 == 203 && o2 == 0 && o3 == 113) next              # TEST-NET-3
        print $0
    }' | sort -u > "$TMP/parsed.list"

V4_COUNT=$(wc -l < "$TMP/parsed.list")
V4_COUNT="${V4_COUNT:-0}"

# v3.23.13 BUG-003 FIX: hard cap на total entries.
# Если feed внезапно даёт >MAX_FEED_ENTRIES — подозрение на compromise.
# Реальные real-world counts (snap 2026-05): Spamhaus DROP ~1100, FireHOL Level1 ~6800,
# blocklist.de ~30k, ipsum L3 ~17k → суммарно threat обычно ~50k unique entries.
# 200k — порог при котором что-то очень не так с источником.
MAX_FEED_ENTRIES=200000
case "$NAME" in
    threat) MAX_FEED_ENTRIES=200000 ;;
    scanner) MAX_FEED_ENTRIES=100000 ;;
    tor)    MAX_FEED_ENTRIES=10000 ;;
    custom) MAX_FEED_ENTRIES=50000 ;;
esac
if [ "$V4_COUNT" -gt "$MAX_FEED_ENTRIES" ]; then
    logger -t "$LOG_TAG" "ABORT: feed has $V4_COUNT entries (>$MAX_FEED_ENTRIES cap) — suspicious, refusing apply. Old set preserved."
    exit 1
fi

# 5.1) v3.27.0 FIX(#7): параллельный IPv6-парсинг того же фида. v6 часто 0 — это НЕ
# ошибка (min-check к v6 НЕ применяем). Префикс-флор V6_MIN_PREFIX отсекает ::/0 и
# слишком широкие блоки (compromised feed). Bogons/ULA/link-local/multicast/doc — drop.
# nft valid'ит каждый элемент при add (backstop против битого синтаксиса).
case "$NAME" in
    threat) V6_MIN_PREFIX=29 ;;   # v3.27.2: было /32 — отвергало /29 Spamhaus drop_v6 (RIR-min). /29 = практический потолок широты v6-блока
    *)      V6_MIN_PREFIX=24 ;;
esac
grep -oiE '^[[:space:]]*([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(/[0-9]{1,3})?' "$TMP/all.raw" 2>/dev/null | \
    awk '{ sub(/^[[:space:]]+/, ""); print tolower($0) }' | \
    awk -v minp="$V6_MIN_PREFIX" '
    {
        raw = $0; addr = raw; pfx = 128; hascidr = 0
        if (index(raw, "/") > 0) { split(raw, a, "/"); addr = a[1]; pfx = a[2] + 0; hascidr = 1 }
        if (pfx < minp || pfx > 128) next
        if (addr == "::" || addr == "::1") next                  # unspecified / loopback
        if (addr ~ /^fe[89ab]/) next                              # fe80::/10 link-local
        if (addr ~ /^f[cd]/)    next                              # fc00::/7 ULA
        if (addr ~ /^ff/)       next                              # ff00::/8 multicast
        if (addr ~ /^2001:0?db8:/) next                           # 2001:db8::/32 documentation
        if (addr ~ /^::ffff:/)  next                              # v4-mapped (обрабатывается как v4)
        if (addr ~ /^64:ff9b:/) next                              # NAT64 well-known
        if (addr !~ /:/) next                                     # обязан содержать ":"
        # структурная валидация (анти-truncation от greedy grep: отсекаем обрезки "2606:4700:")
        if (addr ~ /:$/ && addr !~ /::$/) next                    # одиночный ":" в конце → обрезок
        if (addr ~ /^:/  && addr !~ /^::/) next                   # одиночный ":" в начале
        tmp = addr; ncol = gsub(/:/, ":", tmp)                    # счётчик ":" (tmp не меняется)
        if (addr ~ /::/) { if (ncol > 7) next }                   # с компрессией: не больше 7 ":"
        else { if (ncol != 7) next }                              # без компрессии: ровно 8 групп (7 ":")
        print (hascidr ? addr "/" pfx : addr)
    }' | sort -u > "$TMP/parsed6.list"
V6_COUNT=$(wc -l < "$TMP/parsed6.list"); V6_COUNT="${V6_COUNT:-0}"
if [ "$V6_COUNT" -gt "$MAX_FEED_ENTRIES" ]; then
    logger -t "$LOG_TAG" "ABORT(v6): feed has $V6_COUNT v6 entries (>$MAX_FEED_ENTRIES) — suspicious, пропускаю v6"
    : > "$TMP/parsed6.list"; V6_COUNT=0
fi

# 5.5) v3.23.4: Health warning — если получили намного меньше чем когда-то.
# Источники могут "тихо умирать": URL поменялся, repo удалили, ToS-change.
# Сохраняем peak в state-файле. Auto-reset: если current >= 80% от peak,
# обновляем peak до current — источник восстановился, baseline сместился.
# v3.23.13 BUG-003 ENHANCE: alert при росте >20% от peak (потенциальный compromise feed).
PEAK_FILE="/var/lib/shieldnode/.peak-${NAME}"
PEAK=$(cat "$PEAK_FILE" 2>/dev/null || echo 0)
PEAK="${PEAK:-0}"
if [ "$V4_COUNT" -gt "$PEAK" ]; then
    # Внезапный рост >20% от prev peak (только если peak уже >1000) — alert
    if [ "$PEAK" -gt 1000 ] && [ "$V4_COUNT" -gt "$((PEAK * 120 / 100))" ]; then
        logger -t "$LOG_TAG" "WARN: feed grew >20% (peak=$PEAK → current=$V4_COUNT). Manual review recommended. Applying anyway."
        # NB: продолжаем применять, не блокируем — оператор может выключить sync если нужно.
    fi
    # Новый рекорд
    echo "$V4_COUNT" > "$PEAK_FILE"
elif [ "$PEAK" -gt 1000 ] && [ "$V4_COUNT" -ge "$((PEAK * 80 / 100))" ]; then
    # Current >= 80% от peak — recovery, сдвигаем baseline к current
    # (защита от "застрявшего" peak когда источник временно прыгал высоко)
    echo "$V4_COUNT" > "$PEAK_FILE"
elif [ "$PEAK" -gt 1000 ] && [ "$V4_COUNT" -lt "$((PEAK / 2))" ]; then
    # Current < 50% от peak — источник деградировал, alert
    logger -t "$LOG_TAG" "WARN: degraded feed — got $V4_COUNT entries, peak was $PEAK (<50%, источник мог измениться)"
fi

# 6) Min check (для custom MIN_ENTRIES может быть 0 — допускается пустой)
if [ "$V4_COUNT" -lt "$MIN_ENTRIES" ]; then
    logger -t "$LOG_TAG" "ERROR: только $V4_COUNT IPv4 подсетей (ожидали >=$MIN_ENTRIES) — не применяю"
    # Инкрементируем fail counter
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0)
    CURRENT="${CURRENT:-0}"
    CURRENT=$((CURRENT + 1))
    echo "$CURRENT" > "$FAIL_COUNTER"
    # v3.23.13 BUG-003 FIX: НЕ flush set'а на min-check failures.
    # Stale OK; alert в syslog.
    if [ "$CURRENT" -ge "$FAIL_THRESHOLD_VAL" ]; then
        logger -t "$LOG_TAG" "ALERT: $CURRENT consecutive min-check failures for $NFT_SET — keeping last-known-good (stale OK)"
    fi
    exit 1
fi

# 7) v4 — атомарный flush + add (как раньше). v6 — ОТДЕЛЬНОЙ транзакцией ниже, чтобы
# битый v6-элемент (например, обрезок от greedy-парсинга) НЕ ломал применение v4.
HAVE_V6_SET=0
if [ -n "${NFT_SET_V6:-}" ] && nft list set inet ddos_protect "$NFT_SET_V6" >/dev/null 2>&1; then
    HAVE_V6_SET=1
fi
{
    echo "flush set inet ddos_protect $NFT_SET"
    if [ -s "$TMP/parsed.list" ]; then
        # Группами по 1000 элементов (производительнее чем по одному)
        awk -v setname="$NFT_SET" '
            NR % 1000 == 1 { if (NR > 1) print "}"; printf "add element inet ddos_protect %s { ", setname }
            { printf "%s%s", (NR % 1000 == 1 ? "" : ", "), $0 }
            END { print " }" }' "$TMP/parsed.list"
    fi
} > "$TMP/nft-batch"

V4_OK=0
if nft -f "$TMP/nft-batch" 2>"$TMP/nft.err"; then
    echo 0 > "$FAIL_COUNTER"
    V4_OK=1
else
    logger -t "$LOG_TAG" "ERROR: nft -f failed: $(cat "$TMP/nft.err")"
    CURRENT=$(cat "$FAIL_COUNTER" 2>/dev/null || echo 0); CURRENT="${CURRENT:-0}"
    echo $((CURRENT + 1)) > "$FAIL_COUNTER"
fi

# 7.1) v3.27.0 FIX(#7): v6-транзакция (изолирована — не влияет на статус/exit v4).
V6_APPLIED=0
if [ "$HAVE_V6_SET" = "1" ] && [ -s "$TMP/parsed6.list" ]; then
    {
        echo "flush set inet ddos_protect $NFT_SET_V6"
        awk -v setname="$NFT_SET_V6" '
            NR % 1000 == 1 { if (NR > 1) print "}"; printf "add element inet ddos_protect %s { ", setname }
            { printf "%s%s", (NR % 1000 == 1 ? "" : ", "), $0 }
            END { print " }" }' "$TMP/parsed6.list"
    } > "$TMP/nft-batch6"
    if nft -f "$TMP/nft-batch6" 2>"$TMP/nft6.err"; then
        V6_APPLIED="$V6_COUNT"
    else
        logger -t "$LOG_TAG" "WARN(v6): nft -f failed for $NFT_SET_V6 ($(cat "$TMP/nft6.err")) — v6 пропущен, v4 не затронут"
    fi
fi

if [ "$V4_OK" = "1" ]; then
    logger -t "$LOG_TAG" "Updated $NFT_SET: $V4_COUNT IPv4 + $V6_APPLIED IPv6 подсетей (remote=$REMOTE_DOWNLOADED/$REMOTE_TRIED, local=$LOCAL_FOUND)"
    exit 0
else
    exit 1
fi
UPDATER_EOF
chmod 0755 "$SHIELD_UPDATER_SCRIPT"
print_ok "Updater: $SHIELD_UPDATER_SCRIPT"

# 2.6) v3.14.0: GitHub sync updater — качает lists/custom.txt с github,
#      обновляет /etc/shieldnode/lists/custom.txt (custom-local.txt не трогает).
SHIELD_GITHUB_SYNC_SCRIPT="/usr/local/sbin/shieldnode-github-sync.sh"
cat > "$SHIELD_GITHUB_SYNC_SCRIPT" <<GITHUB_SYNC_EOF
#!/bin/bash
# shieldnode v3.20.4 — github sync для lists/custom.txt
# Запускается через shieldnode-github-sync.timer (раз в 6ч).
# Без интернета или 404 — оставляет существующий файл как есть.

set -o pipefail
export LANG=C LC_ALL=C

LOG_TAG="shieldnode-github-sync"
TARGET="/etc/shieldnode/lists/custom.txt"
URL="$SHIELD_REPO_URL/lists/custom.txt"

# Загружаем конфиг (опциональный)
if [ -f /etc/shieldnode/shieldnode.conf ]; then
    # shellcheck source=/dev/null
    . /etc/shieldnode/shieldnode.conf
fi

# Если sync выключен в конфиге — exit
if [ "\${ENABLE_GITHUB_SYNC:-1}" != "1" ]; then
    logger -t "\$LOG_TAG" "ENABLE_GITHUB_SYNC=\${ENABLE_GITHUB_SYNC}, sync пропущен"
    exit 0
fi

TMP=\$(mktemp /etc/shieldnode/lists/.custom.txt.XXXXXX 2>/dev/null) || TMP=\$(mktemp)
trap 'rm -f "\$TMP"' EXIT

if ! curl -fsSL --max-time 30 --retry 2 "\$URL" -o "\$TMP" 2>/dev/null; then
    logger -t "\$LOG_TAG" "WARN: не смог скачать \$URL — оставляю текущий \$TARGET"
    exit 1
fi

if [ ! -s "\$TMP" ]; then
    logger -t "\$LOG_TAG" "WARN: github вернул пустой файл — оставляю текущий"
    exit 1
fi

# v3.18.11 SH-NEW-56: проверка что content — plain text, не HTML-error-page.
# Github raw обычно возвращает 404 (тогда -f выкинет), но cloudflare maintenance
# / proxy errors могут вернуть 200 OK + HTML body.
# Plain text custom.txt всегда начинается с '#' (header comment) или digit (IP).
FIRST_BYTE=\$(head -c 1 "\$TMP")
case "\$FIRST_BYTE" in
    \\#|[0-9]) ;; # OK plain-text
    *)
        logger -t "\$LOG_TAG" "WARN: github вернул не-text content (first byte: \$(printf '%q' \"\$FIRST_BYTE\")) — оставляю текущий"
        exit 1
        ;;
esac
# Дополнительно: явно отклоняем HTML
if head -3 "\$TMP" | grep -qiE '<html|<!doctype'; then
    logger -t "\$LOG_TAG" "WARN: github вернул HTML — оставляю текущий"
    exit 1
fi

# Sanity-check: новый файл должен быть валидным (хотя бы 1 IP-подобная строка
# или хотя бы заголовок-комментарий — пустые тоже ОК для seed'ов).
NEW_LINES=\$(wc -l < "\$TMP")
NEW_LINES="\${NEW_LINES:-0}"

# Сравниваем с текущим файлом — если идентичны, не делаем ничего
if [ -f "\$TARGET" ] && cmp -s "\$TARGET" "\$TMP"; then
    logger -t "\$LOG_TAG" "no-change: github custom.txt идентичен локальному"
    exit 0
fi

# v3.18.8: атомарная замена. mktemp в той же директории что и TARGET → mv
# не пересекает FS-границу (раньше /tmp могло быть tmpfs → mv = cp+unlink,
# path-watcher ловил partial-файл).
chmod 0644 "\$TMP"
mv "\$TMP" "\$TARGET"   # atomic — same FS
trap - EXIT             # файл уже на месте, cleanup отменяем
logger -t "\$LOG_TAG" "sync OK: \$TARGET обновлён (\$NEW_LINES lines). path-watcher триггерит nft update."
exit 0
GITHUB_SYNC_EOF
chmod 0755 "$SHIELD_GITHUB_SYNC_SCRIPT"
print_ok "GitHub sync updater: $SHIELD_GITHUB_SYNC_SCRIPT"

# 2.7) v3.14.0: Version check updater — проверяет github на новую версию.
SHIELD_VERSION_CHECK_SCRIPT="/usr/local/sbin/shieldnode-version-check.sh"
cat > "$SHIELD_VERSION_CHECK_SCRIPT" <<VERSION_CHECK_EOF
#!/bin/bash
# shieldnode v3.20.4 — version check
# Запускается через shieldnode-version-check.timer (раз в день).
# Парсит первые 10 строк github shieldnode.sh, ищет 'v3.X.Y'.
# Результат пишет в /var/lib/shieldnode/.upstream_version
# guard CLI читает этот файл и показывает [upgrade] на главном экране.

set -o pipefail
export LANG=C LC_ALL=C

LOG_TAG="shieldnode-version-check"
STATE_DIR="/var/lib/shieldnode"
mkdir -p "\$STATE_DIR"
STATE_FILE="\$STATE_DIR/.upstream_version"
URL="$SHIELD_REPO_URL/shieldnode.sh"
LOCAL_VERSION="$SHIELDNODE_VERSION"

if [ -f /etc/shieldnode/shieldnode.conf ]; then
    # shellcheck source=/dev/null
    . /etc/shieldnode/shieldnode.conf
fi

if [ "\${ENABLE_VERSION_CHECK:-1}" != "1" ]; then
    rm -f "\$STATE_FILE"
    exit 0
fi

# Качаем только первые 4KB (для парсинга версии достаточно)
UPSTREAM_HEADER=\$(curl -fsSL --max-time 10 --range 0-4095 "\$URL" 2>/dev/null)
if [ -z "\$UPSTREAM_HEADER" ]; then
    logger -t "\$LOG_TAG" "WARN: не смог скачать header с \$URL"
    exit 1
fi

# Ищем строку формата 'VPN NODE DDoS PROTECTION v3.X.Y' в первых строках
UPSTREAM_VERSION=\$(echo "\$UPSTREAM_HEADER" | grep -oE 'VPN NODE DDoS PROTECTION v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed -E 's/.*v([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

if [ -z "\$UPSTREAM_VERSION" ]; then
    logger -t "\$LOG_TAG" "WARN: не смог распарсить версию из github header"
    exit 1
fi

# Сравниваем (semver через sort -V)
if [ "\$UPSTREAM_VERSION" = "\$LOCAL_VERSION" ]; then
    # Та же версия — записываем для guard но без флага апгрейда
    echo "current=\$LOCAL_VERSION" > "\$STATE_FILE"
    echo "upstream=\$UPSTREAM_VERSION" >> "\$STATE_FILE"
    echo "upgrade_available=0" >> "\$STATE_FILE"
    echo "checked_at=\$(date +%s)" >> "\$STATE_FILE"
    exit 0
fi

NEWER=\$(printf '%s\n%s\n' "\$LOCAL_VERSION" "\$UPSTREAM_VERSION" | sort -V | tail -1)
if [ "\$NEWER" = "\$UPSTREAM_VERSION" ]; then
    # Upstream новее
    {
        echo "current=\$LOCAL_VERSION"
        echo "upstream=\$UPSTREAM_VERSION"
        echo "upgrade_available=1"
        echo "checked_at=\$(date +%s)"
    } > "\$STATE_FILE"
    logger -t "\$LOG_TAG" "Доступна новая версия: \$UPSTREAM_VERSION (текущая: \$LOCAL_VERSION). Run: sudo guard upgrade"
else
    # Local новее (dev-версия) — не показываем upgrade
    {
        echo "current=\$LOCAL_VERSION"
        echo "upstream=\$UPSTREAM_VERSION"
        echo "upgrade_available=0"
        echo "checked_at=\$(date +%s)"
    } > "\$STATE_FILE"
fi
exit 0
VERSION_CHECK_EOF
chmod 0755 "$SHIELD_VERSION_CHECK_SCRIPT"
print_ok "Version-check updater: $SHIELD_VERSION_CHECK_SCRIPT"

# Systemd units для github-sync и version-check
cat > /etc/systemd/system/shieldnode-github-sync.service <<EOF
[Unit]
Description=Sync shieldnode custom.txt from github
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SHIELD_GITHUB_SYNC_SCRIPT
EOF

cat > /etc/systemd/system/shieldnode-github-sync.timer <<EOF
[Unit]
Description=Sync shieldnode custom.txt from github every $DEFAULT_GITHUB_SYNC_INTERVAL
Requires=shieldnode-github-sync.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=$DEFAULT_GITHUB_SYNC_INTERVAL
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/shieldnode-version-check.service <<EOF
[Unit]
Description=Check github for new shieldnode version
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SHIELD_VERSION_CHECK_SCRIPT
EOF

cat > /etc/systemd/system/shieldnode-version-check.timer <<EOF
[Unit]
Description=Check github for new shieldnode version every $DEFAULT_VERSION_CHECK_INTERVAL
Requires=shieldnode-version-check.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=$DEFAULT_VERSION_CHECK_INTERVAL
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
if [ "${ENABLE_GITHUB_SYNC:-1}" = "1" ]; then
    systemctl enable --now shieldnode-github-sync.timer >/dev/null 2>&1
    print_ok "GitHub sync timer активен (раз в $DEFAULT_GITHUB_SYNC_INTERVAL)"
fi
if [ "${ENABLE_VERSION_CHECK:-1}" = "1" ]; then
    systemctl enable --now shieldnode-version-check.timer >/dev/null 2>&1
    print_ok "Version-check timer активен (раз в $DEFAULT_VERSION_CHECK_INTERVAL)"
fi

# 3) Templated systemd unit (обслуживает все 4 blocklist'а)
cat > /etc/systemd/system/shieldnode-update@.service <<EOF
[Unit]
Description=Update shieldnode %i blocklist
After=network-online.target shieldnode-nftables.service
Wants=network-online.target
Requires=shieldnode-nftables.service
# v3.16.1: при rapid edit файла path-watcher может триггерить service'ы
# серией. Расширяем лимит запусков чтобы избежать unit-start-limit-hit.
StartLimitBurst=30
StartLimitIntervalSec=60

[Service]
Type=oneshot
ExecStart=$SHIELD_UPDATER_SCRIPT %i
# v3.18.11 SH-NEW-141: TimeoutStartSec=120s — если updater hangs (slow URL-feed
# за РКН, hung curl), systemd убьёт его через 2 мин. Раньше FINAL TRIGGER
# делал timeout-обертку вокруг systemctl start, но timeout убивал только
# CLI, а не сам updater (который продолжал работать в background).
TimeoutStartSec=120
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$SHIELD_STATE_DIR
EOF

# 4) Per-list timers (с разными интервалами из defaults/config)
make_timer() {
    local n="$1" interval="$2"
    cat > "/etc/systemd/system/shieldnode-update@${n}.timer" <<EOF
[Unit]
Description=Update $n blocklist (every $interval)
Requires=shieldnode-update@${n}.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=$interval
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
}
make_timer scanner      "$DEFAULT_SCANNER_UPDATE_INTERVAL"
make_timer threat       "$DEFAULT_THREAT_UPDATE_INTERVAL"
make_timer tor          "$DEFAULT_TOR_UPDATE_INTERVAL"
make_timer custom       "$DEFAULT_CUSTOM_UPDATE_INTERVAL"
# v3.20.0: timer'ы mobile_ru и broadband_ru УБРАНЫ.

# 5) inotify path-watcher для custom (мгновенно реагирует на изменение файла)
cat > /etc/systemd/system/shieldnode-update@custom.path <<EOF
[Unit]
Description=Watch custom blocklist files (custom.txt + custom-local.txt)
# v3.16.1: при rapid edit файла (например 'tee -a' через скрипт) path-watcher
# может триггерить updater несколько раз в секунду → systemd default
# (StartLimitBurst=5 / Interval=10s) выключает unit как 'unit-start-limit-hit'.
# Расширяем лимит: 30 запусков за минуту.
StartLimitBurst=30
StartLimitIntervalSec=60

[Path]
PathChanged=$SHIELD_LISTS_DIR/custom.txt
PathChanged=$SHIELD_LISTS_DIR/custom-local.txt
PathExists=$SHIELD_LISTS_DIR/custom.txt
Unit=shieldnode-update@custom.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 6) Подготовка lists/ (pipe-mode скачивает с github, git-mode копирует ./lists/)
mkdir -p "$SHIELD_LISTS_DIR"
chmod 0755 "$SHIELD_LISTS_DIR"

prepare_seed_list() {
    local name="$1" target="$SHIELD_LISTS_DIR/${1}.txt"
    # v3.18.8: определяем что seed уже есть И валиден:
    #   (a) содержит IP-подобную строку → точно валиден, или
    #   (b) НЕ помечен как локальный stub-fallback (отсутствует маркер
    #       "Auto-merged with URL sources" из fallback heredoc'а ниже —
    #       значит файл скачан с github и легитимен даже если только
    #       комментарии, как tor.txt seed).
    if [ -f "$target" ]; then
        if grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$target"; then
            return 0   # есть IP — однозначно ок
        fi
        if ! grep -qF "Auto-merged with URL sources при наличии конфига" "$target" 2>/dev/null; then
            return 0   # github seed (header-only валиден)
        fi
        # Иначе это наш локальный stub-fallback — пробуем перекачать
    fi
    if [ "$SHIELD_PIPE_MODE" = "1" ]; then
        # Pipe-mode: качаем дефолтный seed с github (с retry'ями)
        local try ok=0
        for try in 1 2 3; do
            if curl -fsSL --max-time 15 --retry 1 "$SHIELD_REPO_URL/lists/${name}.txt" -o "$target.tmp" 2>/dev/null \
               && [ -s "$target.tmp" ]; then
                # Принимаем если не HTML 404-страница (любой текстовый файл —
                # включая header-only комментариями — валидный seed).
                if ! head -1 "$target.tmp" | grep -qiE '<html|<!doctype'; then
                    mv "$target.tmp" "$target"
                    ok=1
                    break
                fi
            fi
            sleep 2
        done
        rm -f "$target.tmp"
        if [ "$ok" = "1" ]; then
            return 0
        fi
        print_warn "Не смог скачать lists/${name}.txt с github после 3 попыток"
        print_info "Создан пустой stub. Запусти 'sudo guard sync' когда сеть восстановится."
    elif [ -n "$SHIELD_SCRIPT_DIR" ] && [ -f "$SHIELD_SCRIPT_DIR/lists/${name}.txt" ]; then
        cp "$SHIELD_SCRIPT_DIR/lists/${name}.txt" "$target"
        return 0
    fi
    # Fallback: пустой файл с заголовком (только если ничего нет)
    if [ ! -f "$target" ]; then
        cat > "$target" <<HDR_EOF
# shieldnode $name blocklist (one IP or CIDR per line, # = comment)
# Auto-merged with URL sources при наличии конфига.
HDR_EOF
    fi
}
for n in scanner threat tor custom; do
    prepare_seed_list "$n"
done

# v3.14.0: создаём custom-local.txt если нет (пустой с заголовком).
# Этот файл оператор редактирует руками на ноде — github sync его не трогает.
LOCAL_CUSTOM="$SHIELD_LISTS_DIR/custom-local.txt"
if [ ! -e "$LOCAL_CUSTOM" ]; then
    cat > "$LOCAL_CUSTOM" <<'LOCAL_HDR_EOF'
# shieldnode custom-local blocklist (this node only)
# nft set: custom_blocklist_v4 (объединяется с custom.txt)
#
# Этот файл — ЛОКАЛЬНЫЙ список этой конкретной ноды.
# github auto-sync (если включён) НЕ трогает этот файл — только custom.txt.
#
# Добавить IP в ban на лету (path-watcher подхватит за <1сек):
#   echo '198.51.100.42' | sudo tee -a /etc/shieldnode/lists/custom-local.txt
#
# Один IP или CIDR на строку, # = комментарий.

LOCAL_HDR_EOF
    chmod 0644 "$LOCAL_CUSTOM"
fi

# Опциональный shieldnode.conf — если оператор положил рядом со скриптом, копируем
if [ -n "$SHIELD_SCRIPT_DIR" ] && [ -f "$SHIELD_SCRIPT_DIR/shieldnode.conf" ] && [ ! -f "$SHIELD_CONF_FILE" ]; then
    cp "$SHIELD_SCRIPT_DIR/shieldnode.conf" "$SHIELD_CONF_FILE"
    chmod 0640 "$SHIELD_CONF_FILE"
    print_ok "Config: $SHIELD_CONF_FILE (из git-clone)"
fi

print_ok "Lists: $SHIELD_LISTS_DIR/{scanner,threat,tor,custom,custom-local}.txt"

# 7) Включаем и запускаем blocklists. Tor — только если BLOCK_TOR=1.
# v3.13.0: mobile_ru — только если ENABLE_RU_MOBILE_WHITELIST=1 (по умолчанию ON).
# v3.18.3: mobile-RU CIDRы качаются с github (lists/mobile-ru.txt) — никакие
# license key'и не нужны. На первом запуске set может быть пуст пока github-sync
# не отработает (в течение 6 ч от установки).
ENABLED_LISTS=(scanner threat custom)
if [ "$BLOCK_TOR" = "1" ]; then
    ENABLED_LISTS+=(tor)
    mkdir -p /etc/shieldnode
    touch /etc/shieldnode/block_tor
fi
if [ "${ENABLE_RU_MOBILE_WHITELIST:-1}" = "1" ]; then
    # v3.20.0: mobile_ru deprecated. Старые ноды с ENABLE_RU_MOBILE_WHITELIST=1
    # в shieldnode.conf не сломаются — просто игнорируется.
    : # no-op
fi
if [ "${ENABLE_RU_BROADBAND_WHITELIST:-1}" = "1" ]; then
    # v3.20.0: broadband_ru deprecated.
    : # no-op
fi

declare -A LIST_SIZES
# v3.18.8: ждём пока nft table inet ddos_protect станет доступна.
# systemctl restart shieldnode-nftables (выше в ШАГ 4) делает stop+start —
# между ExecStop (nft delete) и ExecStart (nft -f) есть короткое окно
# когда table не существует. Если updater отрабатывает в этот момент —
# выходит с "table не существует" и blocklist остаётся пустым до следующего
# таймера (через 6-24h).
NFT_TABLE_WAIT=0
while ! nft list table inet ddos_protect >/dev/null 2>&1; do
    NFT_TABLE_WAIT=$((NFT_TABLE_WAIT + 1))
    if [ "$NFT_TABLE_WAIT" -ge 30 ]; then
        print_warn "table inet ddos_protect не появилась за 30 сек — blocklists не загрузятся"
        print_info "Ручной фикс позже: sudo systemctl restart shieldnode-nftables"
        print_info "                   sudo /usr/local/sbin/shieldnode-update-blocklist.sh scanner"
        break
    fi
    sleep 1
done
if [ "$NFT_TABLE_WAIT" -gt 0 ] && [ "$NFT_TABLE_WAIT" -lt 30 ]; then
    print_info "Ждал nft table: ${NFT_TABLE_WAIT}s"
fi

for n in "${ENABLED_LISTS[@]}"; do
    systemctl enable "shieldnode-update@${n}.timer" >/dev/null 2>&1
    # Первый запуск (blocking) для немедленного заполнения set'а
    print_status "Загружаю $n blocklist..."
    if systemctl start "shieldnode-update@${n}.service" 2>/dev/null; then
        sleep 1
        SET_NAME=$(case "$n" in
            scanner)      echo "scanner_blocklist_v4" ;;
            threat)       echo "threat_blocklist_v4"  ;;
            tor)          echo "tor_exit_blocklist_v4" ;;
            custom)       echo "custom_blocklist_v4"  ;;
        esac)
        SIZE=$(nft list set inet ddos_protect "$SET_NAME" 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
        SIZE="${SIZE:-0}"
        LIST_SIZES[$n]="$SIZE"
    else
        LIST_SIZES[$n]=0
    fi
    systemctl start "shieldnode-update@${n}.timer" >/dev/null 2>&1
done

# Path-watcher для custom (всегда активен независимо от BLOCK_TOR)
# v3.16.1: при reinstall может быть unit в failed-state из-за прошлых
# StartLimit hit'ов. Сбрасываем перед перезапуском.
systemctl reset-failed shieldnode-update@custom.path 2>/dev/null
systemctl reset-failed 'shieldnode-update@*.service' 2>/dev/null
systemctl daemon-reload
systemctl enable --now shieldnode-update@custom.path >/dev/null 2>&1

# ============================================================================
# v3.17.0: WHITELIST-LOCAL.TXT — symmetric к custom-local.txt но для accept
# ============================================================================
# Файл /etc/shieldnode/lists/whitelist-local.txt → nft manual_whitelist_v4
# IPs из этого файла:
#   - попадают в manual_whitelist_v4 → обходят ВСЕ shieldnode проверки
#   - удаляются из confirmed_attack_v4, suspect_v4, custom_blocklist_v4 и др.
# Path-watcher подхватывает изменения за 1-2 сек.

WHITELIST_LOCAL="$SHIELD_LISTS_DIR/whitelist-local.txt"
WHITELIST_UPDATER="/usr/local/sbin/shieldnode-whitelist-updater.sh"

# 1. Создаём whitelist-local.txt только если его нет (сохраняем существующие записи при reinstall)
if [ ! -e "$WHITELIST_LOCAL" ]; then
    cat > "$WHITELIST_LOCAL" <<'WHITELIST_DEFAULT'
# shieldnode local whitelist (этот узел)
#
# IPs/CIDRs тут добавляются в nft manual_whitelist_v4 — обходят ВСЕ проверки:
# rate-limit, conn-flood, scanner blocklist, threat blocklist, mobile-RU drop.
# Также автоматически удаляются из confirmed_attack_v4, suspect_v4 и blocklist'ов.
#
# Изменения подхватываются path-watcher'ом за 1-2 секунды.
#
# Формат: один IP или CIDR на строку, # = комментарий.
# Примеры:
#   echo '1.2.3.4' | sudo tee -a /etc/shieldnode/lists/whitelist-local.txt
#   echo '10.0.0.0/24' | sudo tee -a /etc/shieldnode/lists/whitelist-local.txt
#
# Удалить: отредактировать файл (удалить строку), изменения применятся за 2 сек.
WHITELIST_DEFAULT
    chmod 0644 "$WHITELIST_LOCAL"
fi

# v3.23.15 P2-2: anti-lockout — текущий админский IP в whitelist-local.txt.
# Durable: whitelist-updater синхронит файл → manual_whitelist_v4 (обходит SSH ct=5
# и все shieldnode-проверки). Защита от self-lockout при параллельных SSH/CI-CD.
# NB: за shared CGNAT это whitelist'ит весь пул — удали строку из файла (применится
# за ~2 сек) или через guard → Trusted IPs.
if [ -n "${ADMIN_IP:-}" ]; then
    case "$ADMIN_IP" in
        *:*) : ;;  # IPv6 — manual_whitelist_v4 это ipv4; v6-whitelist отдельно (2-я волна)
        *)
            if validate_ipv4_or_cidr "$ADMIN_IP" 2>/dev/null && ! grep -qF "$ADMIN_IP" "$WHITELIST_LOCAL" 2>/dev/null; then
                echo "$ADMIN_IP  # v3.23.15 anti-lockout (админ-IP при установке)" >> "$WHITELIST_LOCAL"
                print_ok "Anti-lockout: $ADMIN_IP добавлен в whitelist-local.txt"
            fi
            ;;
    esac
fi

# 2. Updater script
cat > "$WHITELIST_UPDATER" <<'WHITELIST_UPDATER_EOF'
#!/bin/bash
# shieldnode-whitelist-updater — синхронизирует whitelist-local.txt → nft manual_whitelist_v4
set -u
WHITELIST_FILE="/etc/shieldnode/lists/whitelist-local.txt"
NFT_TABLE="inet ddos_protect"
NFT_SET="manual_whitelist_v4"
LOG_TAG="shieldnode-whitelist"

[ -r "$WHITELIST_FILE" ] || { logger -t "$LOG_TAG" "File missing: $WHITELIST_FILE"; exit 1; }

# Парсим IPs (без комментариев, пустых строк, валидируем формат)
IPS=$(grep -vE '^[[:space:]]*(#|$)' "$WHITELIST_FILE" | \
      grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | \
      sort -u)

if [ -n "$IPS" ]; then
    {
        echo "flush set $NFT_TABLE $NFT_SET"
        while IFS= read -r ip; do
            echo "add element $NFT_TABLE $NFT_SET { $ip }"
        done <<< "$IPS"
    } | nft -f - 2>&1

    # Удаляем whitelisted IPs из drop sets — нельзя одновременно whitelist'ить и банить.
    # v3.23.9: batch nft -f - вместо 6 fork'ов на каждый IP.
    # Раньше: 3 IP × 6 sets = 18 nft processes → CPU spike до 90%.
    # Теперь: 1 nft process для всех операций.
    {
        while IFS= read -r ip; do
            echo "delete element $NFT_TABLE confirmed_attack_v4 { $ip }"
            echo "delete element $NFT_TABLE suspect_v4 { $ip }"
            echo "delete element $NFT_TABLE custom_blocklist_v4 { $ip }"
            echo "delete element $NFT_TABLE scanner_blocklist_v4 { $ip }"
            echo "delete element $NFT_TABLE threat_blocklist_v4 { $ip }"
            echo "delete element $NFT_TABLE tor_exit_blocklist_v4 { $ip }"
        done <<< "$IPS"
    } | nft -f - 2>/dev/null || true   # || true — некоторые элементы могут отсутствовать в set'ах

    COUNT=$(echo "$IPS" | wc -l)
    logger -t "$LOG_TAG" "Updated $NFT_SET: $COUNT IPs (cleaned from blocklists/attack sets)"
else
    nft flush set $NFT_TABLE $NFT_SET 2>/dev/null
    logger -t "$LOG_TAG" "Whitelist empty — flushed $NFT_SET"
fi

exit 0
WHITELIST_UPDATER_EOF
chmod 0750 "$WHITELIST_UPDATER"

# 3. Systemd service
cat > /etc/systemd/system/shieldnode-whitelist.service <<EOF
[Unit]
Description=Update shieldnode whitelist (manual_whitelist_v4) from local file
After=shieldnode-nftables.service
Requires=shieldnode-nftables.service
StartLimitBurst=30
StartLimitIntervalSec=60

[Service]
Type=oneshot
ExecStart=$WHITELIST_UPDATER
EOF

# 4. Path-watcher
cat > /etc/systemd/system/shieldnode-whitelist.path <<EOF
[Unit]
Description=Watch shieldnode whitelist-local.txt for changes
StartLimitBurst=30
StartLimitIntervalSec=60

[Path]
PathChanged=$WHITELIST_LOCAL
PathExists=$WHITELIST_LOCAL
Unit=shieldnode-whitelist.service

[Install]
WantedBy=multi-user.target
EOF

# 5. Запуск + первая инициализация (с reset-failed для idempotency)
systemctl daemon-reload
systemctl reset-failed shieldnode-whitelist.path 2>/dev/null
systemctl reset-failed shieldnode-whitelist.service 2>/dev/null
systemctl enable --now shieldnode-whitelist.path >/dev/null 2>&1
systemctl start shieldnode-whitelist.service >/dev/null 2>&1

WHITELIST_COUNT=$(grep -vE '^[[:space:]]*(#|$)' "$WHITELIST_LOCAL" 2>/dev/null | grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
print_ok "Whitelist file-based: $WHITELIST_LOCAL ($WHITELIST_COUNT IPs, path-watcher активен)"

print_ok "Blocklists активны: $(
    for n in "${ENABLED_LISTS[@]}"; do
        printf "%s=%s " "$n" "${LIST_SIZES[$n]:-0}"
    done
)"


# ==============================================================================
# ШАГ 7: УСТАНОВКА CROWDSEC
# ==============================================================================

print_header "ШАГ 7: УСТАНОВКА CROWDSEC"

# v3.18.8: marker-файл указывает что CrowdSec ставился/управляется shieldnode'ом.
# Без marker'а пред-установленный (foreign) CrowdSec НЕ патчится:
# не трогаем profiles.yaml, acquis.d/sshd.yaml, не делаем nft delete table ip crowdsec.
# Это защищает кастомные конфиги оператора от silent-modification.
CROWDSEC_MARKER="/etc/shieldnode/.crowdsec_managed"
SHIELDNODE_CROWDSEC_MANAGED=0

if ! command -v cscli >/dev/null 2>&1; then
    wait_for_apt_lock
    print_status "Подключаю репозиторий CrowdSec..."
    if ! curl -fsSL https://install.crowdsec.net | bash; then
        print_error "Не удалось подключить репозиторий CrowdSec"
        print_info "Проверь интернет: curl -v https://install.crowdsec.net"
        exit 1
    fi

    # v3.18.8: ОТКЛЮЧАЕМ cscli unattended setup в post-inst hook'е CrowdSec.
    # По умолчанию post-inst запускает `cscli setup unattended` который качает
    # GeoLite2-City.mmdb (~80 MB) с hub-data.crowdsec.net БЕЗ timeout'а.
    # На VPS с медленной/блокирующей связью apt висит 10-30 минут и не реагирует
    # на Ctrl+C (sigmask внутри apt-транзакции). Делаем hub upgrade сами,
    # с timeout'ом, после установки.
    #
    # Способ — debconf-set-selections + переменная среды CSCLI_UNATTENDED_SKIP=1.
    # Если CrowdSec в будущей версии переименует переменную — fallback'ы
    # отработают через timeout на самом apt-get.
    mkdir -p /etc/crowdsec
    cat > /etc/crowdsec/.shieldnode-skip-unattended <<'SKIP_EOF'
# Создан установщиком shieldnode v3.20.4
# Сигнал для cscli setup unattended что shieldnode сделает hub upgrade сам.
SKIP_EOF
    # На многих версиях CrowdSec post-inst читает эту env var
    export CSCLI_UNATTENDED_SKIP=1
    export CROWDSEC_SKIP_HUB_UPDATE=1

    wait_for_apt_lock
    print_status "Устанавливаю crowdsec (с timeout 5 мин)..."
    # timeout оборачивает apt-get; если post-inst всё-таки полезет качать MMDB
    # и зависнет — apt будет убит по timeout, а dpkg --configure -a починит
    # состояние ниже.
    # v3.18.8: stdin перенаправлен в /dev/null чтобы cscli setup / post-inst
    # никогда не уходил в SIGTTIN (T-state) пытаясь читать с tty.
    # На CrowdSec 1.7.7 env-переменные SKIP не работают, post-inst всё равно
    # запускает cscli setup unattended, который в конце ждёт ENTER на баннере.
    APT_OK=0
    if timeout --kill-after=30s 300s \
       env DEBIAN_FRONTEND=noninteractive CSCLI_UNATTENDED_SKIP=1 CROWDSEC_SKIP_HUB_UPDATE=1 \
       apt-get install -y crowdsec </dev/null; then
        APT_OK=1
    else
        APT_RC=$?
        if [ "$APT_RC" = "124" ] || [ "$APT_RC" = "137" ]; then
            print_warn "apt-get crowdsec превысил 5-минутный timeout — чиним dpkg"
        else
            print_warn "apt-get crowdsec exit=$APT_RC — пробуем починить dpkg"
        fi
        # Убиваем все висящие cscli setup чтобы dpkg --configure не залип
        pkill -9 -f "cscli setup unattended" 2>/dev/null || true
        sleep 2
        # Иногда post-inst сам зависает — отключаем его на время configure.
        # v3.18.11 SH-NEW-70: устанавливаем trap ПЕРЕД mv (раньше был race window:
        # SIGTERM между mv и trap setup → original hook потерян до следующего apt).
        if [ -f /var/lib/dpkg/info/crowdsec.postinst ]; then
            POSTINST_ORIG="/var/lib/dpkg/info/crowdsec.postinst"
            POSTINST_DISABLED="/var/lib/dpkg/info/crowdsec.postinst.shieldnode-disabled"
            # Trap СНАЧАЛА — если SIGTERM в момент trap'а, condition false (DISABLED ещё нет), no-op
            trap 'if [ -f "$POSTINST_DISABLED" ] && [ ! -f "$POSTINST_ORIG" ]; then
                      mv "$POSTINST_DISABLED" "$POSTINST_ORIG" 2>/dev/null || true
                  fi' EXIT INT TERM
            mv "$POSTINST_ORIG" "$POSTINST_DISABLED"
            DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
            mv "$POSTINST_DISABLED" "$POSTINST_ORIG"
            trap - EXIT INT TERM   # снимаем trap — ручное восстановление прошло
        fi
        DEBIAN_FRONTEND=noninteractive apt-get install -f -y >/dev/null 2>&1 || true
        # Проверяем — возможно crowdsec всё-таки развернулся, просто без MMDB
        if command -v cscli >/dev/null 2>&1 && dpkg -l crowdsec 2>/dev/null | grep -qE "^ii"; then
            APT_OK=1
            print_ok "CrowdSec установлен (без MMDB — geoip-обогащение будет позже)"
        fi
    fi
    if [ "$APT_OK" != "1" ]; then
        print_error "Установка crowdsec провалилась"
        print_info "Попробуй вручную: sudo apt-get install -y crowdsec"
        print_info "Или проверь: sudo apt-cache policy crowdsec"
        exit 1
    fi
    # Мы поставили — мы и управляем
    mkdir -p /etc/shieldnode
    touch "$CROWDSEC_MARKER"
    SHIELDNODE_CROWDSEC_MANAGED=1

    # Hub upgrade с собственным timeout'ом (и не блокирующий установку при fail)
    print_status "Обновляю CrowdSec hub (timeout 2 мин, fail = не критично)..."
    if timeout --kill-after=10s 120s cscli hub update 2>/dev/null \
       && timeout --kill-after=10s 120s cscli hub upgrade 2>/dev/null; then
        print_ok "CrowdSec hub обновлён"
    else
        print_warn "Hub upgrade не успел за 2 мин — продолжаем без него"
        print_info "Запусти позже: sudo cscli hub update && sudo cscli hub upgrade"
    fi
else
    # CrowdSec уже стоял
    if [ -f "$CROWDSEC_MARKER" ]; then
        SHIELDNODE_CROWDSEC_MANAGED=1
    elif [ -d /var/lib/shieldnode ] || [ -f /etc/shieldnode/lists/scanner.txt ]; then
        # Migration: shieldnode на ноде явно был раньше (есть его state) — значит
        # это мы и ставили CrowdSec в прошлый раз, marker'а просто не было до v3.18.8.
        mkdir -p /etc/shieldnode
        touch "$CROWDSEC_MARKER"
        SHIELDNODE_CROWDSEC_MANAGED=1
        print_info "Migration: создан $CROWDSEC_MARKER (shieldnode уже стоял)"
    else
        # Foreign CrowdSec — оператор ставил сам, не трогаем его конфиг
        SHIELDNODE_CROWDSEC_MANAGED=0
        print_warn "Обнаружен ранее установленный CrowdSec (НЕ через shieldnode)."
        print_warn "По умолчанию НЕ модифицируем его конфиги:"
        print_warn "  • /etc/crowdsec/profiles.yaml"
        print_warn "  • /etc/crowdsec/acquis.d/sshd.yaml"
        print_warn "  • /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        print_warn "  • table ip crowdsec в nftables"
        print_info "Чтобы разрешить shieldnode'у управлять CrowdSec:"
        print_info "  sudo touch $CROWDSEC_MARKER && sudo guard upgrade"
        print_info "  security-апдейты CrowdSec ставь сам: sudo apt install --only-upgrade crowdsec"
    fi
fi
# v3.26.5: если CrowdSec под нашим управлением — держим движок и баунсер на последней
# версии (security-релизы CrowdSec, напр. 1.7.8 = фикс обхода WAF + DoS на LAPI).
# Foreign-инсталл НЕ трогаем (только подсказка). Свежая установка уже на candidate → no-op.
if [ "$SHIELDNODE_CROWDSEC_MANAGED" = "1" ]; then
    ensure_latest_apt crowdsec crowdsec
    ensure_latest_apt crowdsec-firewall-bouncer-nftables crowdsec-firewall-bouncer
fi
print_ok "CrowdSec: $(cscli version 2>&1 | head -1 || echo установлен)"
if [ "$SHIELDNODE_CROWDSEC_MANAGED" = "1" ]; then
    print_ok "CrowdSec management: shieldnode-managed"
else
    print_info "CrowdSec management: foreign (read-only mode)"
fi

# Коллекции
# v1.4: убрана crowdsecurity/iptables — она порождает сценарий
# iptables-scan-multi_ports который банит за подключения к разным портам.
# Это ложно срабатывает на VPN-юзеров, у которых в профиле прописано
# несколько Xray-портов (fallback при блокировках). Защита от настоящих
# port-scan'еров теперь делается scanner_blocklist'ом + nft rate-limit'ом.
COLLECTIONS=(
    "crowdsecurity/linux"
    "crowdsecurity/sshd"
)

for col in "${COLLECTIONS[@]}"; do
    # v3.11.1: устойчивая проверка через cscli_collection_installed (BUG-CSCLI-FMT)
    if cscli_collection_installed "$col"; then
        print_info "Уже установлена: $col"
    else
        print_status "Устанавливаю $col..."
        if cscli collections install "$col" >/dev/null 2>&1; then
            print_ok "$col"
        else
            print_warn "Не удалось установить $col"
        fi
    fi
done

# v1.4: удаляем iptables-коллекцию если осталась с v1.3 (false positive prone)
# v3.11.1: устойчивая проверка через cscli_collection_installed (BUG-CSCLI-FMT)
if cscli_collection_installed "crowdsecurity/iptables"; then
    print_status "Удаляю crowdsecurity/iptables (v1.4: ложно банит юзеров)..."
    cscli collections remove crowdsecurity/iptables >/dev/null 2>&1 && \
        print_ok "crowdsecurity/iptables удалена"
fi

# ==============================================================================
# ШАГ 8: BAN DURATION (4h — баланс между защитой и ложными срабатываниями)
# ==============================================================================

print_header "ШАГ 8: BAN DURATION"

# v1.4: ban duration возвращён к дефолтным 4h (было 24h в v1.1-1.3).
# Причина: при ложном срабатывании (юзер за CGNAT, общий IP с атакующим)
# 24h блокировки = это пол-дня без VPN. 4h — приемлемо.
# Атакующих ботнетов community blocklist подхватит и забанит снова
# при следующем срабатывании — нет смысла держать долго.

PROFILES_FILE="/etc/crowdsec/profiles.yaml"

if [ "${SHIELDNODE_CROWDSEC_MANAGED:-0}" != "1" ]; then
    print_info "profiles.yaml: пропускаю (foreign CrowdSec — не трогаем)"
elif [ -f "$PROFILES_FILE" ]; then
    if [ ! -f "$BACKUP_DIR/profiles.yaml.before" ]; then
        cp -a "$PROFILES_FILE" "$BACKUP_DIR/profiles.yaml.before"
    fi

    # Если стоит 24h (от старой версии этого скрипта) — вернуть на 4h
    # v3.10.3 BUG-12 FIX: убран `0,` префикс из sed — теперь патчатся ВСЕ
    # вхождения. Дефолтный profiles.yaml содержит 3 профиля (captcha,
    # default_ip_remediation, default_range_remediation), все с
    # `duration: 4h`. Старая версия (v1.1-1.3) ставила 24h во все три, но
    # downgrade патчил только первый (Ip-scope). Range-scope оставался 24h
    # → юзер за CGNAT сидел в бане 24h вместо 4h.
    if grep -qE "^[[:space:]]*duration:[[:space:]]*24h[[:space:]]*$" "$PROFILES_FILE"; then
        sed -i 's/^\([[:space:]]*\)duration:[[:space:]]*24h[[:space:]]*$/\1duration: 4h/' "$PROFILES_FILE"
        print_ok "Ban duration: 24h → 4h во всех профилях"
    elif grep -qE "^[[:space:]]*duration:[[:space:]]*4h[[:space:]]*$" "$PROFILES_FILE"; then
        print_info "Ban duration уже 4h (дефолт CrowdSec)"
    else
        CURRENT_DURATION=$(grep -m1 -E "^[[:space:]]*duration:" "$PROFILES_FILE" | awk '{print $2}')
        print_info "Ban duration: $CURRENT_DURATION (custom — не трогаю)"
    fi
else
    print_warn "$PROFILES_FILE не найден — пропускаю"
fi

# ==============================================================================
# ШАГ 9: ACQUISITION (источники логов для CrowdSec)
# ==============================================================================

print_header "ШАГ 9: ACQUISITION"

# v3.18.8: foreign CrowdSec — не трогаем acquisition оператора
if [ "${SHIELDNODE_CROWDSEC_MANAGED:-0}" != "1" ]; then
    print_info "ШАГ 9 пропущен (foreign CrowdSec — оператор управляет acquis.d сам)"
else

# v1.4: убрана UFW/iptables acquisition. В v1.1-1.3 она питала сценарий
# crowdsecurity/iptables-scan-multi_ports который ложно срабатывал на
# VPN-юзеров с многопортовыми профилями. Без iptables-коллекции и UFW
# acquisition этот сценарий не запускается.

ACQUIS_DIR="/etc/crowdsec/acquis.d"
mkdir -p "$ACQUIS_DIR"

# Удаляем UFW acquisition если он был создан старой версией скрипта
OLD_UFW_ACQUIS="$ACQUIS_DIR/ufw.yaml"
if [ -f "$OLD_UFW_ACQUIS" ]; then
    if grep -q "vpn-node-ddos-protect" "$OLD_UFW_ACQUIS" 2>/dev/null; then
        rm -f "$OLD_UFW_ACQUIS"
        print_ok "Удалён UFW acquisition (v1.4: source для ложных банов)"
    fi
fi

# v3.10.4 BUG-14 + BUG-18 FIX: явно убеждаемся что SSHD acquisition есть.
# Wizard может НЕ создать acquisition если /var/log/auth.log отсутствует
# (Minimal Ubuntu 24.04, cloud images). Без acquisition коллекция sshd
# работает в холостую — никаких decisions не создаётся.
#
# Стратегия:
#   1. Проверяем существующие acquis-источники для SSH (file или journalctl)
#   2. Если нет ничего — создаём journalctl-based acquis для sshd.service
#   3. Если есть file-based для /var/log/auth.log — НЕ дублируем (BUG-18:
#      double-counting в leaky bucket → ssh-bf срабатывает на 2-3 попытках
#      вместо 5)
SSH_ACQUIS_FOUND=0
SSH_FILE_ACQUIS=0
SSH_JOURNALD_ACQUIS=0

# Сканируем acquis.yaml + acquis.d/*.yaml на SSH-источники
for acquis_file in /etc/crowdsec/acquis.yaml "$ACQUIS_DIR"/*.yaml; do
    [ -f "$acquis_file" ] || continue
    # File-based для auth.log
    if grep -qE "^\s*-\s+/var/log/auth\.log" "$acquis_file" 2>/dev/null; then
        SSH_FILE_ACQUIS=1
        SSH_ACQUIS_FOUND=1
    fi
    # Journalctl-based для sshd.service
    if grep -qE "_SYSTEMD_UNIT=sshd\.service" "$acquis_file" 2>/dev/null; then
        SSH_JOURNALD_ACQUIS=1
        SSH_ACQUIS_FOUND=1
    fi
done

if [ "$SSH_ACQUIS_FOUND" = "0" ] && cscli_collection_installed "crowdsecurity/sshd"; then
    # Нет SSH acquisition, но коллекция установлена — создаём journalctl
    print_status "SSH acquisition отсутствует — создаю journalctl-based"
    cat > "$ACQUIS_DIR/sshd.yaml" <<'SSHD_ACQUIS_EOF'
# v3.10.4: SSH acquisition через journalctl (BUG-14 fix).
# Универсально работает на всех Ubuntu/Debian, не зависит от наличия
# /var/log/auth.log (на Minimal Ubuntu файла нет).
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
SSHD_ACQUIS_EOF
    chmod 644 "$ACQUIS_DIR/sshd.yaml"
    systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1
    print_ok "Создан /etc/crowdsec/acquis.d/sshd.yaml (journalctl)"
elif [ "$SSH_FILE_ACQUIS" = "1" ] && [ "$SSH_JOURNALD_ACQUIS" = "1" ]; then
    # BUG-18: двойной acquisition — auth.log + journalctl. Это double-counts
    # каждое событие. Удаляем дублирующийся journalctl-acquis если он наш.
    if [ -f "$ACQUIS_DIR/sshd.yaml" ] && grep -q "v3.10.4" "$ACQUIS_DIR/sshd.yaml"; then
        rm -f "$ACQUIS_DIR/sshd.yaml"
        systemctl reload crowdsec >/dev/null 2>&1
        print_ok "Удалён дубль journalctl SSH acquisition (file-based уже работает)"
    else
        print_warn "Двойной SSH acquisition (file + journald). leaky bucket будет срабатывать в 2× быстрее."
        print_info "Проверь /etc/crowdsec/acquis.yaml и acquis.d/*.yaml — оставь один источник."
    fi
elif [ "$SSH_FILE_ACQUIS" = "1" ]; then
    print_ok "SSH acquisition: file:/var/log/auth.log"
elif [ "$SSH_JOURNALD_ACQUIS" = "1" ]; then
    print_ok "SSH acquisition: journalctl (sshd.service)"
fi

# Проверим что SSH-коллекция установлена (BUG-CSCLI-FMT fix)
if cscli_collection_installed "crowdsecurity/sshd"; then
    print_ok "SSH parsing активен (через crowdsecurity/sshd)"
else
    print_warn "crowdsecurity/sshd не установлен — SSH-логи не парсятся"
fi

# v3.10.4 BUG-15 FIX: проверяем что CAPI registration реально прошла.
# На машинах за corporate proxy/firewall apt postinst может silently fail.
# Без CAPI нет community blocklist — теряется самая ценная фича.
# v3.18.11 SH-NEW-168: проверяем что crowdsec daemon активен — иначе все
# cscli команды вернут exit 1 silently, скрипт пройдёт "успешно" но без
# CAPI/bouncer config'ов. На 1GB ноде с OOM это реальный сценарий.
if ! systemctl is-active --quiet crowdsec; then
    print_warn "CrowdSec daemon не активен — пропускаю CAPI/bouncer config (см. journalctl -u crowdsec)"
    print_info "После починки запусти: sudo cscli capi register; sudo cscli bouncers add cs-firewall-bouncer-nftables"
else
print_status "Проверяю CAPI registration..."
if cscli capi status >/dev/null 2>&1; then
    print_ok "CAPI: registered + работает"
else
    print_warn "CAPI status не OK — пытаюсь зарегистрироваться..."
    # Удаляем существующие credentials если они невалидные
    if cscli capi register >/dev/null 2>&1; then
        systemctl restart crowdsec >/dev/null 2>&1
        sleep 3
        if cscli capi status >/dev/null 2>&1; then
            print_ok "CAPI зарегистрирован успешно"
        else
            print_warn "CAPI всё ещё не работает — проверь сеть"
            print_info "Без CAPI не будет community blocklist (главная фича CrowdSec)"
            print_info "Проверь: curl -v https://api.crowdsec.net"
            print_info "За proxy/NAT? См. docs.crowdsec.net про HTTP_PROXY"
        fi
    else
        print_warn "cscli capi register failed"
    fi
fi
fi  # v3.18.11 SH-NEW-168: end of "if systemctl is-active crowdsec"

# v3.10.4 BUG-17 FIX: postoverflow whitelist для mgmt IPs.
# `cscli decisions add --type whitelist` не предотвращает scenario trigger
# (alerts всё равно идут в CAPI как сигналы атаки → ухудшение нашего
# community contribution score). Postoverflow whitelist — правильный способ
# глушить scenarios на доверенных IP до того как они попадут в alert.
if [ -n "$MGMT_IPV4" ]; then
    POSTOVERFLOW_WL="/etc/crowdsec/postoverflows/s01-whitelist/shieldnode-mgmt.yaml"
    mkdir -p "$(dirname "$POSTOVERFLOW_WL")"

    # Формируем YAML-список IP
    # Save and restore IFS (we're at top level, can't use `local`)
    OLD_IFS="$IFS"

    # Split MGMT_IPV4 into pure IPs vs CIDRs (different YAML fields per CrowdSec spec)
    TMP_IPS=""
    TMP_CIDRS=""
    IFS=','
    for entry in $MGMT_IPV4; do
        entry=$(echo "$entry" | tr -d ' ')
        [ -z "$entry" ] && continue
        case "$entry" in
            */32)
                # /32 — pure IP, strip /32
                TMP_IPS="$TMP_IPS ${entry%/32}"
                ;;
            */*)
                # CIDR (e.g. 192.168.1.0/24)
                TMP_CIDRS="$TMP_CIDRS $entry"
                ;;
            *)
                # No mask = single IP
                TMP_IPS="$TMP_IPS $entry"
                ;;
        esac
    done
    IFS="$OLD_IFS"

    {
        echo "# v3.10.4 BUG-17: postoverflow whitelist для mgmt IPs."
        echo "# Срабатывает ПОСЛЕ scenario trigger но ДО alert/decision —"
        echo "# scenario не оставляет следов на наших IP."
        echo "name: shieldnode/mgmt-whitelist"
        echo "description: \"Whitelist mgmt IPs from UFW (auto-generated)\""
        echo "whitelist:"
        echo "  reason: \"shieldnode mgmt IP\""
        if [ -n "$TMP_IPS" ]; then
            echo "  ip:"
            for ip in $TMP_IPS; do
                echo "    - \"$ip\""
            done
        fi
        if [ -n "$TMP_CIDRS" ]; then
            echo "  cidr:"
            for cidr in $TMP_CIDRS; do
                echo "    - \"$cidr\""
            done
        fi
    } > "$POSTOVERFLOW_WL"
    chmod 644 "$POSTOVERFLOW_WL"
    systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1
    print_ok "Postoverflow whitelist mgmt IPs"
fi

fi  # /SHIELDNODE_CROWDSEC_MANAGED guard for ШАГ 9

# ==============================================================================
# ШАГ 10: NFTABLES BOUNCER
# ==============================================================================

print_header "ШАГ 10: NFTABLES BOUNCER"

if dpkg -l crowdsec-firewall-bouncer-nftables &>/dev/null; then
    print_info "Bouncer уже установлен"
else
    wait_for_apt_lock
    print_status "Устанавливаю crowdsec-firewall-bouncer-nftables (timeout 3 мин)..."
    # v3.18.8: timeout — bouncer post-inst иногда тоже дёргает hub.
    # v3.18.8: stdin → /dev/null против SIGTTIN.
    if ! timeout --kill-after=30s 180s \
         env DEBIAN_FRONTEND=noninteractive \
         apt-get install -y crowdsec-firewall-bouncer-nftables </dev/null; then
        # Та же реанимация что и для crowdsec — может зависнуть post-inst
        BOUNCER_RC=$?
        if [ "$BOUNCER_RC" = "124" ] || [ "$BOUNCER_RC" = "137" ]; then
            print_warn "Bouncer apt timeout — чиним dpkg"
            pkill -9 -f "cscli" 2>/dev/null || true
            sleep 2
            DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -f -y >/dev/null 2>&1 || true
        fi
        if ! dpkg -l crowdsec-firewall-bouncer-nftables 2>/dev/null | grep -qE "^ii"; then
            print_error "Установка bouncer'а провалилась"
            exit 1
        fi
        print_ok "Bouncer установлен (восстановлен после timeout)"
    else
        print_ok "Bouncer установлен"
    fi
fi

if ! cscli bouncers list 2>/dev/null | grep -q "cs-firewall-bouncer"; then
    print_status "Регистрирую bouncer в LAPI..."
    BOUNCER_KEY=$(cscli bouncers add cs-firewall-bouncer-nftables -o raw 2>/dev/null)
    if [ -n "$BOUNCER_KEY" ]; then
        # v3.18.8: validate формат ДО sed-замены. cscli всегда возвращает
        # [a-zA-Z0-9_-]+ длиной 32-64 символа, но если CrowdSec в будущем
        # поменяет формат (например JSON или base64-with-pipes), наша
        # `sed s|...|key|` корраптила бы yaml. Дополнительно — заменяем
        # через awk вместо sed чтобы избежать экранирования спецсимволов.
        if ! [[ "$BOUNCER_KEY" =~ ^[a-zA-Z0-9_-]{16,128}$ ]]; then
            print_error "cscli вернул bouncer key в неожиданном формате"
            print_info "Длина: ${#BOUNCER_KEY}. Возможно, CrowdSec изменил output."
            print_info "Ручное вмешательство:"
            print_info "  1) sudo cscli bouncers delete cs-firewall-bouncer-nftables"
            print_info "  2) sudo cscli bouncers add cs-firewall-bouncer-nftables"
            print_info "  3) sudo nano /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
            print_info "     → вписать api_key: <значение>"
        else
            BOUNCER_YAML="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
            if [ -f "$BOUNCER_YAML" ]; then
                BOUNCER_TMP=$(mktemp "${BOUNCER_YAML}.XXXXXX")
                # awk-replace — никакого sed-разделителя который мог бы
                # столкнуться со спецсимволом в key
                awk -v key="$BOUNCER_KEY" '
                    /^api_key:/ && !done { print "api_key: " key; done=1; next }
                    { print }
                ' "$BOUNCER_YAML" > "$BOUNCER_TMP"
                if [ -s "$BOUNCER_TMP" ] && grep -q "^api_key: $BOUNCER_KEY" "$BOUNCER_TMP"; then
                    chmod --reference="$BOUNCER_YAML" "$BOUNCER_TMP" 2>/dev/null || chmod 0600 "$BOUNCER_TMP"
                    mv "$BOUNCER_TMP" "$BOUNCER_YAML"
                    print_ok "Bouncer зарегистрирован"
                else
                    rm -f "$BOUNCER_TMP"
                    print_error "Не удалось записать api_key в $BOUNCER_YAML"
                fi
            fi
        fi
    fi
fi

# ============================================================================
# v3.10.3 BUG-9 + BUG-10 FIX: правим bouncer config
# ============================================================================
# BUG-9: bouncer по дефолту: ipv4.priority=-10, hook=input. Это срабатывает
# ПОСЛЕ нашей цепочки prerouting (priority -100). Banned-IP проходит наши
# rate-limits и попадает в suspect_v4 ДО того как bouncer его дропнет.
# Эмпирически проверено: 30 fast pings → 19 hits на newconn_overflow.
# FIX: ставим bouncer на hook prerouting с priority -200 (раньше нашего -100).
# Banned-IP дропнется до того как наша логика его увидит.
#
# BUG-10: ipv6.enabled=true по дефолту. На IPv6-disabled нодах bouncer пишет
# в лог 8640 ошибок/сутки. FIX: если в системе IPv6 отключён — disable в
# bouncer config.
BOUNCER_CFG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
if [ "${SHIELDNODE_CROWDSEC_MANAGED:-0}" != "1" ]; then
    print_info "Bouncer config: пропускаю патчинг hook/priority (foreign CrowdSec)"
elif [ -f "$BOUNCER_CFG" ]; then
    BOUNCER_CHANGED=0

    # Backup before patching
    if [ ! -f "$BACKUP_DIR/crowdsec-firewall-bouncer.yaml.before" ]; then
        cp -a "$BOUNCER_CFG" "$BACKUP_DIR/crowdsec-firewall-bouncer.yaml.before"
    fi

    # BUG-9: ipv4 priority -10 → -200, hook input → prerouting
    if grep -qE '^\s*priority:\s*-10\s*$' "$BOUNCER_CFG"; then
        # Меняем оба priority (ipv4 + ipv6 секции, обе по дефолту -10)
        sed -i 's/^\([[:space:]]*\)priority:[[:space:]]*-10[[:space:]]*$/\1priority: -200/g' "$BOUNCER_CFG"
        BOUNCER_CHANGED=1
        print_ok "Bouncer priority: -10 → -200 (применяется ДО shieldnode prerouting)"
    fi

    # nftables_hooks меняем с [input, forward] на [prerouting]
    if grep -qE '^[[:space:]]*-\s+input\s*$' "$BOUNCER_CFG" && \
       grep -qE '^[[:space:]]*-\s+forward\s*$' "$BOUNCER_CFG"; then
        # Заменяем блок nftables_hooks: [input, forward] → [prerouting]
        # (используем awk для надёжной обработки YAML-блока)
        awk '
        BEGIN { in_hooks = 0 }
        /^nftables_hooks:/ { in_hooks = 1; print; print "  - prerouting"; next }
        in_hooks && /^[[:space:]]*-/ { next }   # пропускаем старые элементы списка
        in_hooks && !/^[[:space:]]*-/ { in_hooks = 0 }
        { print }
        ' "$BOUNCER_CFG" > "$BOUNCER_CFG.new" && chmod --reference="$BOUNCER_CFG" "$BOUNCER_CFG.new" 2>/dev/null && mv "$BOUNCER_CFG.new" "$BOUNCER_CFG"
        BOUNCER_CHANGED=1
        print_ok "Bouncer hooks: input,forward → prerouting"
    fi

    # BUG-10: disable IPv6 если в sysctl отключён
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = "1" ]; then
        # В bouncer.yaml ipv6.enabled может быть в двух местах: ipv6: enabled: true (под nftables)
        # и disable_ipv6: false (top-level). Меняем оба.
        if grep -qE '^\s*disable_ipv6:\s*false' "$BOUNCER_CFG"; then
            sed -i 's/^\([[:space:]]*\)disable_ipv6:[[:space:]]*false[[:space:]]*$/\1disable_ipv6: true/' "$BOUNCER_CFG"
            BOUNCER_CHANGED=1
        fi
        # Под секцией ipv6: меняем enabled: true → false
        # Используем awk чтобы найти блок ipv6: и поменять enabled внутри
        awk '
        BEGIN { in_ipv6_block = 0 }
        /^[[:space:]]*ipv6:/ { in_ipv6_block = 1; print; next }
        in_ipv6_block && /^[a-zA-Z]/ { in_ipv6_block = 0 }
        in_ipv6_block && /^[[:space:]]*enabled:[[:space:]]*true/ {
            sub(/enabled:[[:space:]]*true/, "enabled: false"); print; next
        }
        { print }
        ' "$BOUNCER_CFG" > "$BOUNCER_CFG.new" && chmod --reference="$BOUNCER_CFG" "$BOUNCER_CFG.new" 2>/dev/null && mv "$BOUNCER_CFG.new" "$BOUNCER_CFG"
        print_ok "Bouncer IPv6 отключён (в системе IPv6 disabled)"
        BOUNCER_CHANGED=1
    fi

    if [ "$BOUNCER_CHANGED" = "1" ]; then
        # Удаляем существующие cs-bouncer таблицы — они с правилами на старом hook
        nft delete table ip crowdsec 2>/dev/null || true
        nft delete table ip6 crowdsec6 2>/dev/null || true
    fi
fi

systemctl enable --now crowdsec >/dev/null 2>&1 || true

# v3.24.1: bouncer flap guard.
# Релоады crowdsec выше рвут decision-стрим bouncer'а ("stream halted" → fatal →
# systemd рестарт по кругу). Чтобы не поймать bouncer в момент флапа и не
# напечатать ложное "НЕ active":
#   1) дожидаемся готовности LAPI (агент должен отвечать),
#   2) reset-failed (сбрасываем счётчик авто-рестартов) + чистый рестарт,
#   3) проверяем is-active С РЕТРАЯМИ, а не одним снимком через 3с.
for _i in $(seq 1 10); do
    cscli lapi status >/dev/null 2>&1 && break
    sleep 2
done
systemctl reset-failed crowdsec-firewall-bouncer 2>/dev/null || true
systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || \
    systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true

BOUNCER_OK=0
for _i in $(seq 1 8); do
    sleep 2
    if systemctl is-active --quiet crowdsec-firewall-bouncer; then BOUNCER_OK=1; break; fi
    # ещё не active — мог флапнуть на последнем reload; мягкий повторный старт
    systemctl reset-failed crowdsec-firewall-bouncer 2>/dev/null || true
    systemctl start crowdsec-firewall-bouncer >/dev/null 2>&1 || true
done

if systemctl is-active --quiet crowdsec && [ "$BOUNCER_OK" = "1" ]; then
    print_ok "crowdsec + bouncer активны"
else
    print_warn "Один из сервисов не active:"
    systemctl is-active crowdsec || print_error "  crowdsec НЕ active"
    systemctl is-active crowdsec-firewall-bouncer || print_error "  bouncer НЕ active"
    print_info "Логи: journalctl -u crowdsec -u crowdsec-firewall-bouncer -n 50"
fi

# v3.16.3 BUG-FIX: bouncer pre-inst hook на некоторых дистрах (Ubuntu 24.04
# с custom kernel) может flush'нуть nftables ruleset → наша table inet
# ddos_protect исчезает. Восстанавливаем её принудительной перезагрузкой
# nft конфига после установки bouncer'а.
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    print_warn "Table inet ddos_protect исчезла после установки bouncer'а — восстанавливаю"
    if nft -f /etc/nftables.d/ddos-protect.conf 2>/dev/null; then
        print_ok "Table inet ddos_protect восстановлена"
        systemctl restart shieldnode-nftables.service >/dev/null 2>&1
    else
        print_error "Не удалось восстановить — проверь: sudo nft -f /etc/nftables.d/ddos-protect.conf"
    fi
fi

# ============================================================================
# v3.10.3 BUG-11 SECURITY FIX: добавляем mgmt IPs в CrowdSec whitelist
# ============================================================================
# Без этого: если админ ошибётся 5 раз с SSH-паролем (или CrowdSec обновит
# scenarios с более чувствительным sshd-bf), его IP попадёт в ban → bouncer
# дропнет его на новом priority -200 (после BUG-9 fix) → админ заблокирован.
# Наш `manual_whitelist_v4` set здесь не помогает — bouncer работает в
# отдельной таблице.
if [ -n "$MGMT_IPV4" ]; then
    print_status "Добавляю mgmt IPs в CrowdSec whitelist..."
    IFS=',' read -ra MGMT_LIST <<< "$MGMT_IPV4"
    for mgmt_ip in "${MGMT_LIST[@]}"; do
        # Очищаем от пробелов
        mgmt_ip=$(echo "$mgmt_ip" | tr -d ' ')
        [ -z "$mgmt_ip" ] && continue
        # cscli decisions add создаёт whitelist на 100 лет (3650 дней)
        if cscli decisions add --ip "$mgmt_ip" --type whitelist --duration 87600h \
            --reason "shieldnode mgmt IP whitelist" >/dev/null 2>&1; then
            print_ok "Mgmt whitelist: $mgmt_ip"
        else
            # Возможно уже в whitelist — это OK
            print_info "Mgmt whitelist (возможно уже есть): $mgmt_ip"
        fi
    done
fi

# ============================================================================
# v3.10.3 BUG-13 FIX: hub update + upgrade
# ============================================================================
# Без этого: сценарии устаревают, новые sshd-bf варианты не подхватываются.
# CrowdSec >= 1.7.2 имеет встроенный systemd timer (hubupdate.timer), на
# старых версиях нужен cron.
print_status "Обновляю CrowdSec hub..."
if cscli hub update >/dev/null 2>&1; then
    if cscli hub upgrade >/dev/null 2>&1; then
        print_ok "Hub: коллекции/сценарии обновлены"
    fi
fi

# Проверяем CrowdSec версию для cron-fallback
CS_VER=$(cscli version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d v)
if [ -n "$CS_VER" ]; then
    # dpkg --compare-versions работает с числами
    if dpkg --compare-versions "$CS_VER" lt "1.7.2" 2>/dev/null; then
        # Старая версия — добавляем cron для hub upgrade
        if [ ! -f /etc/cron.daily/cscli-hub-upgrade ]; then
            cat > /etc/cron.daily/cscli-hub-upgrade <<'CRON_EOF'
#!/bin/sh
# v3.10.3 BUG-13: ежедневный hub upgrade для CrowdSec < 1.7.2
# В 1.7.2+ есть встроенный systemd timer hubupdate.timer
cscli hub update >/dev/null 2>&1 && cscli hub upgrade >/dev/null 2>&1 || true
CRON_EOF
            chmod +x /etc/cron.daily/cscli-hub-upgrade
            print_ok "Cron daily hub-upgrade добавлен (CrowdSec $CS_VER < 1.7.2)"
        fi
    else
        # Новая версия — встроенный timer
        if systemctl list-unit-files | grep -q "crowdsec-hubupdate.timer"; then
            systemctl enable --now crowdsec-hubupdate.timer >/dev/null 2>&1 || true
            print_info "CrowdSec $CS_VER >= 1.7.2 — встроенный hub-upgrade timer"
        fi
    fi
fi

# ==============================================================================
# ШАГ 11: HISTORY AGGREGATOR (события из journald → sqlite)
# ==============================================================================

print_header "ШАГ 11: HISTORY AGGREGATOR"

# v2.9: парсим логи nftables [shield:scanner] / [shield:ddos] из journald
# и пишем в /var/lib/shieldnode/events.db с агрегацией.

DB_DIR="/var/lib/shieldnode"
DB_FILE="$DB_DIR/events.db"
mkdir -p "$DB_DIR"
chmod 0750 "$DB_DIR"

# v3.5: human-readable лог-каталог для events.log
LOG_DIR="/var/log/shieldnode"
EVENTS_LOG="$LOG_DIR/events.log"
mkdir -p "$LOG_DIR"
chmod 0750 "$LOG_DIR"
touch "$EVENTS_LOG"
chmod 0640 "$EVENTS_LOG"

# v3.21.3: RSYSLOG DEDUP — убираем дублирование kern.* в syslog
# ------------------------------------------------------------------------------
# Ubuntu 24.04 default /etc/rsyslog.d/50-default.conf содержит:
#     *.*;auth,authpriv.none          -/var/log/syslog
# Это значит kern.* пишется И в /var/log/kern.log, И в /var/log/syslog.
# Каждая строка от nft `log prefix [shield:...]` хранится дважды.
# При 9 активных prefix'ах с rate 1/sec это до ~190 MB/день лишних в syslog.
#
# v3.21.3 FIX (важно!): первая попытка фикса использовала drop-in
# /etc/rsyslog.d/49-shieldnode-kern-dedup.conf с тем же селектором + kern.none.
# Это НЕ РАБОТАЕТ. Rsyslog evaluates ВСЕ matching rules, не "first wins".
# (См. https://rsyslog.readthedocs.io/en/latest/configuration/basic_structure.html:
#  "all rules are always fully evaluated... If message processing shall stop,
#   the discard action must explicitly be executed".)
# Поэтому правильное решение — in-place edit самого 50-default.conf с
# backup'ом для отката при uninstall. Edit идемпотентен (sed с проверкой
# уже-применено через grep).
#
# Discard action не годится — он глобален, выкинет kern.* и из kern.log тоже.
RSYSLOG_DEFAULT="/etc/rsyslog.d/50-default.conf"
RSYSLOG_BACKUP="/etc/rsyslog.d/50-default.conf.shieldnode.bak"
if [ -f "$RSYSLOG_DEFAULT" ] && command -v rsyslogd >/dev/null 2>&1; then
    # Идемпотентность: проверяем, не правили ли мы уже этот файл.
    # Маркер — наличие 'kern.none' рядом с '/var/log/syslog' в той же строке.
    if grep -qE '^\*\.\*;auth,authpriv\.none;kern\.none[[:space:]]+-?/var/log/syslog' "$RSYSLOG_DEFAULT"; then
        print_info "Rsyslog dedup уже применён (kern.none в 50-default.conf)"
    else
        # Создаём backup только если его ещё нет (первый install).
        # На re-install НЕ перезаписываем backup — он содержит pristine
        # оригинал от пакета, не наш изменённый файл из прошлого install'а.
        if [ ! -f "$RSYSLOG_BACKUP" ]; then
            cp -p "$RSYSLOG_DEFAULT" "$RSYSLOG_BACKUP"
        fi
        # Сохраняем копию текущего файла для отката если sed/test упадёт
        TMP_RSYSLOG=$(mktemp /tmp/rsyslog-default.XXXXXX)
        cp -p "$RSYSLOG_DEFAULT" "$TMP_RSYSLOG"
        # Точечный sed: заменяем '*.*;auth,authpriv.none' (стандартная
        # строка Ubuntu) на '*.*;auth,authpriv.none;kern.none', но ТОЛЬКО
        # на строках где идёт запись в /var/log/syslog. Другие строки не
        # трогаем (mail.warn → /var/log/mail.warn и т.п. остаются).
        sed -i -E 's|^(\*\.\*;auth,authpriv\.none)([[:space:]]+-?/var/log/syslog)|\1;kern.none\2|' "$RSYSLOG_DEFAULT"
        # Валидируем конфигурацию rsyslog ПОСЛЕ изменения.
        # Если -N1 fail — откатываем из tmp.
        if rsyslogd -N1 -f /etc/rsyslog.conf >/dev/null 2>&1; then
            # reload (SIGHUP) вместо restart — graceful, без обрыва входящих логов.
            # rsyslog корректно перечитывает конфиг по SIGHUP с версии 8.x.
            if systemctl reload rsyslog 2>/dev/null; then
                print_ok "Rsyslog dedup: kern.* убран из /var/log/syslog (backup: $RSYSLOG_BACKUP)"
            else
                # reload не сработал (старая версия?) — пробуем restart
                if systemctl restart rsyslog 2>/dev/null; then
                    print_ok "Rsyslog dedup: kern.* убран из /var/log/syslog (через restart, backup: $RSYSLOG_BACKUP)"
                else
                    print_warn "Rsyslog reload/restart failed — изменения применятся после следующего restart'а"
                fi
            fi
            rm -f "$TMP_RSYSLOG"
        else
            # Откат: возвращаем сохранённый файл, удаляем backup если он был
            # создан только что (т.е. это первый install и мы его сами создали).
            mv "$TMP_RSYSLOG" "$RSYSLOG_DEFAULT"
            print_warn "rsyslog config test failed после edit — откатили, dedup пропущен"
        fi
    fi
else
    print_info "rsyslog 50-default.conf не найден — kern.log dedup пропущен (другая конфигурация syslog)"
fi

# v3.21.3: JOURNALD LIMIT — третья копия kern.* живёт в systemd-journald
# ------------------------------------------------------------------------------
# journalctl -k показывает все nft log events (kern facility идёт в journal
# напрямую, помимо rsyslog). Дефолтный SystemMaxUse = 10% /var partition
# (на 20GB диске ~2GB). На активной ноде journal быстро забивает квоту.
#
# Drop-in /etc/systemd/journald.conf.d/shieldnode.conf не трогает основной
# конфиг — overrides только три параметра. Удаляется при uninstall.
JOURNALD_DROPIN_DIR="/etc/systemd/journald.conf.d"
mkdir -p "$JOURNALD_DROPIN_DIR"
cat > "$JOURNALD_DROPIN_DIR/shieldnode.conf" <<'JOURNALD_EOF'
# Managed by shieldnode v3.21.3+
# Ограничиваем journald чтобы kern.* events от nft не забивали диск.
# 500M жёсткий потолок, 1G минимально свободного места, 7 дней retention.
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
MaxRetentionSec=7day
JOURNALD_EOF
chmod 0644 "$JOURNALD_DROPIN_DIR/shieldnode.conf"
if systemctl restart systemd-journald 2>/dev/null; then
    # Сразу применяем лимит к существующим логам (журналы могут быть > 500M)
    journalctl --vacuum-size=500M >/dev/null 2>&1 || true
    print_ok "Journald limit: SystemMaxUse=500M, 7 days retention"
else
    print_warn "systemd-journald restart failed — лимит применится при следующем restart'е"
fi

# v3.5: logrotate для events.log + install.log
cat > /etc/logrotate.d/shieldnode <<'LOGROTATE_EOF'
/var/log/shieldnode/*.log {
    daily
    rotate 30
    maxsize 100M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su root root
    create 0640 root root
}
LOGROTATE_EOF
print_ok "Logrotate: /etc/logrotate.d/shieldnode (daily, rotate 30, maxsize 100M, compress)"

# v3.20.3 / v3.23.13 SR-FIX-8: aggressive ротация для /var/log/syslog/kern.log/auth.log.
# Причина: shieldnode/nftables/CrowdSec пишут много drop-events в kern.log.
# Дефолтный rsyslog ротирует ежедневно — но за день может накопиться 1-2 GB.
#
# Старая стратегия (v3.20.3-v3.23.12): отдельный /etc/logrotate.d/shieldnode-syslog-aggressive
# с теми же путями что и /etc/logrotate.d/rsyslog → DUPLICATE LOG ENTRY error.
# Logrotate hourly падал status=1 на каждом тике (24 ошибки/сутки).
#
# Новая стратегия (v3.23.13+): патчим САМ /etc/logrotate.d/rsyslog добавив
# maxsize 100M в каждый блок. Это устраняет дубликат и сохраняет owner-семантику
# rsyslog'а. Если файл недоступен (другой distro?) — fallback к старому подходу
# но БЕЗ /var/log/syslog и /var/log/kern.log (чтобы не конфликтовать).
RSYSLOG_LOGROTATE="/etc/logrotate.d/rsyslog"
# v3.23.13 SR-FIX-8.1: backup ВНЕ /etc/logrotate.d/ (иначе logrotate подхватит
# backup-файл как ещё один config → DUPLICATE LOG ENTRY).
RSYSLOG_BACKUP_DIR="/var/lib/shieldnode/backup"
if [ -f "$RSYSLOG_LOGROTATE" ] && ! grep -q 'shieldnode-aggressive-marker' "$RSYSLOG_LOGROTATE" 2>/dev/null; then
    mkdir -p "$RSYSLOG_BACKUP_DIR"
    cp -a "$RSYSLOG_LOGROTATE" "$RSYSLOG_BACKUP_DIR/rsyslog.original.$(date +%s)" 2>/dev/null || true
    # Добавляем maxsize 100M после каждого `rotate N`. Маркер на отдельной строке
    # (logrotate не поддерживает inline comments после value).
    sed -i -E '/^\s*rotate\s+[0-9]+\s*$/a\    # shieldnode-aggressive-marker\n    maxsize 100M' "$RSYSLOG_LOGROTATE"
    print_ok "Logrotate: добавлен maxsize 100M в $RSYSLOG_LOGROTATE (backup: $RSYSLOG_BACKUP_DIR/)"
elif [ -f "$RSYSLOG_LOGROTATE" ]; then
    print_info "Logrotate: $RSYSLOG_LOGROTATE уже патчен (maxsize 100M)"
else
    # Fallback: rsyslog logrotate config отсутствует (не Debian/Ubuntu? minimal install?)
    # Создаём наш файл БЕЗ системных путей — только наш events.log уже покрыт
    # /etc/logrotate.d/shieldnode выше.
    print_info "Logrotate: /etc/logrotate.d/rsyslog не найден — aggressive rotation skipped"
fi

# v3.23.13 SR-FIX-8.1: убираем старые битые backup'ы которые лежат в /etc/logrotate.d/
# (от первой неудачной попытки SR-FIX-8 — они вызывали duplicate log entry errors).
rm -f /etc/logrotate.d/rsyslog.shieldnode-bak.* 2>/dev/null || true

# v3.23.13 SR-FIX-8: удаляем legacy /etc/logrotate.d/shieldnode-syslog-aggressive
# (если есть с v3.20.x — v3.23.12). Он дублировал /etc/logrotate.d/rsyslog.
if [ -f /etc/logrotate.d/shieldnode-syslog-aggressive ]; then
    rm -f /etc/logrotate.d/shieldnode-syslog-aggressive
    print_info "Removed legacy /etc/logrotate.d/shieldnode-syslog-aggressive (duplicate entries with rsyslog)"
fi

# v3.20.3: Hourly logrotate timer (вместо daily cron)
# Дефолтный logrotate cron запускается раз в день. При активной ноде с DDoS
# атаками логи могут вырасти до 1+ GB за день. Hourly проверка ловит overflow
# раньше — maxsize 100M будет ротировать сразу при превышении.
cat > /etc/systemd/system/shieldnode-logrotate.service <<'EOF'
[Unit]
Description=shieldnode hourly logrotate (catches log overflow before disk fills)
After=multi-user.target

[Service]
Type=oneshot
# v3.23.13 SR-FIX-8: hourly logrotate теперь использует ГЛОБАЛЬНЫЙ конфиг
# /etc/logrotate.conf (который сам подтягивает /etc/logrotate.d/*).
# Это даёт maxsize 100M ротацию для rsyslog logs ПОСЛЕ нашего патча
# /etc/logrotate.d/rsyslog (с aggressive maxsize 100M).
# Старый подход (ExecStart + ExecStartPost разными конфигами) ломался на
# duplicate entries и давал 24 ошибки/сутки.
# State файл /var/lib/shieldnode/logrotate-hourly.state — отдельный от
# системного /var/lib/logrotate/status чтобы daily cron работал независимо.
ExecStart=/usr/sbin/logrotate --state /var/lib/shieldnode/logrotate-hourly.state /etc/logrotate.conf
# Failures игнорируем — exit code 1 (skipped logs) считается успехом
SuccessExitStatus=0 1 2

Restart=on-failure
RestartSec=60
EOF

cat > /etc/systemd/system/shieldnode-logrotate.timer <<'EOF'
[Unit]
Description=Run logrotate hourly (shieldnode aggressive rotation)

[Timer]
OnCalendar=hourly
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now shieldnode-logrotate.timer >/dev/null 2>&1
print_ok "Hourly logrotate timer: shieldnode-logrotate.timer"

# v3.20.3: Weekly cleanup timer — старые backup'ы shieldnode + ASN cache
# v3.20.3 FIX: используем отдельный скрипт вместо ExecStart с inline bash -c.
# Причина: systemd unit'ы НЕ поддерживают многострочный ExecStart с backslash
# continuation, и кавычки/апострофы в комментариях/строках ломают парсер.
cat > /usr/local/sbin/shieldnode-cleanup.sh <<'CLEANUP_EOF'
#!/bin/bash
# shieldnode weekly cleanup — backup'ы + ASN cache + БД vacuum + fail counters

# 1) Оставляем только 2 последних backup'а
if [ -d /var/lib/shieldnode/backup ]; then
    find /var/lib/shieldnode/backup -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
        | sort | head -n -2 | xargs -r rm -rf
fi

# 2) v3.21.3: Чистка events.db — реальная работа с sqlite
# Старый код (v3.20.3) чистил find в /var/lib/shieldnode/asn_cache/ — но
# ASN кэш живёт в таблице asn_cache внутри events.db, директории нет.
# Оставляем find как no-op fallback на случай артефактов от старых версий.
DB="/var/lib/shieldnode/events.db"
if [ -f "$DB" ] && command -v sqlite3 >/dev/null 2>&1; then
    # Используем busy_timeout чтобы не конфликтовать с aggregator'ом который
    # пишет в БД в WAL mode. 5 сек ожидания — достаточно для любого write.
    sqlite3 "$DB" <<SQL 2>/dev/null
PRAGMA busy_timeout=5000;
-- События старше 90 дней (long-term история теряется, но aggregator
-- группирует по (type, ip) с UNIQUE constraint — старые IP уже схлопнуты).
DELETE FROM events WHERE last_seen < strftime('%s','now','-__SHIELD_EVENTS_DB_RETENTION_DAYS__ days');
-- ASN кэш старше 7 дней (TTL и так 7 дней — это просто physical cleanup).
DELETE FROM asn_cache WHERE cached_at < strftime('%s','now','-7 days');
-- Сбрасываем WAL в основной файл, обнуляем -wal (часто распухает в idle).
PRAGMA wal_checkpoint(TRUNCATE);
SQL

    # v3.23.13 BUG-015 FIX: VACUUM заменён на VACUUM INTO + atomic rename.
    # Преимущества:
    #   - Не блокирует main DB на время VACUUM (aggregator продолжает писать).
    #   - Atomic — при крахе VACUUM мы не оставляем corrupted DB.
    #   - Free space нужен только если current DB действительно вырос.
    #
    # Минусы:
    #   - Требует ~equal size free space в /var/lib/shieldnode временно.
    #   - Нужно убедиться что aggregator не пишет в момент rename'а.
    DB_SIZE=$(stat -c%s "$DB" 2>/dev/null || echo 0)
    AVAIL=$(df -B1 --output=avail /var/lib/shieldnode 2>/dev/null | tail -1)
    AVAIL="${AVAIL:-0}"
    # Vacuum только если есть как минимум 2× размера DB свободного места
    if [ "$DB_SIZE" -gt 0 ] && [ "$AVAIL" -gt "$((DB_SIZE * 2))" ]; then
        # v3.23.13: создаём /run/shieldnode если не существует (cleanup может
        # запуститься первым после ребута, до aggregator'а который его создаёт).
        mkdir -p /run/shieldnode 2>/dev/null || true
        VACUUM_TMP="${DB}.vacuum.$$"
        if sqlite3 "$DB" "VACUUM INTO '$VACUUM_TMP'" 2>/dev/null && [ -s "$VACUUM_TMP" ]; then
            # Захватываем lock через aggregator-style flock и переключаем atomic mv
            if exec {VAC_LOCK_FD}> /run/shieldnode/db.lock 2>/dev/null && \
               flock -w 30 "$VAC_LOCK_FD" 2>/dev/null; then
                # Делаем backup main DB перед swap (на случай мусора в vacuum copy)
                BAK="${DB}.pre-vacuum.bak"
                cp -a "$DB" "$BAK" 2>/dev/null || true
                # Atomic replace
                mv "$VACUUM_TMP" "$DB" && rm -f "${DB}-wal" "${DB}-shm" 2>/dev/null
                # Quick integrity check на новом файле
                if sqlite3 "$DB" "PRAGMA integrity_check" 2>/dev/null | head -1 | grep -q "^ok$"; then
                    rm -f "$BAK" 2>/dev/null
                    logger -t shieldnode-cleanup "VACUUM INTO success (db_size=$DB_SIZE)"
                else
                    # Rollback — vacuum copy corrupted
                    mv "$BAK" "$DB" 2>/dev/null
                    logger -t shieldnode-cleanup "WARN: VACUUM INTO produced corrupted DB, rolled back"
                fi
                flock -u "$VAC_LOCK_FD" 2>/dev/null
            else
                # Lock fail — пропускаем vacuum, попробуем в следующий цикл
                rm -f "$VACUUM_TMP" 2>/dev/null
                logger -t shieldnode-cleanup "skip VACUUM — db.lock unavailable"
            fi
        else
            rm -f "$VACUUM_TMP" 2>/dev/null
        fi
    else
        logger -t shieldnode-cleanup "skip VACUUM — insufficient free space (need 2×${DB_SIZE}, have $AVAIL)"
    fi
fi

# 3) Legacy: ASN cache из старых версий (no-op если директории нет)
if [ -d /var/lib/shieldnode/asn_cache ]; then
    find /var/lib/shieldnode/asn_cache -type f -mtime +7 -delete 2>/dev/null
fi

# 4) Удаляем старые failed fetch counters (>30 дней)
find /var/lib/shieldnode -maxdepth 1 -name "*_fail_count" -mtime +30 -delete 2>/dev/null

exit 0
CLEANUP_EOF
# v3.23.13 BUG-019: подставляем retention из limits.conf
sed -i "s|__SHIELD_EVENTS_DB_RETENTION_DAYS__|$SHIELD_EVENTS_DB_RETENTION_DAYS|g" \
    /usr/local/sbin/shieldnode-cleanup.sh
verify_no_placeholders /usr/local/sbin/shieldnode-cleanup.sh || exit 1
chmod 0755 /usr/local/sbin/shieldnode-cleanup.sh

cat > /etc/systemd/system/shieldnode-cleanup.service <<'EOF'
[Unit]
Description=shieldnode weekly cleanup (old backups + stale ASN cache)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shieldnode-cleanup.sh
# v3.22.0: понижаем приоритет CPU+IO. VACUUM на events.db делает
# полный rewrite файла — на shared-disk VPS это блокирует sshd/Xray
# logs на секунды. Nice=19 = lowest CPU prio, idle IO class = "пиши
# только когда диск свободен". На NVMe с multi-queue scheduler'ом
# idle class игнорируется, но Nice=19 всё равно работает.
Nice=19
IOSchedulingClass=idle
EOF

cat > /etc/systemd/system/shieldnode-cleanup.timer <<'EOF'
[Unit]
Description=Weekly shieldnode cleanup

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now shieldnode-cleanup.timer >/dev/null 2>&1
print_ok "Weekly cleanup timer: shieldnode-cleanup.timer (old backups + ASN cache)"

# Инициализируем БД
# v3.21.5 fix: вывод sqlite (PRAGMA journal_mode возвращает 'wal' в stdout) — глушим
sqlite3 "$DB_FILE" <<'SQL_EOF' >/dev/null
-- v3.10.2: WAL mode позволяет concurrent reads (guard) + write (aggregator)
-- без блокировок. synchronous=NORMAL — приемлемый trade-off (риск потерять
-- последний commit при power-loss, но не corrupt'ить БД).
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,            -- 'scanner' | 'ddos'
    ip          TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,         -- unix timestamp
    last_seen   INTEGER NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(type, ip) ON CONFLICT REPLACE
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_last_seen ON events(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_events_count ON events(count DESC);

CREATE TABLE IF NOT EXISTS aggregator_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- v3.12.0: ASN/owner кэш для guard CLI top-attackers column
-- TTL 7 дней (cached_at + 604800 < now → re-lookup via Team Cymru whois)
CREATE TABLE IF NOT EXISTS asn_cache (
    ip         TEXT PRIMARY KEY,
    asn        TEXT,
    owner      TEXT,
    country    TEXT,
    cached_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asn_cache_cached_at ON asn_cache(cached_at);
SQL_EOF
chmod 0640 "$DB_FILE"
print_ok "БД создана: $DB_FILE"

# v3.21.3: Немедленный прогон cleanup'а сразу после инициализации БД.
# Без этого re-install на хосте с распухшей events.db от старых версий
# ждал бы до недели прежде чем cleanup.timer его прогнал. Запускаем
# в фоне с & — VACUUM может занять секунды на большой БД, не блокируем
# дальнейшую установку. systemctl start --no-block тоже подойдёт.
if [ -x /usr/local/sbin/shieldnode-cleanup.sh ]; then
    systemctl start --no-block shieldnode-cleanup.service 2>/dev/null || \
        /usr/local/sbin/shieldnode-cleanup.sh &
    print_ok "Запущен первый прогон cleanup (events.db vacuum в фоне)"
fi

# Скрипт-агрегатор
AGG_SCRIPT="/usr/local/sbin/shieldnode-aggregator.sh"
cat > "$AGG_SCRIPT" <<'AGG_EOF'
#!/bin/bash
# Парсит journald на предмет log-сообщений от nft и пишет в sqlite.
# v3.5: дополнительно пишет человекочитаемый лог в /var/log/shieldnode/events.log

DB="/var/lib/shieldnode/events.db"
EVENTS_LOG="/var/log/shieldnode/events.log"
LOG_TAG="shieldnode-agg"

# Если БД нет — выходим
[ -r "$DB" ] || { logger -t "$LOG_TAG" "DB not found: $DB"; exit 0; }

# v3.5: убедимся что events.log пишется (создан в установщике, но защита от удаления)
mkdir -p "$(dirname "$EVENTS_LOG")" 2>/dev/null
touch "$EVENTS_LOG" 2>/dev/null

# Получаем cursor (где остановились в прошлый раз)
CURSOR=$(sqlite3 "$DB" "SELECT value FROM aggregator_state WHERE key='cursor' LIMIT 1" 2>/dev/null)

# Читаем journald с того места где остановились
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

if [ -n "$CURSOR" ]; then
    # v3.22.0: --lines cap защищает от RAM blow-up под штормом
    # (массовая атака, per-IP attribution всё равно теряется
    # из-за nft rate-limit 1/sec на лог-prefix, важнее не уронить агрегатор).
    # v3.23.13 BUG-020 FIX: фильтр по _TRANSPORT=kernel + SYSLOG_IDENTIFIER=kernel
    # для shield/UFW логов (idz kernel facility) и отдельно crowdsec identifier.
    # Без фильтра aggregator парсит ВСЁ — sshd, systemd, snap, NetworkManager,
    # etc. — и любой user может через `logger` инжектить fake [shield:ddos]
    # SRC=... записи в journald (vector SQL injection в events.db, BUG-002).
    journalctl --output=cat --output-fields=MESSAGE --no-pager --lines=__SHIELD_AGG_JOURNAL_LINES__ \
        --after-cursor="$CURSOR" --show-cursor \
        _TRANSPORT=kernel + SYSLOG_IDENTIFIER=kernel + SYSLOG_IDENTIFIER=crowdsec \
        2>/dev/null > "$TMP" || true
else
    # Первый запуск — берём за последний час
    journalctl --output=cat --output-fields=MESSAGE --no-pager --lines=__SHIELD_AGG_JOURNAL_LINES__ \
        --since="1 hour ago" --show-cursor \
        _TRANSPORT=kernel + SYSLOG_IDENTIFIER=kernel + SYSLOG_IDENTIFIER=crowdsec \
        2>/dev/null > "$TMP" || true
fi

# Извлекаем cursor из последней строки и удаляем его из вывода
NEW_CURSOR=$(grep -oE '^-- cursor: .+$' "$TMP" | tail -1 | sed 's/^-- cursor: //')

# Парсим сообщения [shield:scanner], [shield:ddos], [shield:tor] (v3.11),
# [shield:threat] и [shield:custom] (v3.12.0), [shield:mobile_ru_drop] (v3.13.1),
# [shield:conn_flood] и [shield:newconn_flood] (v3.15.2),
# [shield:tcp_invalid], [shield:fib_spoof], [shield:syn_escalate], [shield:udp_escalate] (v3.15.3)
# Формат kernel-лога: "[shield:scanner] IN=eth0 SRC=85.142.100.2 DST=... PROTO=TCP DPT=8443 ..."
declare -A scanner_ips ddos_ips tor_ips threat_ips custom_ips conn_flood_ips newconn_flood_ips
declare -A tcp_invalid_ips fib_spoof_ips syn_escalate_ips udp_escalate_ips
# v3.16.0: UFW дропы (если оператор включил 'ufw logging on')
declare -A ufw_block_ips ufw_block_ports
# v3.5: для events.log — собираем порт назначения и тип flood'а
declare -A ddos_ports ddos_proto

# v3.23.5: определяем MY_IP для self-flood detection
MY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')
MY_IP_ALERT_FILE="/var/lib/shieldnode/.my-ip-self-flood-alert"

# Helper: skip MY_IP в счётчиках (self-flood = некорректная конфигурация nginx/proxy)
# Возвращает 0 если IP — это наш собственный (skip), 1 если нет (учитывать)
is_my_ip() {
    [ -n "$MY_IP" ] && [ "$1" = "$MY_IP" ] && return 0
    return 1
}

# Один раз в час алертим в syslog если видим MY_IP в потоке (не спамим)
alert_self_flood() {
    local now alert_ts
    now=$(date +%s)
    alert_ts=$(cat "$MY_IP_ALERT_FILE" 2>/dev/null || echo 0)
    alert_ts="${alert_ts:-0}"
    if [ $((now - alert_ts)) -gt 3600 ]; then
        logger -t "$LOG_TAG" "WARNING: self-flood detected (MY_IP=$MY_IP в drop logs) — проверь nginx proxy_pass на public_ip, должно быть 127.0.0.1 или unix socket"
        echo "$now" > "$MY_IP_ALERT_FILE"
    fi
}

# v3.10.2 PERF FIX: заменили per-line `echo $line | grep | head | cut` на
# single-pass awk. Бенчмарк на 10k log-lines: 94 сек → 0.026 сек (3700×).
# Под штормом 100k events/min теперь обрабатывается за <1 сек.
#
# v3.23.13 BUG-002+007 FIX:
#   - validate IPv4 format перед добавлением в hash (defence-in-depth поверх awk gsub).
#   - cap unique IPs per-type (MAX_UNIQUE_IPS_PER_TYPE) — защита от RAM blow-up
#     при rotating-botnet атаке (100k+ unique sources).
MAX_UNIQUE_IPS_PER_TYPE="${MAX_UNIQUE_IPS_PER_TYPE:-__SHIELD_AGG_MAX_UNIQUE_IPS__}"
STORM_MODE=0
STORM_DROPPED=0
storm_warn() {
    STORM_DROPPED=$((STORM_DROPPED + 1))
    [ "$STORM_MODE" = "1" ] && return 0
    STORM_MODE=1
    logger -t "$LOG_TAG" "WARN: storm mode — dropping unique IPs beyond ${MAX_UNIQUE_IPS_PER_TYPE}/type (nft drops still active)"
}
# Strict IPv4-only validation (журнал даёт нам почищенные числа+точки через gsub).
# Регекс: 4 октета 0-255. Без regex-backtracking — bash native parameter expansion.
is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local IFS=. o1 o2 o3 o4
    read -r o1 o2 o3 o4 <<< "$ip"
    [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ] || return 1
    return 0
}
while IFS='|' read -r kind ip port proto; do
    # v3.23.5: self-flood — наш IP в drop logs → alert и skip
    if [ -n "$ip" ] && is_my_ip "$ip"; then
        alert_self_flood
        continue
    fi
    # v3.23.13 BUG-002: defence-in-depth IPv4 validation.
    # awk gsub чистит мусор, но мы доверяем по второму уровню. Невалидные —
    # просто skip (без логирования каждой штуки — DoS на logger).
    [ -n "$ip" ] && ! is_valid_ipv4 "$ip" && continue
    # v3.23.13 BUG-007: при достижении cap для конкретного типа — не добавляем
    # новые IP, но продолжаем инкрементировать существующие (партиальная
    # attribution лучше OOM).
    case "$kind" in
        scanner)
            if [ -n "$ip" ]; then
                if [ -n "${scanner_ips[$ip]:-}" ] || [ ${#scanner_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    scanner_ips[$ip]=$((${scanner_ips[$ip]:-0} + 1))
                else
                    storm_warn
                fi
            fi
            ;;
        ddos)
            if [ -n "$ip" ]; then
                if [ -n "${ddos_ips[$ip]:-}" ] || [ ${#ddos_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    ddos_ips[$ip]=$((${ddos_ips[$ip]:-0} + 1))
                    [ -n "$port" ]  && ddos_ports[$ip]="$port"
                    [ -n "$proto" ] && ddos_proto[$ip]="$proto"
                else
                    storm_warn
                fi
            fi
            ;;
        tor)
            if [ -n "$ip" ]; then
                if [ -n "${tor_ips[$ip]:-}" ] || [ ${#tor_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    tor_ips[$ip]=$((${tor_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        threat)
            if [ -n "$ip" ]; then
                if [ -n "${threat_ips[$ip]:-}" ] || [ ${#threat_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    threat_ips[$ip]=$((${threat_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        custom)
            if [ -n "$ip" ]; then
                if [ -n "${custom_ips[$ip]:-}" ] || [ ${#custom_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    custom_ips[$ip]=$((${custom_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        conn_flood)
            if [ -n "$ip" ]; then
                if [ -n "${conn_flood_ips[$ip]:-}" ] || [ ${#conn_flood_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    conn_flood_ips[$ip]=$((${conn_flood_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        newconn_flood)
            if [ -n "$ip" ]; then
                if [ -n "${newconn_flood_ips[$ip]:-}" ] || [ ${#newconn_flood_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    newconn_flood_ips[$ip]=$((${newconn_flood_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        tcp_invalid)
            if [ -n "$ip" ]; then
                if [ -n "${tcp_invalid_ips[$ip]:-}" ] || [ ${#tcp_invalid_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    tcp_invalid_ips[$ip]=$((${tcp_invalid_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        fib_spoof)
            if [ -n "$ip" ]; then
                if [ -n "${fib_spoof_ips[$ip]:-}" ] || [ ${#fib_spoof_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    fib_spoof_ips[$ip]=$((${fib_spoof_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        syn_escalate)
            if [ -n "$ip" ]; then
                if [ -n "${syn_escalate_ips[$ip]:-}" ] || [ ${#syn_escalate_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    syn_escalate_ips[$ip]=$((${syn_escalate_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        udp_escalate)
            if [ -n "$ip" ]; then
                if [ -n "${udp_escalate_ips[$ip]:-}" ] || [ ${#udp_escalate_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    udp_escalate_ips[$ip]=$((${udp_escalate_ips[$ip]:-0} + 1))
                else storm_warn; fi
            fi
            ;;
        ufw_block)
            if [ -n "$ip" ]; then
                if [ -n "${ufw_block_ips[$ip]:-}" ] || [ ${#ufw_block_ips[@]} -lt "$MAX_UNIQUE_IPS_PER_TYPE" ]; then
                    ufw_block_ips[$ip]=$((${ufw_block_ips[$ip]:-0} + 1))
                    [ -n "$port" ] && ufw_block_ports[$ip]="$port"
                else storm_warn; fi
            fi
            ;;
    esac
done < <(awk '
    /\[shield:scanner\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "scanner|" ip "||"
        }
    }
    /\[shield:ddos\]/ {
        ip=""; port=""; proto=""
        # v3.23.13 BUG-002 FIX: gsub очистка от не-IP символов (защита от
        # SQL injection через journald log lines с инжектированным SRC=...).
        if (match($0, /SRC=[^ ]+/))    { ip    = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip) }
        if (match($0, /DPT=[0-9]+/))   port  = substr($0, RSTART+4, RLENGTH-4)
        if (match($0, /PROTO=[A-Z]+/)) proto = substr($0, RSTART+6, RLENGTH-6)
        if (ip != "") print "ddos|" ip "|" port "|" proto
    }
    /\[shield:tor\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "tor|" ip "||"
        }
    }
    /\[shield:threat\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "threat|" ip "||"
        }
    }
    /\[shield:custom\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "custom|" ip "||"
        }
    }
    # v3.20.0: patterns для [shield:mobile_ru_drop] и [shield:broadband_ru_drop]
    # УБРАНЫ — whitelists более не используются, эти log prefixes не генерируются.
    #
    # v3.21.3 BUGFIX: ранее тут был апостроф в русском слове (whitelist + апостроф + ы).
    # Апостроф в КОММЕНТАРИИ внутри awk-блока, обернутого в single quotes,
    # закрывал bash single-quoted строку раньше времени. Дальнейший awk-код
    # парсился bash как команды → aggregator падал с exit 2.
    # ВАЖНО: в комментариях внутри single-quoted блоков НЕ должно быть символа ASCII 0x27.
    # Эта секция намеренно содержит ноль таких символов.
    /\[shield:conn_flood\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "conn_flood|" ip "||"
        }
    }
    /\[shield:newconn_flood\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "newconn_flood|" ip "||"
        }
    }
    /\[shield:tcp_invalid\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "tcp_invalid|" ip "||"
        }
    }
    /\[shield:fib_spoof\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "fib_spoof|" ip "||"
        }
    }
    /\[shield:syn_escalate\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "syn_escalate|" ip "||"
        }
    }
    /\[shield:udp_escalate\]/ {
        if (match($0, /SRC=[^ ]+/)) {
            ip = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip)
            if (ip != "") print "udp_escalate|" ip "||"
        }
    }
    # v3.16.0: UFW BLOCK дропы (когда оператор включил ufw logging on)
    # Формат: "[UFW BLOCK] IN=ens3 OUT= MAC=... SRC=1.2.3.4 DST=... DPT=22 ..."
    # v3.23.13 BUG-002 FIX: gsub очистка от не-IP символов (SQL injection защита).
    /\[UFW BLOCK\]/ {
        ip=""; port=""
        if (match($0, /SRC=[^ ]+/))  { ip   = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip) }
        if (match($0, /DPT=[0-9]+/)) port = substr($0, RSTART+4, RLENGTH-4)
        if (ip != "") print "ufw_block|" ip "|" port "|"
    }
    /\[UFW LIMIT BLOCK\]/ {
        ip=""; port=""
        if (match($0, /SRC=[^ ]+/))  { ip   = substr($0, RSTART+4, RLENGTH-4); gsub(/[^0-9.:]/, "", ip) }
        if (match($0, /DPT=[0-9]+/)) port = substr($0, RSTART+4, RLENGTH-4)
        if (ip != "") print "ufw_block|" ip "|" port "|"
    }
' "$TMP")

# v3.23.6: state-based logging в events.log (БЕЗ багов v3.23.5).
# Главное правило: пишем только если событие "новое" или "значимое".
# Это снижает throughput логов в 100-1000 раз при длительных атаках.
#
# Архитектура (исправлено с v3.23.5):
#   - State load: один раз в начале — читаем state-файл в bash hash
#   - Lookup: O(1) через ${LAST_COUNT[key]} (не grep на каждой проверке)
#   - State save: atomic write (tmp + mv) в конце
#   - Concurrency: flock защищает от пересечения тиков
#
# Решение писать:
#   - впервые увидели (ip,type) → пишем
#   - count вырос >= LOG_DELTA_THRESHOLD от last_logged_count → пишем
#   - прошло >= LOG_REFRESH_INTERVAL с last_logged_ts → пишем (refresh)
#   - иначе skip

LOG_STATE_FILE="/var/lib/shieldnode/.events-log-state"
LOG_STATE_LOCK="/run/shieldnode/agg-state.lock"
LOG_DELTA_THRESHOLD=1000   # +1000 hits с последнего лога
LOG_REFRESH_INTERVAL=3600  # 1 час периодический refresh
LOG_STATE_TTL=259200       # 3 дня — старые записи cleanup

mkdir -p /run/shieldnode 2>/dev/null

# Lock на запись state — защита от race между тиками
if ! exec {STATE_LOCK_FD}> "$LOG_STATE_LOCK" 2>/dev/null; then
    logger -t "$LOG_TAG" "CRITICAL: не могу открыть $LOG_STATE_LOCK (RO fs / sandbox ReadWritePaths?) — events.db НЕ обновляется"
    exit 1
fi
flock -n "$STATE_LOCK_FD" || {
    logger -t "$LOG_TAG" "another aggregator run holds state lock — skip this tick"
    exit 0
}

NOW_TS=$(date +%s)

# === Load state file в bash hash (O(N) единоразово) ===
declare -A LAST_COUNT
declare -A LAST_TS

if [ -f "$LOG_STATE_FILE" ]; then
    while IFS='|' read -r s_ip s_type s_cnt s_ts; do
        # Defensive: пропускаем malformed строки
        [ -z "$s_ip" ] && continue
        [ -z "$s_type" ] && continue
        s_cnt="${s_cnt:-0}"
        s_ts="${s_ts:-0}"
        # TTL cleanup при load: записи старше TTL — выбрасываем
        if [ $((NOW_TS - s_ts)) -lt "$LOG_STATE_TTL" ]; then
            local_key="${s_ip}|${s_type}"
            LAST_COUNT["$local_key"]="$s_cnt"
            LAST_TS["$local_key"]="$s_ts"
        fi
    done < "$LOG_STATE_FILE"
fi

# Helper: должны ли логировать (ip, type, current_count)?
# Возвращает 0 (да) или 1 (нет). При "да" — обновляет в-памяти state.
should_log() {
    local ip="$1" type="$2" cnt="$3"
    local key="${ip}|${type}"

    local last_cnt="${LAST_COUNT[$key]:-}"
    local last_ts="${LAST_TS[$key]:-}"

    if [ -z "$last_cnt" ]; then
        # Впервые видим — логируем
        LAST_COUNT["$key"]="$cnt"
        LAST_TS["$key"]="$NOW_TS"
        return 0
    fi

    local delta=$((cnt - last_cnt))
    local age=$((NOW_TS - last_ts))

    if [ "$delta" -ge "$LOG_DELTA_THRESHOLD" ] || [ "$age" -ge "$LOG_REFRESH_INTERVAL" ]; then
        # Значительное событие — логируем + обновляем state
        LAST_COUNT["$key"]="$cnt"
        LAST_TS["$key"]="$NOW_TS"
        return 0
    fi

    return 1
}

# Atomic dump state в файл (вызывается в конце скрипта через trap)
# v3.23.13 BUG-014 FIX: hard cap по count entries. При превышении —
# сохраняем top-N по last_ts (самые свежие). Без cap'а файл рос неограниченно
# при rotating-IP атаках (300k+ unique IP × 3 дня TTL).
LOG_STATE_MAX_ENTRIES="${LOG_STATE_MAX_ENTRIES:-30000}"
save_state() {
    local tmp="${LOG_STATE_FILE}.tmp.$$"
    local total=${#LAST_COUNT[@]}
    if [ "$total" -le "$LOG_STATE_MAX_ENTRIES" ]; then
        {
            for key in "${!LAST_COUNT[@]}"; do
                # key = "ip|type"
                echo "${key}|${LAST_COUNT[$key]}|${LAST_TS[$key]}"
            done
        } > "$tmp" 2>/dev/null && mv "$tmp" "$LOG_STATE_FILE" 2>/dev/null
    else
        # Превысили cap — сохраняем top-N по last_ts (через sort -t'|' -k4 -rn)
        {
            for key in "${!LAST_COUNT[@]}"; do
                echo "${key}|${LAST_COUNT[$key]}|${LAST_TS[$key]}"
            done | sort -t'|' -k4 -rn | head -n "$LOG_STATE_MAX_ENTRIES"
        } > "$tmp" 2>/dev/null && mv "$tmp" "$LOG_STATE_FILE" 2>/dev/null
        logger -t "$LOG_TAG" "state-file capped: kept top ${LOG_STATE_MAX_ENTRIES}/${total} by recency"
    fi
    rm -f "$tmp" 2>/dev/null
}
trap save_state EXIT

# Hard-cap проверка перед записью (v3.23.7+): если events.log >100MB —
# СЖИМАЕМ (не теряем данные!). gzip в фоне через nohup чтобы не блокировать
# aggregator. Старые archive'ы старше 30 дней удаляются.
EVENTS_LOG_ROTATE_THRESHOLD=$((100 * 1024 * 1024))  # 100 MB

# v3.23.8: retry для брошенных несжатых архивов (если предыдущий gzip упал)
# Ищем events.log.<TS> файлы БЕЗ .gz/.xz суффикса — пробуем сжать
for leftover in /var/log/shieldnode/events.log.[0-9]*; do
    [ -f "$leftover" ] || continue
    case "$leftover" in
        *.gz|*.xz) continue ;;  # уже сжаты
    esac
    # Несжатый archive остался от прошлого падения — досжимаем
    nohup bash -c "
        gzip '$leftover' 2>&1 | logger -t shieldnode-agg-retry || \
            logger -t shieldnode-agg-retry 'gzip retry FAILED for $leftover (диск может быть полон)'
    " >/dev/null 2>&1 &
done

if [ -f "$EVENTS_LOG" ]; then
    EVENTS_SIZE=$(stat -c%s "$EVENTS_LOG" 2>/dev/null || echo 0)
    if [ "$EVENTS_SIZE" -gt "$EVENTS_LOG_ROTATE_THRESHOLD" ]; then
        ROTATE_TS=$(date +%Y%m%d-%H%M%S)
        ARCHIVED="${EVENTS_LOG}.${ROTATE_TS}"
        # Atomic move (writer переоткроет fd на следующем тике)
        if mv "$EVENTS_LOG" "$ARCHIVED" 2>/dev/null; then
            touch "$EVENTS_LOG"
            chmod 0640 "$EVENTS_LOG"
            # v3.23.8: gzip с error logging — не глотаем stderr
            nohup bash -c "
                if gzip '$ARCHIVED' 2>&1 | logger -t shieldnode-gzip; then
                    logger -t shieldnode-agg 'gzip OK: ${ARCHIVED}.gz'
                else
                    logger -t shieldnode-agg 'WARNING: gzip FAILED for $ARCHIVED (диск переполнен? permissions?)'
                fi
            " >/dev/null 2>&1 &
            logger -t "$LOG_TAG" "events.log rotated to ${ARCHIVED}.gz ($((EVENTS_SIZE / 1024 / 1024))MB → gzip in background)"
        fi
    fi
fi

TS=$(date '+%Y-%m-%d %H:%M:%S')
{
    for ip in "${!scanner_ips[@]}"; do
        cnt=${scanner_ips[$ip]}
        should_log "$ip" "SCANNER" "$cnt" && echo "[$TS] SCANNER ip=$ip hits=$cnt"
    done
    for ip in "${!ddos_ips[@]}"; do
        cnt=${ddos_ips[$ip]}
        port=${ddos_ports[$ip]:-?}
        proto=${ddos_proto[$ip]:-?}
        case "$proto" in
            TCP) ftype="SYN-flood" ;;
            UDP) ftype="UDP-flood" ;;
            *)   ftype="$proto-flood" ;;
        esac
        should_log "$ip" "DDOS" "$cnt" && echo "[$TS] DDOS BLOCK ip=$ip port=$port type=$ftype hits=$cnt"
    done
    for ip in "${!tor_ips[@]}"; do
        cnt=${tor_ips[$ip]}
        should_log "$ip" "TOR" "$cnt" && echo "[$TS] TOR EXIT BLOCK ip=$ip hits=$cnt"
    done
    for ip in "${!threat_ips[@]}"; do
        cnt=${threat_ips[$ip]}
        should_log "$ip" "THREAT" "$cnt" && echo "[$TS] THREAT BLOCK ip=$ip hits=$cnt"
    done
    for ip in "${!custom_ips[@]}"; do
        cnt=${custom_ips[$ip]}
        should_log "$ip" "CUSTOM" "$cnt" && echo "[$TS] CUSTOM BLOCK ip=$ip hits=$cnt"
    done
    for ip in "${!conn_flood_ips[@]}"; do
        cnt=${conn_flood_ips[$ip]}
        should_log "$ip" "CONN-FLOOD" "$cnt" && echo "[$TS] CONN-FLOOD ip=$ip hits=$cnt (exceeded ct=15000)"
    done
    for ip in "${!newconn_flood_ips[@]}"; do
        cnt=${newconn_flood_ips[$ip]}
        should_log "$ip" "NEWCONN-FLOOD" "$cnt" && echo "[$TS] NEWCONN-FLOOD ip=$ip hits=$cnt (>40000 new conn/min — banned 15min)"
    done
    for ip in "${!tcp_invalid_ips[@]}"; do
        cnt=${tcp_invalid_ips[$ip]}
        should_log "$ip" "TCP-INVALID" "$cnt" && echo "[$TS] TCP-INVALID ip=$ip hits=$cnt (nmap-like scanner: XMAS/NULL/SYN+FIN)"
    done
    for ip in "${!fib_spoof_ips[@]}"; do
        cnt=${fib_spoof_ips[$ip]}
        should_log "$ip" "FIB-SPOOF" "$cnt" && echo "[$TS] FIB-SPOOF ip=$ip hits=$cnt (spoofed src, kernel can't route back)"
    done
    for ip in "${!syn_escalate_ips[@]}"; do
        cnt=${syn_escalate_ips[$ip]}
        should_log "$ip" "SYN-ESCALATE" "$cnt" && echo "[$TS] SYN-ESCALATE ip=$ip hits=$cnt (suspect→confirmed via SYN-flood — banned 1h)"
    done
    for ip in "${!udp_escalate_ips[@]}"; do
        cnt=${udp_escalate_ips[$ip]}
        should_log "$ip" "UDP-ESCALATE" "$cnt" && echo "[$TS] UDP-ESCALATE ip=$ip hits=$cnt (suspect→confirmed via UDP-flood — banned 1h)"
    done
    for ip in "${!ufw_block_ips[@]}"; do
        cnt=${ufw_block_ips[$ip]}
        port="${ufw_block_ports[$ip]:-?}"
        should_log "$ip" "UFW-BLOCK" "$cnt" && echo "[$TS] UFW-BLOCK ip=$ip dpt=$port hits=$cnt (port scan / closed port)"
    done
} >> "$EVENTS_LOG" 2>/dev/null

# v3.5: CrowdSec bans — читаем из decisions, дописываем НОВЫЕ в events.log
CS_DB="/var/lib/crowdsec/data/crowdsec.db"
LAST_CS_ID_FILE="/var/lib/shieldnode/.last_crowdsec_decision_id"
if [ -r "$CS_DB" ]; then
    LAST_ID=$(cat "$LAST_CS_ID_FILE" 2>/dev/null || echo 0)
    LAST_ID="${LAST_ID:-0}"
    # v3.18.11 SH-NEW-89: проверяем что LAST_ID не больше MAX(id) в БД.
    # Если CrowdSec БД пересоздана (apt purge + install, sqlite recover, etc) —
    # id начинается с 1, но наш LAST_ID хранит старое (например 50000) →
    # WHERE id > 50000 ничего не возвращает → события CrowdSec пропускаются навсегда.
    DB_MAX_ID=$(sqlite3 "$CS_DB" "SELECT COALESCE(MAX(id),0) FROM decisions" 2>/dev/null)
    DB_MAX_ID="${DB_MAX_ID:-0}"
    if [ "$LAST_ID" -gt "$DB_MAX_ID" ]; then
        logger -t "$LOG_TAG" "DB recreated detected (LAST_ID=$LAST_ID > MAX=$DB_MAX_ID), reset cursor"
        LAST_ID=0
    fi
    NEW_DECISIONS=$(sqlite3 -separator '|' "$CS_DB" \
        "SELECT id, value, scenario, until FROM decisions WHERE type='ban' AND id > $LAST_ID ORDER BY id" 2>/dev/null)
    if [ -n "$NEW_DECISIONS" ]; then
        MAX_ID=$LAST_ID
        while IFS='|' read -r did val scen until; do
            [ -z "$did" ] && continue
            # value формата "Ip:1.2.3.4" или "Range:1.2.3.0/24"
            ip=${val#*:}
            # Краткий reason из scenario
            reason=${scen##*/}
            # duration: пытаемся прикинуть из until - now
            if [ -n "$until" ]; then
                until_ts=$(date -d "$until" +%s 2>/dev/null)
                now_ts=$(date +%s)
                if [ -n "$until_ts" ] && [ "$until_ts" -gt "$now_ts" ]; then
                    dur_sec=$((until_ts - now_ts))
                    if [ $dur_sec -lt 3600 ]; then dur="${dur_sec}s"
                    elif [ $dur_sec -lt 86400 ]; then dur="$((dur_sec/3600))h"
                    else dur="$((dur_sec/86400))d"
                    fi
                else
                    dur="?"
                fi
            else
                dur="?"
            fi
            echo "[$TS] CROWDSEC BAN ip=$ip reason=$reason duration=$dur" >> "$EVENTS_LOG"
            [ "$did" -gt "$MAX_ID" ] && MAX_ID=$did
        done <<< "$NEW_DECISIONS"
        echo "$MAX_ID" > "$LAST_CS_ID_FILE" 2>/dev/null
    fi
fi

# Bulk-update в БД через одну транзакцию (быстро)
NOW=$(date +%s)
{
    # v3.22.0: busy_timeout защищает от SQLITE_BUSY когда guard одновременно
    # делает DELETE/UPDATE через settings menu. WAL mode даёт concurrent reads,
    # но write-write коллизия фейлила батч без timeout'а.
    echo "PRAGMA busy_timeout=5000;"
    echo "BEGIN TRANSACTION;"
    for ip in "${!scanner_ips[@]}"; do
        cnt=${scanner_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('scanner', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    for ip in "${!ddos_ips[@]}"; do
        cnt=${ddos_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('ddos', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.11: Tor exits
    for ip in "${!tor_ips[@]}"; do
        cnt=${tor_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('tor', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.12.0: threat + custom blocklists
    for ip in "${!threat_ips[@]}"; do
        cnt=${threat_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('threat', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    for ip in "${!custom_ips[@]}"; do
        cnt=${custom_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('custom', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.20.0: mobile_ru/broadband_ru INSERT loops УБРАНЫ (whitelist'ы удалены)
    # v3.20.0: conn-flood events (>3000 concurrent)
    for ip in "${!conn_flood_ips[@]}"; do
        cnt=${conn_flood_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('conn_flood', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.15.2: newconn-flood events (>500/min, escalated to confirmed_attack)
    for ip in "${!newconn_flood_ips[@]}"; do
        cnt=${newconn_flood_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('newconn_flood', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.15.3: tcp-invalid (nmap scanner) events
    for ip in "${!tcp_invalid_ips[@]}"; do
        cnt=${tcp_invalid_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('tcp_invalid', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.15.3: fib-spoof events
    for ip in "${!fib_spoof_ips[@]}"; do
        cnt=${fib_spoof_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('fib_spoof', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.15.3: syn/udp escalation events
    for ip in "${!syn_escalate_ips[@]}"; do
        cnt=${syn_escalate_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('syn_escalate', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    for ip in "${!udp_escalate_ips[@]}"; do
        cnt=${udp_escalate_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('udp_escalate', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    # v3.16.0: UFW BLOCK events
    for ip in "${!ufw_block_ips[@]}"; do
        cnt=${ufw_block_ips[$ip]}
        echo "INSERT INTO events(type, ip, first_seen, last_seen, count) VALUES('ufw_block', '$ip', $NOW, $NOW, $cnt) ON CONFLICT(type, ip) DO UPDATE SET last_seen=$NOW, count=count+$cnt;"
    done
    if [ -n "$NEW_CURSOR" ]; then
        # Экранируем одинарные кавычки в cursor
        ESC_CURSOR=$(echo "$NEW_CURSOR" | sed "s/'/''/g")
        echo "INSERT OR REPLACE INTO aggregator_state(key, value) VALUES('cursor', '$ESC_CURSOR');"
    fi
    echo "COMMIT;"
} | (
    # v3.23.13 BUG-015 FIX: db.lock shared с cleanup'ом (VACUUM INTO swap).
    # WAL mode позволяет concurrent reads, но для safe VACUUM INTO swap
    # cleanup'у нужно эксклюзивное окно. Берём lock в shared (exclusive не нужен —
    # SQLite сам через WAL обработает concurrent inserts, нам важно только
    # не пересечься с `mv` в момент cleanup'a).
    exec {DB_LOCK_FD}> /run/shieldnode/db.lock 2>/dev/null || true
    flock -s -w 10 "$DB_LOCK_FD" 2>/dev/null || true
    sqlite3 "$DB" 2>/dev/null
)

# Лог
TOTAL_SCANNERS=${#scanner_ips[@]}
TOTAL_DDOS=${#ddos_ips[@]}
TOTAL_TOR=${#tor_ips[@]}
TOTAL_THREAT=${#threat_ips[@]}
TOTAL_CUSTOM=${#custom_ips[@]}
# v3.20.0: TOTAL_MOBILE_RU и TOTAL_BROADBAND_RU УБРАНЫ (whitelist'ы удалены)
TOTAL_CONN_FLOOD=${#conn_flood_ips[@]}
TOTAL_NEWCONN_FLOOD=${#newconn_flood_ips[@]}
TOTAL_TCP_INVALID=${#tcp_invalid_ips[@]}
TOTAL_FIB_SPOOF=${#fib_spoof_ips[@]}
TOTAL_SYN_ESC=${#syn_escalate_ips[@]}
TOTAL_UDP_ESC=${#udp_escalate_ips[@]}
TOTAL_UFW_BLOCK=${#ufw_block_ips[@]}
TOTAL_ANY=$((TOTAL_SCANNERS + TOTAL_DDOS + TOTAL_TOR + TOTAL_THREAT + TOTAL_CUSTOM + TOTAL_CONN_FLOOD + TOTAL_NEWCONN_FLOOD + TOTAL_TCP_INVALID + TOTAL_FIB_SPOOF + TOTAL_SYN_ESC + TOTAL_UDP_ESC + TOTAL_UFW_BLOCK))
if [ $TOTAL_ANY -gt 0 ]; then
    logger -t "$LOG_TAG" "Processed: scanners=$TOTAL_SCANNERS, ddos=$TOTAL_DDOS, tor=$TOTAL_TOR, threat=$TOTAL_THREAT, custom=$TOTAL_CUSTOM, conn_flood=$TOTAL_CONN_FLOOD, newconn_flood=$TOTAL_NEWCONN_FLOOD, tcp_invalid=$TOTAL_TCP_INVALID, fib_spoof=$TOTAL_FIB_SPOOF, syn_esc=$TOTAL_SYN_ESC, udp_esc=$TOTAL_UDP_ESC, ufw_block=$TOTAL_UFW_BLOCK unique IPs"
fi
# v3.23.13 SR-FIX-2: видимость storm-cap drops
if [ "$STORM_DROPPED" -gt 0 ]; then
    logger -t "$LOG_TAG" "STORM: $STORM_DROPPED unique IPs dropped from attribution (cap $MAX_UNIQUE_IPS_PER_TYPE/type reached). nft drops continue independently."
fi
AGG_EOF

# v3.23.13 BUG-019: подставляем настраиваемые значения из limits.conf
sed -i \
    -e "s|__SHIELD_AGG_JOURNAL_LINES__|$SHIELD_AGG_JOURNAL_LINES|g" \
    -e "s|__SHIELD_AGG_MAX_UNIQUE_IPS__|$SHIELD_AGG_MAX_UNIQUE_IPS|g" \
    "$AGG_SCRIPT"
verify_no_placeholders "$AGG_SCRIPT" || exit 1

chmod 0750 "$AGG_SCRIPT"
print_ok "Aggregator: $AGG_SCRIPT"

# Systemd service + timer (раз в минуту)
cat > /etc/systemd/system/shieldnode-aggregator.service <<EOF
[Unit]
Description=Shieldnode events aggregator (journald → sqlite)
After=systemd-journald.service

[Service]
Type=oneshot
ExecStart=$AGG_SCRIPT
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DB_DIR
ReadWritePaths=$LOG_DIR
# v3.23.19 FIX: под ProtectSystem=strict вся ФС RO кроме ReadWritePaths.
# Агрегатор пишет lock в /run/shieldnode/agg-state.lock — без этих строк путь RO,
# lock падает, агрегатор скипает каждый тик и events.db не обновляется.
# Зеркалит ports-update unit. Preserve=yes — /run/shieldnode делят несколько юнитов.
RuntimeDirectory=shieldnode
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ReadWritePaths=/run/shieldnode
# v3.23.13 BUG-007: hard memory limit — защита от RAM blow-up при rotating-IP
# атаках (>100k unique sources). MAX 512MB = достаточно для 50k IP × 13 типов
# в bash hash. Если упёрлись — systemd убивает aggregator, защита nft drops
# продолжает работать независимо. TasksMax защищает от fork-bomb scenarios.
MemoryMax=512M
MemoryHigh=384M
TasksMax=20
# CPU quota: на shared-VPS не утопим соседей
CPUQuota=80%
EOF

cat > /etc/systemd/system/shieldnode-aggregator.timer <<'EOF'
[Unit]
Description=Run shieldnode aggregator every minute
Requires=shieldnode-aggregator.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now shieldnode-aggregator.timer >/dev/null 2>&1
print_ok "Aggregator timer активен (запуск раз в минуту)"

# ==============================================================================
# ШАГ 12: УСТАНОВКА КОМАНДЫ guard (снимок состояния)
# ==============================================================================

print_header "ШАГ 12: УСТАНОВКА КОМАНДЫ guard"

# Команда показывает текущее состояние защиты ОДНИМ снимком:
#   - Статус всех сервисов (CrowdSec, bouncer, watcher'ы)
#   - Защищаемые порты (TCP/UDP)
#   - Сколько IP заблокировано прямо сейчас
#   - Активные whitelist'ы
#   - Когда последний раз обновлялся blocklist
#
# v2.1: команда работает в one-shot режиме — никакой фоновой нагрузки,
# никаких циклов. Каждый запуск — независимый snapshot.
#
# Запуск:
#   sudo guard          текстовый снимок
#   sudo guard --json   JSON для интеграций (Zabbix/Prometheus/боты)
#   sudo watch -n 5 guard   "live"-режим через стандартный watch(1)

GUARD_BIN="/usr/local/bin/guard"

cat > "$GUARD_BIN" <<'GUARD_EOF'
#!/bin/bash
# guard — minimalist snapshot dashboard для VPN-ноды.
#
# v2.3: минималистичный английский интерфейс + интерактив.
#   sudo guard            снимок + интерактивное меню (1/2/3/4/r/0)
#   sudo guard --json     JSON для интеграций
#   sudo guard --once     снимок без меню (для cron/мониторинга)
#   sudo guard --help     помощь

case "${1:-}" in
    --help|-h)
        cat <<HELP
guard — VPN node protection snapshot

Usage:
  sudo guard            snapshot + interactive menu
  sudo guard --once     snapshot only, no menu (for cron / monitoring)
  sudo guard --json     JSON output (for integrations)
  sudo guard upgrade    re-run installer from github (apply latest version)
  sudo guard rollback   restore state from before last 'guard upgrade'
  sudo guard sync       force github sync of custom.txt now
  sudo guard check      force version check now
  sudo guard self-test  health check (v3.23.5+): conntrack, disk, MY_IP, services

Interactive menu:
  [2] crowdsec banned IPs       [3] whitelist IPs
  [6] recent history            [7] top attackers (all-time)
  [s] settings                  [r] refresh
  [0] exit

HELP
        exit 0
        ;;
    self-test)
        # v3.23.5: диагностика готовности ноды
        if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo guard self-test"; exit 1; fi
        ISSUES=0
        WARNINGS=0
        echo "════════ shieldnode self-test ════════"
        echo ""

        # 1. shieldnode-nftables service
        if systemctl is-active --quiet shieldnode-nftables; then
            echo "  [✓] shieldnode-nftables: active"
        else
            echo "  [✗] shieldnode-nftables: NOT ACTIVE"
            ISSUES=$((ISSUES + 1))
        fi

        # 2. nft table existence
        if nft list table inet ddos_protect >/dev/null 2>&1; then
            echo "  [✓] nft table inet ddos_protect: exists"
        else
            echo "  [✗] nft table inet ddos_protect: MISSING"
            ISSUES=$((ISSUES + 1))
        fi

        # 2.5 ctguard (v3.26.3): таймер жив? heartbeat свежий (тик каждые 15с)?
        if systemctl is-active --quiet shieldnode-ctguard.timer; then
            hb=$(cat /run/shieldnode/ctguard.heartbeat 2>/dev/null || echo 0)
            age=$(( $(date +%s) - ${hb:-0} ))
            if [ "${hb:-0}" -le 0 ]; then
                echo "  [i] ctguard: timer активен, heartbeat ещё нет (свежий старт?)"
            elif [ "$age" -le 60 ]; then
                echo "  [✓] ctguard: active (last tick ${age}s ago)"
            else
                echo "  [⚠] ctguard: heartbeat ${age}s назад (>60s) — тик залип? journalctl -t shieldnode-ctguard"
                ISSUES=$((ISSUES + 1))
            fi
        else
            echo "  [i] ctguard: timer не активен (SHIELD_CTGUARD=0?)"
        fi

        # 3. CrowdSec
        if systemctl is-active --quiet crowdsec; then
            echo "  [✓] crowdsec: active"
        else
            echo "  [✗] crowdsec: NOT ACTIVE"
            ISSUES=$((ISSUES + 1))
        fi

        # 4. CrowdSec firewall bouncer
        if systemctl is-active --quiet crowdsec-firewall-bouncer; then
            echo "  [✓] crowdsec-firewall-bouncer: active (stream mode)"
        else
            echo "  [✗] crowdsec-firewall-bouncer: NOT ACTIVE — community blocklist не применяется"
            ISSUES=$((ISSUES + 1))
        fi

        # 5. conntrack_max vs RAM
        CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
        RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
        RECOMMENDED=262144
        [ "$RAM_MB" -gt 2000 ] && RECOMMENDED=786432
        [ "$RAM_MB" -gt 4000 ] && RECOMMENDED=2097152
        [ "$RAM_MB" -gt 8000 ] && RECOMMENDED=4194304
        if [ "$CT_MAX" -ge "$RECOMMENDED" ]; then
            echo "  [✓] nf_conntrack_max: $CT_MAX (рекомендованный для ${RAM_MB}MB RAM: $RECOMMENDED)"
        else
            echo "  [⚠] nf_conntrack_max: $CT_MAX — мало для ${RAM_MB}MB RAM (рекомендовано $RECOMMENDED)"
            echo "      Fix: upgrade vpn-node-setup до v5.1.1+ (tier-aware sizing)"
            WARNINGS=$((WARNINGS + 1))
        fi

        # 6. Disk usage (/var/log)
        DISK_PCT=$(df --output=pcent /var/log 2>/dev/null | tail -1 | tr -d ' %')
        if [ "${DISK_PCT:-0}" -ge 90 ]; then
            echo "  [✗] disk /var/log: ${DISK_PCT}% — CRITICAL, очисти срочно"
            ISSUES=$((ISSUES + 1))
        elif [ "${DISK_PCT:-0}" -ge 80 ]; then
            echo "  [⚠] disk /var/log: ${DISK_PCT}% — высокая нагрузка"
            WARNINGS=$((WARNINGS + 1))
        else
            echo "  [✓] disk /var/log: ${DISK_PCT}% used"
        fi

        # 7. events.log size
        if [ -f /var/log/shieldnode/events.log ]; then
            EV_SIZE=$(stat -c%s /var/log/shieldnode/events.log 2>/dev/null || echo 0)
            EV_MB=$((EV_SIZE / 1024 / 1024))
            if [ "$EV_MB" -gt 400 ]; then
                echo "  [⚠] events.log: ${EV_MB} MB — близко к hard cap 500MB"
                WARNINGS=$((WARNINGS + 1))
            else
                echo "  [✓] events.log: ${EV_MB} MB"
            fi
        fi

        # 8. MY_IP в suspect_v4 (self-flood detection)
        MY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')
        if [ -n "$MY_IP" ]; then
            if nft list set inet ddos_protect suspect_v4 2>/dev/null | grep -qF "$MY_IP"; then
                echo "  [✗] MY_IP ($MY_IP) находится в suspect_v4 — self-flood!"
                echo "      Причина: nginx/proxy_pass через public IP вместо 127.0.0.1 или unix socket"
                echo "      Fix: добавить MY_IP в TRUSTED_IPS (guard → Trusted IPs → Add)"
                echo "           и проверить nginx config (proxy_pass http://127.0.0.1:PORT)"
                ISSUES=$((ISSUES + 1))
            else
                echo "  [✓] MY_IP ($MY_IP): чист в suspect_v4"
            fi
        fi

        # 9. logrotate работает
        # v3.23.11: grep -c всегда возвращает число (0 если пусто), но exit != 0
        # при пустом матче. `|| echo 0` приклеивал ВТОРУЮ строку "0" → integer
        # expression error. Используем default через ${X:-0} вместо ||.
        LR_FAILED=$(journalctl -u shieldnode-logrotate --since "24 hours ago" --no-pager 2>/dev/null | grep -c "FAILURE" 2>/dev/null)
        LR_FAILED="${LR_FAILED:-0}"
        if [ "$LR_FAILED" -gt 5 ]; then
            echo "  [⚠] shieldnode-logrotate: $LR_FAILED ошибок за 24ч"
            WARNINGS=$((WARNINGS + 1))
        else
            echo "  [✓] shieldnode-logrotate: OK"
        fi

        # 10. PCAP capture
        if systemctl is-active --quiet shieldnode-pcap; then
            echo "  [✓] shieldnode-pcap: active (forensics готов)"
        else
            echo "  [⚠] shieldnode-pcap: не активен — нет pcap для хостера при DDoS"
            WARNINGS=$((WARNINGS + 1))
        fi

        # 11. Threat blocklist health
        THREAT_COUNT=$(nft list set inet ddos_protect threat_blocklist_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
        if [ "$THREAT_COUNT" -lt 1000 ]; then
            echo "  [⚠] threat_blocklist_v4: только $THREAT_COUNT IPs — feeds могли сломаться"
            WARNINGS=$((WARNINGS + 1))
        else
            echo "  [✓] threat_blocklist_v4: $THREAT_COUNT IPs"
        fi

        echo ""
        echo "════════ Summary ════════"
        if [ "$ISSUES" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
            echo "  All checks passed — нода в норме"
            exit 0
        else
            echo "  Issues: $ISSUES | Warnings: $WARNINGS"
            [ "$ISSUES" -gt 0 ] && exit 2
            exit 1
        fi
        ;;
    upgrade)
        # v3.14.0: re-run установщика с github
        # v3.18.8: качаем во временный файл с -fsSL + sanity-check ПЕРЕД exec.
        #          Без этого 404/MITM/empty body превращался в `bash <(<html>)` и
        #          мог снести работающую установку.
        if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo guard upgrade"; exit 1; fi
        REPO_URL="${SHIELD_REPO_URL:-https://raw.githubusercontent.com/SpofyJet/shield/main}"
        TMP_INSTALLER=$(mktemp /tmp/shieldnode-upgrade.XXXXXX.sh) || { echo "FATAL: mktemp failed"; exit 1; }
        # Удалим временный файл при выходе если до exec не дойдём
        trap 'rm -f "$TMP_INSTALLER"' EXIT
        echo "Downloading installer from $REPO_URL/shieldnode.sh ..."
        if ! curl -fsSL --max-time 60 --retry 2 "$REPO_URL/shieldnode.sh" -o "$TMP_INSTALLER"; then
            echo "FATAL: download failed (network/404/TLS). Aborting upgrade — старая версия не тронута."
            exit 1
        fi
        if [ ! -s "$TMP_INSTALLER" ]; then
            echo "FATAL: downloaded file is empty. Aborting upgrade."
            exit 1
        fi
        if ! head -3 "$TMP_INSTALLER" | grep -q '^#!/bin/bash'; then
            echo "FATAL: downloaded file is not a bash script (нет shebang). Aborting upgrade."
            echo "Проверь: head -5 $TMP_INSTALLER"
            exit 1
        fi
        if ! grep -qE 'VPN NODE DDoS PROTECTION v[0-9]+\.[0-9]+\.[0-9]+' "$TMP_INSTALLER"; then
            echo "FATAL: downloaded file missing version marker. Aborting upgrade."
            exit 1
        fi
        if ! bash -n "$TMP_INSTALLER" 2>/dev/null; then
            echo "FATAL: downloaded installer has syntax errors. Aborting upgrade."
            echo "Проверь: bash -n $TMP_INSTALLER"
            exit 1
        fi
        echo "Sanity checks passed."

        # v3.18.8: snapshot critical state ПЕРЕД exec — для `guard rollback`.
        # Если новый installer наглухо ломает ноду (regression в nft template,
        # battered conf и т.п.), оператор делает `sudo guard rollback` и
        # возвращается к рабочей версии без пересоздания ноды.
        SNAPSHOT_ROOT="/var/lib/shieldnode/snapshots"
        SNAPSHOT_DIR="$SNAPSHOT_ROOT/upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$SNAPSHOT_DIR"
        # Конфиг и lists
        cp -a /etc/shieldnode "$SNAPSHOT_DIR/etc-shieldnode" 2>/dev/null || true
        # nft templates
        if [ -d /etc/nftables.d ]; then
            cp -a /etc/nftables.d "$SNAPSHOT_DIR/etc-nftables.d" 2>/dev/null || true
        fi
        # Текущий live-ruleset (для прямого восстановления через nft -f)
        nft list ruleset > "$SNAPSHOT_DIR/nft-ruleset.snapshot" 2>/dev/null || true
        # Бинарники которые скрипт перезаписывает.
        # v3.28.8 FIX: глоб по ВСЕМ shieldnode-скриптам + guard. Раньше список был
        # неполный — synproxy/ctguard/remnawave-sync/auto-promote/cleanup/pcap/
        # mobile-ru НЕ сохранялись → rollback оставлял их на НОВОЙ версии (рассинхрон
        # компонентов, хуже любой из версий).
        for f in /usr/local/bin/guard /usr/local/sbin/shieldnode-*.sh; do
            [ -f "$f" ] && cp -a "$f" "$SNAPSHOT_DIR/$(basename "$f").previous" 2>/dev/null || true
        done
        # v3.28.8 FIX: snapshot systemd-юнитов (раньше не сохранялись вовсе → после
        # rollback юниты оставались на новой версии, напр. изменённый synproxy.service).
        mkdir -p "$SNAPSHOT_DIR/units"
        for u in /etc/systemd/system/shieldnode-* /etc/systemd/system/protected-ports-update.*; do
            [ -e "$u" ] && cp -a "$u" "$SNAPSHOT_DIR/units/" 2>/dev/null || true
        done
        # Запоминаем версию-источник для проверки совместимости при rollback
        echo "${SHIELDNODE_VERSION:-unknown}" > "$SNAPSHOT_DIR/.from_version"
        # Указатель на последний snapshot
        echo "$SNAPSHOT_DIR" > /var/lib/shieldnode/.last_upgrade_snapshot
        # Чистим старые snapshots — оставляем последние 3
        ls -1dt "$SNAPSHOT_ROOT"/upgrade-* 2>/dev/null | tail -n +4 | xargs -r rm -rf

        echo "Snapshot: $SNAPSHOT_DIR"
        echo "Rollback (если что-то пойдёт не так): sudo guard rollback"
        echo "Re-installing..."
        # Снимаем trap чтобы файл не удалился до exec'нувшегося bash
        trap - EXIT
        exec bash "$TMP_INSTALLER"
        ;;
    rollback)
        # v3.18.8: возврат к состоянию ПЕРЕД последним `guard upgrade`.
        # Восстанавливает /etc/shieldnode, /etc/nftables.d, скрипты в /usr/local
        # и live nft ruleset. Перезапускает все shieldnode-юниты.
        if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo guard rollback"; exit 1; fi
        SNAP_PTR="/var/lib/shieldnode/.last_upgrade_snapshot"
        if [ ! -f "$SNAP_PTR" ]; then
            echo "Нет snapshot'а — `guard upgrade` ещё не запускался на этой версии."
            exit 1
        fi
        SNAP=$(cat "$SNAP_PTR" 2>/dev/null)
        if [ -z "$SNAP" ] || [ ! -d "$SNAP" ]; then
            echo "FATAL: snapshot директория не найдена ($SNAP)"
            exit 1
        fi
        FROM_VER=$(cat "$SNAP/.from_version" 2>/dev/null || echo "?")
        echo "Rolling back to version $FROM_VER (snapshot: $SNAP)"
        echo -n "Подтвердить rollback? [y/N]: "
        read -r CONFIRM
        case "$CONFIRM" in
            y|Y|yes|YES) ;;
            *) echo "Отменено."; exit 0 ;;
        esac

        # Останавливаем юниты ПЕРЕД восстановлением файлов чтобы избежать race
        # v3.18.11 SH-NEW-98: правильные имена unit'ов (раньше были опечатки —
        # shieldnode-watcher, shieldnode-whitelist-watcher, shieldnode-whitelist-updater
        # таких юнитов не существует, systemctl stop молча fail'ил → race с aggregator
        # пишущим в БД во время копирования).
        systemctl stop shieldnode-aggregator.timer shieldnode-aggregator.service \
                       protected-ports-update.path protected-ports-update.timer \
                       protected-ports-update.service \
                       shieldnode-nftables.service \
                       shieldnode-whitelist.path shieldnode-whitelist.service \
                       shieldnode-update@custom.path 2>/dev/null || true

        # Восстанавливаем /etc/shieldnode
        if [ -d "$SNAP/etc-shieldnode" ]; then
            rm -rf /etc/shieldnode
            cp -a "$SNAP/etc-shieldnode" /etc/shieldnode
            echo "  ✔ /etc/shieldnode восстановлен"
        fi
        # /etc/nftables.d
        if [ -d "$SNAP/etc-nftables.d" ]; then
            rm -rf /etc/nftables.d
            cp -a "$SNAP/etc-nftables.d" /etc/nftables.d
            echo "  ✔ /etc/nftables.d восстановлен"
        fi
        # Бинарники
        for prev in "$SNAP"/*.previous; do
            [ -f "$prev" ] || continue
            base=$(basename "$prev" .previous)
            case "$base" in
                guard) dst="/usr/local/bin/$base" ;;
                shieldnode-*) dst="/usr/local/sbin/$base" ;;
                *) continue ;;
            esac
            cp -a "$prev" "$dst"
            chmod +x "$dst"
            echo "  ✔ $dst восстановлен"
        done
        # v3.28.8 FIX: восстанавливаем systemd-юниты из снапшота (раньше не
        # восстанавливались → юниты оставались на новой версии, напр. synproxy.service).
        if [ -d "$SNAP/units" ] && ls "$SNAP"/units/* >/dev/null 2>&1; then
            cp -a "$SNAP"/units/* /etc/systemd/system/ 2>/dev/null || true
            echo "  ✔ systemd-юниты восстановлены"
        fi

        # Восстанавливаем nft ruleset напрямую — flush и применяем snapshot
        if [ -s "$SNAP/nft-ruleset.snapshot" ]; then
            # v3.28.8 FIX: флашим ВСЕ наши таблицы (раньше только ddos_protect →
            # shield_synproxy/shield_ctguard из снапшота конфликтовали с живыми
            # при nft -f → частичный/битый restore).
            for _t in ddos_protect shield_synproxy shield_ctguard; do
                nft delete table inet "$_t" 2>/dev/null || true
            done
            if nft -f "$SNAP/nft-ruleset.snapshot" 2>/tmp/.nft-rollback.err; then
                echo "  ✔ nft ruleset восстановлен"
            else
                echo "  ⚠ nft -f частично failed — детали: cat /tmp/.nft-rollback.err"
                echo "    Юниты shieldnode-nftables всё равно перезагружают template'ы при старте."
            fi
        fi

        # Перезапускаем юниты (v3.18.11 SH-NEW-98: правильные имена)
        systemctl daemon-reload 2>/dev/null || true
        systemctl restart shieldnode-nftables.service 2>/dev/null || true
        systemctl start shieldnode-aggregator.timer 2>/dev/null || true
        systemctl start protected-ports-update.path 2>/dev/null || true
        systemctl start protected-ports-update.timer 2>/dev/null || true
        systemctl start shieldnode-whitelist.path 2>/dev/null || true
        systemctl start shieldnode-update@custom.path 2>/dev/null || true
        systemctl start shieldnode-remnawave-sync.service 2>/dev/null || true  # v3.28.0: переналить whitelist нод после reload
        # v3.28.8 FIX: эти юниты раньше не перезапускались на rollback → их состояние
        # не возвращалось к снапшоту.
        systemctl start shieldnode-ctguard.timer 2>/dev/null || true
        [ -f /etc/shieldnode/synproxy.nft ] && systemctl restart shieldnode-synproxy.service 2>/dev/null || true

        echo ""
        echo "Rollback complete. Версия: $FROM_VER"
        echo "Проверь: sudo guard"
        exit 0
        ;;
    sync)
        if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo guard sync"; exit 1; fi
        echo "Syncing lists/custom.txt from github..."
        systemctl start shieldnode-github-sync.service
        sleep 2
        journalctl -t shieldnode-github-sync -n 5 --no-pager 2>/dev/null
        exit 0
        ;;
    check)
        if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo guard check"; exit 1; fi
        echo "Checking for new version..."
        systemctl start shieldnode-version-check.service
        sleep 2
        if [ -r /var/lib/shieldnode/.upstream_version ]; then
            cat /var/lib/shieldnode/.upstream_version
        fi
        exit 0
        ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo guard"
    exit 1
fi

MODE="interactive"
case "${1:-}" in
    --json) MODE="json" ;;
    --once) MODE="once" ;;
esac

# ANSI цвета
if [ "$MODE" != "json" ] && [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
    M='\033[0;35m'; W='\033[1;37m'; B='\033[1m'; N='\033[0m'
    DIM='\033[2m'
else
    R=''; G=''; Y=''; C=''; M=''; W=''; B=''; N=''; DIM=''
fi

CS_DB="/var/lib/crowdsec/data/crowdsec.db"

# === СБОР МЕТРИК ===
collect_stats() {
    SYN_BAN=$(nft list set inet ddos_protect syn_flood_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    UDP_BAN=$(nft list set inet ddos_protect udp_flood_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    # v2.5: suspect (под наблюдением 5 мин) + confirmed (бан 1 час)
    SUSPECT_COUNT=$(nft list set inet ddos_protect suspect_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    CONFIRMED_COUNT=$(nft list set inet ddos_protect confirmed_attack_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    PROTECTED_TCP_LIST=$(nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | \
        sort -un | tr '\n' ',' | sed 's/,$//')
    PROTECTED_UDP_LIST=$(nft list set inet ddos_protect protected_ports_udp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | \
        sort -un | tr '\n' ',' | sed 's/,$//')
    PROTECTED_TCP_LIST="${PROTECTED_TCP_LIST:-—}"
    PROTECTED_UDP_LIST="${PROTECTED_UDP_LIST:-—}"

    BL_V4=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)

    MANUAL_WHITE=$(nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)

    CS_ACTIVE="$(systemctl is-active crowdsec 2>/dev/null)"
    BOUNCER_ACTIVE="$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)"
    PORTS_PATH_ACTIVE="$(systemctl is-active protected-ports-update.path 2>/dev/null)"

    CS_BANS=0
    if [ -r "$CS_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        CS_BANS=$(sqlite3 "$CS_DB" "SELECT COUNT(*) FROM decisions WHERE type='ban' AND until > datetime('now')" 2>/dev/null)
        CS_BANS="${CS_BANS:-0}"
    elif command -v cscli >/dev/null 2>&1; then
        CS_BANS=$(cscli decisions list --type ban -o raw 2>/dev/null | tail -n +2 | wc -l)
    fi

    LAST_UPDATE=$(systemctl show shieldnode-update@scanner.service \
        --property=ExecMainExitTimestamp --value 2>/dev/null | \
        xargs -I{} env LC_ALL=C date -d {} '+%Y-%m-%d %H:%M' 2>/dev/null)
    LAST_UPDATE="${LAST_UPDATE:-—}"

    # v2.7: nftables counters — статистика "всего заблокировано"
    # Формат вывода: "counter packets X bytes Y"
    read_counter() {
        local name="$1"
        local out
        out=$(nft list counter inet ddos_protect "$name" 2>/dev/null | \
            grep -oE 'packets [0-9]+ bytes [0-9]+' | head -1)
        if [ -n "$out" ]; then
            local pkts bytes
            pkts=$(echo "$out" | awk '{print $2}')
            bytes=$(echo "$out" | awk '{print $4}')
            echo "${pkts:-0} ${bytes:-0}"
        else
            echo "0 0"
        fi
    }

    read SCANNER_PKTS_V4 SCANNER_BYTES_V4 <<< "$(read_counter scanner_drops_v4)"
    read CONFIRMED_PKTS_V4 CONFIRMED_BYTES_V4 <<< "$(read_counter confirmed_drops_v4)"
    read SYN_CONF_PKTS_V4 SYN_CONF_BYTES_V4 <<< "$(read_counter syn_confirmed_v4)"
    read UDP_CONF_PKTS_V4 UDP_CONF_BYTES_V4 <<< "$(read_counter udp_confirmed_v4)"
    read TOR_PKTS_V4 TOR_BYTES_V4 <<< "$(read_counter tor_drops_v4)"     # v3.11
    # v3.12.0: threat + custom counters
    read THREAT_PKTS_V4 THREAT_BYTES_V4 <<< "$(read_counter threat_drops_v4)"
    read CUSTOM_PKTS_V4 CUSTOM_BYTES_V4 <<< "$(read_counter custom_drops_v4)"
    # v3.5: HTTP/conn-flood counters
    read CONN_FLOOD_PKTS_V4 CONN_FLOOD_BYTES_V4 <<< "$(read_counter conn_flood_v4)"
    read NEWCONN_FLOOD_PKTS_V4 NEWCONN_FLOOD_BYTES_V4 <<< "$(read_counter newconn_flood_v4)"
    # v3.26.3: ctguard-слой дропает в СВОЕЙ таблице shield_ctguard — включаем в тоталы.
    CTG_EVICT_PKTS=$(nft list counter inet shield_ctguard ctguard_drops 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | head -1); CTG_EVICT_PKTS="${CTG_EVICT_PKTS:-0}"
    CTG_CAP_PKTS=$(nft list counter inet shield_ctguard ctguard_capdrop 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | head -1); CTG_CAP_PKTS="${CTG_CAP_PKTS:-0}"
    read TCP_INVALID_PKTS TCP_INVALID_BYTES <<< "$(read_counter tcp_invalid)"
    # v3.21.0: SSH pre-auth flood counters
    read SSH_CONN_FLOOD_PKTS_V4 SSH_CONN_FLOOD_BYTES_V4 <<< "$(read_counter ssh_conn_flood_v4)"
    read SSH_NEWCONN_FLOOD_PKTS_V4 SSH_NEWCONN_FLOOD_BYTES_V4 <<< "$(read_counter ssh_newconn_flood_v4)"
    # v3.21.5: infrastructure bypass counters (Cloudflare/Google/AWS/etc passes)
    read INFRA_PASSES_PKTS_V4 INFRA_PASSES_BYTES_V4 <<< "$(read_counter infrastructure_passes_v4)"
    read INFRA_PASSES_PKTS_V6 INFRA_PASSES_BYTES_V6 <<< "$(read_counter infrastructure_passes_v6)"
    # Размер infrastructure_v4 set'а для дашборда
    INFRA_SET_SIZE=$(nft list set inet ddos_protect infrastructure_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | wc -l)
    INFRA_SET_SIZE="${INFRA_SET_SIZE:-0}"

    # v3.11: размер tor blocklist set'а
    TOR_SET_SIZE=$(nft list set inet ddos_protect tor_exit_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    TOR_SET_SIZE="${TOR_SET_SIZE:-0}"

    # v3.12.0: размеры threat + custom blocklist set'ов
    THREAT_SET_SIZE=$(nft list set inet ddos_protect threat_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
    THREAT_SET_SIZE="${THREAT_SET_SIZE:-0}"
    CUSTOM_SET_SIZE=$(nft list set inet ddos_protect custom_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
    CUSTOM_SET_SIZE="${CUSTOM_SET_SIZE:-0}"

    # v3.20.0+: mobile-RU и broadband-RU stats УБРАНЫ (whitelist'ы удалены)

    # Когда nft started — для "stats since"
    # v3.23.1: читаем shieldnode-nftables.service вместо nftables.service.
    # Последний masked в установщике (стр 1000) → ActiveEnterTimestamp пуст →
    # NFT_SINCE всегда был "—" после первого ребута.
    NFT_SINCE=$(systemctl show shieldnode-nftables.service --property=ActiveEnterTimestamp --value 2>/dev/null | \
        xargs -I{} env LC_ALL=C date -d {} '+%Y-%m-%d %H:%M' 2>/dev/null)
    NFT_SINCE="${NFT_SINCE:-—}"

    # v2.9: All-time stats из /var/lib/shieldnode/events.db
    SHIELD_DB="/var/lib/shieldnode/events.db"
    ALLTIME_SCANNERS=0
    ALLTIME_DDOS=0
    ALLTIME_SCANNER_PKTS=0
    ALLTIME_DDOS_PKTS=0
    DB_SINCE="—"

    if [ -r "$SHIELD_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        ALLTIME_SCANNERS=$(sqlite3 "$SHIELD_DB" "SELECT COUNT(*) FROM events WHERE type='scanner'" 2>/dev/null)
        ALLTIME_DDOS=$(sqlite3 "$SHIELD_DB" "SELECT COUNT(*) FROM events WHERE type='ddos'" 2>/dev/null)
        ALLTIME_SCANNER_PKTS=$(sqlite3 "$SHIELD_DB" "SELECT COALESCE(SUM(count), 0) FROM events WHERE type='scanner'" 2>/dev/null)
        ALLTIME_DDOS_PKTS=$(sqlite3 "$SHIELD_DB" "SELECT COALESCE(SUM(count), 0) FROM events WHERE type='ddos'" 2>/dev/null)
        ALLTIME_SCANNERS="${ALLTIME_SCANNERS:-0}"
        ALLTIME_DDOS="${ALLTIME_DDOS:-0}"
        ALLTIME_SCANNER_PKTS="${ALLTIME_SCANNER_PKTS:-0}"
        ALLTIME_DDOS_PKTS="${ALLTIME_DDOS_PKTS:-0}"

        # Самое раннее событие — "since"
        FIRST_TS=$(sqlite3 "$SHIELD_DB" "SELECT MIN(first_seen) FROM events" 2>/dev/null)
        # v3.28.6: событий ещё нет (пустая БД) → since = время создания БД (старт
        # трекинга), а не прочерк. Раньше показывало "since —" — путало.
        if [ -z "$FIRST_TS" ]; then
            FIRST_TS=$(stat -c %W "$SHIELD_DB" 2>/dev/null)
            { [ -z "$FIRST_TS" ] || [ "$FIRST_TS" = "0" ]; } && \
                FIRST_TS=$(stat -c %Y "$SHIELD_DB" 2>/dev/null || stat -f %m "$SHIELD_DB" 2>/dev/null)
        fi
        if [ -n "$FIRST_TS" ] && [ "$FIRST_TS" != "" ]; then
            DB_SINCE=$(LC_ALL=C date -d "@$FIRST_TS" '+%Y-%m-%d %H:%M' 2>/dev/null || LC_ALL=C date -r "$FIRST_TS" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "—")
        fi
    fi

    # CrowdSec all-time bans (за всю историю в crowdsec.db)
    CS_ALLTIME_BANS=0
    if [ -r "$CS_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        # Считаем уникальные IP которые когда-либо были забанены
        CS_ALLTIME_BANS=$(sqlite3 "$CS_DB" "SELECT COUNT(DISTINCT value) FROM decisions WHERE type='ban'" 2>/dev/null)
        CS_ALLTIME_BANS="${CS_ALLTIME_BANS:-0}"
    fi
}

# v2.7: human-readable bytes formatter (1234567 → 1.18M)
human_bytes() {
    local b="${1:-0}"
    awk -v b="$b" 'BEGIN {
        if (b < 1024) printf "%dB", b
        else if (b < 1048576) printf "%.1fK", b/1024
        else if (b < 1073741824) printf "%.1fM", b/1048576
        else if (b < 1099511627776) printf "%.1fG", b/1073741824
        else printf "%.1fT", b/1099511627776
    }'
}

# v2.7: human-readable numbers (1234567 → 1,234,567)
human_num() {
    printf "%'d" "${1:-0}" 2>/dev/null || echo "${1:-0}"
}

# v3.12.0: ASN/owner lookup для top attackers. v3.27.2: через Team Cymru whois.
# Кэш в events.db (asn_cache table), TTL 7 дней.
# При no-internet или rate-limit возвращает "?" — guard продолжает работать.
asn_ttl=604800   # 7 дней

asn_cache_get() {
    # echoes "asn|owner|country" if cached and fresh; empty otherwise
    local ip="$1" db="/var/lib/shieldnode/events.db"
    [ -r "$db" ] || return 1
    command -v sqlite3 >/dev/null 2>&1 || return 1
    local now; now=$(date +%s)
    # v3.18.11 SH-NEW-106: SQL escape ip — защита от rogue logger-пакетов в journal
    local esc_ip="${ip//\'/\'\'}"
    sqlite3 "$db" "SELECT asn || '|' || COALESCE(owner,'') || '|' || COALESCE(country,'') FROM asn_cache WHERE ip = '$esc_ip' AND cached_at + $asn_ttl > $now LIMIT 1" 2>/dev/null
}

asn_cache_put() {
    local ip="$1" asn="$2" owner="$3" country="$4" db="/var/lib/shieldnode/events.db"
    [ -w "$db" ] || return 1
    command -v sqlite3 >/dev/null 2>&1 || return 1
    local now; now=$(date +%s)
    # SQL-escape одинарных кавычек (v3.18.11 SH-NEW-106: ip также)
    local esc_ip esc_asn esc_owner esc_country
    esc_ip="${ip//\'/\'\'}"
    esc_asn=$(echo "$asn"     | sed "s/'/''/g")
    esc_owner=$(echo "$owner" | sed "s/'/''/g")
    esc_country=$(echo "$country" | sed "s/'/''/g")
    sqlite3 "$db" "INSERT INTO asn_cache(ip, asn, owner, country, cached_at) VALUES('$esc_ip','$esc_asn','$esc_owner','$esc_country',$now) ON CONFLICT(ip) DO UPDATE SET asn='$esc_asn', owner='$esc_owner', country='$esc_country', cached_at=$now" 2>/dev/null
}

asn_lookup_remote() {
    # v3.27.2 FIX(#3): ipinfo.io (legacy free API) заменён на Team Cymru whois.
    # Причина: ipinfo legacy без токена = 1000 req/день ОБЩИЕ на исходящий IP +
    # deprecation-путь + утечка IP атакующих коммерческому geoIP. Team Cymru: без
    # ключа, поддерживается, отдаёт ASN+owner одним запросом, стандарт в netsec.
    # Нужен пакет 'whois' (best-effort ставится; нет → "?" в дашборде, не лагает).
    local ip="$1"
    if [ -n "${SHIELDNODE_ASN_OFFLINE:-}" ]; then
        return 1
    fi
    command -v whois >/dev/null 2>&1 || { export SHIELDNODE_ASN_OFFLINE=1; return 1; }
    local resp
    # timeout-обёртка: whois может зависнуть; 2с — запас для RU→Cymru.
    resp=$(timeout 2 whois -h whois.cymru.com " -v $ip" 2>/dev/null)
    if [ -z "$resp" ]; then
        export SHIELDNODE_ASN_OFFLINE=1
        return 1
    fi
    # Формат Cymru -v (pipe-delimited): AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    # Берём строку, где первое поле — чистое число (данные, не заголовок/NA).
    echo "$resp" | awk -F'|' '
        { for (i=1;i<=NF;i++){ gsub(/^[ \t]+|[ \t]+$/,"",$i) } }
        $1 ~ /^[0-9]+$/ { printf "AS%s|%s|%s\n", $1, ($7==""?"?":$7), ($4==""?"?":$4); exit }'
}

# Lookup IP → "owner (country)" string (для отображения).
# Использует кэш + если miss/expired → один lookup через Team Cymru whois.
asn_owner_string() {
    local ip="$1"
    local cached; cached=$(asn_cache_get "$ip")
    if [ -n "$cached" ]; then
        local owner country
        IFS='|' read -r _asn owner country <<< "$cached"
        if [ -n "$owner" ] && [ "$owner" != "?" ]; then
            echo "${owner} (${country})"
        else
            echo "?"
        fi
        return 0
    fi
    # Cache miss
    local fresh; fresh=$(asn_lookup_remote "$ip" 2>/dev/null)
    if [ -n "$fresh" ]; then
        local asn owner country
        IFS='|' read -r asn owner country <<< "$fresh"
        asn_cache_put "$ip" "$asn" "$owner" "$country"
        if [ -n "$owner" ] && [ "$owner" != "?" ]; then
            echo "${owner} (${country})"
        else
            echo "?"
        fi
        return 0
    fi
    echo "?"
}

# Top-N attackers из events.db за последние 24 часа.
# Печатает строки "ip<TAB>hits" (наибольшие сверху).
top_attackers_24h() {
    local n="${1:-20}" db="/var/lib/shieldnode/events.db"
    [ -r "$db" ] || return 1
    command -v sqlite3 >/dev/null 2>&1 || return 1
    local since=$(( $(date +%s) - 86400 ))
    sqlite3 -separator $'\t' "$db" \
        "SELECT ip, SUM(count) as hits FROM events WHERE last_seen >= $since GROUP BY ip ORDER BY hits DESC LIMIT $n" 2>/dev/null
}

# === ВЫВОД ===
draw_snapshot() {
    local now=$(date '+%Y-%m-%d %H:%M:%S')
    local ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    local hn=$(hostname -s 2>/dev/null)
    local uptime_str
    uptime_str=$(uptime -p 2>/dev/null | sed 's/^up //')

    # ===== HEADER (v3.12.0) =====
    echo ""
    echo -e "${C}══════════════════════════════════════════════════════════════════${N}"
    printf  "  ${B}shieldnode v${SHIELDNODE_VERSION}${N}   %s   ${DIM}up %s${N}\n" "$hn ($ip)" "${uptime_str:-?}"
    echo -e "${C}══════════════════════════════════════════════════════════════════${N}"

    # v3.14.0: upgrade banner (если version-check нашёл новую версию)
    if [ -r /var/lib/shieldnode/.upstream_version ]; then
        UPGRADE_AVAIL=$(grep '^upgrade_available=' /var/lib/shieldnode/.upstream_version 2>/dev/null | cut -d= -f2)
        UPSTREAM_VER=$(grep '^upstream=' /var/lib/shieldnode/.upstream_version 2>/dev/null | cut -d= -f2)
        if [ "$UPGRADE_AVAIL" = "1" ] && [ -n "$UPSTREAM_VER" ]; then
            echo -e "  ${Y}▲${N} ${B}upgrade available:${N} ${G}v$UPSTREAM_VER${N} — run ${C}sudo guard upgrade${N}"
        fi
    fi
    echo ""

    # ===== ACTIVE THREATS (right now) =====
    local active_color="${G}"
    [ "$((CS_BANS + CONFIRMED_COUNT))" -gt 0 ] && active_color="${R}"
    echo -e "  ${B}Active threats (right now)${N}"
    printf  "  ├─ ${active_color}confirmed attack${N}    %s IP banned 15min\n"          "$(human_num "$CONFIRMED_COUNT")"
    printf  "  ├─ ${active_color}suspect (watched)${N}   %s IP under 30min observation\n" "$(human_num "$SUSPECT_COUNT")"
    printf  "  ├─ ${active_color}crowdsec bans${N}       %s IPs\n"                       "$(human_num "$CS_BANS")"
    local bl_summary="scanner=$(human_num "$BL_V4")"
    [ "$THREAT_SET_SIZE" -gt 0 ] && bl_summary+=", threat=$(human_num "$THREAT_SET_SIZE")"
    [ "$TOR_SET_SIZE"    -gt 0 ] && bl_summary+=", tor=$(human_num "$TOR_SET_SIZE")"
    bl_summary+=", custom=$(human_num "$CUSTOM_SET_SIZE")"   # v3.23.18: всегда видно (даже 0)
    # v3.27.0 FIX(#7): суммарный v6-blocklist (если фиды отдали v6)
    BL_V6_TOTAL=0
    for s in scanner_blocklist_v6 threat_blocklist_v6 custom_blocklist_v6 tor_exit_blocklist_v6; do
        _n=$(nft list set inet ddos_protect "$s" 2>/dev/null | tr '\n' ' ' | grep -oiE '([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(/[0-9]+)?' | grep -c ':')
        BL_V6_TOTAL=$(( BL_V6_TOTAL + ${_n:-0} ))
    done
    [ "$BL_V6_TOTAL" -gt 0 ] 2>/dev/null && bl_summary+=", ${C}v6=$(human_num "$BL_V6_TOTAL")${N}"
    # v3.28.2 FIX: %b (не %s) — bl_summary содержит ${C}/${N} (=\033[..]); в %s-аргументе
    # printf escape НЕ интерпретирует → раньше печатался сырой "\033[0;36m" вокруг v6.
    printf  "  └─ ${DIM}blocklists${N}          %b\n" "$bl_summary"
    # v3.20.0+: mobile-RU и broadband-RU whitelist строки УБРАНЫ (whitelist'ы удалены)
    echo ""

    # ===== SERVICES (compact one-line) =====
    local svc_line=""
    svc_line+=$(svc_dot "$CS_ACTIVE" "crowdsec")"  "
    svc_line+=$(svc_dot "$BOUNCER_ACTIVE" "bouncer")"  "
    svc_line+=$(svc_dot "$PORTS_PATH_ACTIVE" "ports")
    echo -e "  ${B}Services${N}    $svc_line"
    echo ""

    # ===== CONNTRACK PRESSURE (v3.24.0) =====
    local ct_cnt ct_max ct_pct ct_color="${G}"
    ct_cnt=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
    ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
    if [ "${ct_max:-0}" -gt 0 ] 2>/dev/null; then
        ct_pct=$(( ct_cnt * 100 / ct_max ))
        [ "$ct_pct" -ge 80 ] && ct_color="${Y}"
        [ "$ct_pct" -ge 90 ] && ct_color="${R}"
        printf "  ${B}Conntrack${N}   ${ct_color}%s%%${N} ${DIM}(%s / %s)${N}" "$ct_pct" "$(human_num "$ct_cnt")" "$(human_num "$ct_max")"
        if [ -s /run/shieldnode/ctguard.evicted ]; then
            printf "   ${R}ctguard: %s IP evicted${N}" "$(wc -l < /run/shieldnode/ctguard.evicted 2>/dev/null || echo 0)"
        fi
        echo ""
        echo ""
    fi

    # ===== CTGUARD REAL DROPS (v3.26.1) =====
    # Новый ctguard-слой дропает в СВОЕЙ таблице shield_ctguard — guard раньше
    # читал счётчики только из ddos_protect, поэтому фантом-эвикт/кап не были видны.
    if nft list table inet shield_ctguard >/dev/null 2>&1; then
        local ctg_mode ctg_phr ctg_evd ctg_capd ctg_col="${G}"
        ctg_mode=$(cat /run/shieldnode/ctguard.mode 2>/dev/null || echo normal)
        ctg_phr=$(cat /run/shieldnode/ctguard.phr 2>/dev/null || echo 0)
        ctg_evd=$(nft list counter inet shield_ctguard ctguard_drops 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | head -1); ctg_evd="${ctg_evd:-0}"
        ctg_capd=$(nft list counter inet shield_ctguard ctguard_capdrop 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | head -1); ctg_capd="${ctg_capd:-0}"
        [ "$ctg_mode" = "attack" ] && ctg_col="${R}"
        printf "  ${B}ctguard${N}     ${ctg_col}%s${N} ${DIM}phantom-ratio${N} %s%%   ${DIM}phantom-evict${N} %s ${DIM}pkts${N}   ${DIM}cap${N} %s ${DIM}pkts${N}\n" \
            "$ctg_mode" "$ctg_phr" "$(human_num "$ctg_evd")" "$(human_num "$ctg_capd")"
    fi
    # ===== SYNPROXY (v3.26.1) =====
    if nft list table inet shield_synproxy >/dev/null 2>&1; then
        printf "  ${B}synproxy${N}    ${G}active${N} ${DIM}(SYN перехват до conntrack)${N}\n"
    elif [ -f /var/lib/shieldnode/.synproxy-degraded ]; then
        # v3.27.0 FIX(#5): не молчим о деградации
        printf "  ${B}synproxy${N}    ${R}DEGRADED${N} ${DIM}(не включился — SYN-защита ослаблена; %s)${N}\n" "$(grep -m1 '^reason=' /var/lib/shieldnode/.synproxy-degraded 2>/dev/null | cut -d= -f2)"
        # v3.28.5: kernel-aware подсказка. Раньше печаталось буквально "$(uname -r)"
        # (экранированный $) + совет "apt install linux-modules-extra" неверен для XanMod,
        # где nf_synproxy встроен в ядро и такого пакета не существует.
        _kr="$(uname -r)"
        if printf '%s' "$_kr" | grep -qi xanmod; then
            printf "             ${DIM}fix: на XanMod nf_synproxy встроен — пакет не нужен. Запусти${N}\n"
            printf "             ${DIM}     shieldnode-synproxy.sh on  и смотри причину (dmesg | grep -i synproxy)${N}\n"
        else
            printf "             ${DIM}fix: apt install linux-modules-extra-%s && shieldnode-synproxy.sh on${N}\n" "$_kr"
        fi
    fi

    # ===== v3.27.0 FIX(#10): BRIDGE/WHITELIST DRIFT ADVISORY (read-only, O(1) на IP) =====
    # TRUSTED_IPS из conf, которых НЕТ в живом nft manual_whitelist_v4 → их трафик
    # пойдёт через conn_flood/rate-лимиты. Для bridge/upstream-ноды (агрегирует всех
    # клиентов с одного IP) это = риск бана и аутажа downstream. Подсказываем, не чиним.
    if [ -r /etc/shieldnode/shieldnode.conf ] && nft list set inet ddos_protect manual_whitelist_v4 >/dev/null 2>&1; then
        _ti=$(grep -E '^TRUSTED_IPS=' /etc/shieldnode/shieldnode.conf 2>/dev/null | head -1 | sed -E 's/^TRUSTED_IPS="?([^"]*)"?.*/\1/')
        _miss=""
        IFS=',' read -ra _arr <<< "$_ti"
        for _ip in "${_arr[@]}"; do
            _ip=$(echo "$_ip" | tr -d ' '); [ -z "$_ip" ] && continue
            case "$_ip" in */*) continue ;; esac   # CIDR живёт в whitelist-local, не в single-set
            nft get element inet ddos_protect manual_whitelist_v4 "{ $_ip }" >/dev/null 2>&1 || _miss="${_miss:+$_miss }$_ip"
        done
        if [ -n "$_miss" ]; then
            printf "  ${Y}⚠ whitelist drift${N} ${DIM}TRUSTED_IPS не в nft manual_whitelist_v4:${N} ${Y}%s${N}\n" "$_miss"
            printf "             ${DIM}их трафик идёт через лимиты — мост/upstream рискует баном. Проверь UFW 'ALLOW from' / whitelist-local.txt${N}\n"
        fi
    fi

    # ===== v3.28.0: REMNAWAVE FLEET-SYNC STATUS =====
    if [ -f /etc/shieldnode/remnawave.env ]; then
        _rwn4=$(nft list set inet ddos_protect remnawave_nodes_v4 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l)
        _rwn6=$(nft list set inet ddos_protect remnawave_nodes_v6 2>/dev/null | tr ',' '\n' | grep -ciE '[0-9a-f]*:[0-9a-f:]+')
        _rwts=$(grep -m1 -oE 'updated [0-9T:-]+Z' /var/lib/shieldnode/remnawave-nodes.list 2>/dev/null | sed 's/updated //')
        if systemctl is-active --quiet shieldnode-remnawave-sync.timer 2>/dev/null; then
            printf "  ${B}fleet-sync${N}  ${G}active${N} ${DIM}(ноды Remnawave → whitelist: %s v4 + %s v6%s)${N}\n" "${_rwn4:-0}" "${_rwn6:-0}" "${_rwts:+, last $_rwts}"
        else
            printf "  ${B}fleet-sync${N}  ${Y}настроен, таймер не активен${N} ${DIM}(systemctl enable --now shieldnode-remnawave-sync.timer)${N}\n"
        fi
    fi

    # ===== PROTECTED PORTS =====
    echo -e "  ${B}Protected${N}"
    printf  "  ├─ ${DIM}TCP:${N}  ${C}%s${N}\n" "$PROTECTED_TCP_LIST"
    printf  "  └─ ${DIM}UDP:${N}  ${C}%s${N}\n" "$PROTECTED_UDP_LIST"
    echo ""

    # ===== TOP ATTACKERS (v3.12.0, last 24h, with ASN/owner) =====
    local top_lines
    top_lines=$(top_attackers_24h 5)
    if [ -n "$top_lines" ]; then
        echo -e "  ${B}Top attackers${N} ${DIM}(last 24h)${N}"
        local fmtd=""
        local lcount=0
        while IFS=$'\t' read -r ip hits; do
            [ -z "$ip" ] && continue
            lcount=$((lcount+1))
            local owner; owner=$(asn_owner_string "$ip")
            local prefix="├─"
            fmtd+=$(printf "  %s ${R}%-15s${N} ${DIM}%5s hits${N}   %s\n" "$prefix" "$ip" "$(human_num "$hits")" "$owner")
            fmtd+=$'\n'
        done <<< "$top_lines"
        # Меняем последний ├─ на └─
        if [ -n "$fmtd" ]; then
            fmtd=$(echo -e "$fmtd" | sed -E '$ s/├─/└─/' )
            echo -e "$fmtd"
        fi
        echo ""
    fi

    # ===== TODAY (drops / bytes) =====
    local total_pkts=$((SCANNER_PKTS_V4 + TOR_PKTS_V4 + THREAT_PKTS_V4 + CUSTOM_PKTS_V4 + CONFIRMED_PKTS_V4 + SYN_CONF_PKTS_V4 + UDP_CONF_PKTS_V4 + CONN_FLOOD_PKTS_V4 + NEWCONN_FLOOD_PKTS_V4 + TCP_INVALID_PKTS + SSH_CONN_FLOOD_PKTS_V4 + SSH_NEWCONN_FLOOD_PKTS_V4 + ${CTG_EVICT_PKTS:-0} + ${CTG_CAP_PKTS:-0}))
    local total_bytes=$((SCANNER_BYTES_V4 + TOR_BYTES_V4 + THREAT_BYTES_V4 + CUSTOM_BYTES_V4 + CONFIRMED_BYTES_V4 + SYN_CONF_BYTES_V4 + UDP_CONF_BYTES_V4 + CONN_FLOOD_BYTES_V4 + NEWCONN_FLOOD_BYTES_V4 + TCP_INVALID_BYTES + SSH_CONN_FLOOD_BYTES_V4 + SSH_NEWCONN_FLOOD_BYTES_V4))

    echo -e "  ${B}Drops since reboot${N} ${DIM}($NFT_SINCE)${N}"
    printf  "  ├─ ${DIM}scanner${N}             %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$SCANNER_PKTS_V4")" "$(human_bytes "$SCANNER_BYTES_V4")"
    if [ "$THREAT_SET_SIZE" -gt 0 ] || [ "$THREAT_PKTS_V4" -gt 0 ]; then
        printf  "  ├─ ${DIM}threat${N}              %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$THREAT_PKTS_V4")" "$(human_bytes "$THREAT_BYTES_V4")"
    fi
    if [ "$CUSTOM_SET_SIZE" -gt 0 ] || [ "$CUSTOM_PKTS_V4" -gt 0 ]; then
        printf  "  ├─ ${DIM}custom${N}              %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$CUSTOM_PKTS_V4")" "$(human_bytes "$CUSTOM_BYTES_V4")"
    fi
    if [ "$TOR_SET_SIZE" -gt 0 ] || [ "$TOR_PKTS_V4" -gt 0 ]; then
        printf  "  ├─ ${DIM}tor exit${N}            %12s pkts  ${DIM}/${N} %s\n" "$(human_num "$TOR_PKTS_V4")" "$(human_bytes "$TOR_BYTES_V4")"
    fi
    printf  "  ├─ ${DIM}confirmed-attack${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$CONFIRMED_PKTS_V4")" "$(human_bytes "$CONFIRMED_BYTES_V4")"
    printf  "  ├─ ${DIM}rate-limit (syn)${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$SYN_CONF_PKTS_V4")" "$(human_bytes "$SYN_CONF_BYTES_V4")"
    printf  "  ├─ ${DIM}rate-limit (udp)${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$UDP_CONF_PKTS_V4")" "$(human_bytes "$UDP_CONF_BYTES_V4")"
    printf  "  ├─ ${DIM}conn-flood (ct>15000)${N} %10s pkts  ${DIM}/${N} %s\n"   "$(human_num "$CONN_FLOOD_PKTS_V4")" "$(human_bytes "$CONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}new-conn flood${N}      %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$NEWCONN_FLOOD_PKTS_V4")" "$(human_bytes "$NEWCONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}ssh conn-flood${N}      %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$SSH_CONN_FLOOD_PKTS_V4")" "$(human_bytes "$SSH_CONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}ssh new-conn flood${N}  %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$SSH_NEWCONN_FLOOD_PKTS_V4")" "$(human_bytes "$SSH_NEWCONN_FLOOD_BYTES_V4")"
    printf  "  ├─ ${DIM}TCP flag invalid${N}    %12s pkts  ${DIM}/${N} %s\n"   "$(human_num "$TCP_INVALID_PKTS")" "$(human_bytes "$TCP_INVALID_BYTES")"
    if nft list table inet shield_ctguard >/dev/null 2>&1; then
        printf  "  ├─ ${DIM}ctguard phantom-evict${N} %10s pkts\n" "$(human_num "${CTG_EVICT_PKTS:-0}")"
        printf  "  ├─ ${DIM}ctguard cap${N}         %12s pkts\n"   "$(human_num "${CTG_CAP_PKTS:-0}")"
    fi
    printf  "  └─ ${B}total${N}               ${B}%12s${N} pkts  ${DIM}/${N} ${B}%s${N}\n" "$(human_num "$total_pkts")" "$(human_bytes "$total_bytes")"
    echo ""

    # ===== ALL-TIME (persistent) =====
    echo -e "  ${B}All-time history${N} ${DIM}(since $DB_SINCE)${N}"
    printf  "  ├─ ${M}scanners blocked:${N}    %12s unique IPs ${DIM}(%s hits)${N}\n" "$(human_num "$ALLTIME_SCANNERS")"   "$(human_num "$ALLTIME_SCANNER_PKTS")"
    printf  "  ├─ ${M}ddos blocked:${N}        %12s unique IPs ${DIM}(%s hits)${N}\n" "$(human_num "$ALLTIME_DDOS")"       "$(human_num "$ALLTIME_DDOS_PKTS")"
    printf  "  └─ ${M}ssh brute attempts:${N}  %12s unique IPs ${DIM}(crowdsec)${N}\n" "$(human_num "$CS_ALLTIME_BANS")"
    echo ""

    # v3.15.1: блок "Recent events (last 5)" убран — дублировал [9] view full log

    printf "  ${DIM}Blocklist updated: %s${N}\n" "$LAST_UPDATE"
}

# Helper: status dot для compact services line
svc_dot() {
    local status="$1"
    local label="$2"
    case "$status" in
        active)        echo -e "${G}●${N} ${DIM}${label}${N}" ;;
        inactive)      echo -e "${Y}●${N} ${DIM}${label}${N}" ;;
        failed)        echo -e "${R}●${N} ${DIM}${label}${N}" ;;
        activating)    echo -e "${Y}◐${N} ${DIM}${label}${N}" ;;
        *)             echo -e "${Y}?${N} ${DIM}${label}${N}" ;;
    esac
}

# === Просмотр списков ===
show_crowdsec_bans() {
    echo ""
    echo -e "${B}CrowdSec banned IPs${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    if command -v cscli >/dev/null 2>&1; then
        cscli decisions list --type ban 2>/dev/null | head -50
    fi
    echo ""
}

show_whitelist_ips() {
    local WL_FILE="/etc/shieldnode/lists/whitelist-local.txt"

    while true; do
        clear 2>/dev/null
        echo ""
        echo -e "${B}═══ Whitelist Management ═══${N}"
        echo ""
        echo -e "${DIM}Whitelist file: $WL_FILE${N}"
        echo -e "${DIM}IPs пропускаются МИМО всех проверок (rate-limit, blocklists, conn-flood).${N}"
        echo -e "${DIM}Изменения применяются за 1-2 секунды через path-watcher.${N}"
        echo ""

        # Auto whitelist (SSH-keys из CrowdSec)
        echo -e "${B}Auto whitelist (CrowdSec SSH-key)${N}"
        echo -e "${DIM}─────────────────────────────────${N}"
        if command -v cscli >/dev/null 2>&1; then
            local cs_count
            cs_count=$(cscli decisions list --type whitelist 2>/dev/null | grep -cE '^\| [0-9]')
            if [ "$cs_count" -gt 0 ]; then
                cscli decisions list --type whitelist 2>/dev/null | head -10
            else
                echo -e "  ${DIM}(пусто)${N}"
            fi
        fi
        echo ""

        # Manual whitelist (nftables active)
        echo -e "${B}Active whitelist (nft manual_whitelist_v4)${N}"
        echo -e "${DIM}─────────────────────────────────${N}"
        local active_ips
        active_ips=$(nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
            tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | \
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | sort -u)
        if [ -n "$active_ips" ]; then
            echo "$active_ips" | sed 's/^/  /'
            echo ""
            echo -e "  ${DIM}Total: $(echo "$active_ips" | wc -l) IPs${N}"
        else
            echo -e "  ${DIM}(пусто)${N}"
        fi
        echo ""

        # Действия
        echo -e "${C}┌─────────────────────────────────────────────────────────────────┐${N}"
        echo -e "${C}│${N}  ${B}Whitelist actions${N}                                              ${C}│${N}"
        echo -e "${C}├─────────────────────────────────────────────────────────────────┤${N}"
        echo -e "${C}│${N}  [${B}a${N}] Add IP to whitelist                                        ${C}│${N}"
        echo -e "${C}│${N}  [${B}d${N}] Delete IP from whitelist                                   ${C}│${N}"
        echo -e "${C}│${N}  [${B}l${N}] List file content                                          ${C}│${N}"
        echo -e "${C}│${N}  [${B}f${N}] Force re-sync (apply file → nft)                           ${C}│${N}"
        echo -e "${C}├─────────────────────────────────────────────────────────────────┤${N}"
        echo -e "${C}│${N}  [${B}b${N}] Back to main menu                                          ${C}│${N}"
        echo -e "${C}└─────────────────────────────────────────────────────────────────┘${N}"
        echo -ne "  ${B}>${N} "
        read -r WL_ACTION

        case "$WL_ACTION" in
            a|A)
                echo ""
                echo -ne "  Enter IP or CIDR to whitelist (e.g. 1.2.3.4 or 10.0.0.0/24): "
                read -r NEW_IP
                # Валидация
                # v3.18.11 SH-NEW-10: явно отклоняем 0.0.0.0/x (whitelist всего интернета)
                #                     и multicast/broadcast.
                if ! echo "$NEW_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
                    echo -e "  ${Y}Invalid format. Expected: 1.2.3.4 or 10.0.0.0/24${N}"
                elif echo "$NEW_IP" | grep -qE '^(0\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.|255\.255\.255\.255)'; then
                    echo -e "  ${R}Refused:${N} $NEW_IP (0.0.0.0/x, multicast и broadcast не разрешены)"
                else
                    # Проверяем дубликат
                    if grep -qxF "$NEW_IP" "$WL_FILE" 2>/dev/null; then
                        echo -e "  ${Y}$NEW_IP уже в whitelist${N}"
                    else
                        echo "$NEW_IP" >> "$WL_FILE"
                        echo -e "  ${G}✓${N} $NEW_IP добавлен. Применяется..."
                        # v3.21.2: явно триггерим updater вместо ожидания path-watcher'а
                        # (path-watcher может отставать на debounce-окно и юзеру
                        # приходилось вручную нажимать [f] Force re-sync).
                        /usr/local/sbin/update-protected-ports.sh >/dev/null 2>&1 || true
                        sleep 1
                        if nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
                            tr ',' '\n' | grep -qE "(^|[ {])$(echo "$NEW_IP" | sed 's/\./\\./g')([ },]|$)"; then
                            echo -e "  ${G}✓${N} $NEW_IP активен в nft"
                        else
                            echo -e "  ${Y}!${N} Не применилось — попробуй [f] Force re-sync"
                        fi
                    fi
                fi
                echo -ne "  ${DIM}Press Enter...${N}"
                read -r _
                ;;
            d|D)
                echo ""
                echo -ne "  Enter IP or CIDR to remove from whitelist: "
                read -r DEL_IP
                if [ -z "$DEL_IP" ]; then
                    echo -e "  ${Y}Empty input${N}"
                elif ! grep -qxF "$DEL_IP" "$WL_FILE" 2>/dev/null; then
                    echo -e "  ${Y}$DEL_IP не найден в whitelist file${N}"
                else
                    # Escape для sed (точки, слэши)
                    local DEL_ESC
                    DEL_ESC=$(echo "$DEL_IP" | sed 's/[.\/]/\\&/g')
                    sed -i "/^${DEL_ESC}$/d" "$WL_FILE"
                    echo -e "  ${G}✓${N} $DEL_IP удалён из файла. Применяется..."
                    # v3.21.2: явно триггерим updater (см. add-ветку выше)
                    /usr/local/sbin/update-protected-ports.sh >/dev/null 2>&1 || true
                    sleep 1
                    if ! nft list set inet ddos_protect manual_whitelist_v4 2>/dev/null | \
                        tr ',' '\n' | grep -qE "(^|[ {])$(echo "$DEL_IP" | sed 's/\./\\./g')([ },]|$)"; then
                        echo -e "  ${G}✓${N} $DEL_IP убран из nft"
                    else
                        echo -e "  ${Y}!${N} Не применилось — попробуй [f] Force re-sync"
                    fi
                fi
                echo -ne "  ${DIM}Press Enter...${N}"
                read -r _
                ;;
            l|L)
                echo ""
                echo -e "${B}File: $WL_FILE${N}"
                echo -e "${DIM}─────────────────────────────────${N}"
                if [ -r "$WL_FILE" ]; then
                    cat "$WL_FILE" | sed 's/^/  /'
                else
                    echo -e "  ${Y}File not found${N}"
                fi
                echo ""
                echo -ne "  ${DIM}Press Enter...${N}"
                read -r _
                ;;
            f|F)
                echo ""
                echo -e "  Force re-sync..."
                systemctl start shieldnode-whitelist.service 2>&1
                sleep 1
                echo -e "  ${G}✓${N} Re-sync done"
                journalctl -t shieldnode-whitelist -n 1 --no-pager 2>/dev/null | sed 's/^/  /'
                echo ""
                echo -ne "  ${DIM}Press Enter...${N}"
                read -r _
                ;;
            b|B|"")
                return
                ;;
            *)
                echo -e "  ${Y}Unknown: $WL_ACTION${N}"
                sleep 1
                ;;
        esac
    done
}

show_history() {
    echo ""
    local db="/var/lib/shieldnode/events.db"

    if [ ! -r "$db" ] || ! command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${Y}History DB not available${N}"
        echo -e "${DIM}Aggregator должен запуститься: sudo systemctl start shieldnode-aggregator.service${N}"
        echo ""
        return
    fi

    echo -e "${B}Recent blocked events${N} ${DIM}(last 30, from /var/lib/shieldnode/events.db)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    printf "  ${DIM}%-10s %-18s %-9s %s${N}\n" "TYPE" "IP" "HITS" "LAST SEEN"

    sqlite3 "$db" "
        SELECT type, ip, count, datetime(last_seen, 'unixepoch', 'localtime')
        FROM events
        ORDER BY last_seen DESC
        LIMIT 30
    " 2>/dev/null | while IFS='|' read -r type ip cnt ts; do
        case "$type" in
            scanner) color="${Y}" ;;
            ddos)    color="${R}" ;;
            *)       color="${N}" ;;
        esac
        printf "  ${color}%-10s${N} %-18s ${B}%-9s${N} ${DIM}%s${N}\n" "$type" "$ip" "$cnt" "$ts"
    done
    echo ""

    local total_scan total_ddos
    total_scan=$(sqlite3 "$db" "SELECT COUNT(*) FROM events WHERE type='scanner'" 2>/dev/null)
    total_ddos=$(sqlite3 "$db" "SELECT COUNT(*) FROM events WHERE type='ddos'" 2>/dev/null)
    printf "  Total in DB: ${Y}${B}%d${N} scanners, ${R}${B}%d${N} ddos\n" "${total_scan:-0}" "${total_ddos:-0}"
    echo ""
}

# v2.9: топ-атакующих из sqlite
show_top_attackers() {
    echo ""
    local db="/var/lib/shieldnode/events.db"

    if [ ! -r "$db" ] || ! command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${Y}History DB not available${N}"
        echo ""
        return
    fi

    echo -e "${B}Top-20 attackers (by hit count, all-time)${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    printf "  ${DIM}%-10s %-18s %-9s %s${N}\n" "TYPE" "IP" "HITS" "FIRST SEEN"

    sqlite3 "$db" "
        SELECT type, ip, count, datetime(first_seen, 'unixepoch', 'localtime')
        FROM events
        ORDER BY count DESC
        LIMIT 20
    " 2>/dev/null | while IFS='|' read -r type ip cnt ts; do
        case "$type" in
            scanner) color="${Y}" ;;
            ddos)    color="${R}" ;;
            *)       color="${N}" ;;
        esac
        printf "  ${color}%-10s${N} %-18s ${B}%-9s${N} ${DIM}%s${N}\n" "$type" "$ip" "$cnt" "$ts"
    done
    echo ""
    echo -e "  ${DIM}Tip: высокий hit-count → персистентный сканер/атакующий${N}"
    echo ""
}

# v3.9: разбан всех IP в suspect_v4 и confirmed_attack_v4 одной командой.
# Используется при ложных срабатываниях или при ручной коррекции.
unban_all() {
    echo ""
    local susp conf banned_ips
    susp=$(nft list set inet ddos_protect suspect_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    conf=$(nft list set inet ddos_protect confirmed_attack_v4 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    # v3.22.0: собираем уникальные IP из обоих set'ов для последующего
    # conntrack -D. Это критично для CGNAT FP: если юзер успел до бана
    # открыть 15000+ соединений (conntrack ESTABLISHED держит до 5 дней),
    # ct count over 15000 продолжает дропать его SYN'ы даже после
    # nft flush. conntrack -D -s сбрасывает существующие entries.
    banned_ips=$( (nft list set inet ddos_protect suspect_v4 2>/dev/null;
                   nft list set inet ddos_protect confirmed_attack_v4 2>/dev/null) | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
    echo -e "${B}Unban all confirmed attack + suspect${N}"
    echo -e "${DIM}─────────────────────────────────${N}"
    echo -e "  Сейчас в suspect:          ${Y}${susp}${N} IP"
    echo -e "  Сейчас в confirmed_attack: ${R}${conf}${N} IP"
    echo ""
    echo -ne "  ${B}Очистить оба set'а? [y/N]:${N} "
    read -r confirm
    case "$confirm" in
        y|Y|yes|YES)
            nft flush set inet ddos_protect suspect_v4 2>/dev/null
            nft flush set inet ddos_protect confirmed_attack_v4 2>/dev/null
            # v3.22.0: conntrack cleanup для разбаниваемых IP
            local ct_flushed=0
            if command -v conntrack >/dev/null 2>&1 && [ -n "$banned_ips" ]; then
                while IFS= read -r bip; do
                    [ -z "$bip" ] && continue
                    # -D = delete, -s = source IP. Tихий exit если 0 matches.
                    conntrack -D -s "$bip" >/dev/null 2>&1 && \
                        ct_flushed=$((ct_flushed + 1)) || true
                done <<< "$banned_ips"
            fi
            echo -e "  ${G}✓${N} Очищено: $susp suspect + $conf confirmed = $((susp + conf)) IP разбанены"
            if [ "$ct_flushed" -gt 0 ]; then
                echo -e "  ${G}✓${N} Conntrack entries сброшены для $ct_flushed IP (extreme-CGNAT defence)"
            elif ! command -v conntrack >/dev/null 2>&1; then
                echo -e "  ${Y}!${N} conntrack пакет не установлен — extreme-CGNAT юзеры могут остаться в ct count over 15000"
                echo -e "  ${DIM}Установи: sudo apt install -y conntrack${N}"
            fi
            ;;
        *)
            echo -e "  ${DIM}Отменено${N}"
            ;;
    esac
    echo ""
}


# v3.5: показать /var/log/shieldnode/events.log через less
_trusted_regen_postoverflow() {
    local csv="$1"
    local PO_DIR=/etc/crowdsec/postoverflows/s01-whitelist
    local PO_FILE="$PO_DIR/shieldnode-trusted.yaml"
    # Не трогаем foreign CrowdSec
    [ -f /etc/shieldnode/.crowdsec_managed ] || return 0
    command -v cscli >/dev/null 2>&1 || return 0
    mkdir -p "$PO_DIR"
    if [ -z "$csv" ]; then
        rm -f "$PO_FILE" 2>/dev/null
        systemctl reload crowdsec >/dev/null 2>&1
        return 0
    fi
    local TMP_FILE
    TMP_FILE=$(mktemp "${PO_FILE}.XXXXXX") || return 1
    {
        echo "# Auto-generated by guard (TRUSTED_IPS management)."
        echo "# Parser-level whitelist — scenarios не триггерят на этих IPs."
        echo "name: shieldnode/trusted-whitelist"
        echo "description: \"Whitelist trusted infrastructure IPs (TRUSTED_IPS)\""
        echo "whitelist:"
        echo "  reason: \"Trusted infrastructure (TRUSTED_IPS)\""
        # v3.23.1: разделяем single IPs и CIDR в две секции
        local ip _ips="" _cidrs=""
        IFS=',' read -ra _ARR <<< "$csv"
        for ip in "${_ARR[@]}"; do
            ip=$(echo "$ip" | tr -d ' ')
            [ -z "$ip" ] && continue
            if [[ "$ip" == */* ]]; then
                # Валидный CIDR: X.X.X.X/N
                echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' || continue
                _cidrs="$_cidrs $ip"
            else
                echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || continue
                _ips="$_ips $ip"
            fi
        done
        if [ -n "$_ips" ]; then
            echo "  ip:"
            for ip in $_ips; do
                echo "    - \"$ip\""
            done
        fi
        if [ -n "$_cidrs" ]; then
            echo "  cidr:"
            for cidr in $_cidrs; do
                echo "    - \"$cidr\""
            done
        fi
    } > "$TMP_FILE"
    chmod 0644 "$TMP_FILE"
    mv "$TMP_FILE" "$PO_FILE"
    systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1
}

# v3.14.0: settings menu — toggle ENABLE_* flags
# v3.18.8: убран MAXMIND_LICENSE_KEY (deprecated с v3.15.0)
show_settings_menu() {
    local CONF="/etc/shieldnode/shieldnode.conf"
    mkdir -p /etc/shieldnode
    [ -f "$CONF" ] || touch "$CONF"

    # Хелпер: читает текущее значение настройки (ищет в конфиге, fallback на default)
    _read_setting() {
        local key="$1" default="$2"
        local val
        val=$(grep -E "^${key}=" "$CONF" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' | tr -d "'")
        if [ -n "$val" ]; then
            echo "$val"
        else
            echo "$default"
        fi
    }

    # Хелпер: пишет/обновляет настройку в конфиге (idempotent)
    # v3.18.11 SH-NEW-125: используем awk вместо sed чтобы не сломать config'ом
    # с символом '|'. Также сохраняем perms через chmod --reference.
    _write_setting() {
        local key="$1" value="$2"
        local tmp="${CONF}.tmp.$$"
        if [ -f "$CONF" ] && grep -qE "^${key}=" "$CONF" 2>/dev/null; then
            awk -v k="$key" -v v="$value" '
                $0 ~ "^"k"=" { print k"=\""v"\""; next }
                { print }
            ' "$CONF" > "$tmp" && {
                chmod --reference="$CONF" "$tmp" 2>/dev/null || chmod 0640 "$tmp"
                mv "$tmp" "$CONF"
            }
        else
            echo "${key}=\"${value}\"" >> "$CONF"
        fi
    }

    while true; do
        clear 2>/dev/null
        local sync_state vc_state tor_state
        sync_state=$(_read_setting "ENABLE_GITHUB_SYNC" "1")
        vc_state=$(_read_setting "ENABLE_VERSION_CHECK" "1")
        tor_state=$(_read_setting "BLOCK_TOR" "0")

        # ON/OFF строки (зелёный для ON, серый для OFF)
        local s1 s2 s4
        [ "$sync_state"      = "1" ] && s1="${G}ON ${N}" || s1="${DIM}OFF${N}"
        [ "$vc_state"        = "1" ] && s2="${G}ON ${N}" || s2="${DIM}OFF${N}"
        [ "$tor_state"       = "1" ] && s4="${G}ON ${N}" || s4="${DIM}OFF${N}"

        # v3.20.0: mobile-RU и broadband-RU extra status строки УБРАНЫ
        # (whitelist'ы удалены — см. changelog).

        # v3.20.0: блоки расчёта mobile_extra/broadband_extra УБРАНЫ
        # вместе со whitelist'ами.

        echo ""
        echo -e "${C}══════════════════════════════════════════════════════════════════${N}"
        echo -e "  ${B}Settings${N}                                                       "
        echo -e "${C}══════════════════════════════════════════════════════════════════${N}"
        echo ""
        echo -e "  [${B}1${N}] Auto-sync github custom.txt    $s1  ${DIM}(every 6h)${N}"
        echo -e "  [${B}2${N}] Check for shieldnode updates  $s2  ${DIM}(every 1d)${N}"
        echo -e "  [${B}3${N}] Tor exit blocklist            $s4"
        echo ""
        echo -e "  ${DIM}Единый лимит ct=15000 для всех IP.${N}"
        echo ""
        echo ""
        # v3.18.8: Trusted IPs counter
        local trusted_count=0
        local trusted_csv
        trusted_csv=$(_read_setting "TRUSTED_IPS" "")
        if [ -n "$trusted_csv" ]; then
            trusted_count=$(echo "$trusted_csv" | tr ',' '\n' | grep -c '[0-9]')
        fi
        echo -e "  [${B}t${N}] Trusted IPs ${DIM}(infrastructure whitelist: ${trusted_count} IPs)${N}"
        echo ""
        echo -e "  [${B}q${N}] Back to main menu"
        echo ""
        echo -e "  ${DIM}Config: $CONF${N}"
        echo -ne "  ${B}>${N} "
        read -r SC

        case "$SC" in
            1)
                if [ "$sync_state" = "1" ]; then
                    _write_setting "ENABLE_GITHUB_SYNC" "0"
                    systemctl disable --now shieldnode-github-sync.timer >/dev/null 2>&1
                    echo -e "  ${G}✓${N} GitHub sync ${R}disabled${N}"
                else
                    _write_setting "ENABLE_GITHUB_SYNC" "1"
                    systemctl enable --now shieldnode-github-sync.timer >/dev/null 2>&1
                    echo -e "  ${G}✓${N} GitHub sync ${G}enabled${N}"
                fi
                sleep 1
                ;;
            2)
                if [ "$vc_state" = "1" ]; then
                    _write_setting "ENABLE_VERSION_CHECK" "0"
                    systemctl disable --now shieldnode-version-check.timer >/dev/null 2>&1
                    rm -f /var/lib/shieldnode/.upstream_version
                    echo -e "  ${G}✓${N} Version check ${R}disabled${N}"
                else
                    _write_setting "ENABLE_VERSION_CHECK" "1"
                    systemctl enable --now shieldnode-version-check.timer >/dev/null 2>&1
                    echo -e "  ${G}✓${N} Version check ${G}enabled${N}"
                fi
                sleep 1
                ;;
            3)
                if [ "$tor_state" = "1" ]; then
                    _write_setting "BLOCK_TOR" "0"
                    rm -f /etc/shieldnode/block_tor
                    nft flush set inet ddos_protect tor_exit_blocklist_v4 2>/dev/null
                    nft flush set inet ddos_protect tor_exit_blocklist_v6 2>/dev/null   # v3.27.0 FIX(#7): v6 parity
                    systemctl disable --now shieldnode-update@tor.timer >/dev/null 2>&1
                    echo -e "  ${G}✓${N} Tor blocklist ${R}disabled${N}"
                else
                    _write_setting "BLOCK_TOR" "1"
                    touch /etc/shieldnode/block_tor
                    systemctl enable --now shieldnode-update@tor.timer >/dev/null 2>&1
                    systemctl start shieldnode-update@tor.service >/dev/null 2>&1 &
                    echo -e "  ${G}✓${N} Tor blocklist ${G}enabled${N} (загрузка запущена)"
                fi
                sleep 1
                ;;
            t|T)
                # v3.18.8: Trusted IPs management — full whitelist (shieldnode + UFW + CrowdSec)
                while true; do
                    clear 2>/dev/null
                    local trusted_csv current_list
                    trusted_csv=$(_read_setting "TRUSTED_IPS" "")
                    echo ""
                    echo -e "${C}══════════════════════════════════════════════════════════════════${N}"
                    echo -e "  ${B}Trusted IPs${N} ${DIM}(infrastructure whitelist)${N}"
                    echo -e "${C}══════════════════════════════════════════════════════════════════${N}"
                    echo ""
                    echo -e "  Каждый IP получает ${B}полный whitelist${N}:"
                    echo -e "    • shieldnode rate-limit обходится"
                    echo -e "    • UFW allow from <ip> (любой порт)"
                    echo -e "    • CrowdSec whitelist на 1 год"
                    echo ""
                    echo -e "  ${B}Текущий список:${N}"
                    if [ -z "$trusted_csv" ]; then
                        echo -e "    ${DIM}(пусто)${N}"
                    else
                        local idx=1
                        IFS=',' read -ra TRUSTED_ARR <<< "$trusted_csv"
                        for ip in "${TRUSTED_ARR[@]}"; do
                            ip=$(echo "$ip" | tr -d ' ')
                            [ -z "$ip" ] && continue
                            echo -e "    ${idx}. ${G}$ip${N}"
                            idx=$((idx + 1))
                        done
                    fi
                    echo ""
                    echo -e "  [${B}a${N}] Add IP"
                    echo -e "  [${B}d${N}] Delete IP"
                    echo -e "  [${B}r${N}] Re-apply all (shieldnode + UFW + CrowdSec)"
                    echo -e "  [${B}q${N}] Back"
                    echo ""
                    echo -ne "  ${B}>${N} "
                    read -r TC
                    case "$TC" in
                        a|A)
                            echo -ne "  Enter IP or CIDR (e.g. 1.2.3.4 or 10.0.0.0/24): "
                            read -r NEW_IP
                            NEW_IP=$(echo "$NEW_IP" | tr -d ' ')
                            # v3.23.1: принимаем и single IP, и CIDR
                            local is_cidr_input=0
                            if ! echo "$NEW_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'; then
                                echo -e "  ${R}Невалидный IP/CIDR${N}"
                                sleep 1
                                continue
                            fi
                            [[ "$NEW_IP" == */* ]] && is_cidr_input=1
                            # Для CIDR проверяем prefix length
                            if [ "$is_cidr_input" = "1" ]; then
                                local prefix="${NEW_IP##*/}"
                                if [ "$prefix" -lt 8 ] || [ "$prefix" -gt 32 ]; then
                                    echo -e "  ${R}Refused:${N} prefix должен быть от /8 до /32"
                                    sleep 1
                                    continue
                                fi
                            fi
                            # v3.18.11 SH-NEW-10: отклоняем 0.0.0.0, multicast, broadcast
                            if echo "$NEW_IP" | grep -qE '^(0\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.|255\.255\.255\.255)'; then
                                echo -e "  ${R}Refused:${N} $NEW_IP (0.x, multicast и broadcast не разрешены)"
                                sleep 1
                                continue
                            fi
                            # Проверяем что не дубль (escape точки и слэш)
                            local NEW_RE="${NEW_IP//./\\.}"
                            NEW_RE="${NEW_RE//\//\\/}"
                            if echo ",$trusted_csv," | grep -qE ",[[:space:]]*${NEW_RE}[[:space:]]*,"; then
                                echo -e "  ${Y}Уже в списке${N}"
                                sleep 1
                                continue
                            fi
                            # Append в conf
                            local new_csv
                            if [ -z "$trusted_csv" ]; then
                                new_csv="$NEW_IP"
                            else
                                new_csv="$trusted_csv,$NEW_IP"
                            fi
                            _write_setting "TRUSTED_IPS" "$new_csv"
                            # Применяем сразу через все слои
                            echo ""
                            local WL=/etc/shieldnode/lists/whitelist-local.txt
                            mkdir -p "$(dirname "$WL")"
                            [ -f "$WL" ] || echo "# shieldnode trusted IPs" > "$WL"
                            grep -qxF "$NEW_IP" "$WL" 2>/dev/null || echo "$NEW_IP" >> "$WL"
                            echo -e "    ${G}✓${N} shieldnode whitelist"
                            if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
                                ufw allow from "$NEW_IP" comment "Trusted (TRUSTED_IPS)" >/dev/null 2>&1 || true
                                ufw reload >/dev/null 2>&1 || true
                                echo -e "    ${G}✓${N} UFW allow"
                            fi
                            if command -v cscli >/dev/null 2>&1; then
                                # v3.23.1: --range для CIDR, --ip для single
                                if [ "$is_cidr_input" = "1" ]; then
                                    cscli decisions add --range "$NEW_IP" --duration 8760h --type whitelist --reason "Trusted (TRUSTED_IPS)" >/dev/null 2>&1 || true
                                else
                                    cscli decisions add --ip "$NEW_IP" --duration 8760h --type whitelist --reason "Trusted (TRUSTED_IPS)" >/dev/null 2>&1 || true
                                fi
                                echo -e "    ${G}✓${N} CrowdSec whitelist (decision-level)"
                            fi
                            # Очистить старые events (только для single IPs — events.db хранит per-IP)
                            if [ "$is_cidr_input" = "0" ]; then
                                sqlite3 /var/lib/shieldnode/events.db "DELETE FROM events WHERE ip='$NEW_IP';" 2>/dev/null || true
                            fi
                            # v3.23.1: регенерируем postoverflow whitelist (parser-level)
                            _trusted_regen_postoverflow "$new_csv"
                            echo -e "    ${G}✓${N} CrowdSec postoverflow whitelist (parser-level)"
                            echo -e "  ${G}Done.${N}"
                            sleep 2
                            ;;
                        d|D)
                            if [ -z "$trusted_csv" ]; then
                                echo -e "  ${Y}Список пуст${N}"
                                sleep 1
                                continue
                            fi
                            echo -ne "  Enter IP to remove: "
                            read -r DEL_IP
                            DEL_IP=$(echo "$DEL_IP" | tr -d ' ')
                            # v3.23.1: определяем CIDR vs single IP
                            local del_is_cidr=0
                            [[ "$DEL_IP" == */* ]] && del_is_cidr=1
                            # Удалить из CSV
                            local cleaned
                            cleaned=$(echo "$trusted_csv" | tr ',' '\n' | grep -vxF "$DEL_IP" | paste -sd',' -)
                            _write_setting "TRUSTED_IPS" "$cleaned"
                            # shieldnode whitelist
                            # v3.23.1: sed delimiter '|' вместо '/' чтобы CIDR (содержит /) не ломал regex
                            local DEL_IP_SED="${DEL_IP//./\\.}"
                            sed -i "\\|^${DEL_IP_SED}\$|d" /etc/shieldnode/lists/whitelist-local.txt 2>/dev/null || true
                            echo -e "    ${G}✓${N} shieldnode whitelist"
                            # UFW
                            if command -v ufw >/dev/null 2>&1; then
                                # v3.23.1 CRIT FIX: экранируем точки и слэш в IP — иначе regex
                                # "1.2.3.4" сматчит "1.2.3.40" и т.п., и `yes | ufw delete N` без
                                # подтверждения снесёт чужие правила. Также добавляем end-anchor.
                                # CIDR в UFW отображается как "10.0.0.0/24" — экранируем слэш отдельно.
                                local DEL_IP_RE="${DEL_IP//./\\.}"
                                DEL_IP_RE="${DEL_IP_RE//\//\\/}"
                                # Найти rule number и удалить (ufw нумерует rules)
                                while ufw status numbered 2>/dev/null | grep -E "^\[[0-9]+\] +Anywhere.* ${DEL_IP_RE}( |$|/)" >/dev/null 2>&1; do
                                    local rule_num
                                    rule_num=$(ufw status numbered 2>/dev/null | grep -E "^\[[0-9]+\] +Anywhere.* ${DEL_IP_RE}( |$|/)" | head -1 | grep -oE '\[[0-9]+\]' | tr -d '[]')
                                    [ -z "$rule_num" ] && break
                                    yes | ufw delete "$rule_num" >/dev/null 2>&1 || break
                                done
                                ufw reload >/dev/null 2>&1 || true
                                echo -e "    ${G}✓${N} UFW rule removed"
                            fi
                            # CrowdSec
                            if command -v cscli >/dev/null 2>&1; then
                                # v3.23.1: --range для CIDR, --ip для single
                                if [ "$del_is_cidr" = "1" ]; then
                                    cscli decisions delete --range "$DEL_IP" >/dev/null 2>&1 || true
                                else
                                    cscli decisions delete --ip "$DEL_IP" >/dev/null 2>&1 || true
                                fi
                                echo -e "    ${G}✓${N} CrowdSec decision removed"
                            fi
                            # v3.23.1: регенерируем postoverflow whitelist (parser-level)
                            _trusted_regen_postoverflow "$cleaned"
                            echo -e "    ${G}✓${N} CrowdSec postoverflow whitelist updated"
                            echo -e "  ${G}Done.${N}"
                            sleep 2
                            ;;
                        r|R)
                            if [ -z "$trusted_csv" ]; then
                                echo -e "  ${Y}Список пуст — нечего применять${N}"
                                sleep 1
                                continue
                            fi
                            echo ""
                            echo -e "  ${DIM}Re-applying TRUSTED_IPS across all layers...${N}"
                            IFS=',' read -ra TRUSTED_ARR <<< "$trusted_csv"
                            for ip in "${TRUSTED_ARR[@]}"; do
                                ip=$(echo "$ip" | tr -d ' ')
                                [ -z "$ip" ] && continue
                                # v3.23.1: экранируем точки и слэш для grep, и трекаем CIDR
                                local ip_re="${ip//./\\.}"
                                ip_re="${ip_re//\//\\/}"
                                local is_cidr_ra=0
                                [[ "$ip" == */* ]] && is_cidr_ra=1
                                local WL=/etc/shieldnode/lists/whitelist-local.txt
                                grep -qxF "$ip" "$WL" 2>/dev/null || echo "$ip" >> "$WL"
                                if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
                                    ufw status 2>/dev/null | grep -qE "(^|[[:space:]])${ip_re}([[:space:]]|$)" || \
                                        ufw allow from "$ip" comment "Trusted (TRUSTED_IPS)" >/dev/null 2>&1
                                fi
                                if command -v cscli >/dev/null 2>&1; then
                                    # v3.23.1: --range для CIDR, --ip для single, --type whitelist в list-запросе
                                    if [ "$is_cidr_ra" = "1" ]; then
                                        cscli decisions list --range "$ip" --type whitelist -o json 2>/dev/null | grep -q '"id":' || \
                                            cscli decisions add --range "$ip" --duration 8760h --type whitelist --reason "Trusted (TRUSTED_IPS)" >/dev/null 2>&1
                                    else
                                        cscli decisions list --ip "$ip" --type whitelist -o json 2>/dev/null | grep -q '"id":' || \
                                            cscli decisions add --ip "$ip" --duration 8760h --type whitelist --reason "Trusted (TRUSTED_IPS)" >/dev/null 2>&1
                                    fi
                                fi
                                echo -e "    ${G}✓${N} $ip"
                            done
                            command -v ufw >/dev/null 2>&1 && ufw reload >/dev/null 2>&1 || true
                            # v3.23.1: регенерируем postoverflow whitelist (parser-level)
                            _trusted_regen_postoverflow "$trusted_csv"
                            echo -e "  ${G}Done.${N}"
                            sleep 2
                            ;;
                        q|Q|"")
                            break
                            ;;
                        *)
                            echo -e "  ${Y}Unknown: $TC${N}"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            q|Q|"")
                return
                ;;
            *)
                echo -e "  ${Y}Unknown: $SC${N}"
                sleep 1
                ;;
        esac
    done
}

# === MODE: JSON ===
if [ "$MODE" = "json" ]; then
    collect_stats
    cat <<JSON
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "ip": "$(hostname -I 2>/dev/null | awk '{print $1}')",
  "services": {
    "crowdsec": "$CS_ACTIVE",
    "bouncer": "$BOUNCER_ACTIVE",
    "ports_path_watcher": "$PORTS_PATH_ACTIVE"
  },
  "protected_ports": {
    "tcp": "$PROTECTED_TCP_LIST",
    "udp": "$PROTECTED_UDP_LIST"
  },
  "blocked_now": {
    "syn_flood_v4": $SYN_BAN,
    "udp_flood_v4": $UDP_BAN,
    "crowdsec_bans": $CS_BANS,
    "scanner_blocklist_v4": $BL_V4
  },
  "whitelist": {
    "manual": $MANUAL_WHITE
  },
  "total_blocked": {
    "since": "$NFT_SINCE",
    "scanners_v4_packets": $SCANNER_PKTS_V4,
    "scanners_v4_bytes": $SCANNER_BYTES_V4,
    "confirmed_v4_packets": $CONFIRMED_PKTS_V4,
    "confirmed_v4_bytes": $CONFIRMED_BYTES_V4,
    "syn_confirmed_v4_packets": $SYN_CONF_PKTS_V4,
    "udp_confirmed_v4_packets": $UDP_CONF_PKTS_V4,
    "conn_flood_v4_packets": $CONN_FLOOD_PKTS_V4,
    "newconn_flood_v4_packets": $NEWCONN_FLOOD_PKTS_V4,
    "ssh_conn_flood_v4_packets": $SSH_CONN_FLOOD_PKTS_V4,
    "ssh_newconn_flood_v4_packets": $SSH_NEWCONN_FLOOD_PKTS_V4,
    "tcp_invalid_packets": $TCP_INVALID_PKTS,
    "infrastructure_passes_v4_packets": $INFRA_PASSES_PKTS_V4,
    "infrastructure_passes_v6_packets": $INFRA_PASSES_PKTS_V6,
    "infrastructure_set_size": $INFRA_SET_SIZE
  },
  "last_blocklist_update": "$LAST_UPDATE"
}
JSON
    exit 0
fi

# === MODE: ONCE (без интерактива) ===
if [ "$MODE" = "once" ]; then
    collect_stats
    draw_snapshot
    exit 0
fi

# === MODE: INTERACTIVE ===
while true; do
    collect_stats
    clear 2>/dev/null
    draw_snapshot

    # ===== MENU =====
    # v3.2: убраны эмодзи из меню — они занимают 2-cell в терминале и ломают рамки
    echo -e "${C}┌─────────────────────────────────────────────────────────────────┐${N}"
    echo -e "${C}│${N}  ${B}Actions${N}                                                        ${C}│${N}"
    echo -e "${C}├─────────────────────────────────────────────────────────────────┤${N}"
    echo -e "${C}│${N}  [${B}1${N}] CrowdSec bans          [${B}2${N}] Whitelist manage                ${C}│${N}"
    echo -e "${C}│${N}  [${B}3${N}] Recent history         [${B}4${N}] Top attackers                   ${C}│${N}"
    echo -e "${C}│${N}  [${B}5${N}] Unban all                                                  ${C}│${N}"
    echo -e "${C}│${N}  [${B}s${N}] Settings                                                   ${C}│${N}"
    echo -e "${C}├─────────────────────────────────────────────────────────────────┤${N}"
    echo -e "${C}│${N}  [${B}r${N}] Refresh                [${B}0${N}] Exit                            ${C}│${N}"
    echo -e "${C}└─────────────────────────────────────────────────────────────────┘${N}"
    echo -ne "  ${B}>${N} "

    read -r CHOICE
    case "$CHOICE" in
        1) show_crowdsec_bans    ;;
        2) show_whitelist_ips    ;;
        3) show_history          ;;
        4) show_top_attackers    ;;
        5) unban_all             ;;
        s|S) show_settings_menu  ;;
        r|R|"") continue ;;
        0|q|quit|exit) clear 2>/dev/null; exit 0 ;;
        *) echo -e "  ${Y}Unknown: $CHOICE${N}" ;;
    esac

    if [ "$CHOICE" != "r" ] && [ "$CHOICE" != "R" ] && [ "$CHOICE" != "" ]; then
        echo -ne "  ${DIM}Press Enter to return...${N}"
        read -r _
    fi
done
GUARD_EOF

# v3.20.6: literal '${SHIELDNODE_VERSION}' внутри quoted heredoc'а не expand'ится.
# Подставляем актуальную версию через sed после генерации файла.
sed -i "s/\${SHIELDNODE_VERSION}/${SHIELDNODE_VERSION}/g" "$GUARD_BIN"

chmod 0755 "$GUARD_BIN"
print_ok "Команда установлена: $GUARD_BIN"
print_info "Снимок состояния: ${BOLD}sudo guard${NC}  (или ${BOLD}sudo guard --json${NC})"

# ==============================================================================
# ШАГ 12.5: TRUSTED_IPS (v3.18.8) — полный whitelist через все три слоя защиты
# ==============================================================================
# Применяет TRUSTED_IPS из shieldnode.conf к: shieldnode whitelist + UFW +
# CrowdSec. Идемпотентно: повторный запуск не дублирует записи.
# Если TRUSTED_IPS пуст — шаг тихо пропускается.

apply_trusted_ip() {
    local ip="$1"
    local comment="${2:-Trusted infrastructure (TRUSTED_IPS)}"

    # v3.18.11 SH-NEW-10: строгая валидация (отклоняет 0.0.0.0/x, multicast)
    if ! validate_ipv4_or_cidr "$ip"; then
        print_warn "  Пропускаю невалидный IP: '$ip' (запрещены 0.0.0.0/x, multicast, prefix<8)"
        return 1
    fi

    # v3.23.1: CIDR теперь поддерживаются (cscli umеет --range, ufw allow from <CIDR>).
    local is_cidr=0
    [[ "$ip" == */* ]] && is_cidr=1

    # v3.23.1: экранируем точки для безопасного использования в grep -E.
    # Без этого regex "1.2.3.4" сматчит "1A2B3C4", "1.2.3.40" и т.п.
    # Для CIDR экранируем точки и слэш отдельно.
    local ip_re="${ip//./\\.}"
    ip_re="${ip_re//\//\\/}"

    local layer_count=0

    # 1. shieldnode whitelist-local (works for single IP и CIDR, nft set с flags interval)
    local WL=/etc/shieldnode/lists/whitelist-local.txt
    if [ -f "$WL" ] && grep -qxF "$ip" "$WL"; then
        :
    else
        echo "$ip" >> "$WL"
        layer_count=$((layer_count + 1))
    fi

    # 2. UFW (поддерживает single IP и CIDR одинаково)
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        # v3.23.1: ip_re с экранированными точками вместо raw $ip
        if ! ufw status 2>/dev/null | grep -qE "(^|[[:space:]])${ip_re}([[:space:]]|$)"; then
            ufw allow from "$ip" comment "$comment" >/dev/null 2>&1 || true
            layer_count=$((layer_count + 1))
        fi
    fi

    # 3. CrowdSec decision-level whitelist (быстрая отмена существующих banов)
    if command -v cscli >/dev/null 2>&1; then
        if [ "$is_cidr" = "1" ]; then
            # v3.23.1: CIDR через --range
            # Note: --range делает scope=Range вместо Ip; список не дублируется
            # благодаря reason-check (cscli не отклоняет дубль самостоятельно).
            if ! cscli decisions list --range "$ip" --type whitelist -o json 2>/dev/null | \
                 grep -q '"id":'; then
                cscli decisions add --range "$ip" --duration 8760h --type whitelist --reason "$comment" >/dev/null 2>&1 || true
                layer_count=$((layer_count + 1))
            fi
        else
            # v3.23.1: --type whitelist в самом list-запросе вместо grep'а вывода
            if ! cscli decisions list --ip "$ip" --type whitelist -o json 2>/dev/null | \
                 grep -q '"id":'; then
                cscli decisions add --ip "$ip" --duration 8760h --type whitelist --reason "$comment" >/dev/null 2>&1 || true
                layer_count=$((layer_count + 1))
            fi
        fi
    fi

    # Слой 4 (postoverflow whitelist для parser-level) применяется не здесь
    # а после цикла — одним файлом со всеми IP сразу (см. ниже).
    # Postoverflow умеет ip: для single и cidr: для CIDR.

    if [ "$layer_count" -gt 0 ]; then
        print_ok "  $ip — применено в $layer_count слое(в)"
    else
        print_info "  $ip — уже whitelisted во всех слоях"
    fi
    return 0
}

# v3.23.1: CRIT FIX — генерация postoverflow whitelist для TRUSTED_IPS.
# Раньше (≤v3.23.0): TRUSTED_IPS жили только в decision-level whitelist
# (cscli decisions add --type whitelist). Это отменяет ban-decisions, но НЕ
# предотвращает scenarios (crowdsecurity/http-probing, ssh-bf, etc) от
# срабатывания → alerts уходили в CAPI как сигналы атаки от trusted IP.
# Хуже: между моментом создания ban-decision и применения whitelist-decision
# было короткое окно когда bouncer мог дропнуть IP.
#
# Симметрично с MGMT_IPV4 которые с v3.10.4 уже через postoverflow.
generate_trusted_postoverflow() {
    if [ "${SHIELDNODE_CROWDSEC_MANAGED:-0}" != "1" ]; then
        return 0   # foreign CrowdSec — не трогаем
    fi
    local PO_DIR=/etc/crowdsec/postoverflows/s01-whitelist
    local PO_FILE="$PO_DIR/shieldnode-trusted.yaml"
    mkdir -p "$PO_DIR"

    # Если TRUSTED_IPS пуст — удалим файл (idempotent)
    if [ -z "${TRUSTED_IPS:-}" ]; then
        if [ -f "$PO_FILE" ]; then
            rm -f "$PO_FILE"
            systemctl reload crowdsec >/dev/null 2>&1
        fi
        return 0
    fi

    # Собираем валидные IP и CIDR в отдельные списки
    local TMP_IPS=""
    local TMP_CIDRS=""
    IFS=',' read -ra _ARR <<< "$TRUSTED_IPS"
    for _ip in "${_ARR[@]}"; do
        _ip=$(echo "$_ip" | tr -d ' ')
        [ -z "$_ip" ] && continue
        validate_ipv4_or_cidr "$_ip" 2>/dev/null || continue
        # v3.23.1: CIDR поддержан через cidr: секцию postoverflow
        if [[ "$_ip" == */* ]]; then
            TMP_CIDRS="$TMP_CIDRS $_ip"
        else
            TMP_IPS="$TMP_IPS $_ip"
        fi
    done

    if [ -z "$TMP_IPS" ] && [ -z "$TMP_CIDRS" ]; then
        rm -f "$PO_FILE" 2>/dev/null
        return 0
    fi

    # Atomic write: tmp в той же директории + mv
    local TMP_FILE
    TMP_FILE=$(mktemp "${PO_FILE}.XXXXXX") || return 1
    {
        echo "# v3.23.1: parser-level whitelist для TRUSTED_IPS."
        echo "# Срабатывает ПОСЛЕ scenario trigger но ДО alert/decision —"
        echo "# scenarios (http-probing, ssh-bf, etc) не оставляют следов на trusted IPs."
        echo "# Симметрично с MGMT_IPV4 (shieldnode-mgmt.yaml)."
        echo "name: shieldnode/trusted-whitelist"
        echo "description: \"Whitelist trusted infrastructure IPs (TRUSTED_IPS)\""
        echo "whitelist:"
        echo "  reason: \"Trusted infrastructure (TRUSTED_IPS)\""
        if [ -n "$TMP_IPS" ]; then
            echo "  ip:"
            for ip in $TMP_IPS; do
                echo "    - \"$ip\""
            done
        fi
        if [ -n "$TMP_CIDRS" ]; then
            echo "  cidr:"
            for cidr in $TMP_CIDRS; do
                echo "    - \"$cidr\""
            done
        fi
    } > "$TMP_FILE"
    chmod 0644 "$TMP_FILE"
    mv "$TMP_FILE" "$PO_FILE"   # atomic — same FS
    systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1
}

if [ -n "${TRUSTED_IPS:-}" ]; then
    print_header "ШАГ 12.5: TRUSTED_IPS"
    print_status "Применяю trust-stack для IP'шников из TRUSTED_IPS..."
    IFS=',' read -ra TRUSTED_ARR <<< "$TRUSTED_IPS"
    for raw_ip in "${TRUSTED_ARR[@]}"; do
        ip=$(echo "$raw_ip" | tr -d ' ')
        [ -z "$ip" ] && continue
        apply_trusted_ip "$ip"
    done
    # UFW reload один раз в конце (а не на каждый IP)
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw reload >/dev/null 2>&1 || true
    fi
    # v3.23.1: postoverflow whitelist одним файлом (parser-level)
    generate_trusted_postoverflow
    print_ok "Postoverflow whitelist: /etc/crowdsec/postoverflows/s01-whitelist/shieldnode-trusted.yaml"
fi

# ==============================================================================
# ШАГ 13: HEALTHCHECK
# ==============================================================================

# ==============================================================================
# ШАГ 12.6: CLEANUP LEGACY (v3.23.4) — удаление компонентов прошлых версий
# ==============================================================================

print_header "ШАГ 12.6: CLEANUP LEGACY"

# v3.23.13 SR-FIX-5: миграция perms 0644 → 0640 для shieldnode.conf
# Предыдущие версии оставляли conf world-readable (TRUSTED_IPS видны любому
# юзеру). При upgrade auto-migrate. shield_safe_source также делает это
# при load, но прямо здесь — чтобы оператор увидел warning в install logs.
for sensitive_conf in /etc/shieldnode/shieldnode.conf /etc/shieldnode/limits.conf; do
    if [ -f "$sensitive_conf" ]; then
        current_perms=$(stat -c "%a" "$sensitive_conf" 2>/dev/null)
        if [ "$current_perms" = "644" ]; then
            chmod 0640 "$sensitive_conf"
            print_warn "Перемигрировал permissions: $sensitive_conf 0644 → 0640 (security)"
        fi
        # Гарантируем owner=root:root
        chown root:root "$sensitive_conf" 2>/dev/null || true
    fi
done

# === DISK CLEANUP (v3.23.6) ===
# Критично для нод где предыдущая атака разлила /var/log до 100%.
# Если /var/log >80% — агрессивная чистка ДО продолжения установки
# (apt install и nft reload могут упасть на полном диске).
DISK_USAGE=$(df --output=pcent /var/log 2>/dev/null | tail -1 | tr -d ' %')
DISK_USAGE="${DISK_USAGE:-0}"

if [ "$DISK_USAGE" -ge 80 ]; then
    print_warn "Disk /var/log заполнен на ${DISK_USAGE}% — выполняю cleanup"
    CLEANED_MB=0

    # 1. v3.23.7+: events.log — gzip ИЛИ truncate в зависимости от свободного места.
    # При >=95% диск критичен — gzip может не уместиться (нужна tmp space).
    # При 80-94% — gzip (сохраняем историю).
    if [ -f /var/log/shieldnode/events.log ]; then
        OLD_SIZE=$(stat -c%s /var/log/shieldnode/events.log 2>/dev/null || echo 0)
        if [ "$OLD_SIZE" -gt 104857600 ]; then  # >100MB
            if [ "$DISK_USAGE" -ge 95 ]; then
                # CRITICAL: нет места для gzip, делаем truncate (теряем старые записи)
                tail -c 50M /var/log/shieldnode/events.log > /var/log/shieldnode/events.log.tmp 2>/dev/null && \
                    mv /var/log/shieldnode/events.log.tmp /var/log/shieldnode/events.log
                NEW_SIZE=$(stat -c%s /var/log/shieldnode/events.log 2>/dev/null || echo 0)
                CLEANED_MB=$((CLEANED_MB + (OLD_SIZE - NEW_SIZE) / 1024 / 1024))
                print_warn "  events.log: $((OLD_SIZE / 1024 / 1024))MB → 50MB (TRUNCATE — диск >95%, gzip не вмещается)"
                print_info "  → история старее ~часа потеряна (диск был критичен)"
            else
                # NORMAL: сжимаем (сохраняем историю)
                ARCHIVED_NAME="/var/log/shieldnode/events.log.upgrade-$(date +%Y%m%d-%H%M%S)"
                if mv /var/log/shieldnode/events.log "$ARCHIVED_NAME" 2>/dev/null; then
                    touch /var/log/shieldnode/events.log
                    chmod 0640 /var/log/shieldnode/events.log
                    print_info "  events.log: $((OLD_SIZE / 1024 / 1024))MB → сжимаю gzip (может занять несколько минут)..."

                    # Запускаем gzip в фоне с progress notifier
                    (
                        if gzip "$ARCHIVED_NAME" 2>&1 | logger -t shieldnode-upgrade-gzip; then
                            logger -t shieldnode-upgrade-gzip "OK: ${ARCHIVED_NAME}.gz"
                        else
                            logger -t shieldnode-upgrade-gzip "FAILED for $ARCHIVED_NAME"
                        fi
                    ) &
                    GZIP_PID=$!

                    # Прогресс каждые 10 сек пока gzip работает
                    while kill -0 "$GZIP_PID" 2>/dev/null; do
                        sleep 10
                        if [ -f "${ARCHIVED_NAME}.gz" ]; then
                            CUR_GZ_MB=$(stat -c%s "${ARCHIVED_NAME}.gz" 2>/dev/null | awk '{print int($1/1024/1024)}')
                            print_info "    gzip progress: ${CUR_GZ_MB}MB compressed..."
                        fi
                    done
                    wait "$GZIP_PID"

                    if [ -f "${ARCHIVED_NAME}.gz" ]; then
                        NEW_SIZE=$(stat -c%s "${ARCHIVED_NAME}.gz" 2>/dev/null || echo 0)
                        SAVED_MB=$(( (OLD_SIZE - NEW_SIZE) / 1024 / 1024 ))
                        CLEANED_MB=$((CLEANED_MB + SAVED_MB))
                        RATIO=$(( NEW_SIZE * 100 / OLD_SIZE ))
                        print_info "  events.log: $((OLD_SIZE / 1024 / 1024))MB → $((NEW_SIZE / 1024 / 1024))MB (${RATIO}%, сохранено в ${ARCHIVED_NAME}.gz)"
                    else
                        # gzip упал — оставляем несжатый, потом aggregator retry
                        print_warn "  events.log: gzip упал, несжатый архив в $ARCHIVED_NAME (aggregator попробует retry)"
                    fi
                fi
            fi
        fi
    fi

    # 2. Старые .gz архивы события — ретенция 30 дней (история атак сохраняется)
    BEFORE=$(du -sm /var/log/shieldnode 2>/dev/null | awk '{print $1}')
    BEFORE="${BEFORE:-0}"
    find /var/log/shieldnode -name "*.gz" -mtime +30 -delete 2>/dev/null
    find /var/log/shieldnode -name "*.xz" -mtime +90 -delete 2>/dev/null
    find /var/log/shieldnode -name "*.[0-9]" -mtime +7 -delete 2>/dev/null
    AFTER=$(du -sm /var/log/shieldnode 2>/dev/null | awk '{print $1}')
    AFTER="${AFTER:-0}"
    if [ "$BEFORE" -gt "$AFTER" ]; then
        SAVED=$((BEFORE - AFTER))
        CLEANED_MB=$((CLEANED_MB + SAVED))
        print_info "  shieldnode old archives (>30d gz, >7d numbered): -${SAVED}MB"
    fi

    # 3. v3.23.8: пересжатие .gz архивов старше 14 дней в xz -6 (быстрее чем -9, ratio 95%)
    XZ_RECOMPRESSED=0
    if command -v xz >/dev/null 2>&1; then
        for gz_file in $(find /var/log/shieldnode -name "*.gz" -mtime +14 2>/dev/null); do
            xz_file="${gz_file%.gz}.xz"
            [ -f "$xz_file" ] && continue   # Уже пересжато
            if zcat "$gz_file" 2>/dev/null | xz -6 -T 2 > "$xz_file" 2>/dev/null && [ -s "$xz_file" ]; then
                rm -f "$gz_file"
                XZ_RECOMPRESSED=$((XZ_RECOMPRESSED + 1))
            else
                rm -f "$xz_file"  # cleanup при неудаче
            fi
        done
        [ "$XZ_RECOMPRESSED" -gt 0 ] && \
            print_info "  recompressed $XZ_RECOMPRESSED archives gz→xz -6 (extra savings)"
    fi

    # 4. v3.23.8: системные логи — whitelist известных паттернов (не broad match!)
    # Защита от случайного удаления docker logs, custom logs, etc.
    BEFORE=$(du -sm /var/log 2>/dev/null | awk '{print $1}')
    BEFORE="${BEFORE:-0}"

    # Удаляем только известные системные ротации
    SYSTEM_LOG_PATTERNS=(
        "syslog.*.gz"
        "syslog.[0-9]*"
        "kern.log.*.gz"
        "kern.log.[0-9]*"
        "auth.log.*.gz"
        "auth.log.[0-9]*"
        "messages-*.gz"
        "messages.[0-9]*"
        "mail.*.gz"
        "mail.[0-9]*"
        "daemon.log.*.gz"
        "daemon.log.[0-9]*"
        "user.log.*.gz"
        "user.log.[0-9]*"
        "ufw.log.*.gz"
        "ufw.log.[0-9]*"
        "dpkg.log.*.gz"
        "alternatives.log.*.gz"
        "apt/history.log.*.gz"
        "apt/term.log.*.gz"
    )
    for pattern in "${SYSTEM_LOG_PATTERNS[@]}"; do
        # Только в /var/log/ верхнего уровня, не в подпапках произвольных
        find /var/log -maxdepth 2 -name "$pattern" -mtime +7 -delete 2>/dev/null
    done

    AFTER=$(du -sm /var/log 2>/dev/null | awk '{print $1}')
    AFTER="${AFTER:-0}"
    if [ "$BEFORE" -gt "$AFTER" ]; then
        SAVED=$((BEFORE - AFTER))
        CLEANED_MB=$((CLEANED_MB + SAVED))
        print_info "  /var/log known system patterns (>7d): -${SAVED}MB"
    fi

    # 5. Journald vacuum
    JOURNAL_BEFORE=$(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[GMK]' | head -1)
    journalctl --vacuum-size=200M >/dev/null 2>&1 || true
    JOURNAL_AFTER=$(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[GMK]' | head -1)
    [ -n "$JOURNAL_BEFORE" ] && [ -n "$JOURNAL_AFTER" ] && \
        print_info "  journald: $JOURNAL_BEFORE → $JOURNAL_AFTER"

    # 6. APT cache
    apt-get clean >/dev/null 2>&1 || true

    # 7. Активные kern.log/syslog/auth.log > 200MB → принудительная ротация (сжатый архив)
    LARGE_LOGS_ROTATED=0
    for log in /var/log/syslog /var/log/kern.log /var/log/auth.log; do
        if [ -f "$log" ]; then
            SIZE=$(stat -c%s "$log" 2>/dev/null || echo 0)
            if [ "$SIZE" -gt 209715200 ]; then  # > 200MB
                # v3.23.13 SR-FIX-8: используем /etc/logrotate.d/rsyslog
                # (наш патч добавил maxsize 100M туда)
                logrotate -f /etc/logrotate.d/rsyslog 2>/dev/null && \
                    LARGE_LOGS_ROTATED=$((LARGE_LOGS_ROTATED + 1))
            fi
        fi
    done
    [ "$LARGE_LOGS_ROTATED" -gt 0 ] && \
        print_info "  forced rotate $LARGE_LOGS_ROTATED больших системных логов"

    # 8. v3.23.8: PCAP archive — СЖИМАЕМ старее 7 дней в tar.zst, удаляем старее 30 дней.
    # Защищает forensics от потери (раньше удаляли >3 дней при critical disk).
    if [ -d /var/lib/shieldnode/pcap-archive ]; then
        PCAP_USAGE_MB=$(du -sm /var/lib/shieldnode/pcap-archive 2>/dev/null | awk '{print $1}')
        PCAP_USAGE_MB="${PCAP_USAGE_MB:-0}"

        # Сжимаем директории старше 7 дней в tar.zst (если zstd есть)
        if command -v zstd >/dev/null 2>&1; then
            PCAP_COMPRESSED=0
            for archive_dir in $(find /var/lib/shieldnode/pcap-archive -mindepth 1 -maxdepth 1 -type d -mtime +7 2>/dev/null); do
                tar_name="${archive_dir}.tar.zst"
                [ -f "$tar_name" ] && continue
                if tar --use-compress-program="zstd -19 -T2" -cf "$tar_name" -C "$(dirname "$archive_dir")" "$(basename "$archive_dir")" 2>/dev/null && [ -s "$tar_name" ]; then
                    rm -rf "$archive_dir"
                    PCAP_COMPRESSED=$((PCAP_COMPRESSED + 1))
                fi
            done
            [ "$PCAP_COMPRESSED" -gt 0 ] && \
                print_info "  PCAP archives (>7d): compressed $PCAP_COMPRESSED to tar.zst"
        fi

        # Удаляем tar.zst и uncompressed >30 дней
        BEFORE=$PCAP_USAGE_MB
        find /var/lib/shieldnode/pcap-archive -mindepth 1 -maxdepth 1 -mtime +30 -exec rm -rf {} \; 2>/dev/null
        AFTER=$(du -sm /var/lib/shieldnode/pcap-archive 2>/dev/null | awk '{print $1}')
        AFTER="${AFTER:-0}"
        if [ "$BEFORE" -gt "$AFTER" ]; then
            SAVED=$((BEFORE - AFTER))
            CLEANED_MB=$((CLEANED_MB + SAVED))
            print_info "  pcap-archive (>30d): -${SAVED}MB"
        fi
    fi

    # Финальная проверка
    NEW_DISK_USAGE=$(df --output=pcent /var/log 2>/dev/null | tail -1 | tr -d ' %')
    print_ok "Disk cleanup: ${DISK_USAGE}% → ${NEW_DISK_USAGE}% (освобождено ~${CLEANED_MB}MB)"

    if [ "$NEW_DISK_USAGE" -ge 90 ]; then
        print_warn "Диск всё ещё >90% после cleanup — проверь что ещё его занимает:"
        print_info "  du -sh /var/log/* /var/lib/* 2>/dev/null | sort -rh | head"
        print_info "  Подсказки:"
        print_info "    • Docker logs:   sudo du -sh /var/lib/docker/containers/*/*.log 2>/dev/null"
        print_info "    • Coredumps:     sudo du -sh /var/lib/systemd/coredump/ 2>/dev/null"
        print_info "    • Старые ядра:   sudo apt autoremove --purge"
    fi
else
    print_info "Disk /var/log: ${DISK_USAGE}% — cleanup не требуется"
fi

# ==============================================================================
# ШАГ 12.7: PCAP-CAPTURE (v3.23.3) — rolling forensics для DDoS-инцидентов
# ==============================================================================

print_header "ШАГ 12.7: PCAP-CAPTURE (rolling SYN dump)"

# Хостер при DDoS требует pcap для блокировки upstream / abuse-report.
# tcpdump на SYN-пакеты без ACK (начало TCP-соединения), 128 байт payload.
# Ring buffer: 20 нумерованных файлов × 50MB = max 1GB (-W 20 -C 50).
# v3.23.17 FIX: убраны strftime-имя и -G — с ними -W НЕ удалял старые файлы,
# каждый rotate создавал уникальное имя → /var/log/pcap рос до десятков GB.
# На нормальной нагрузке: ~100-200MB/сутки.

# v3.23.9: tcpdump install с retry + проверка что binary реально доступен
TCPDUMP_BIN=""
if ! command -v tcpdump >/dev/null 2>&1; then
    print_status "Устанавливаю tcpdump..."
    for try in 1 2 3; do
        if apt-get install -y tcpdump >/dev/null 2>&1; then
            break
        fi
        sleep $((try * 2))
    done
fi

# Auto-detect tcpdump path (Ubuntu 22/24: /usr/bin, RHEL/Debian-old: /usr/sbin)
TCPDUMP_BIN=$(command -v tcpdump 2>/dev/null)
if [ -z "$TCPDUMP_BIN" ] || [ ! -x "$TCPDUMP_BIN" ]; then
    print_warn "tcpdump НЕ установлен или недоступен — PCAP capture будет disabled"
    print_info "  Ручная установка: sudo apt update && sudo apt install -y tcpdump"
    TCPDUMP_AVAILABLE=0
else
    TCPDUMP_AVAILABLE=1
    print_info "tcpdump найден: $TCPDUMP_BIN"
fi

mkdir -p /var/log/pcap
chmod 755 /var/log/pcap
# v3.23.17: удаляем legacy strftime-pcap от старого сломанного ring (могло быть десятки GB)
find /var/log/pcap -maxdepth 1 -type f -name 'syn-*.pcap' -delete 2>/dev/null || true

if [ "$TCPDUMP_AVAILABLE" = "1" ]; then
# Используем single-quote heredoc (literal) чтобы $VAR и % не expand'ились,
# затем sed подставляет ровно один placeholder __TCPDUMP_BIN__.
cat > /etc/systemd/system/shieldnode-pcap.service <<'PCAP_UNIT_EOF'
[Unit]
Description=Shieldnode rolling SYN packet capture for DDoS forensics
After=network.target shieldnode-nftables.service
Wants=network.target

[Service]
Type=simple
ExecStart=__TCPDUMP_BIN__ -i any -nn -s 128 \
    -w /var/log/pcap/syn.pcap \
    -W 20 -C 50 -Z root \
    '(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)'
Restart=always
RestartSec=10
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
PCAP_UNIT_EOF

# Подставляем actual путь к tcpdump
sed -i "s|__TCPDUMP_BIN__|$TCPDUMP_BIN|g" /etc/systemd/system/shieldnode-pcap.service

systemctl daemon-reload
systemctl enable shieldnode-pcap.service >/dev/null 2>&1

# Restart только если сервис ещё не запущен ИЛИ конфиг изменился.
# Не обрывать активный capture зря: если идёт атака, теряются последние секунды.
PCAP_UNIT_HASH_NEW=$(sha256sum /etc/systemd/system/shieldnode-pcap.service 2>/dev/null | awk '{print $1}')
# Hash в /run/ (volatile, очищается при reboot — это ок: после ребута restart ОК).
mkdir -p /run/shieldnode
PCAP_UNIT_HASH_FILE=/run/shieldnode/pcap-unit-hash
PCAP_UNIT_HASH_OLD=$(cat "$PCAP_UNIT_HASH_FILE" 2>/dev/null || echo "")

if ! systemctl is-active --quiet shieldnode-pcap.service; then
    systemctl start shieldnode-pcap.service >/dev/null 2>&1
    echo "$PCAP_UNIT_HASH_NEW" > "$PCAP_UNIT_HASH_FILE"
elif [ "$PCAP_UNIT_HASH_NEW" != "$PCAP_UNIT_HASH_OLD" ]; then
    systemctl restart shieldnode-pcap.service >/dev/null 2>&1
    echo "$PCAP_UNIT_HASH_NEW" > "$PCAP_UNIT_HASH_FILE"
fi
sleep 2

if systemctl is-active --quiet shieldnode-pcap.service; then
    print_ok "PCAP capture запущен (ring 1GB, /var/log/pcap/syn.pcap*)"
else
    print_warn "PCAP capture не стартовал — проверь: systemctl status shieldnode-pcap"
fi

else
    # tcpdump не доступен — пропускаем установку pcap service
    # Если был установлен ранее — disable чтобы не было crashes status=203/EXEC
    systemctl disable --now shieldnode-pcap.service 2>/dev/null || true
    rm -f /etc/systemd/system/shieldnode-pcap.service 2>/dev/null
    print_warn "PCAP capture skipped — tcpdump не установлен (apt не сработал)"
fi

# Note: logrotate для /var/log/pcap НЕ нужен — tcpdump сам ротирует через -W 20 -C 50.
# Сторонний logrotate может удалить файлы которые tcpdump переиспользует в ring buffer.
# Если есть legacy logrotate-config от старых версий — удаляем.
rm -f /etc/logrotate.d/shieldnode-pcap 2>/dev/null

# === PCAP archive-on-attack-detect ===
# Ring buffer 1GB при volumetric атаке 100k SYN/sec заполнится за ~80 секунд
# и начнёт перезаписывать сами себя. Если хостер попросит pcap через час —
# уже поздно. Каждую минуту проверяем drop-counters: если резкий скачок
# (>10k drops за минуту = атака), копируем все текущие pcap-файлы в
# /var/lib/shieldnode/pcap-archive/ с меткой времени.

mkdir -p /var/lib/shieldnode/pcap-archive
chmod 700 /var/lib/shieldnode/pcap-archive

cat > /usr/local/sbin/shieldnode-pcap-archiver.sh <<'PCAP_ARCH_EOF'
#!/bin/bash
# Архивирует pcap-файлы при детекте атаки (по nft drop counters)
# Запускается каждую минуту через timer
set -euo pipefail

LOCK_DIR=/run/shieldnode
LOCK="$LOCK_DIR/pcap-archiver.lock"
LOG_TAG=shieldnode-pcap-arch
STATE_FILE=/var/lib/shieldnode/.pcap-arch-state
ARCHIVE_DIR=/var/lib/shieldnode/pcap-archive
PCAP_DIR=/var/log/pcap
TRIGGER_THRESHOLD=__SHIELD_PCAP_TRIGGER_DROPS__   # drops/min → trigger archive

mkdir -p "$LOCK_DIR"
exec {LOCK_FD}> "$LOCK"
flock -n "$LOCK_FD" || exit 0

# Проверяем что nft table существует. Если нет — shieldnode-nftables упал,
# что само по себе серьёзный инцидент. Записываем alert и не делаем сравнения
# (иначе CURRENT_DROPS=0 → дельта negative → trigger не сработает в реальной атаке).
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "CRITICAL: nft table 'inet ddos_protect' missing — shieldnode-nftables.service may be down"
    exit 1
fi

# Текущий счётчик drop'ов из всех counters в ddos_protect
CURRENT_DROPS=$(nft list table inet ddos_protect 2>/dev/null | \
    awk '/counter packets/ {gsub(/[^0-9]/,"",$3); sum+=$3} END {print sum+0}')

# Предыдущий замер (из state файла)
PREV_DROPS=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
PREV_DROPS="${PREV_DROPS:-0}"

# Записываем текущий замер для следующей итерации
echo "$CURRENT_DROPS" > "$STATE_FILE"

# Дельта за минуту
DELTA=$((CURRENT_DROPS - PREV_DROPS))
[ "$DELTA" -lt 0 ] && DELTA=0   # после ребута/flush counter обнулился

if [ "$DELTA" -ge "$TRIGGER_THRESHOLD" ]; then
    TS=$(date -u +%Y%m%d-%H%M%S)
    ARCH_SUBDIR="$ARCHIVE_DIR/attack-$TS"
    mkdir -p "$ARCH_SUBDIR"

    # Копируем все pcap-файлы (cp -p сохранит mtime)
    if compgen -G "$PCAP_DIR/syn.pcap*" > /dev/null; then
        cp -p "$PCAP_DIR"/syn.pcap* "$ARCH_SUBDIR/" 2>/dev/null || true
        # Метаданные: drop-counters, conntrack snapshot, suspect_v4
        nft list table inet ddos_protect > "$ARCH_SUBDIR/nft-state.txt" 2>/dev/null || true
        # v3.23.13 BUG-012 FIX: conntrack snapshot полный + gzip (раньше head -10000
        # обрезал на 10k entries, и uncompressed файл занимал 5-10MB на каждый
        # attack-archive). Предпочитаем conntrack(8) который через netlink работает
        # без блокировки kernel'а; fallback на /proc если нет.
        if command -v conntrack >/dev/null 2>&1; then
            conntrack -L -o save 2>/dev/null | gzip -1 > "$ARCH_SUBDIR/conntrack.txt.gz" || true
        else
            gzip -1 < /proc/net/nf_conntrack 2>/dev/null > "$ARCH_SUBDIR/conntrack.txt.gz" || true
        fi
        echo "delta_drops=$DELTA, total_drops=$CURRENT_DROPS, ts=$TS" > "$ARCH_SUBDIR/metadata.txt"
        logger -t "$LOG_TAG" "ATTACK DETECTED ($DELTA drops/min) — pcap archived to $ARCH_SUBDIR"
    fi
fi

# Cleanup: v3.23.13 BUG-010 FIX. Раньше было только `rm -rf` после 7 дней,
# tar.zst compression жил только в install-time disk-cleanup и почти никогда
# не срабатывал. Теперь:
#   - >7 дней без compress → tar.zst (lossless forensics).
#   - >SHIELD_PCAP_RETENTION_DAYS (compressed или uncompressed) → удаление.
# Это реализует обещанную retention из design doc / changelog v3.23.7.
PCAP_RETENTION_DAYS=__SHIELD_PCAP_RETENTION_DAYS__
if command -v zstd >/dev/null 2>&1; then
    find "$ARCHIVE_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +7 2>/dev/null | while read -r archive_dir; do
        tar_name="${archive_dir}.tar.zst"
        [ -f "$tar_name" ] && continue
        if tar --use-compress-program="zstd -19 -T2" \
            -cf "$tar_name" \
            -C "$(dirname "$archive_dir")" "$(basename "$archive_dir")" 2>/dev/null \
            && [ -s "$tar_name" ]; then
            rm -rf "$archive_dir"
            logger -t "$LOG_TAG" "compressed archive $(basename "$archive_dir") to tar.zst"
        else
            # Compression failed — оставляем uncompressed (лучше чем потерять)
            rm -f "$tar_name" 2>/dev/null
            logger -t "$LOG_TAG" "WARN: failed to compress $(basename "$archive_dir"), keeping uncompressed"
        fi
    done
fi
# Удаляем всё (uncompressed dirs + tar.zst) старше retention
find "$ARCHIVE_DIR" -mindepth 1 -maxdepth 1 -mtime +"$PCAP_RETENTION_DAYS" \( -type d -o -name '*.tar.zst' \) -exec rm -rf {} \; 2>/dev/null || true
# v3.23.17: чистим legacy strftime-pcap (старый сломанный ring) + жёсткий size-cap на ring-каталог.
find /var/log/pcap -maxdepth 1 -type f -name 'syn-*.pcap' -delete 2>/dev/null || true
RING_MB=$(du -sm /var/log/pcap 2>/dev/null | awk '{print $1+0}')
if [ "${RING_MB:-0}" -gt 1536 ]; then
    ls -1t /var/log/pcap/syn.pcap* 2>/dev/null | tail -n +21 | while read -r f; do rm -f "$f" 2>/dev/null || true; done
    logger -t "$LOG_TAG" "WARN: /var/log/pcap=${RING_MB}MB > 1536MB cap — trimmed stale files"
fi

exit 0
PCAP_ARCH_EOF

# v3.23.13 BUG-019: подставляем настраиваемые значения
sed -i \
    -e "s|__SHIELD_PCAP_TRIGGER_DROPS__|$SHIELD_PCAP_TRIGGER_DROPS|g" \
    -e "s|__SHIELD_PCAP_RETENTION_DAYS__|$SHIELD_PCAP_RETENTION_DAYS|g" \
    /usr/local/sbin/shieldnode-pcap-archiver.sh
verify_no_placeholders /usr/local/sbin/shieldnode-pcap-archiver.sh || exit 1

chmod +x /usr/local/sbin/shieldnode-pcap-archiver.sh

cat > /etc/systemd/system/shieldnode-pcap-archiver.service <<'PCAP_ARCH_UNIT_EOF'
[Unit]
Description=Shieldnode PCAP archiver (on attack detect)
After=shieldnode-pcap.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shieldnode-pcap-archiver.sh
Nice=15
PCAP_ARCH_UNIT_EOF

cat > /etc/systemd/system/shieldnode-pcap-archiver.timer <<'PCAP_ARCH_TIMER_EOF'
[Unit]
Description=Run shieldnode-pcap-archiver every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
PCAP_ARCH_TIMER_EOF

systemctl daemon-reload
systemctl enable shieldnode-pcap-archiver.timer >/dev/null 2>&1
systemctl start shieldnode-pcap-archiver.timer >/dev/null 2>&1
print_ok "PCAP archiver enabled (trigger >10k drops/min, archive 7d retention)"

# ==============================================================================
# ШАГ 12.8: AUTO-PROMOTE (v3.23.3) — events.db → custom-local.txt
# ==============================================================================

print_header "ШАГ 12.8: AUTO-PROMOTE events.db → custom-local.txt"

# Каждые 6ч: IP с count>=2000 за 24ч И type IN (conn_flood, syn_flood)
# автоматом попадают в custom-local.txt навсегда.
# Защита от повторных атак с тех же source IP после истечения suspect_v4 1h.

cat > /usr/local/sbin/shieldnode-auto-promote.sh <<'PROMOTE_SCRIPT_EOF'
#!/bin/bash
# Auto-promote chronic attackers from events.db to custom-local.txt
# v3.23.3: динамический whitelist + TTL cleanup для записей старше 90 дней
set -euo pipefail

DB=/var/lib/shieldnode/events.db
CUSTOM_LOCAL=/etc/shieldnode/lists/custom-local.txt
LOCK_DIR=/run/shieldnode
LOCK="$LOCK_DIR/auto-promote.lock"
LOG_TAG=shieldnode-auto-promote
TTL_DAYS=__SHIELD_CUSTOM_LOCAL_TTL_DAYS__
PROMOTE_THRESHOLD=__SHIELD_AUTOPROMOTE_THRESHOLD__
PROMOTE_WINDOW_HOURS=__SHIELD_AUTOPROMOTE_WINDOW_HOURS__

mkdir -p "$LOCK_DIR"
exec {LOCK_FD}> "$LOCK"
flock -n "$LOCK_FD" || { logger -t "$LOG_TAG" "already running, skip"; exit 0; }

[ -f "$DB" ] || { logger -t "$LOG_TAG" "events.db not found, skip"; exit 0; }
[ -f "$CUSTOM_LOCAL" ] || {
    mkdir -p "$(dirname "$CUSTOM_LOCAL")"
    echo "# shieldnode custom-local blocklist (this node only, auto-managed)" > "$CUSTOM_LOCAL"
}

# === Selection: count >= 2000 за 24ч, conn_flood / syn_escalate / newconn_flood ===
# v3.23.13 BUG-004b FIX: было `type IN ('conn_flood','syn_flood')` — но в aggregator
# никогда не пишется type='syn_flood' (есть только syn_escalate). Это была typo от
# рефакторинга v3.15.x — auto-promote НИКОГДА не находил кандидатов через syn-flood.
# Также добавляем newconn_flood (тоже признак persistent атакующего).
NEW_IPS=$(sqlite3 "$DB" "
    SELECT DISTINCT ip FROM events
    WHERE last_seen > strftime('%s','now') - ($PROMOTE_WINDOW_HOURS * 3600)
      AND count >= $PROMOTE_THRESHOLD
      AND type IN ('conn_flood','syn_escalate','udp_escalate')
    ORDER BY count DESC;
" 2>/dev/null || true)

# === Existing entries: для дедупа ===
EXISTING=$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' "$CUSTOM_LOCAL" 2>/dev/null | sort -u || true)

# === TTL cleanup: удаляем записи старше TTL_DAYS если IP больше не в events.db ===
# Формат записи: после блока заголовка "# Auto-promoted YYYY-MM-DDTHH:MM:SSZ ..." идут IP'шники.
# Если timestamp блока > TTL_DAYS дней назад И IP не появлялся в events.db за последние 30д — удаляем.
cleanup_old_entries() {
    local cutoff_ttl
    cutoff_ttl=$(date -u -d "$TTL_DAYS days ago" +%s 2>/dev/null || date -v-${TTL_DAYS}d -u +%s 2>/dev/null || echo 0)
    if [ "$cutoff_ttl" -eq 0 ]; then
        logger -t "$LOG_TAG" "WARN: TTL cleanup skipped — date command failed (GNU/BSD compat issue?)"
        return 0
    fi

    local recent_attackers
    recent_attackers=$(sqlite3 "$DB" "
        SELECT DISTINCT ip FROM events
        WHERE last_seen > strftime('%s','now') - 2592000
        ORDER BY ip;
    " 2>/dev/null | sort -u)

    # Парсим файл блочно: блок начинается с "# Auto-promoted DATE..."
    python3 - <<CLEANUP_PYTHON_EOF
import re
import datetime
import os

custom_file = "$CUSTOM_LOCAL"
cutoff_ttl = $cutoff_ttl
ttl_days = $TTL_DAYS

with open(custom_file) as f:
    content = f.read()

# Recent attackers (last 30 days) — IP, который мы НЕ удаляем даже если старый
recent_set = set("""$recent_attackers""".strip().splitlines())

lines = content.splitlines(keepends=True)
out = []
i = 0
removed_count = 0

while i < len(lines):
    line = lines[i]
    # Ищем заголовок auto-promoted блока
    m = re.match(r'^# Auto-promoted (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', line.strip())
    if m:
        try:
            block_time = datetime.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
        except Exception:
            block_time = None

        if block_time and block_time < cutoff_ttl:
            # Блок старый — собираем IP'шники
            block_ips = []
            j = i + 1
            while j < len(lines):
                ip_line = lines[j].strip()
                if not ip_line or ip_line.startswith('#'):
                    break
                if re.match(r'^\d+\.\d+\.\d+\.\d+', ip_line):
                    block_ips.append(ip_line)
                else:
                    break
                j += 1

            # Фильтруем: оставляем только те IP что недавно атаковали
            kept = [ip for ip in block_ips if ip in recent_set]
            removed_count += len(block_ips) - len(kept)

            if kept:
                out.append(line)  # сохраняем заголовок
                # Обновляем заголовок: помечаем как TTL-сurated
                out[-1] = out[-1].rstrip('\n') + ' (TTL-curated)\n'
                for ip in kept:
                    out.append(ip + '\n')
            # Если kept пустой — блок полностью удалён

            i = j
            continue

    out.append(line)
    i += 1

with open(custom_file, 'w') as f:
    f.writelines(out)

print(f"TTL cleanup: removed {removed_count} stale entries (>{ttl_days}d, not seen in events.db last 30d)")
CLEANUP_PYTHON_EOF
}

# Запускаем cleanup только раз в сутки (не на каждом тике каждые 6h)
LAST_CLEANUP_FILE=/var/lib/shieldnode/.last-promote-cleanup
LAST_CLEANUP=$(cat "$LAST_CLEANUP_FILE" 2>/dev/null || echo 0)
LAST_CLEANUP="${LAST_CLEANUP:-0}"
NOW=$(date +%s)
if [ $((NOW - LAST_CLEANUP)) -gt 86400 ]; then
    cleanup_output=$(cleanup_old_entries 2>&1 || true)
    [ -n "$cleanup_output" ] && logger -t "$LOG_TAG" "$cleanup_output"
    echo "$NOW" > "$LAST_CLEANUP_FILE"
fi

# Перечитываем EXISTING после cleanup (могли удалиться записи)
EXISTING=$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' "$CUSTOM_LOCAL" 2>/dev/null | sort -u || true)

[ -z "$NEW_IPS" ] && { logger -t "$LOG_TAG" "no candidates"; exit 0; }

TO_ADD=$(comm -23 <(echo "$NEW_IPS" | sort -u) <(echo "$EXISTING"))
[ -z "$TO_ADD" ] && { logger -t "$LOG_TAG" "all candidates already in custom-local"; exit 0; }

# === Динамический whitelist ===
detect_my_ip() {
    local ip iface
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')
    [ -n "$ip" ] && { echo "$ip"; return; }
    iface=$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')
    [ -n "$iface" ] && ip=$(ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$ip" ] && { echo "$ip"; return; }
    hostname -I 2>/dev/null | tr ' ' '\n' | \
        grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)' | \
        head -1
}
MY_IP=$(detect_my_ip)

get_dns_servers() {
    {
        grep -hE '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'
        resolvectl status 2>/dev/null | awk '/Current DNS Server:|DNS Servers:/ {for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i}'
        [ -r /run/systemd/resolve/resolv.conf ] && grep -hE '^nameserver' /run/systemd/resolve/resolv.conf 2>/dev/null | awk '{print $2}'
    } | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u
}
DNS_SERVERS=$(get_dns_servers)

LOCAL_IPS=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -vE '^127\.' || true)

WHITELIST_BASE='^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|2[3-5][0-9]\.)'

FILTER_IPS=$(echo "$TO_ADD" | grep -vE "$WHITELIST_BASE" || true)

for system_ip in $DNS_SERVERS $LOCAL_IPS $MY_IP; do
    [ -z "$system_ip" ] && continue
    FILTER_IPS=$(echo "$FILTER_IPS" | grep -vxF "$system_ip" || true)
done

[ -z "$FILTER_IPS" ] && { logger -t "$LOG_TAG" "all candidates whitelisted"; exit 0; }

COUNT=$(echo "$FILTER_IPS" | wc -l)
{
    echo ""
    echo "# Auto-promoted $(date -u +%FT%TZ) ($COUNT IPs, count>=$PROMOTE_THRESHOLD cumulative, conn_flood/syn-udp-escalate)"
    echo "$FILTER_IPS"
} >> "$CUSTOM_LOCAL"

DNS_LIST=$(echo "$DNS_SERVERS" | tr '\n' ',' | sed 's/,$//')
logger -t "$LOG_TAG" "promoted $COUNT IPs (whitelist DNS=$DNS_LIST, MY_IP=$MY_IP)"

# CrowdSec whitelist cross-check: убираем из custom-local IP которые
# CrowdSec пометил как whitelisted (избегаем конфликта приоритетов).
if command -v cscli >/dev/null 2>&1; then
    CS_WHITELIST=$(cscli alerts list -o json 2>/dev/null | \
        python3 -c "import json,sys
try:
    data=json.load(sys.stdin)
    for alert in data or []:
        for dec in (alert.get('decisions') or []):
            if dec.get('type')=='whitelist' and dec.get('scope')=='Ip':
                print(dec.get('value',''))
except Exception: pass" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)

    if [ -n "$CS_WHITELIST" ]; then
        REMOVED=0
        while IFS= read -r wl_ip; do
            if grep -qxF "$wl_ip" "$CUSTOM_LOCAL" 2>/dev/null; then
                sed -i "/^${wl_ip//./\\.}$/d" "$CUSTOM_LOCAL"
                REMOVED=$((REMOVED + 1))
            fi
        done <<< "$CS_WHITELIST"
        [ "$REMOVED" -gt 0 ] && logger -t "$LOG_TAG" "removed $REMOVED IPs from custom-local (CrowdSec whitelist conflict)"
    fi
fi

# Trigger custom-updater
if ! systemctl is-active --quiet shieldnode-update@custom.path 2>/dev/null; then
    systemctl start shieldnode-update@custom.service 2>/dev/null || true
fi
PROMOTE_SCRIPT_EOF

# v3.23.13 BUG-019 FIX: подставляем настраиваемые значения из limits.conf
sed -i \
    -e "s|__SHIELD_CUSTOM_LOCAL_TTL_DAYS__|$SHIELD_CUSTOM_LOCAL_TTL_DAYS|g" \
    -e "s|__SHIELD_AUTOPROMOTE_THRESHOLD__|$SHIELD_AUTOPROMOTE_THRESHOLD|g" \
    -e "s|__SHIELD_AUTOPROMOTE_WINDOW_HOURS__|$SHIELD_AUTOPROMOTE_WINDOW_HOURS|g" \
    /usr/local/sbin/shieldnode-auto-promote.sh
verify_no_placeholders /usr/local/sbin/shieldnode-auto-promote.sh || exit 1

chmod +x /usr/local/sbin/shieldnode-auto-promote.sh

cat > /etc/systemd/system/shieldnode-auto-promote.service <<'PROMOTE_UNIT_EOF'
[Unit]
Description=Shieldnode auto-promote chronic attackers to custom-local.txt
After=shieldnode-nftables.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shieldnode-auto-promote.sh
Nice=10
PROMOTE_UNIT_EOF

cat > /etc/systemd/system/shieldnode-auto-promote.timer <<'PROMOTE_TIMER_EOF'
[Unit]
Description=Run shieldnode-auto-promote every 6 hours

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
PROMOTE_TIMER_EOF

systemctl daemon-reload
systemctl enable shieldnode-auto-promote.timer >/dev/null 2>&1
systemctl start shieldnode-auto-promote.timer >/dev/null 2>&1
print_ok "Auto-promote enabled (каждые 6ч, count>=800 cumulative, conn_flood/syn-udp-escalate)"

# ==============================================================================
# ШАГ 12.9: CROWDSEC SCENARIO (v3.23.3) — conn_flood публикация в community
# ==============================================================================

print_header "ШАГ 12.9: CROWDSEC scenario для conn_flood"

# Локальные conn_flood/syn_flood events публикуются в CrowdSec community blocklist.
# Twoи данные помогают community, ты получаешь более полный feed.
# v3.23.3: парсер исправлен под реальный формат events.log:
#   [2026-05-24 12:34:56] SYN-ESCALATE ip=1.2.3.4 hits=2000 (suspect→confirmed via SYN-flood)
#   [2026-05-24 12:35:01] CONN-FLOOD ip=5.6.7.8 hits=5000 (...)

CS_SCEN_DIR=/etc/crowdsec/scenarios
EVENTS_LOG_FILE=/var/log/shieldnode/events.log

if [ -d "$CS_SCEN_DIR" ] && [ -f "$EVENTS_LOG_FILE" ]; then
    cat > "$CS_SCEN_DIR/shieldnode-conn-flood.yaml" <<'CS_SCEN_EOF'
# shieldnode conn_flood scenario for CrowdSec community publication
# Reads from /var/log/shieldnode/events.log
type: leaky
name: shieldnode/conn-flood
description: "Detect chronic conn_flood/syn_flood attackers via shieldnode events"
filter: "evt.Meta.log_type == 'shieldnode_event' && evt.Meta.event_type in ['SYN-ESCALATE','UDP-ESCALATE','CONN-FLOOD','SYN-FLOOD']"
groupby: evt.Meta.source_ip
distinct: evt.Meta.source_ip
leakspeed: "10s"
capacity: 5
blackhole: 24h
labels:
    service: shieldnode
    type: ddos
    remediation: true
    classification:
        - attack.t1499
CS_SCEN_EOF

    # Parser под реальный формат: [YYYY-MM-DD HH:MM:SS] EVENT-TYPE ip=X.X.X.X hits=N (...)
    CS_PARSER_DIR=/etc/crowdsec/parsers/s01-parse
    mkdir -p "$CS_PARSER_DIR"
    cat > "$CS_PARSER_DIR/shieldnode-events.yaml" <<'CS_PARSER_EOF'
# Parser для /var/log/shieldnode/events.log
# Реальный формат строки:
#   [2026-05-24 12:34:56] SYN-ESCALATE ip=1.2.3.4 hits=2000 (...)
filter: "evt.Line.Labels.type == 'shieldnode_event'"
onsuccess: next_stage
name: shieldnode/events-parser
description: "Parse shieldnode event log entries"
nodes:
    - grok:
        # Реальный формат:
        #   [2026-05-24 12:34:56] SYN-ESCALATE ip=1.2.3.4 hits=2000 (...)
        #   [TS] UFW-BLOCK ip=X.X.X.X dpt=N hits=N (port scan / closed port)
        # Используем NOTSPACE для event_type (точечный матч без жадности).
        pattern: '^\[%{TIMESTAMP_ISO8601:timestamp}\] %{NOTSPACE:event_type} ip=%{IPV4:source_ip}(?: dpt=%{NUMBER:dport})? hits=%{NUMBER:hits}'
        apply_on: message
      statics:
        - meta: log_type
          value: shieldnode_event
        - meta: source_ip
          expression: evt.Parsed.source_ip
        - meta: event_type
          expression: evt.Parsed.event_type
CS_PARSER_EOF

    # Acquisition (только если events.log реально существует и пишется)
    CS_ACQ_DIR=/etc/crowdsec/acquis.d
    mkdir -p "$CS_ACQ_DIR"
    cat > "$CS_ACQ_DIR/shieldnode.yaml" <<CS_ACQ_EOF
filenames:
  - $EVENTS_LOG_FILE
labels:
  type: shieldnode_event
CS_ACQ_EOF

    # Reload CrowdSec
    if systemctl is-active --quiet crowdsec 2>/dev/null; then
        systemctl reload crowdsec 2>/dev/null || systemctl restart crowdsec 2>/dev/null || true
        print_ok "CrowdSec scenario shieldnode/conn-flood добавлен (parser исправлен под реальный формат)"
    else
        print_info "CrowdSec scenario записан, но сервис не активен — старт пропущен"
    fi
elif [ ! -f "$EVENTS_LOG_FILE" ]; then
    print_info "events.log ещё не создан — CrowdSec scenario пропущен (создастся при следующих событиях)"
else
    print_warn "CrowdSec не установлен, scenario пропущен"
fi

# ==============================================================================
# ШАГ 13: HEALTHCHECK
# ==============================================================================

print_header "ШАГ 13: HEALTHCHECK"

# v3.10.2 SMOKE TEST: ловим регрессии типа v3.5 ct count bug или v3.10 parser bug
# на этапе установки, чтобы не выкатывать сломанную защиту в прод.
print_status "Smoke-test: проверяю что защита реально активна..."

SMOKE_FAIL=0

# v3.18.8 UFW-FIX: восстановление UFW kernel state.
# `ufw status` определяет active/inactive по наличию kernel chain
# `ufw-user-input` (через iptables-nft на Ubuntu 24). Если что-то в процессе
# установки флушнуло ruleset (bouncer post-inst regression / external race),
# config-файл /etc/ufw/ufw.conf остаётся ENABLED=yes, но `ufw status` →
# inactive. Восстанавливаем через disable→enable: ufw перечитает rules.* и
# заново создаст цепочки в kernel.
if [ "${FIREWALL_TYPE:-}" = "ufw" ]; then
    if ! LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
        print_warn "UFW потерял kernel state в процессе установки — восстанавливаю"
        ufw --force disable >/dev/null 2>&1 || true
        if ufw --force enable >/dev/null 2>&1 && \
           LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
            print_ok "UFW восстановлен"
            # Наша таблица могла улететь вместе с UFW — рестартуем сервис
            systemctl restart shieldnode-nftables.service >/dev/null 2>&1 || true
            # Bouncer тоже мог потерять свои таблицы
            systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || true
        else
            print_error "UFW не восстановился — manual fix: sudo ufw --force enable"
        fi
    fi
fi

# 1. Таблица создана?
# v3.16.3: если нет — пробуем re-load один раз (например bouncer pre-inst flushed)
if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    print_warn "Таблица inet ddos_protect отсутствует — пробую перезагрузить"
    nft -f /etc/nftables.d/ddos-protect.conf 2>/dev/null
    sleep 1
    systemctl restart shieldnode-nftables.service >/dev/null 2>&1
    sleep 2
fi

if ! nft list table inet ddos_protect >/dev/null 2>&1; then
    print_error "FAIL: таблица inet ddos_protect не создана"
    print_info "Manual fix: sudo nft -f /etc/nftables.d/ddos-protect.conf"
    SMOKE_FAIL=1
else
    print_ok "Smoke: таблица inet ddos_protect создана"
fi

# 2. protected_ports_tcp непустой если в UFW есть TCP-правила
# v3.11.3 BUG-MULTILINE FIX: nft форматирует длинные `elements = { ... }`
# на несколько строк (после ~7 элементов). grep -oE на single-line не матчит
# multi-line блок → SMOKE_TCP=0 → ложный FAIL даже когда set заполнен.
# Fix: tr '\n' ' ' для flattening (тот же подход что в updater'e CUR_TCP).
if [ -n "$PROTECTED_TCP" ]; then
    SMOKE_TCP=$(nft list set inet ddos_protect protected_ports_tcp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | wc -l)
    if [ "$SMOKE_TCP" -eq 0 ]; then
        print_error "FAIL: protected_ports_tcp пуст, ожидается: $PROTECTED_TCP"
        print_info "Возможные причины: port-range в UFW или локализованный 'ufw status'"
        print_info "Проверь:  sudo /usr/local/sbin/update-protected-ports.sh"
        print_info "          sudo journalctl -t protected-ports -n 20"
        SMOKE_FAIL=1
    else
        print_ok "Smoke: protected_ports_tcp содержит $SMOKE_TCP портов/диапазонов"
    fi
fi

# 3. protected_ports_udp непустой если в UFW есть UDP-правила (same multi-line fix)
if [ -n "$PROTECTED_UDP" ]; then
    SMOKE_UDP=$(nft list set inet ddos_protect protected_ports_udp 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+(-[0-9]+)?' | wc -l)
    if [ "$SMOKE_UDP" -eq 0 ]; then
        print_error "FAIL: protected_ports_udp пуст, ожидается: $PROTECTED_UDP"
        SMOKE_FAIL=1
    else
        print_ok "Smoke: protected_ports_udp содержит $SMOKE_UDP портов/диапазонов"
    fi
fi

# 4. Все обязательные cleanup-цепочки и подцепочки на месте.
# v3.20.6: УБРАН 'forward' из списка обязательных — MSS clamp forward chain
# удалён в v3.20.5 (зона ответственности vpn-node-setup, table inet vpn_node_mss_clamp).
# Раньше smoke-test FAIL'ил на нодах с v3.20.5 потому что forward chain
# намеренно отсутствует.
for chain in prerouting newconn_overflow syn_overflow udp_overflow; do
    if ! nft list chain inet ddos_protect "$chain" >/dev/null 2>&1; then
        print_error "FAIL: цепочка inet ddos_protect $chain не создана"
        SMOKE_FAIL=1
    fi
done

# v3.21.5: проверка что infrastructure bypass работает.
# Set должен существовать и содержать хотя бы Apple /8 (стабильнее всех).
if ! nft list set inet ddos_protect infrastructure_v4 >/dev/null 2>&1; then
    print_error "FAIL: set inet ddos_protect infrastructure_v4 не создан"
    print_info "Manual check: sudo nft list set inet ddos_protect infrastructure_v4"
    SMOKE_FAIL=1
else
    INFRA_COUNT=$(nft list set inet ddos_protect infrastructure_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE 'elements = \{[^}]*\}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | wc -l)
    if [ "$INFRA_COUNT" -lt 50 ]; then
        print_warn "WARN: infrastructure_v4 содержит только $INFRA_COUNT CIDR (ожидается >50)"
    else
        print_ok "Smoke: infrastructure_v4 set активен ($INFRA_COUNT CIDR блоков)"
    fi
fi

# v3.21.5: проверка что counter infrastructure_passes_v4 объявлен.
if ! nft list counter inet ddos_protect infrastructure_passes_v4 >/dev/null 2>&1; then
    print_warn "WARN: counter infrastructure_passes_v4 не объявлен"
fi

# 5. shieldnode-nftables.service в active-состоянии
if ! systemctl is-active --quiet shieldnode-nftables.service; then
    print_error "FAIL: shieldnode-nftables.service не active"
    print_info "Логи: sudo journalctl -u shieldnode-nftables -n 30"
    SMOKE_FAIL=1
fi

# 6. updater запускается без ошибок и нашёл хоть что-то
print_status "Smoke: запускаю updater вручную для проверки парсера..."
if ! /usr/local/sbin/update-protected-ports.sh 2>&1 | head -10; then
    : # не fatal — updater может exit 0 с "no change"
fi
sleep 1

# 7. Проверка что FIREWALL_ACTIVE детектится (для locale-fix BUG-8)
case "$FIREWALL_TYPE" in
    ufw)
        if ! LANG=C LC_ALL=C ufw status 2>/dev/null | grep -q "Status: active"; then
            print_warn "WARN: FIREWALL_ACTIVE детект мог не сработать"
            print_info "Если у тебя локализованный 'ufw status' — обновись до v3.10.2+"
        fi
        ;;
esac

# 8. v3.10.3 BUG-9: bouncer работает на правильном hook (prerouting, не input)
if systemctl is-active --quiet crowdsec-firewall-bouncer; then
    sleep 2  # дать bouncer'у время создать таблицу
    # Bouncer создаёт `table ip crowdsec` (не inet, не наша). Проверяем что
    # цепочка в этой таблице висит на prerouting hook с priority -200.
    if nft list chain ip crowdsec crowdsec-chain-prerouting >/dev/null 2>&1; then
        BOUNCER_PRIO=$(nft list chain ip crowdsec crowdsec-chain-prerouting 2>/dev/null | grep -oE 'priority [a-z]* ?[+-]?[0-9]+' | head -1)
        print_ok "Smoke: bouncer на prerouting hook ($BOUNCER_PRIO) — раньше нашего"
    elif nft list chain ip crowdsec crowdsec-chain-input >/dev/null 2>&1; then
        print_warn "WARN: bouncer всё ещё на input hook — fix не сработал"
        print_info "Проверь /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
        print_info "Должно быть: nftables_hooks: - prerouting, priority: -200"
    elif nft list table ip crowdsec >/dev/null 2>&1; then
        print_info "Smoke: bouncer table создана, но цепочка с непредсказуемым именем"
    else
        # Bouncer ещё не успел создать таблицу — возможно CAPI sync в процессе
        print_info "Smoke: bouncer table ещё не создана (вероятно в процессе sync с CAPI)"
    fi
fi

# 9. v3.10.3 BUG-10: bouncer не пытается работать с IPv6 если он отключён
if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = "1" ]; then
    if [ -f /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ]; then
        # Проверяем что в config'е ipv6 disabled
        if awk '/^[[:space:]]*ipv6:/{f=1} f && /^[[:space:]]*enabled:[[:space:]]*true/{exit 1} /^[a-zA-Z]/{f=0}' \
            /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml; then
            print_ok "Smoke: bouncer IPv6 disabled (соответствует sysctl)"
        else
            print_warn "WARN: IPv6 disabled в системе, но НЕ в bouncer config — будут ошибки в логе"
        fi
    fi
fi

# 10. v3.10.3 BUG-11: mgmt IPs в CrowdSec whitelist
if [ -n "$MGMT_IPV4" ] && command -v cscli >/dev/null 2>&1; then
    # v3.22.0: timeout 5s — на ноде с активным CAPI subscription
    # (~28k decisions) cscli list делает full table scan и может зависнуть.
    WL_COUNT=$(timeout 5 cscli decisions list --type whitelist -o raw 2>/dev/null | tail -n +2 | wc -l)
    EXPECTED_COUNT=$(echo "$MGMT_IPV4" | tr ',' '\n' | grep -c .)
    if [ "$WL_COUNT" -ge "$EXPECTED_COUNT" ]; then
        print_ok "Smoke: $WL_COUNT mgmt IPs в CrowdSec whitelist"
    else
        print_warn "WARN: только $WL_COUNT из $EXPECTED_COUNT mgmt IPs в whitelist"
    fi
fi

# 11. v3.10.4 BUG-14: SSH acquisition реально работает
if command -v cscli >/dev/null 2>&1; then
    sleep 1
    # cscli metrics show acquisition покажет источники
    # v3.22.0: timeout 5s
    SSH_ACQ_LINES=$(timeout 5 cscli metrics show acquisition 2>/dev/null | grep -cE "auth\.log|sshd\.service")
    SSH_ACQ_LINES="${SSH_ACQ_LINES:-0}"
    if [ "$SSH_ACQ_LINES" -gt 0 ]; then
        print_ok "Smoke: SSH acquisition активен ($SSH_ACQ_LINES источников)"
    else
        # Может быть еще не успели получить метрики - не fatal
        print_info "Smoke: SSH acquisition метрики ещё пустые (нет логин-попыток с момента старта)"
    fi
fi

# 12. v3.10.4 BUG-15: CAPI работает → community blocklist приходит
if command -v cscli >/dev/null 2>&1; then
    if cscli capi status >/dev/null 2>&1; then
        # Подсчёт CAPI decisions (community blocklist)
        # v3.22.0: timeout 5s + fallback на sqlite если cscli таймаут
        CAPI_DECISIONS=$(timeout 5 cscli decisions list --origin CAPI -o raw 2>/dev/null | tail -n +2 | wc -l)
        if [ -z "$CAPI_DECISIONS" ] || [ "$CAPI_DECISIONS" -eq 0 ]; then
            # Fallback на прямой SQL — быстрее для больших БД
            if [ -r /var/lib/crowdsec/data/crowdsec.db ] && command -v sqlite3 >/dev/null 2>&1; then
                CAPI_DECISIONS=$(timeout 5 sqlite3 /var/lib/crowdsec/data/crowdsec.db \
                    "SELECT COUNT(*) FROM decisions WHERE origin='CAPI' AND until > datetime('now')" \
                    2>/dev/null)
                CAPI_DECISIONS="${CAPI_DECISIONS:-0}"
            fi
        fi
        if [ "$CAPI_DECISIONS" -gt 0 ]; then
            print_ok "Smoke: $CAPI_DECISIONS CAPI decisions (community blocklist работает)"
        else
            print_info "Smoke: CAPI registered, но 0 decisions yet (придут через 1-2 часа)"
        fi
    else
        print_warn "WARN: CAPI status не OK — нет community blocklist"
    fi
fi

# 13. v3.10.4 BUG-19: scenarios в simulation mode (не банят, только alerts)
if command -v cscli >/dev/null 2>&1; then
    SIM_COUNT=$(cscli simulation status 2>/dev/null | grep -cE "^\s*-\s+")
    SIM_COUNT="${SIM_COUNT:-0}"
    if [ "$SIM_COUNT" -gt 0 ]; then
        print_info "Smoke: $SIM_COUNT scenarios в simulation mode (alerts only, без bans)"
        print_info "       Список: cscli simulation status"
    fi
fi

# 14. v3.11: Tor blocklist загружен если BLOCK_TOR=1
if [ "$BLOCK_TOR" = "1" ]; then
    TOR_SET_COUNT=$(nft list set inet ddos_protect tor_exit_blocklist_v4 2>/dev/null | \
        tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    if [ "$TOR_SET_COUNT" -ge 100 ]; then
        print_ok "Smoke: Tor blocklist загружен ($TOR_SET_COUNT exit nodes)"
    elif [ "$TOR_SET_COUNT" -gt 0 ]; then
        print_warn "WARN: Tor blocklist подозрительно мал ($TOR_SET_COUNT IPs, ожидается 1000+)"
        print_info "       Проверь: journalctl -u shieldnode-update@tor -n 30"
    else
        print_error "FAIL: BLOCK_TOR=1 включён, но Tor blocklist пустой"
        print_info "       Проверь: journalctl -u shieldnode-update@tor -n 30"
        SMOKE_FAIL=1
    fi
    # Timer должен быть active (v3.12.0: templated unit)
    if systemctl is-active --quiet shieldnode-update@tor.timer; then
        print_ok "Smoke: shieldnode-update@tor.timer активен (hourly refresh)"
    else
        print_warn "WARN: shieldnode-update@tor.timer не active"
    fi
fi

if [ "$SMOKE_FAIL" -eq 1 ]; then
    print_error ""
    print_error "Smoke-test НЕ ПРОЙДЕН. Защита может работать частично или не работать совсем."
    print_error "Не используй ноду в проде до устранения проблем выше."
    print_error ""
else
    print_ok "Smoke-test пройден"

    # v3.18.8: гарантированный finalize-trigger всех blocklists после smoke-test.
    # Защита от race condition в ШАГ 6: если первый запуск updater'а попал в
    # окно между ExecStop/ExecStart shieldnode-nftables.service — set остался
    # пустой. Сейчас nft table 100% активна (smoke-test это проверил),
    # перезапускаем все updater'ы один раз для гарантии загрузки.
    print_status "Финальная загрузка blocklists (после smoke-test)..."
    # v3.20.6: mobile_ru удалён из списка — whitelist отменён в v3.20.0
    for n in scanner threat tor custom; do
        # Только если сервис вообще существует (например tor — только при BLOCK_TOR=1)
        if [ -f "/etc/systemd/system/shieldnode-update@${n}.service" ] || \
           systemctl cat "shieldnode-update@${n}.service" >/dev/null 2>&1; then
            # timeout — на случай если внешний URL feed виснет
            timeout --kill-after=10s 60s \
              systemctl start "shieldnode-update@${n}.service" 2>/dev/null || true
        fi
    done
    # Краткий отчёт по размерам set'ов
    for n in scanner threat tor custom; do
        SET_NAME=$(case "$n" in
            scanner)      echo "scanner_blocklist_v4" ;;
            threat)       echo "threat_blocklist_v4"  ;;
            tor)          echo "tor_exit_blocklist_v4" ;;
            custom)       echo "custom_blocklist_v4"  ;;
        esac)
        SIZE=$(nft list set inet ddos_protect "$SET_NAME" 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
        SIZE="${SIZE:-0}"
        if [ "$SIZE" -gt 0 ]; then
            print_ok "  $n: $SIZE entries"
        else
            print_info "  $n: 0 entries (внешние feeds могут быть недоступны или disabled)"
        fi
    done
fi
echo ""

print_info "Жду 5 секунд чтобы парсеры успели прочитать логи..."
sleep 5

print_status "CrowdSec metrics:"
echo ""
# v1.5 fix: head закрывает pipe раньше времени → SIGPIPE → false-negative.
# Сохраняем в переменную, потом печатаем — без pipe-зависимости.
METRICS_OUT=$(cscli metrics 2>/dev/null)
if [ -n "$METRICS_OUT" ]; then
    echo "$METRICS_OUT" | head -50 | sed 's/^/    /'
else
    print_warn "cscli metrics вернул пусто — проверь journalctl -u crowdsec"
fi
echo ""

# v3.22.0: timeout 5s + sqlite fallback. На нодах с активной CAPI subscription
# (~28k decisions) cscli делает full scan, что может занять 10+ сек.
ACTIVE_BANS=$(timeout 5 cscli decisions list --type ban -o raw 2>/dev/null | tail -n +2 | wc -l)
if [ -z "$ACTIVE_BANS" ] || [ "$ACTIVE_BANS" -eq 0 ]; then
    if [ -r /var/lib/crowdsec/data/crowdsec.db ] && command -v sqlite3 >/dev/null 2>&1; then
        ACTIVE_BANS=$(timeout 5 sqlite3 /var/lib/crowdsec/data/crowdsec.db \
            "SELECT COUNT(*) FROM decisions WHERE type='ban' AND until > datetime('now')" \
            2>/dev/null)
        ACTIVE_BANS="${ACTIVE_BANS:-0}"
    fi
fi
ACTIVE_BANS="${ACTIVE_BANS:-0}"

if [ "$ACTIVE_BANS" -gt 0 ]; then
    print_ok "Активных банов: $ACTIVE_BANS"
else
    print_info "Активных банов нет (норма для свежей установки)"
fi

# v1.3: scanner blocklist size
BL_V4=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
if [ "$BL_V4" -gt 0 ]; then
    print_ok "Scanner blocklist: $BL_V4 IPv4 подсетей"
else
    print_warn "Scanner blocklist пуст — проверь journalctl -u shieldnode-update@scanner"
fi

# ==============================================================================
# ШАГ 14: ИТОГИ (v3.12.0 — компактно)
# ==============================================================================

# v1.5 fix: $0 на pipe-mode = /dev/fd/63
SCRIPT_NAME="$0"
case "$SCRIPT_NAME" in
    /dev/fd/*|/proc/*|bash|-bash|sh|-sh) SCRIPT_NAME="shieldnode.sh" ;;
esac

# Метрики для summary
SCANNER_NUM=$(nft list set inet ddos_protect scanner_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
THREAT_NUM=$(nft list set inet ddos_protect threat_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
CUSTOM_NUM=$(nft list set inet ddos_protect custom_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | wc -l)
TOR_NUM=$(nft list set inet ddos_protect tor_exit_blocklist_v4 2>/dev/null | tr '\n' ' ' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
# v3.20.6: MOBILE_RU_NUM удалён — mobile_ru_whitelist_v4 set не существует
# после удаления whitelist'а в v3.20.0.
CS_NUM=0
if [ -r /var/lib/crowdsec/data/crowdsec.db ] && command -v sqlite3 >/dev/null 2>&1; then
    CS_NUM=$(sqlite3 /var/lib/crowdsec/data/crowdsec.db "SELECT COUNT(*) FROM decisions WHERE type='ban' AND until > datetime('now')" 2>/dev/null)
fi
CS_NUM="${CS_NUM:-0}"
TCP_PORTS_COUNT=$(echo "$XRAY_PORTS_TCP" | tr ',' '\n' | grep -c .)

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓${NC} ${BOLD}shieldnode v${SHIELDNODE_VERSION} установлен${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Защита активна:${NC}"
echo -e "   • TCP-порты:     ${CYAN}${XRAY_PORTS_TCP}${NC} (${TCP_PORTS_COUNT} шт.)"
[ -n "$XRAY_PORTS_UDP" ] && echo -e "   • UDP-порты:     ${CYAN}${XRAY_PORTS_UDP}${NC}"
echo -e "   • CrowdSec:      $(printf "%'d" "$CS_NUM") IPs (community CAPI)"
BL_LINE="scanner=$(printf "%'d" "${SCANNER_NUM:-0}"), threat=$(printf "%'d" "${THREAT_NUM:-0}"), custom=$(printf "%'d" "${CUSTOM_NUM:-0}")"
[ "${TOR_NUM:-0}" -gt 0 ] && BL_LINE="$BL_LINE, tor=$(printf "%'d" "$TOR_NUM")"
echo -e "   • Blocklists:    ${BL_LINE}"
# v3.20.6: блок Mobile-RU удалён — whitelist отменён в v3.20.0, оставшаяся
# отображалка вводила в заблуждение ("первый sync через несколько минут" —
# никакого sync не будет, фичи нет).
echo -e "   • Лимиты:        ct=15000, new-conn=40000/min ${DIM}(500-1000 client base)${NC}"
# v3.14.0: статус auto-sync features
if [ "${ENABLE_GITHUB_SYNC:-1}" = "1" ]; then
    echo -e "   • GitHub sync:   ${GREEN}ON${NC}  ${DIM}(custom.txt каждые 6ч)${NC}"
else
    echo -e "   • GitHub sync:   ${DIM}OFF${NC}"
fi
if [ "${ENABLE_VERSION_CHECK:-1}" = "1" ]; then
    echo -e "   • Version check: ${GREEN}ON${NC}  ${DIM}(раз в день)${NC}"
else
    echo -e "   • Version check: ${DIM}OFF${NC}"
fi
echo ""
echo -e "  ${BOLD}Команды:${NC}"
echo -e "   ${CYAN}sudo guard${NC}                — дашборд защиты + меню (включая [s] settings)"
echo -e "   ${CYAN}sudo guard --once${NC}         — снимок без меню"
echo -e "   ${CYAN}sudo guard upgrade${NC}        — обновить до новой версии с github"
echo -e "   ${CYAN}sudo guard sync${NC}           — синк custom.txt прямо сейчас"
echo -e "   ${CYAN}sudo guard check${NC}          — проверить новую версию прямо сейчас"
echo -e "   ${CYAN}sudo bash $SCRIPT_NAME --uninstall${NC}  — удалить"
echo ""
if [ "${SSHD_PASSWORD_AUTH_ENABLED:-0}" = "1" ]; then
    echo -e "  ${YELLOW}⚠${NC} SSH password-auth ВКЛЮЧЁН. Для максимальной защиты:"
    echo -e "    ${DIM}1) ssh-keygen → ssh-copy-id → проверь логин по ключу${NC}"
    echo -e "    ${DIM}2) sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config${NC}"
    echo -e "    ${DIM}3) sshd -t && systemctl reload ssh${NC}"
    echo ""
fi
if [ -d "$BACKUP_DIR" ]; then
    echo -e "  ${DIM}Бэкап: $BACKUP_DIR${NC}"
fi
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
