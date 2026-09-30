# INSTALL 02 — HA-пара (Go-контур)

Продолжает [01-standalone.md](01-standalone.md): пара собирается из ДВУХ уже работающих одиночных узлов.

> **§1–4 делает установщик** (`deploy/install.sh`): раскладку, пользователя `dns-ha`, базу `dns_ha` с её грантами,
> `ha.toml`/`ha-agent.toml`, запуск `dns-ha-agent` и `dns-ha-manager` и `[ha] enabled = true`. Они описаны ниже
> как справка — что и почему лежит на узле. Руками начинается с §5: сопряжение и создание пары в панели.

Механику и обоснования см. в [../23-ha-manager.md](../23-ha-manager.md), правила переключения — в
[../22-ha-contract.md](../22-ha-contract.md).

---

## 0. Что получится

```
                    http://<service-address>/           ← панель работает ТОЛЬКО отсюда
                              │
                       текущий ACTIVE
              MariaDB rw · PowerDNS primary · сервисный адрес
                              │  async-репликация
                          STANDBY
              MariaDB read-only · PowerDNS без роли (no/no)
```

Два процесса на каждом узле:

| процесс | под кем | зачем |
|---|---|---|
| `dns-ha-manager` | `dns-ha` | наблюдает, решает, проводит операции; peer-канал к соседу (TCP 7901) |
| `dns-ha-agent` | `root` | единственный, кто трогает узел: MariaDB, PowerDNS, адрес публикации |

Граница между ними — не украшение: сетевой процесс не имеет прав менять роль узла, а привилегированный не
принимает решений.

---

## 1. Раскладка

Продукт живёт одним деревом (см. [../23-ha-manager.md](../23-ha-manager.md) §14.4):

```
/opt/dns-panel/{bin,etc,var,www,docs}
/run/dns-panel/ha      сокеты и блокировки HA-контура    root:dns-ha    0770
/run/dns-panel/pdns    сокет dns-agent                   pdns:www-data  2750
/run/dns-panel/sync    wake-сокет dns-sync-worker        www-data:dns-ha 2750
/run/dns-panel/pulse   управляющий сокет pulse-server    root:www-data  0770
/var/www/vhost/dns-panel → /opt/dns-panel/www
```

Каталоги в `/run` создаёт `etc/tmpfiles/dns-panel.conf`; системные каталоги (`/etc/systemd/system`,
`/etc/tmpfiles.d`, `/etc/apache2/sites-available`, `/etc/mysql/mariadb.conf.d`, `/etc/powerdns/pdns.d`)
содержат только симлинки в `/opt/dns-panel/etc`.

---

## 2. Учётные записи и секреты (на каждом узле)

Системный пользователь и группа `dns-ha`; `www-data` входит в `dns-ha` — панель пользуется IPC-сокетами HA и
ничем сверх этого. MariaDB: пользователь `dns-ha` с unix_socket-аутентификацией (§3).

**Секреты пары руками не создаются.** Ни одного из этих файлов на одиночном узле нет, и это правильное
состояние:

```
/opt/dns-panel/etc/secrets/peer.key            появляется при СОПРЯЖЕНИИ (§5.1); dns-ha:dns-ha 0600
/opt/dns-panel/etc/secrets/repl.secret         появляется при СОЗДАНИИ ПАРЫ (§5.3); root:root 0600
/opt/dns-panel/etc/secrets/ha_monitor.secret   появляется при СОЗДАНИИ ПАРЫ (§5.3); root:root 0600
```

`peer.key` вырабатывают сами узлы во время сопряжения, по сети он не передаётся вообще. Пароли репликации
придумывает донор и передаёт соседу зашифрованными; учётные записи `repl` и `ha_monitor` создаёт агент на
обоих узлах в момент создания пары. Человек не набирает и не копирует ни одного секрета.

`peer.key` подписывает команды между узлами (HMAC). Трафик не шифруется, но подделать команду без ключа
нельзя; то немногое, что обязано ехать тайно (пароли), шифруется отдельно ключом, выведенным из него же.

---

## 3. Локальная БД `dns_ha`

Не реплицируется — намеренно: в ней лежит то, что у каждого узла своё (журнал операций, ревизии
конфигурации, проекция состояния, UUID узла). Установщик создаёт базу и выдаёт гранты:

```sql
CREATE USER IF NOT EXISTS 'dns-ha'@'localhost' IDENTIFIED VIA unix_socket;
GRANT ALL PRIVILEGES ON dns_ha.* TO 'dns-ha'@'localhost';
GRANT READ_ONLY ADMIN, SLAVE MONITOR ON *.* TO 'dns-ha'@'localhost';
```

Схему manager применяет сам при старте (она встроена в бинарник). Права на данные — только на `dns_ha`. Два
глобальных без доступа к данным: `READ_ONLY ADMIN` (на STANDBY база read-only, а manager обязан писать свою
`dns_ha`) и `SLAVE MONITOR` (`SHOW REPLICA STATUS`; без него manager говорит «репликация не наблюдалась», и
пару не собрать). `DROP DATABASE dns_ha` уносит гранты на базу — при пересоздании руками их выдают заново
(§5.4), иначе manager не поднимется с «CREATE command denied».

BINLOG ADMIN и SUPER не нужны: `dns_ha` не попадает в binlog, потому что исключена конфигурацией узла
(`etc/mariadb/dns-panel.cnf`):

```ini
binlog_ignore_db         = dns_ha
replicate_ignore_db      = dns_ha
```

---

## 4. Конфигурация узла

Идентичности в конфигах НЕТ: при первом запуске узел выдаёт себе UUID и сохраняет его в СВОЕЙ локальной
`dns_ha` (таблица `ha_identity`). Имя, площадка и описание — метаданные, живут в конфигурации пары и правятся в
панели.

`/opt/dns-panel/etc/ha.toml` (manager, `root:dns-ha 0640`) — только доступ к собственной БД:

```toml
[database]
socket   = "/run/mysqld/mysqld.sock"
database = "dns_ha"
```

`/opt/dns-panel/etc/ha-agent.toml` (агент, `root:root 0600`) — доступ к узлу:

```toml
[mysql]
socket = "/run/mysqld/mysqld.sock"
user   = "root"

[replication]
user             = "repl"
secret_file      = "/opt/dns-panel/etc/secrets/repl.secret"
port             = 3306
dump_user        = "ha_monitor"
dump_secret_file = "/opt/dns-panel/etc/secrets/ha_monitor.secret"
databases        = ["dns_panel", "pdns"]

[pdns]
role_conf = "/etc/powerdns/pdns.d/90-ha-role.conf"

[publication]
# Пусто: сервисный адрес живёт в реплицируемой конфигурации пары и приезжает в команде публикации.
```

Ключа `node` у агента нет (при старте он отвергается). Значения по умолчанию, которые обычно не меняют:
`peer_key.path`/`peer_key.owner`, `panel_secret_group` (группа веб-процесса — `auth-master.key` обязан остаться
читаемым панелью), `failsafe.source`/`failsafe.link` (`etc/mariadb/ha-failsafe.cnf` →
`/etc/mysql/mariadb.conf.d/61-dns-panel-ha.cnf`).

Роль PowerDNS — `primary` и `secondary` парой — хранится ТОЛЬКО в `/etc/powerdns/pdns.d/90-ha-role.conf`
([01 §3](01-standalone.md#3-почему-powerdns-настроен-так)). В паре агент держит ACTIVE в `yes/yes`, STANDBY — в
`no/no`; разбор пары возвращает оба узла в `yes/yes`. Смена роли — один рестарт PowerDNS при закрытой пробе
готовности. Роль, заданная где-то ещё, перекрыла бы файл роли: агент тогда не докажет STANDBY
(`role_unverified`) и безопасности ради остановит PowerDNS. Установщик такую роль находит и останавливается;
та же проверка руками:

```bash
sudo grep -Hn '^\s*\(primary\|secondary\|master\|slave\)\s*=' /etc/powerdns/pdns.conf /etc/powerdns/pdns.d/*.conf
# ожидается ровно две строки, обе из 90-ha-role.conf
```

---

## 5. Создание пары

Пара собирается из двух РАБОТАЮЩИХ одиночных узлов, без файла с описанием пары, ручного секрета и правки
конфигов.

**В панели** это раздел High availability на обоих узлах: на первом «Open pairing on this node», на втором —
«Join existing pair» с адресом первого, затем сверка шести цифр и Approve. После подтверждения там же
показывается опись данных обеих сторон, выбирается, чьи данные остаются, и создаётся пара. Ниже те же шаги
командной строкой — они делают ровно то же самое (панель ходит в тот же manager через
`/run/dns-panel/ha/manager.sock`, поэтому команды — от `dns-ha`):

```bash
M="sudo -u dns-ha /opt/dns-panel/bin/dns-ha-manager"
```

### 5.1 Сопряжение: узлы начинают доверять друг другу

Свежий узел НЕ держит наружу интерфейс сопряжения: пока человек не открыл окно, все команды отвергаются.

```bash
# A (там, где решают): открыть окно
$M -pair create

# B (тот, кто просится): попроситься к A
$M -pair join -address 10.0.0.1
#   → печатает шесть цифр

# A: посмотреть, кто просится, и СВЕРИТЬ ЦИФРЫ ГЛАЗАМИ
$M -pair status
#   state=pending, code=418302, peer_node_id=…, hostname (заявленный), peer_address (наблюдаемый)

# A: цифры совпали — подтвердить
$M -pair approve
```

После `approve` у обоих узлов появляется одинаковый `peer.key`, о котором каждый знает, от кого он. Если
цифры не совпали — `-pair reject`, и оба узла остаются ровно там, где были. Прерванную попытку убирает
`-pair reset`; уже установленное доверие снимается только явно (`-pair reset -force`).

Пары ещё нет: у обоих узлов свои данные и своя работа.

### 5.2 Чьи данные остаются

```bash
$M -pair inventory
```

Показывает обе стороны сразу: какие базы есть и сколько в них строк. Данные ПРИЁМНИКА будут заменены
данными донора — слияния двух баз нет. Если данные есть только у одного узла, донор очевиден; если у обоих —
решение принимает человек, глядя на эту опись.

### 5.3 Создание пары

Команда выполняется на ДОНОРЕ — узле, чьи данные остаются:

```bash
$M -pair build -provider floating_ip -address 10.0.0.10/32
# anycast: $M -pair build -provider anycast -address 10.0.0.53/32 -probe-port 17900
```

Что происходит по шагам (см. [../23-ha-manager.md](../23-ha-manager.md) §14.6):

```
секреты репликации → гранты на обоих → пересев приёмника из донора
→ ключ шифрования TOTP → fail-safe и ревизия 1 на обоих (поколение 1)
→ донор ACTIVE, приёмник STANDBY, сервисный адрес поднимается
```

Интерфейс для сервисного адреса не спрашивается: каждый узел определяет свой сам (адрес уже поднят — это его
интерфейс; иначе тот, чьей подсети адрес принадлежит). Имена сетевых карт на двух машинах совпадать не
обязаны.

До пересева данные приёмника не тронуты: любой отказ раньше него оставляет ОБА узла работающими
одиночными. Команда заканчивается проверкой репликации `IO=Yes`, `SQL=Yes` и сошедшейся позиции. Повтор
прерванной попытки — та же команда с `-id <тот же>`: пересев второй раз не выполняется.

`-provider marker` означает «адресом распоряжается кто-то снаружи» (BGP-демон, балансировщик) — тогда
`-address` не нужен.

### 5.4 Пересборка пары с нуля

Если пару собирают заново на узлах, где она уже была, состояние прежней пары нужно убрать целиком — иначе
новая унаследует чужие поколения и чужую историю. На обоих узлах:

```bash
sudo systemctl stop dns-ha-manager dns-ha-agent
sudo mysql -e "STOP SLAVE; RESET SLAVE ALL; SET GLOBAL read_only=0;"
# DROP уносит гранты на базу, READ_ONLY ADMIN и SLAVE MONITOR (на *.*) остаются
sudo mysql -e "DROP DATABASE dns_ha; CREATE DATABASE dns_ha; GRANT ALL PRIVILEGES ON dns_ha.* TO 'dns-ha'@'localhost';"
sudo rm -f /opt/dns-panel/var/{safety.json,agent-state.json}                # поколение прежней пары
sudo rm -f /opt/dns-panel/etc/secrets/{peer.key,repl.secret,ha_monitor.secret}
sudo rm -f /etc/mysql/mariadb.conf.d/61-dns-panel-ha.cnf                    # fail-safe прежней пары
sudo mysql -e "FLUSH BINARY LOGS; PURGE BINARY LOGS BEFORE NOW();"          # история, которой в новой паре нет
sudo systemctl start dns-ha-agent dns-ha-manager
```

`dns_panel` и `pdns` на будущем доноре при этом СОХРАНЯЮТСЯ — их и перельют на приёмник.

## 6. Сервисный адрес

Панель обслуживается по ОДНОМУ адресу, который живёт на текущем ACTIVE. Адрес задан в конфигурации пары
(`publication.params` ревизии).

**Floating IP** — адрес поднимает и снимает агент, подтверждая результат чтением интерфейса, и рассылает
gratuitous ARP при переезде.

**Anycast** — адрес `/32` на `lo` обоих узлов, а переезжает не адрес, а маршрут: проба готовности (TCP, по
умолчанию 17900) открыта только у ACTIVE, и по ней внешняя сеть держит маршрут на него — Cisco IP SLA + track,
BGP или [dns-watcher](reference/07-dns-watcher.md).

В `etc/panel.toml` про пару — ровно один переключатель, `[ha] enabled = true` (ставит установщик; означает
«контур установлен», а не «пара создана»). Всё остальное про пару (кто мы, кто сосед, сервисный адрес, роль)
панель спрашивает у `dns-ha-manager`.

Адреса узлов остаются управляющими: на STANDBY панель не может даже создать сессию (MariaDB read-only), и
страница входа отправляет на сервисный адрес.

---

## 7. Проверка

Состояние обоих узлов — страница High availability. Глазами manager'а (на каждом узле):

```bash
echo '{"cmd":"status"}' | sudo -u dns-ha nc -U /run/dns-panel/ha/manager.sock

# ACTIVE: role=active, route_announced=1, ha_healthy=true, decision.reason=steady_active
# STANDBY: role=standby, route_announced=0, репликация IO/SQL=Yes
```

```bash
curl -s http://<service-address>/health/ready     # на ACTIVE: "ready":1
ip -br -4 a                                       # Floating IP: адрес публикации только на ACTIVE
```

Плановое переключение — с ACTIVE (панель, страница High availability, или напрямую):

```bash
sudo -u dns-ha /opt/dns-panel/bin/dns-ha-manager -switchover
```

Ожидаемое поведение: несколько секунд пара не принимает запись, сервисный адрес переезжает, новый ACTIVE готов
через 7–12 с.

---

## 8. Аварийные пути

| ситуация | действие (`dns-ha-manager …`, от `dns-ha`) |
|---|---|
| ACTIVE недоступен, роль нужна здесь | `-emergency -ack <основание> -operator <кто>`; основания: `old_active_database_stopped`, `old_active_host_down`, `operator_isolated`; сосед огораживается |
| узел огорожен (`RESEED_REQUIRED`) | `-reseed` — данные узла стираются и заливаются с ACTIVE, роль не меняется |
| операция прервалась | `-resume -id <операция>` — продолжает с прерванного шага, выполненные не повторяются; `-operation` показывает текущую |
| панель недоступна | те же команды из командной строки; HA не зависит от web-стека |

Аварийное повышение НИКОГДА не происходит само: пара из двух узлов не отличает «сосед умер» от «сеть
порвалась», и решение принимает человек, а основание записывается в журнал операции.
