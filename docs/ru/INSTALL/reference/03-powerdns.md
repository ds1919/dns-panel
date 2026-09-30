# 03 — PowerDNS (shadow-master) + gmysql

Панель управляет зонами и записями в **MySQL-бэкенде PowerDNS** (`gmysql`, БД `pdns`). PowerDNS работает как
скрытый мастер: хранит данные, рассылает NOTIFY, отдаёт AXFR secondary. Публичный сервинг — на
BIND-secondary ([06-bind-secondaries.md](06-bind-secondaries.md)). Всё ниже делает `deploy/install.sh`.

## Установка: PowerDNS 5.1

Панель собрана и проверена на **PowerDNS 5.1**; ставится из официального репозитория (ветка `auth-51`), а не из
дистрибутива (у Ubuntu 24.04 там EOL 4.8, API которой не принимает `TSIG-ALLOW-AXFR`):

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://repo.powerdns.com/FD380FBB-pub.asc -o /etc/apt/keyrings/powerdns.asc
echo "deb [signed-by=/etc/apt/keyrings/powerdns.asc] http://repo.powerdns.com/ubuntu $(. /etc/os-release; echo $VERSION_CODENAME)-auth-51 main" \
  | sudo tee /etc/apt/sources.list.d/powerdns.list
printf 'Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n' | sudo tee /etc/apt/preferences.d/powerdns
sudo apt-get update && sudo apt-get install pdns-server pdns-backend-mysql
dpkg-query -W -f='${Version}\n' pdns-server      # установщик требует 5.1.x, иначе останавливается
```

`pdns-backend-bind` удаляется вместе с `/etc/powerdns/pdns.d/*bind*` и `/etc/powerdns/bindbackend.conf`:
PowerDNS должен поднимать только gmysql.

## БД `pdns`

База и пользователь `'pdns'@'127.0.0.1'` — [02-mariadb.md](02-mariadb.md). В ПУСТУЮ базу грузится схема из
пакета и два поля «кто/когда менял запись» (пишет панель, PowerDNS их не читает):

```bash
sudo mysql pdns < /usr/share/pdns-backend-mysql/schema/schema.mysql.sql
sudo mysql pdns -e "ALTER TABLE records ADD COLUMN updated_by VARCHAR(255) NULL, ADD COLUMN updated_at DATETIME(6) NULL"
```

## Конфиг

`/opt/dns-panel/etc/powerdns/dns-panel.conf` (`root:pdns 0640`) → симлинк `/etc/powerdns/pdns.d/dns-panel.conf`.
Файл целиком пишет установщик при каждом запуске (правки руками перезаписываются); PowerDNS перезапускается,
только если файл изменился или PowerDNS не запущен.

```ini
launch=gmysql
gmysql-host=127.0.0.1
gmysql-dbname=pdns
gmysql-user=pdns
gmysql-password=<etc/secrets/pdns-db.password>
gmysql-dnssec=yes
dnsupdate=yes
allow-dnsupdate-from=
forward-dnsupdate=no
local-address=0.0.0.0
api=yes
api-key=<etc/secrets/pdns-api.key>
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
zone-cache-refresh-interval=300
allow-axfr-ips=127.0.0.0/8,::1
send-signed-notify=no
xfr-cycle-interval=5
```

Почему именно эти значения — [../01-standalone.md §3](../01-standalone.md#3-почему-powerdns-настроен-так).

Роли (`primary`/`secondary`) здесь НЕТ: она живёт только в `/etc/powerdns/pdns.d/90-ha-role.conf` (на одиночном
узле `yes/yes`, в паре им управляет dns-ha-agent). Установщик создаёт этот файл, если его нет, и
останавливается, если роль задана где-то ещё.

Правки **записей внутри известной зоны** отдаются сразу (records читаются из gmysql на каждый запрос);
`zone-cache-refresh-interval` влияет только на список зон. Новую зону PowerDNS узнаёт по `rediscover` от
dns-agent, который ещё и подтверждает сервинг по SOA-serial ([05-dns-agent.md](05-dns-agent.md)).

## Проверка

```bash
sudo pdns_control rping        # → PONG
curl -fsS -H "X-API-Key: $(sudo cat /opt/dns-panel/etc/secrets/pdns-api.key)" http://127.0.0.1:8081/api/v1/servers/localhost
dig @127.0.0.1 <zone> SOA +noall +answer     # после создания тестовой зоны панелью
```

## Подключение из панели

`etc/panel.toml`:

```toml
[pdns_db]
host          = "127.0.0.1"
name          = "pdns"
user          = "pdns"
password_file = "/opt/dns-panel/etc/secrets/pdns-db.password"

[pdns_api]
url      = "http://127.0.0.1:8081"
server   = "localhost"
key_file = "/opt/dns-panel/etc/secrets/pdns-api.key"
```

## Дальше

- Раздача зон secondary (ALLOW-AXFR-FROM / TSIG / ALSO-NOTIFY, Catalog Zones) — [../../16-delivery.md](../../16-delivery.md).
- HA — [../02-ha-pair.md](../02-ha-pair.md), [../../13-ha-topology.md](../../13-ha-topology.md).
- Модель зон и записей — [../../05-dns-model.md](../../05-dns-model.md).
