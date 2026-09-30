# 02 — MariaDB и БД панели

На узле три базы: `dns_panel` (панель: пользователи, права, сессии, аудит, раздача…), `pdns` (gmysql-бэкенд
PowerDNS, [03-powerdns.md](03-powerdns.md)) и локальная `dns_ha` (HA, не реплицируется —
[../02-ha-pair.md §3](../02-ha-pair.md#3-локальная-бд-dns_ha)). Всё ниже делает `deploy/install.sh`.

## Конфигурация: одиночный узел, готовый к паре

`etc/mariadb/dns-panel.cnf` ставится СРАЗУ, ещё на одиночной установке:

Его создаёт `deploy/install.sh` из `dns-panel.example.cnf` со СЛУЧАЙНЫМ server_id и ставит симлинком в
`/etc/mysql/mariadb.conf.d/60-dns-panel.cnf`. Проверка:
```bash
mysql -e "SELECT @@server_id, @@log_bin, @@gtid_strict_mode\G"
```

Повторный запуск скрипта существующий файл не трогает: его `server_id` уже может быть в журнале и в
репликации. `server_id` обязан различаться у участников репликации и в MariaDB не динамический.

Файл включает журнал (`log_bin` в каталоге данных, `binlog_format = ROW`), GTID (`gtid_strict_mode`),
`log_slave_updates`, `bind-address = 0.0.0.0` (реплика подключается к источнику по TCP) и исключение `dns_ha`
из репликации. Всё это не динамическое, поэтому стоит заранее: иначе сопряжение двух РАБОТАЮЩИХ серверов
начиналось бы с правки `my.cnf` и перезапуска MariaDB под живым DNS. Репликации при этом нет — узел просто к
ней готов. Порт 3306 стоит закрыть firewall'ом до сети управления.

> `read_only` и `skip_slave_start` сюда НЕ входят: одиночный узел после перезагрузки обязан оставаться
> рабочим. Это fail-safe HA-роли: создание пары кладёт `etc/mariadb/ha-failsafe.cnf` симлинком
> `/etc/mysql/mariadb.conf.d/61-dns-panel-ha.cnf`, без перезапуска MariaDB — текущее значение `read_only`
> выставляет агент по доказанной роли.

## Базы и пользователи

Пароли — из `etc/secrets/` (генерирует установщик); повторный запуск приводит пароль пользователя к файлу.
Всё пишется мимо журнала (`sql_log_bin=0`), на STANDBY (`read_only=1`) — не пишется вовсе.

| пользователь | хост | права | вход |
|---|---|---|---|
| `dnspanel` | `127.0.0.1`, `localhost` | `ALL` на `dns_panel` | пароль `panel-db.password` |
| `pdns` | `127.0.0.1` | `ALL` на `pdns` | пароль `pdns-db.password` |
| `dns-ha` | `localhost` | `ALL` на `dns_ha`; `READ_ONLY ADMIN, SLAVE MONITOR` на `*.*` | unix_socket |

Панель и PowerDNS ходят по TCP на `127.0.0.1`, поэтому нужен именно `'…'@'127.0.0.1'`: `'…'@'localhost'`
матчит только socket-подключения.

> Пользователю панели **не** давать `SUPER` / `READ ONLY ADMIN`: иначе запись пройдёт и при `read_only=1` на
> STANDBY.

## Схема

Схемы грузятся только в ПУСТУЮ базу: `docs/INSTALL/schema.sql` → `dns_panel`, схема gmysql из пакета → `pdns`.
`schema.sql` существующие таблицы не меняет, миграций нет; изменение схемы на стенде — `DROP DATABASE dns_panel`
и повторный запуск установщика ([../01-standalone.md §2](../01-standalone.md#2-что-делает-установщик)). Таблицы
описаны в [../../03-database.md](../../03-database.md).

## Подключение из панели

`etc/panel.toml` — пароли не в конфиге, а в файлах секретов:

```toml
[panel_db]
host          = "127.0.0.1"
name          = "dns_panel"
user          = "dnspanel"
password_file = "/opt/dns-panel/etc/secrets/panel-db.password"
```
