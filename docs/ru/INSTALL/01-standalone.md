# 01 — Standalone: один рабочий узел с нуля

Узел ставится **одной командой**. Одиночная установка сразу несёт HA-контур (dns-ha-agent и dns-ha-manager
запущены, `[ha] enabled = true`), но пары при этом нет: пара собирается потом, в панели, из двух таких узлов —
[02-ha-pair.md](02-ha-pair.md). Отдельной «HA-установки» нет.

**Условия:** Ubuntu 24.04 (noble) или 26.04 (resolute), LXC-контейнер; на другой ОС установщик останавливается.
Выход в интернет до `repo.powerdns.com` (PowerDNS 5.1 ставится оттуда), root на узле. Go для установки не нужен:
пакет несёт собранные бинарники.

## 1. Установка

Из релиза: `dns-panel_<версия>_amd64.deb` и `powerdns-repo.sh`. Под root на узле:

```bash
sh powerdns-repo.sh                      # репозиторий PowerDNS 5.1 (repo.powerdns.com, с pin)
apt install ./dns-panel_1.0.0_amd64.deb
```

apt ставит зависимости (PowerDNS, MariaDB, Apache, Perl-модули); postinst пакета запускает
`deploy/install.sh --package` — тот же установщик, что ниже, без его apt-части.

Из исходников (для разработки): `make build` (Go 1.24+), затем `deploy/deploy.sh ds@10.0.0.11 [...]` проверяет сразу все
указанные узлы (ssh, версия Ubuntu, sudo или root), привозит дерево в `~/dns-panel` на каждый (tar-поток по ssh) и
запускает там установщик; `make deb` собирает пакет.

Или на самом узле из уже привезённого дерева (в `bin/` должны лежать собранные `dns-agent`, `dns-sync-worker`,
`dns-ha-agent`, `dns-ha-manager` — без них установщик останавливается):

```bash
sudo ~/dns-panel/deploy/install.sh [--admin ЛОГИН]
```

Установщик ничего не спрашивает и заканчивается проверками и временным паролем первого администратора:

```
==> checks
  ok    panel.toml parses
  ok    PowerDNS answers
  ok    PowerDNS API
  ok    dns-agent answers
  ok    dns-ha-agent running
  ok    dns-ha-manager running
  ok    dns-sync-worker running
  ok    panel ready (/health/ready)
  ok    config outside web root
==> first administrator
  TEMPORARY PASSWORD (shown once — must be changed at first login): …
DNS Panel is installed: http://10.0.0.11/
```

Дальше — браузер: `http://<адрес узла>/`, вход под временным паролем, смена пароля, TOTP. Создайте тестовую
зону и проверьте `dig @<адрес узла> <зона> SOA` — сквозной путь панель → dns-agent → PowerDNS.

## 2. Что делает установщик

По порядку, и каждый шаг безопасно повторяется:

| шаг | что |
|-----|-----|
| пакеты | репозиторий `repo.powerdns.com` (`<codename>-auth-51`, ключ в `/etc/apt/keyrings/powerdns.asc`, pin `pdns-*` 600); Perl-модули из apt, Apache с `libapache2-mod-fcgid`, MariaDB, `pdns-server` + `pdns-backend-mysql` — [reference/01-packages.md](reference/01-packages.md). Если PowerDNS не 5.1.x — остановка. `pdns-backend-bind` удаляется; модули Apache `cgid fcgid rewrite headers env`; заглушка `systemd-resolved` снимается с `:53`, если она там |
| пользователи | `dns-ha` (manager HA), `www-data` входит в группу `dns-ha` — только чтобы пользоваться IPC-сокетами HA |
| дерево | `/opt/dns-panel/{www,bin,docs,etc,var}`: `www`, `bin`, `docs` синхронизируются целиком, в `etc` — только шаблоны, юниты и то, что несёт репозиторий; рабочие конфиги узла не трогаются |
| секреты | `etc/secrets/{panel-db.password,pdns-db.password,pdns-api.key,auth-master.key}` — случайные, `0640 root:www-data`; секретов пары здесь нет, они появятся при сопряжении |
| конфиги узла | `panel.toml`, `dns-agent.toml`, `ha.toml`, `ha-agent.toml` из `*.example.toml` — только если их ещё нет; в `panel.toml` включается `[ha] enabled = true` |
| MariaDB | `etc/mariadb/dns-panel.cnf` (случайный `server_id`, журнал, GTID — §4) → `/etc/mysql/mariadb.conf.d/60-dns-panel.cnf`; базы `dns_panel`, `pdns`, `dns_ha`; пользователи `dnspanel`, `pdns` (пароль всегда приводится к файлу секрета), `dns-ha` (unix_socket, данные — только `dns_ha`); схемы — только в пустые базы |
| … на паре | всё это — мимо журнала (`sql_log_bin=0`): пароли у каждого узла свои, и `ALTER USER`, уехавший соседу, отрезал бы его панель от базы, а на STANDBY дал бы «свои» GTID реплики; на узле с `read_only=ON` (STANDBY) базы не трогаются вовсе |
| PowerDNS | `etc/powerdns/dns-panel.conf` → `/etc/powerdns/pdns.d/` (пишется целиком каждый раз — §3); `90-ha-role.conf` с `primary=yes secondary=yes` — только если его нет (дальше им владеет HA); роль, заданная где-то ещё, — остановка; перезапуск — только если конфиг изменился или PowerDNS не запущен (на ACTIVE это пауза в DNS) |
| сервисы | tmpfiles `/run/dns-panel/{ha,pdns,pulse,sync}`, юниты симлинками из `etc/systemd`: `dns-agent`, `dns-sync-worker`, `dns-ha-agent`, `dns-ha-manager`, `pulse-server` — enable + restart |
| Apache | `/var/www/vhost/dns-panel → /opt/dns-panel/www`, сайт `dns-panel` из `etc/apache`, `000-default` выключается — [reference/04-panel-deploy.md](reference/04-panel-deploy.md) |
| администратор | `deploy/bootstrap-admin.pl`, если в базе нет ни одного пользователя |

Рабочие `etc/*.toml`, `etc/secrets/`, `etc/powerdns/`, `etc/mariadb/dns-panel.cnf` создаются на узле и в
репозиторий не входят.

> **Схема БД.** `schema.sql` — полная схема для чистой установки: установщик грузит его только в пустую базу и
> отмечает все миграции релиза как выполненные. Существующая база обновляется миграциями (§5).

## 3. Почему PowerDNS настроен так

**`local-address=0.0.0.0`** — слушать на ВСЕХ локальных адресах, а не перечислять их.

Перечисление адресов ломает HA: сервисный адрес пары (Floating IP, anycast-`/32` на `lo`) появляется на узле
ПОЗЖЕ установки и меняется из панели. С явным списком PowerDNS на нём не слушает — адрес поднят, роль ACTIVE,
проба готовности открыта, а `dig` по опубликованному адресу отвечает `connection refused`. С `0.0.0.0` смена
сервисного адреса не касается конфигурации PowerDNS. Интерфейсы, где DNS слушать нельзя, закрываются
firewall'ом.

**Роль — `primary` и `secondary` — живёт ТОЛЬКО в `90-ha-role.conf`**, парой: одиночный узел и ACTIVE —
`yes/yes`, STANDBY — `no/no`. `primary` рассылает NOTIFY, `secondary` сам проверяет secondary-зоны (перенос со
старого мастера, чужие зоны) у их primary по SOA refresh и принимает от него NOTIFY; без него такая зона
приезжает, только пока трансфер просит панель, а потом тихо застывает. Обе пишут в базу, а база STANDBY —
read-only реплика, поэтому HA переключает их вместе, одним рестартом. В `dns-panel.conf` их быть НЕ должно:
PowerDNS читает `pdns.d` по алфавиту, `dns-panel.conf` идёт после `90-ha-role.conf` и перекрыл бы роль,
которую ставит HA.

**Динамические обновления:** `dnsupdate=yes`, **пустой** `allow-dnsupdate-from`, `forward-dnsupdate=no`
(RFC 2136). Кому их можно слать, панель задаёт у каждой dynamic-зоны сама, метаданными. Глобальный список
складывается с зоновым: `0.0.0.0/0` здесь открыл бы обновления по адресу всем зонам, а умолчание
(`127.0.0.0/8,::1`) тихо добавило бы localhost. Secondary-зоны обновляет их мастер, поэтому обновления ему не
пересылаются.

**`zone-cache-refresh-interval=300`** — страховочный фон. Панель пишет зоны прямо в gmysql, и новую зону
PowerDNS узнаёт по явному `rediscover` через dns-agent ([reference/05-dns-agent.md](reference/05-dns-agent.md)),
а не по опросу БД.

**`allow-axfr-ips`, `xfr-cycle-interval`, `send-signed-notify` — раздача зон вниз** ([../16-delivery.md](../16-delivery.md)):

`allow-axfr-ips=127.0.0.0/8,::1` разрешает AXFR **по адресу, то есть без TSIG**. Авторизацию держит per-zone
`TSIG-ALLOW-AXFR`, который выставляет панель, поэтому адреса secondary сюда добавлять НЕЛЬЗЯ: любой адрес
отсюда обходит всю политику панели целиком. Проверяется одной командой С АДРЕСА secondary:
```bash
dig @<powerdns> <любая-раздаваемая-зона> AXFR      # без ключа обязан ответить "Transfer failed"
```

`xfr-cycle-interval=5` — как быстро consumers узнают о появлении/уходе зоны в каталоге. Содержимое
PRODUCER-зоны PowerDNS считает сам в этом цикле; до его прохода serial каталога прежний, поэтому NOTIFY извне
(в том числе из панели) несёт старый serial и ничего не меняет. Дефолт 60 с даёт до минуты задержки. Единицу не
ставим: в этом же цикле PowerDNS опрашивает свежесть своих secondary-зон.

`send-signed-notify=no` — NOTIFY уходит неподписанным. У каждого secondary свой TSIG-ключ, а PowerDNS
подписывает NOTIFY по зоне ОДНИМ ключом (первым найденным у зоны) → у всех остальных `tsig verify failure
(BADKEY)`, и о появлении новой зоны они узнают только по SOA-refresh каталога. AXFR это не ослабляет: он
продолжает требовать личный ключ, а BIND принимает неподписанный NOTIFY от своего primary.

## 4. MariaDB: одиночный узел, готовый к паре

`server_id` случайный и на каждом узле свой, журнал и GTID включены, `bind-address = 0.0.0.0`, `dns_ha` исключена
из репликации. Всё это не динамическое: правка в момент сопряжения означала бы перезапуск живой базы под DNS.
`read_only` и `skip_slave_start` сюда НЕ входят — это fail-safe роли, его кладёт создание пары отдельным файлом.
Подробно — [reference/02-mariadb.md](reference/02-mariadb.md).

## 5. Обновление кода

`apt install ./dns-panel_<новая версия>_amd64.deb` (или из исходников тот же `deploy/deploy.sh <узел>`): код и шаблоны
приезжают заново, сервисы перезапускаются, конфигурация узла, секреты и данные остаются.

Схема базы обновляется миграциями ([deploy/migrations/](../../../deploy/migrations/README.md)). Первым шагом, **до
замены кода**, установщик выполняет файлы, которых нет в `schema_migrations`, — только на записываемом узле
(standalone или ACTIVE); перед этим — дамп `dns_panel` в `/opt/dns-panel/var/backup/` (хранятся пять
последних). Миграция упала — установка останавливается, узел продолжает работать на старой версии и старой
схеме. С пакетом к моменту postinst dpkg уже распаковал новые файлы: упавшая миграция оставляет пакет
ненастроенным (`apt` об этом скажет), база — как была, плюс дамп.

**Пара** — сначала ACTIVE, потом STANDBY (`deploy/deploy.sh <ACTIVE> <STANDBY>` делает именно в таком порядке):

Миграции выполняются на ACTIVE и доходят до STANDBY репликацией; manager и панель связаны JSON-контрактом, поэтому
обновляются оба узла. Какая версия и схема стоят на узле — в `/health/ready`: `version` (файл `VERSION`) и
`schema` (последняя миграция, `base` — схема самого релиза).

## 6. NS Pulse (переключение записей по состоянию хостов)

Раздел необязательный: без него панель работает, просто страница NS Pulse честно говорит, что переключать
некому. Но если правила заводятся — демон обязан быть поднят, иначе «Turn on» ничего не включит.

**pulse-server** (решает и правит записи) ставит и запускает `deploy/install.sh` на каждом узле панели: пользователь
`dns-pulse`, `etc/pulse-server.toml` из шаблона (`[apply]`, `[control]` и `[ha]` включены), юнит. Свой TLS-сертификат
он хранит в `dns_panel` и создаёт при первом старте (узел ещё standalone, база writable). При создании пары
база receiver заменяется базой donor, и обе ноды работают с сертификатом donor — агенты не замечают switchover. В журнале при старте — отпечаток сертификата
и путь сокета.

**pulse-agent** ставится на каждую площадку, откуда проверяют (можно и на узел панели), своим пакетом
`dns-panel-pulse-agent_<версия>_amd64.deb`. Адрес сервера для агентов задаётся В ПАНЕЛИ: **NS Pulse → Agent config**.
Там же лежит готовый файл агента — четыре строки, одинаковые для всех площадок: личного секрета в нём нет, свой
ключ агент делает себе сам при первом запуске. Под root:
```bash
apt install ./dns-panel-pulse-agent_1.0.0_amd64.deb     # пользователь pulse-agent, юнит (включён)
nano /opt/dns-panel/etc/pulse-agent.toml                 # вставить то, что показала панель
systemctl start pulse-agent
journalctl -u pulse-agent -n 5                           # → код вида 7F3A-91C2 и «waiting for approval»
```
Агент появится в панели заявкой — **NS Pulse → Waiting for approval**. Опознают его по имени хоста и коду из
журнала; после `Approve` он получает имя и задания.

Проверка, что контур живой: на странице NS Pulse НЕТ полосы «The Pulse server is not running on this node», а
подтверждённый агент показан `online`.
