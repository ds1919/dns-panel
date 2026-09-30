# 04 — Панель: Apache, FastCGI, panel.toml

Панель — Perl без сборки. Страницы и API работают в постоянном FastCGI-процессе `www/panel.fcgi` под
`mod_fcgid` (`libapache2-mod-fcgid`, `libfcgi-perl`); `login.pl`, `logout.pl`, `404.pl` — обычный CGI (`cgid`).
Всё ниже делает `deploy/install.sh`.

## Раскладка

```
/opt/dns-panel/www/              ← DocumentRoot (через симлинк /var/www/vhost/dns-panel)
├── panel.fcgi index.pl api.pl login.pl logout.pl 404.pl header.pl .htaccess
├── css/ js/ images/
└── include/ API/ pages/ mcp/    ← закрыты .htaccess (403)
```

Конфиги, секреты, `bin/` и `docs/` лежат рядом, в `/opt/dns-panel`, — вне web-корня. Установщик синхронизирует
`www/` целиком (`rsync --delete`), владелец `root:www-data`, без записи для группы.

## Apache vhost

`/opt/dns-panel/etc/apache/dns-panel.conf` → симлинк `/etc/apache2/sites-available/dns-panel.conf`; сайт
`dns-panel` включён, `000-default` выключен. Модули: `cgid fcgid rewrite headers env`. Сам сайт
(`DocumentRoot`, `<Directory>`, лимиты FastCGI) — в `dns-panel-common.conf`, общем для vhost `:80` и `:443`, который пишет
`deploy/tls.sh` (HTTPS ниже):

```apache
    DocumentRoot /var/www/vhost/dns-panel
    <Directory /var/www/vhost/dns-panel>
        AllowOverride All
        Options +ExecCGI +FollowSymLinks -Indexes
        Require all granted
        DirectoryIndex index.pl
        AddHandler cgi-script .pl
    </Directory>
    <IfModule mod_fcgid.c>
        FcgidMaxProcessesPerClass 8
        FcgidMaxRequestsPerProcess 1000
        FcgidIOTimeout 600
        FcgidBusyTimeout 600
        FcgidMaxRequestLen 2000000
    </IfModule>
```

`+FollowSymLinks` обязателен: DocumentRoot — симлинк. Маршруты — в `www/.htaccess`: `/`, страницы
(`/zones`, `/records`, …), `/ajax/*`, `/dns-api/*` и `/health/{live,ready}` идут в `panel.fcgi`; туда же он
закрывает `include/ API/ pages/ mcp/`, dot-пути и файлы `*.json|sql|pm|md`.

После обновления кода установщик перезапускает Apache — вместе с ним перезапускается и процесс `panel.fcgi`.

## etc/panel.toml

Единственный конфиг панели на узле: доступ к базам, PowerDNS API, сокеты dns-agent и pulse-server, флаг
`[ha] enabled`. Создаётся установщиком из `etc/panel.example.toml` один раз (`root:www-data 0640`) и в
репозиторий не входит. Паролей в нём нет — только пути к файлам секретов в `etc/secrets/` (`*_file`). Всё, чем
управляет администратор (таймауты синхронизации, политика MCP, время жизни сессии), — в таблице `settings`
и правится в панели.

Вход — только реальные сессии (bootstrap-admin → логин + пароль + TOTP) или mTLS-сертификат.

## HTTPS + mTLS (клиентский сертификат)

Положите сертификаты в `/opt/dns-panel/etc/tls/` и запустите под root `/opt/dns-panel/deploy/tls.sh`:

| Файл | |
|------|--|
| `server.crt`, `server.key` | сертификат сервера и ключ (должен называть адрес, который открывают: узел или сервисное имя пары) |
| `chain.crt` | промежуточные сертификаты, если их требует CA (необязательно) |
| `client-ca.crt` | CA клиентских сертификатов: включает вход по сертификату (необязательно) |

`tls.sh` пишет vhost `:443` (`etc/apache/dns-panel-tls.conf`) и перенаправляет на него `:80`, кроме `/health/`
(пробы готовности пары остаются на HTTP). Клиентский сертификат запрашивается, но не обязателен
(`SSLVerifyClient optional`): без него входят по паролю, API и MCP-клиенты — по токену. Без файлов HTTPS снимается.
Установщик запускает его при каждой установке и обновлении пакета, так что настройка переживает обновления; после
замены сертификатов запустите сами. На паре — одни и те же файлы на обоих узлах.

Панель принимает сертификат при `SSL_CLIENT_VERIFY=SUCCESS` и берёт CN из `SSL_CLIENT_S_DN_CN` →
`auth_identities`. Заведение пользователей — [../../08-auth.md](../../08-auth.md).

## Проверка

```bash
curl -s  http://<узел>/health/ready                     # → JSON, "ready":1 (без сессии)
curl -sI http://<узел>/ | grep -E '^(HTTP|Location:)'   # без сессии → 302, Location: …/login
curl -sI http://<узел>/login | head -1                  # → 200
curl -sI http://<узел>/pages/zones.pl | head -1         # → 403 (обход auth закрыт)
curl -sI http://<узел>/include/functions.pm | head -1   # → 403
```
