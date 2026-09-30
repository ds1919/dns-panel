# 08 — Авторизация

Вход — одним из двух способов:

- **клиентский сертификат (mTLS)** — полная сессия сразу, без пароля и TOTP;
- **пароль + второй фактор (TOTP)** — второй фактор добровольный, см. ниже.

Права после входа — [20-permissions.md](20-permissions.md). Колонки таблиц — [03-database.md](03-database.md)
и `docs/INSTALL/schema.sql`.

## Модель данных

Идентичность отделена от способов входа:

- **`users`** — кто пользователь (username, email, display_name, is_active, session_ttl, theme, timezone,
  totp_required). Роли у пользователя нет: права дают группы и личные разрешения.
- **`auth_identities`** — внешняя идентичность, несколько на пользователя. `type`: `cert` | `oauth`;
  `provider`/`principal` NOT NULL (для cert `provider=''`), UNIQUE(type, provider, principal) — один CN
  нельзя привязать двум пользователям. `oauth` заложен в схему, входа по нему нет.
- **Credentials** — отдельные таблицы: `password_credentials` (Argon2id, `must_change`),
  `totp_credentials` (`secret_encrypted`, `confirmed_at`, `last_used_step` — анти-replay,
  `pending_secret_encrypted` — кандидат при замене приложения), `recovery_codes` (`code_hash`, `used_at`).
- **`sessions`** — в БД только SHA-256 токена; `stage` (`pending`|`full`), `pending_step`, `auth_type`,
  `remember`, `ip`, `user_agent`, `expires_at`.
- **`auth_throttle`** — ограничение попыток входа.

## Клиентский сертификат (mTLS)

TLS-проверку клиентского серта делает **Apache**; панель доверяет ему и читает переменные окружения
`SSL_CLIENT_VERIFY` и `SSL_CLIENT_S_DN_CN`.

1. `GET /login`: если `SSL_CLIENT_VERIFY eq 'SUCCESS'`, principal = CN (`SSL_CLIENT_S_DN_CN`).
2. Ищется `auth_identities` с `type='cert' AND provider='' AND principal=<CN> AND is_active=1` у активного
   пользователя.
3. Найден — открывается полная сессия (`auth_type='cert'`, постоянная cookie с TTL пользователя), редирект.
   Не найден — обычная страница входа по паролю. Само-регистрации нет.

Нужные директивы Apache (в поставляемом `etc/apache/dns-panel.conf` их нет — добавляются в TLS-vhost):

```apache
SSLCACertificateFile /etc/ssl/panel/company-ca.crt
SSLVerifyClient      require      # или optional, если без серта должен оставаться вход по паролю
SSLVerifyDepth       2
SSLOptions           +StdEnvVars
```

Для решений по IP (throttle, сессия) берётся только `REMOTE_ADDR`; прокси перед панелью выставляет его через
`mod_remoteip`.

> Вход по сертификату вживую не проверен: на стенде нет клиентских сертов.

Привязка серта — операторская задача: identity в Settings → Users & access
(`POST /dns-api/users/:id/identities`) или `deploy/bootstrap-admin.pl --cert-cn "<CN>"` для первого администратора.

## Пароль и второй фактор

- Пароль — `password_credentials.password_hash` (Argon2id, t=3, m=19 MiB, p=1). Неизвестный пользователь
  и неверный пароль неразличимы (всегда одна проверка Argon2id). `must_change=1` — временный пароль, при
  входе его обязательно меняют.
- TOTP — RFC 6238 (SHA1, 30 с, 6 цифр, окно ±1 шаг), совместим с Google/Microsoft Authenticator. Секрет
  шифруется AES-256-GCM ключом из файла `auth.master_key_file` (`etc/panel.toml`). Принятый шаг запоминается
  (`last_used_step`) — повтор кода отвергается. QR рисуется локально (`Imager::QRCode`).
- Коды восстановления — 10 одноразовых `xxxxx-xxxxx`, в БД SHA-256.
- Попытки ограничены: пароль — 5 за 15 мин на пару (пользователь, IP), коды — 5 за 5 мин на пользователя; при
  превышении `429`.

Вход по паролю — многошаговый (`POST /login`, JSON `action`). Пока шаги не пройдены, сессия `pending`
(15 мин), и ни панель, ни API её не принимают. Следующий шаг выбирается по факту (`_first_pending_step`):

| Состояние | Что спрашивает вход |
|-----------|---------------------|
| временный пароль (`must_change`) | сменить пароль (`password`) |
| приложение заведено | код (`totp_verify`) или код восстановления (`recovery_use`) |
| приложения нет, но его ждут (`users.totp_required=1`) | завести приложение (`totp_begin` → `totp_confirm`: QR → код → полная сессия + коды восстановления) |
| приложения нет и не ждут | ничего: полная сессия сразу после пароля |

`users.totp_required` — единственное, что отличает сброс от выключения. Действия администратора (право
`users.manage`, все в audit):

| Действие | Маршрут | Что делает |
|----------|---------|------------|
| **Reset** — потерял телефон | `POST /dns-api/users/:id/totp/reset` | секрет и коды удалены, `totp_required=1`, сессии отозваны → следующий вход ведёт завести приложение |
| **Turn off** | `DELETE /dns-api/users/:id/totp` | то же удаление, но `totp_required=0` → вход спрашивает только пароль |
| **Require / Stop asking** | `PUT /dns-api/users/:id/totp/required` | только флаг; ничего не удаляет, сессии не трогает |

Администратор завести приложение за другого не может. Если единственный администратор потерял доступ —
`libexec/recover-access.pl --username U [--password [S]] [--reset-totp]` на самом узле.

## Сессии

- Cookie `session_token`: `HttpOnly`, `SameSite=Lax`, `Secure` при HTTPS. В БД — SHA-256 токена.
- TTL полной сессии — личная политика `users.session_ttl`, иначе настройка `auth.session_ttl` (по умолчанию
  86400 с). «Remember this device» решает только, переживёт ли cookie закрытие браузера.
- Изменяющие запросы к API и к `/login` — CSRF double-submit: cookie `csrf_token` = заголовок `X-CSRF-Token`.
- Каждый запрос к страницам и `/dns-api/*` (кроме health) проверяет полную сессию.
- `logout` закрывает текущую сессию и чистит cookie.
- На STANDBY-узле HA сессию не создать: `/login` показывает ссылку на сервисный адрес пары.

## Личный кабинет (Account)

Человек распоряжается только собой: id берётся из сессии, в запросе его нет (`/dns-api/account*`).

| Действие | Особенность |
|----------|-------------|
| Смена пароля | Спрашивается текущий. Сеанс, из которого меняют, остаётся; остальные закрываются. |
| Включение / замена приложения | Прежнее приложение работает, пока новое не подтверждено кодом (кандидат — `pending_secret_encrypted`). При подтверждении выдаются новые коды восстановления. |
| Новые коды восстановления | Требуют код из приложения. |
| Выключение второго фактора | По коду из приложения; коды восстановления удаляются, сеансы не закрываются. При `totp_required=1` выключения нет ни на экране, ни в API. |
| Свои сеансы | Текущий закрыть нельзя; остальные — по одному или все разом. |

В шапке Account показываются группы, в которых человек состоит.

### Оформление и часовой пояс

`users.theme` и `users.timezone` (NULL = как в браузере). Тему подключает сервер (`<link>` в `header.pl` и на
странице входа), поэтому вспышки чужого оформления нет. Тёмная тема — сам `main.css`; остальные лежат в
`css/themes/` и переопределяют только CSS-переменные в `:root`. «Как в браузере» — `themes/auto.css`:
светлая палитра по `prefers-color-scheme: light`.

Кроме палитры тема может задавать `--font-ui`, `--bg-pattern`, `--sheen`/`--sheen-soft` и `--bevel`. Узоры —
градиенты или SVG прямо в значении переменной, внешних файлов у темы нет. Цвет кнопок и ярлыков задаётся
через `background-color`, не `background:` — сокращение сбросило бы `background-image` с бликом темы.
Список тем — `functions::account_themes`; у каждой темы из списка должен быть файл палитры.

Время хранится в UTC. Сервер печатает его как UTC с подписью, браузер переводит в выбранный пояс. На
расписание фоновых процессов пояс не влияет.
