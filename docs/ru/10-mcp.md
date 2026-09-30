# 10 — MCP-сервер (управление DNS через ИИ)

MCP-сервер даёт ИИ-агенту смотреть зоны и записи, править записи, создавать и удалять зоны. Он использует
тот же слой `include/functions.pm`, что и панель: те же права, тот же путь записи (транзакция, bump SOA,
NOTIFY), тот же HA-гейт и аудит.

- **Инструменты и диспетчер:** `www/include/MCPServer.pm`.
- **Remote (основной):** `https://<service-адрес>/mcp`, Streamable HTTP — `www/mcp/http.pl` внутри `panel.fcgi`.
  Включается в Settings → External access.
- **Локальный stdio:** `www/mcp/dns-mcp.pl` — для агента на самом узле.

## Инструменты (tools)

| Инструмент | Назначение | Пишет? |
|-----------|-----------|:---:|
| `whoami` | capabilities и список зон с `write` | — |
| `list_zones` | доступные зоны (с `access`); `No access` не показывается | — |
| `get_zone` | зона по имени/id + SOA + metadata; `No access` → «Zone not found» | — |
| `list_rrsets` | RRset'ы зоны (`name+type`), фильтры `type`/`name` | — |
| `count_records` | total + разбивка по типам + число хостов (опц. `type`) | — |
| `list_subdomains` | хосты зоны + делегированные зоны (с учётом доступа) | — |
| `search_records` | поиск по доступным зонам (`field`: name/content/any, `type`, `limit`) | — |
| `dns_query` | живой DNS-запрос (`dig TYPE NAME @server`) | — |
| `check_propagation` | SOA serial/запись на мастере и secondary — доехало/отстало | — |
| `apply_rrsets` | batch RRset-изменений (контракт как `PATCH /dns-api/v1/zones/:id/rrsets`): REPLACE/DELETE, атомарно, один bump SOA; `write` на зону | ✎ |
| `create_zone` | создать primary-зону (SOA+NS из `profile`); `zones.manage` | ✎ |
| `delete_zone` | удалить зону целиком; `confirm=true` + `zones.manage` | ✎ |

Зона задаётся `zone` (имя) или `zone_id`. Имя записи — `@`, относительное (`www`) или FQDN. Изменяющие
инструменты работают только на ACTIVE-узле пары; на STANDBY — ошибка `standby_read_only`.

## Кто вызывает

Права — всегда права конкретного пользователя панели ([20-permissions.md](20-permissions.md)). Как он
определяется, зависит от транспорта.

**Remote `/mcp`** — пользователя доказывает запрос, клиент его не называет (`requester` в схемах нет и
игнорируется):

| Заголовок | Кто |
|-----------|-----|
| `Authorization: Bearer dnsp_…` или `X-API-Key: dnsp_…` | владелец API-токена (Settings → External access → API tokens) |
| `Authorization: Bearer <JWT>` | пользователь из токена одного из OIDC-провайдеров (ниже) |
| нет, «Anonymous read» включён | `anonymous`: только читающие инструменты, чтение всех зон |
| нет | `401` + `WWW-Authenticate: Bearer` |

**OIDC.** Провайдеров может быть сколько угодно (Settings → External access → OIDC providers: имя, Issuer,
Audience, Username claim, вкл/выкл). Провайдер выбирается по `iss` токена — ему должен в точности
соответствовать Issuer включённого провайдера; разные провайдеры ведут к одним и тем же пользователям панели.
Панель проверяет подпись токена ключом из JWKS провайдера (`<issuer>/.well-known/openid-configuration`
→ `jwks_uri`; ключи держатся в процессе и перечитываются при незнакомом `kid`), `iss`, `aud`, `exp`/`nbf`.
Алгоритмы RS256/384/512, ES256/384. Пользователь ищется по значению claim'а (по умолчанию
`preferred_username`) — точное совпадение (без учёта регистра) с `username`, e-mail или любым CN
сертификата пользователя. Собираются все совпадения: они должны указывать на одного пользователя, иначе
отказ — первое совпадение или «у кого больше прав» не выбирается. Не нашёлся или неоднозначно — `401`.
Сопоставлений вручную не ведётся. Чтобы неоднозначность не возникала, панель не даёт сохранить CN, e-mail или
username, который уже называет другого пользователя (у одного пользователя CN может быть несколько).

Audience — через запятую, если принимается несколько значений. Для Microsoft Entra: issuer
`https://login.microsoftonline.com/<tenant>/v2.0`, audience — Application ID URI или client id регистрации
приложения; токен должен быть выписан **для этого приложения** (токены для Microsoft Graph проверить нельзя).

**Локальный stdio** — агент на узле доверенный и сам называет человека в `requester` каждого вызова. Сервер
ищет его как CN сертификата, затем как `username`; не передан — `mcp.default_user`; не нашёлся —
«Permission denied: unknown requester».

Все изменения и отказы (`result=denied`) — в [аудите](15-audit-log.md) с `source=mcp`; для remote — ещё
`via` (`token <имя>`, `oidc <провайдер>`, `anonymous`).

## Протокол remote

- `POST /mcp` — одно JSON-RPC-сообщение (или массив); ответ `application/json`. Только уведомления → `202`.
- `GET /mcp` → `405`: поток от сервера не используется, сессий (`Mcp-Session-Id`) нет.
- `Origin`, если прислан, должен совпадать с `Host` (защита от DNS rebinding) — иначе `403`.
- `protocolVersion`: 2024-11-05, 2025-03-26, 2025-06-18.
- Если есть включённые OIDC-провайдеры — `/.well-known/oauth-protected-resource` (RFC 9728): `resource` и
  `authorization_servers` = их issuer'ы; `WWW-Authenticate` в `401` на него ссылается.
- Панель слушает HTTP; для клиентов из интернета (Copilot и т.п.) её публикуют по HTTPS снаружи
  (reverse proxy на service-адрес).

## Настройки

Settings → External access (право `users.manage`), в таблице `settings`, общие для пары:

| Ключ | По умолчанию | Назначение |
|------|--------------|-----------|
| `external.mcp_http` | `0` | remote MCP на `/mcp` |
| `external.anonymous_read` | `0` | чтение зон и записей без токена (API и MCP) |
| `mcp.readonly` | `0` | изменяющие инструменты скрыты и отвергаются (оба транспорта) |
| `mcp.default_user` | `''` | `requester` по умолчанию для stdio (экрана нет) |

## Подключение клиента

Remote (любой клиент со Streamable HTTP):

```json
{
  "mcpServers": {
    "dns-panel": {
      "url": "https://dns.example.com/mcp",
      "headers": { "Authorization": "Bearer dnsp_…" }
    }
  }
}
```

Microsoft Copilot Studio: MCP-сервер по URL `…/mcp`; аутентификация — API key (заголовок `X-API-Key`,
значение `dnsp_…`; действует от одного пользователя — владельца токена) или OAuth 2.0 через регистрацию приложения в
Entra (действует от того, кто пишет в Teams) — тогда в панели добавляется OIDC-провайдер с тем же issuer и
audience.

Локальный stdio (процесс должен читать `etc/panel.toml` — запуск от пользователя панели):

```json
{
  "mcpServers": {
    "dns-panel": { "command": "sudo", "args": ["-u", "www-data", "perl", "/opt/dns-panel/www/mcp/dns-mcp.pl"] }
  }
}
```

## Быстрая проверка

```bash
curl -s -X POST https://dns.example.com/mcp -H 'Authorization: Bearer dnsp_…' -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'

printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_zones","arguments":{"requester":"Fedya"}}}' \
 | sudo -u www-data perl /opt/dns-panel/www/mcp/dns-mcp.pl
```
