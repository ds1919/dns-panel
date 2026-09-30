# 11 — HTTP API

JSON-API панели. Им пользуется фронтенд, и его же могут звать скрипты. Тот же слой `functions.pm`, что у
страниц и MCP ([10-mcp.md](10-mcp.md)). Реализация — [api.pl](../../www/api.pl) +
[API/Router.pm](../../www/API/Router.pm) (таблица `@ROUTES` — источник истины для списка маршрутов) +
[API/Response.pm](../../www/API/Response.pm). Запросы обслуживает постоянный процесс `panel.fcgi`.

## Куда стучаться

Префикс — **`/dns-api/v1/`** (`.htaccess`: `^dns-api/(.*)$ → panel.fcgi`); `/dns-api/` без версии — тот же
API, им пользуется UI:

```
https://<service-адрес>/dns-api/v1/<endpoint>
```

Внешний контракт (маршруты для скриптов и интеграций) описан в OpenAPI:
`GET /dns-api/v1/openapi.json` (без аутентификации; [API/OpenAPI.pm](../../www/API/OpenAPI.pm)). Остальные
маршруты — внутренние маршруты UI.

Пробы балансировщика доступны и с корня: `/health/live`, `/health/ready`.

## Аутентификация и порядок проверок

1. **Health** (`/health`, `/health/live`, `/health/ready`) и `openapi.json` — без сессии и CSRF; `/health/live`
   не ходит в БД.
2. **Кто вызывает** — первое, что есть:
   - cookie `session_token` полной сессии ([08-auth.md](08-auth.md)) — браузер;
   - `Authorization: Bearer <token>` (или `X-API-Key: <token>`): API-токен `dnsp_…` действует как его
     владелец; JWT — как пользователь из токена настроенного OIDC-провайдера ([10-mcp.md](10-mcp.md#кто-вызывает)).
     Неверный токен → `401`;
   - без всего, при включённом «Anonymous read» — `anonymous`, только `GET /zones`, `/zones/:id`,
     `/zones/:id/rrsets`, `/subdomains`, `/stats`, чтение всех зон.
   Иначе → `401` `Authentication required`. Токены и настройки — Settings → External access (`users.manage`).
3. **CSRF** для POST/PUT/PATCH/DELETE сессией браузера — заголовок `X-CSRF-Token`, равный cookie `csrf_token`.
   Нет → `403`. Для токенов CSRF не применяется (нет cookie).
4. **HA write-gate** для изменяющих методов: в паре проходят только на ACTIVE, записываемом, не замороженном
   узле, иначе `409`/`503` с `code`. Исключения — команды управления HA (`POST /ha/switchover`, `/ha/emergency`,
   `/ha/reseed`, `/ha/pair/*`, `/ha/operations/:id/resume`): у менеджера свой гейт.
5. **Права** в хендлере — доступ к зоне или capability ([20-permissions.md](20-permissions.md)).

```bash
curl -H 'Authorization: Bearer dnsp_…' https://<service-адрес>/dns-api/v1/zones
curl -X PATCH -H 'Authorization: Bearer dnsp_…' -H 'Content-Type: application/json' \
  --data '{"rrsets":[{"name":"www","type":"A","ttl":300,"changetype":"REPLACE","records":[{"content":"192.0.2.10"}]}]}' \
  https://<service-адрес>/dns-api/v1/zones/12/rrsets
```

В аудите у таких изменений `source=api` и `via` — `token <имя>`, `oidc <провайдер>` или `anonymous`.

## Права (кратко)

- Зонные маршруты: `No access` → **404** (существование не раскрывается), `read` — только GET, изменение
  содержимого (`rrsets`, `records`, `soa`, `name-servers`, `labels`, `retry-sync`, `refresh-axfr`) — `write`.
  В ответах зоны есть поле `access`.
- Сама зона (создание, удаление, профиль, promote/demote, secondary-source, DNSSEC, dynamic, reverse, импорт,
  zone-profiles) — `zones.manage`.
- `secondary/*` — `secondary.manage` / `distribution.manage` (TSIG, IP-группы, привязки);
  `catalogs/*` — `catalog.manage`; `zones/:id/distribution`, `direct-axfr`, `zones/:id/catalog` —
  `distribution.manage`; `pulse/*` — `pulse.manage`; `users/*`, `permission-groups/*`, `identities`,
  `zone-access` — `users.manage`; `audit` — `audit.read`; `labels/*` (изменение) — `labels.manage`;
  `ha/*` — `ha.manage` / `ha.emergency`; `account/*` — только сам пользователь.

## Формат

Запрос: параметры-фильтры в query-string, тело изменяющих запросов — JSON (`Content-Type: application/json`).

Ответ ([API/Response.pm](../../www/API/Response.pm)):

```jsonc
{ "success": true,  "data": { /* ... */ } }
{ "success": false, "error": "текст" }
```

Статусы: `200`, `201`, `400`, `401`, `403`, `404`, `409`, `500`, `503`. `/health/live`, `/health/ready` и HA-маршруты
отдают свой JSON без конверта (`/health/ready`: `200` или `503` со структурой проверок; HA — ответ менеджера, `503` если он
недоступен). Нет маршрута → `404` `No route for METHOD /path`.

## Маршруты

Пути — относительно `/dns-api`; `:id` — числовой.

**Health**
```
GET  /health  /health/live  /health/ready
```

**Зоны**
```
GET    /zones                          POST   /zones
GET    /zones/defaults                 GET    /zones/upstream-keys
GET    /zones/:id                      PATCH  /zones/:id        DELETE /zones/:id
GET    /zones/:id/stats                GET    /zones/:id/subdomains?type=
GET    /zones/:id/propagation          GET    /zones/:id/ptr-status
GET    /zones/:id/audit
POST   /zones/:id/retry-sync           POST   /zones/:id/refresh-axfr
POST   /zones/:id/promote              POST   /zones/:id/demote
PUT    /zones/:id/secondary-source
GET|PUT /zones/:id/dynamic
PUT    /zones/:id/labels
GET    /sync/problems
GET    /reverse/preview?cidr=          POST   /reverse
```

**DNSSEC**
```
GET|PUT /zones/:id/dnssec
POST    /zones/:id/dnssec/keys
PUT|DELETE /zones/:id/dnssec/keys/:kid
```

**Записи**
```
GET    /zones/:id/rrsets               PATCH  /zones/:id/rrsets     # RRset-контракт: name+type, REPLACE/DELETE
PATCH  /zones/:id/soa
POST   /zones/:id/name-servers         PATCH|DELETE /zones/:id/name-servers/:nid
POST   /zones/:id/records              PATCH|DELETE /zones/:id/records/:rid
POST   /zones/:id/records/batch        POST   /zones/:id/records/delete
POST   /zones/:id/records/with-ptr     POST   /zones/:id/records/:rid/ptr
GET    /records/search?q=&field=name|content|any&type=&limit=
GET    /dns/query?name=&type=&server=&port=
```

**Профили зон и Dynamic DHCP**
```
GET|POST /zone-profiles                GET|PUT|DELETE /zone-profiles/:id
GET|POST /dynamic/profiles             PUT|DELETE /dynamic/profiles/:id
```

**Импорт со старого мастера** ([26-zone-import.md](26-zone-import.md))
```
GET|POST /import/sources               GET  /import/sources/:id
POST   /import/sources/:id/probe
GET    /import/zones/:id/diff?tsig=
POST   /import/zones/:id/take          POST /import/zones/:id/copy     POST /import/zones/:id/mark
GET|PUT /import/zones/:id/dnssec       POST /import/zones/:id/dnssec/keys
POST   /zones/import/sources           POST /zones/import
```

**Метки**
```
GET    /labels
POST   /labels/categories              DELETE /labels/categories/:id
POST   /labels/values                  DELETE /labels/values/:id
```

**Раздача: серверы, TSIG, IP-группы**
```
GET    /secondary/tsig-keys/:id/secret
GET|POST /secondary/ip-groups          GET|PATCH|DELETE /secondary/ip-groups/:id
POST   /secondary/ip-groups/:id/members          DELETE /secondary/ip-groups/:id/members/:mid
GET|POST /secondary/groups             GET|PATCH|DELETE /secondary/groups/:id
POST   /secondary/groups/:id/members             DELETE /secondary/groups/:id/members/:nid
POST   /secondary/groups/:id/ip-groups           DELETE /secondary/groups/:id/ip-groups/:gid
POST   /secondary/groups/:id/tsig-keys           DELETE /secondary/groups/:id/tsig-keys/:kid
POST   /secondary/groups/:id/tsig-keys/:kid/primary
GET|POST /secondary/servers            GET|PUT|DELETE /secondary/servers/:id
GET    /secondary/servers/:id/audit
PUT    /secondary/servers/:id/catalogs           PUT /secondary/servers/:id/default-group
POST   /secondary/servers/:id/tsig-keys          DELETE /secondary/servers/:id/tsig-keys/:kid
POST   /secondary/servers/:id/tsig-keys/:kid/primary
GET|POST /secondary/nodes              GET|PATCH|DELETE /secondary/nodes/:id
POST   /secondary/nodes/:id/endpoints            PATCH|DELETE /secondary/nodes/:id/endpoints/:eid
```

**Каталоги и раздача зоны**
```
GET|POST /catalogs                     GET|PATCH|DELETE /catalogs/:id
PUT    /catalogs/:id/groups            POST   /catalogs/:id/provision
DELETE /catalogs/:id/nodes/:nid
GET    /catalogs/:id/subscriptions/:sid/config   POST /catalogs/:id/subscriptions/:sid/recheck
GET    /zones/:id/distribution
PUT    /zones/:id/direct-axfr          PUT    /zones/direct-axfr    # bulk, один запрос
PUT    /zones/:id/catalog              # {catalog_id} или null — убрать из каталога
```

**NS Pulse** ([25-ns-pulse.md](25-ns-pulse.md))
```
GET    /pulse                          PUT    /pulse/settings
POST   /pulse/enrollment/key           PUT    /pulse/server/address
POST   /pulse/testers/:id/approve      PUT|DELETE /pulse/testers/:id
POST   /pulse/groups                   PUT|DELETE /pulse/groups/:id     PUT /pulse/groups/:id/members
POST   /pulse/checks                   PUT|DELETE /pulse/checks/:id     PUT /pulse/checks/:id/groups
POST   /pulse/rules                    GET|PUT|DELETE /pulse/rules/:id
PUT    /pulse/rules/:id/branches       POST   /pulse/rules/:id/clone
GET    /pulse/history
GET    /pulse/zones/:id/records        GET    /pulse/zones/:id/rrset
GET    /pulse/zones/:id/rrset/history  GET    /pulse/zones/:id/rrset/sweep
```

**HA** ([23-ha-manager.md](23-ha-manager.md))
```
GET    /ha/status                      GET|PUT /ha/config
PUT    /ha/publication                 PUT    /ha/pair-address
GET    /ha/operations                  GET    /ha/operations/:op
POST   /ha/switchover   /ha/emergency   /ha/reseed   /ha/dismantle
POST   /ha/operations/:op/resume
GET    /ha/pair   /ha/pair/inventory   /ha/pair/devices
POST   /ha/pair/create   /ha/pair/join   /ha/pair/approve   /ha/pair/reject   /ha/pair/reset   /ha/pair/build
```

**Аудит**
```
GET    /audit
```

**Account** (только свой пользователь)
```
GET    /account                        PUT    /account/preferences
POST   /account/password               POST   /account/recovery-codes
POST   /account/totp/begin             POST   /account/totp/confirm
DELETE /account/totp/pending           DELETE /account/totp
DELETE /account/sessions/:sid          DELETE /account/sessions      # все, кроме текущей
```

**Пользователи и права**
```
GET|POST /users                        GET|PUT|DELETE /users/:id
POST   /users/:id/password
POST   /users/:id/totp/reset           PUT    /users/:id/totp/required    DELETE /users/:id/totp
GET    /users/:id/sessions             DELETE /users/:id/sessions/:sid    DELETE /users/:id/sessions
PUT    /users/:id/session-policy
GET    /users/:id/effective-access     POST   /users/:id/access/preview   PUT /users/:id/access
POST   /users/:id/groups               DELETE /users/:id/groups/:gid
POST   /users/:id/capabilities         DELETE /users/:id/capabilities/:cap
POST   /users/:id/zone-access          DELETE /zone-access/:id
POST   /users/:id/identities           DELETE /identities/:id
GET|POST /permission-groups            GET|PUT|DELETE /permission-groups/:id
POST   /permission-groups/:id/members  DELETE /permission-groups/:id/members/:uid
POST   /permission-groups/:id/capabilities   DELETE /permission-groups/:id/capabilities/:cap
POST   /permission-groups/:id/zone-access    PUT /permission-groups/:id/access
```

## Примеры

```bash
curl https://<panel>/dns-api/health
# { "success": true, "data": { "status": "ok", "service": "dns-panel" } }

curl -b cookies.txt https://<panel>/dns-api/zones/1/rrsets
# { "success": true, "data": { "zone": "example.net", "access": "write", "rrsets": [ ... ] } }

curl -b cookies.txt -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X PATCH \
     -d '{"rrsets":[{"name":"www","type":"A","changetype":"REPLACE","records":[{"content":"10.0.0.5"}]}]}' \
     https://<panel>/dns-api/zones/1/rrsets
```

`$CSRF` — значение cookie `csrf_token`, которую ставит страница панели.

## Как добавить эндпоинт

1. Логика — в `include/functions.pm` (её переиспользуют страницы и MCP).
2. Маршрут — в `@ROUTES` (`API/Router.pm`): `[ 'GET', qr{^/path$}, \&_handler ]`. Узкие пути — раньше широких.
3. Хендлер проверяет права и возвращает `API::Response->ok({...})` / `->not_found(...)` и т.п.
4. Изменения содержимого зоны — через write-функции `functions.pm` (они делают bump SOA и NOTIFY), с записью
   в аудит.
