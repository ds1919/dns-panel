# DNS Panel — документация

English: [../README.md](../README.md)

Внутренняя веб-панель для DNS-кластера **shadow-master PowerDNS + BIND-secondary**. Панель пишет зоны и
записи в MySQL-бэкенд PowerDNS (`gmysql`), PowerDNS рассылает NOTIFY, secondary забирают зоны по AXFR/IXFR.

Стек: **Perl FastCGI + фронтенд без сборки**, фоновые демоны на Go; без Docker и Python.

Документы описывают текущее состояние. Если документ расходится с кодом, источник истины — код; правьте документ.

## Карта документов

| Документ | О чём |
|----------|-------|
| [INSTALL/](INSTALL/README.md)        | Установка: одиночный узел и HA-пара, пакеты, MariaDB, PowerDNS, BIND; `schema.sql` |
| [01-overview.md](01-overview.md)     | Зачем проект, принципы, область |
| [02-architecture.md](02-architecture.md) | Архитектура DNS-кластера и панели, компоненты на узле |
| [03-database.md](03-database.md)     | БД панели и используемые таблицы PowerDNS |
| [04-panel-code.md](04-panel-code.md) | Код панели: раскладка `www/`, маршрутизация, API, фронтенд |
| [05-dns-model.md](05-dns-model.md)   | Модель зон и записей |
| [07-ui-design.md](07-ui-design.md)   | UI: лейаут, навигация, палитра и темы, правила компонентов |
| [08-auth.md](08-auth.md)             | Аутентификация |
| [10-mcp.md](10-mcp.md)               | MCP-сервер для ИИ-агентов |
| [11-api.md](11-api.md)               | HTTP API: эндпоинты, авторизация, формат |
| [13-ha-topology.md](13-ha-topology.md) | Прод-топология HA: два узла, MariaDB-репликация, anycast |
| [15-audit-log.md](15-audit-log.md)   | Аудит-лог |
| [16-delivery.md](16-delivery.md)     | Раздача зон: прямая раздача и каталоги (RFC 9432) |
| [20-permissions.md](20-permissions.md) | Права: доступ к зонам, группы, админ-права |
| [22-ha-contract.md](22-ha-contract.md) | HA-контракт: standalone/pair, switchover, emergency, split-brain |
| [23-ha-manager.md](23-ha-manager.md) | `dns-ha-manager` (Go): устройство HA-контура |
| [24-dns-engine.md](24-dns-engine.md) | Движок DNS: почему PowerDNS + gmysql, что пишется прямым SQL |
| [25-ns-pulse.md](25-ns-pulse.md)     | NS Pulse: тестеры ICMP/TCP (TLS + JSON), переключение записей на резервный адрес |
| [26-zone-import.md](26-zone-import.md) | Перенос зон со старого мастера |
| [ROADMAP.md](../ROADMAP.md)           | Что сделано в v1.0, что дальше, история проекта |
