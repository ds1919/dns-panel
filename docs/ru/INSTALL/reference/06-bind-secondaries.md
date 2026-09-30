# 06 — BIND-secondary + Catalog Zones

Публичное обслуживание DNS — на BIND-secondary, которые забирают зоны у PowerDNS по AXFR/IXFR. Панель
управляет только стороной PowerDNS (кому разрешён AXFR, кому идёт NOTIFY, что в каталоге); BIND она не
настраивает. Готовый фрагмент конфига для каждого сервера панель показывает сама:
**Propagation → Catalog → Servers → «?»** у сервера. Модель раздачи — [../../16-delivery.md](../../16-delivery.md).

```bash
sudo apt install bind9      # consumer RFC 9432 — BIND 9.18.3 и новее
```

## Что должно быть в конфиге

```named
# named.conf.local
key "dc-ns1-key" { algorithm hmac-sha256; secret "..."; };   # только если сервер авторизован TSIG

zone "internal.catalog" {
    type secondary;
    primaries { 10.0.0.53 port 53 key "dc-ns1-key"; };      # сервисный адрес пары, не адреса нод
    allow-notify { 10.0.0.11; 10.0.0.12; };           # адреса обеих нод пары
};

# внутри options { }
allow-notify { 10.0.0.11; 10.0.0.12; };
catalog-zones {
    zone "internal.catalog" default-primaries { 10.0.0.53 port 53 key "dc-ns1-key"; };
};
```

- **`primaries` — сервисный адрес пары**: забирать зоны надо у той ноды, что сейчас ACTIVE.
- **`allow-notify` — адреса обеих нод.** NOTIFY уходит с адреса ACTIVE-ноды, а не с сервисного; без этой
  строки BIND пишет `refused notify from non-primary` и узнаёт об изменениях только по SOA-refresh.
- **Авторизация** — либо TSIG-ключ сервера, либо IP ACL по его адресу, не оба сразу: у сервера с ключом
  адрес в `ALLOW-AXFR-FROM` не попадает (PowerDNS объединяет их через ИЛИ). С TSIG сервер забирает зоны с
  любого адреса, но адрес в панели всё равно нужен — на него идёт NOTIFY и по нему видно состояние подписки.
- **Сервер, который берёт зоны не у нас** (AXFR у сервера = Deny или группа без zone AXFR): каталог — у пары,
  а `default-primaries` — его собственный upstream со своим ключом; `allow-notify` в options ему не нужен.

## После смены каталога — перезапуск, а не reconfig

Если в конфиге меняется сам каталог (другое имя, другие `default-primaries`), BIND 9.18 после `rndc reconfig`
может не завести зоны-члены: `catz: failed to configure zone '...' - 22`. Помогает `systemctl restart named`.
Обычное добавление и удаление зон в каталоге панелью перезапуска не требует.

## Проверка

```bash
dig +short +norec SOA <зона> @127.0.0.1                     # serial совпадает с PowerDNS
journalctl -u named | grep -E 'transfer of|notify'         # трансферы с TSIG, NOTIFY принят
```
