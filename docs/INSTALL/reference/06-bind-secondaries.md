# 06 — BIND secondaries + Catalog Zones

Public DNS serving is done by BIND secondaries, which pull zones from PowerDNS over AXFR/IXFR. The panel
manages only the PowerDNS side (who is allowed AXFR, who gets NOTIFY, what is in the catalog); it does not
configure BIND. The panel itself shows a ready config snippet for each server:
**Propagation → Catalog → Servers → "?"** next to the server. The distribution model — [../../16-delivery.md](../../16-delivery.md).

```bash
sudo apt install bind9      # RFC 9432 consumer — BIND 9.18.3 and newer
```

## What the config must contain

```named
# named.conf.local
key "dc-ns1-key" { algorithm hmac-sha256; secret "..."; };   # only if the server is authorized by TSIG

zone "internal.catalog" {
    type secondary;
    primaries { 10.0.0.53 port 53 key "dc-ns1-key"; };      # the pair's service address, not the node addresses
    allow-notify { 10.0.0.11; 10.0.0.12; };           # addresses of both nodes of the pair
};

# inside options { }
allow-notify { 10.0.0.11; 10.0.0.12; };
catalog-zones {
    zone "internal.catalog" default-primaries { 10.0.0.53 port 53 key "dc-ns1-key"; };
};
```

- **`primaries` is the pair's service address**: zones must be pulled from whichever node is ACTIVE right now.
- **`allow-notify` lists the addresses of both nodes.** NOTIFY is sent from the ACTIVE node's address, not from the service address; without this
  line BIND logs `refused notify from non-primary` and learns about changes only via SOA refresh.
- **Authorization** is either the server's TSIG key or an IP ACL on its address, not both: for a server with a key
  the address does not go into `ALLOW-AXFR-FROM` (PowerDNS combines them with OR). With TSIG the server pulls zones from
  any address, but the address is still needed in the panel — NOTIFY goes to it, and the subscription state is seen by it.
- **A server that does not take zones from us** (AXFR for the server = Deny, or a group without zone AXFR): the catalog comes from the pair,
  and `default-primaries` is its own upstream with its own key; it does not need `allow-notify` in options.

## After a catalog change — restart, not reconfig

If the catalog itself changes in the config (a different name, different `default-primaries`), BIND 9.18 after `rndc reconfig`
may fail to set up member zones: `catz: failed to configure zone '...' - 22`. `systemctl restart named` helps.
Ordinary adding and removing of zones in the catalog by the panel does not require a restart.

## Check

```bash
dig +short +norec SOA <zone> @127.0.0.1                     # serial matches PowerDNS
journalctl -u named | grep -E 'transfer of|notify'         # transfers with TSIG, NOTIFY accepted
```
