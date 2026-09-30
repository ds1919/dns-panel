# 04 — The panel: Apache, FastCGI, panel.toml

The panel is Perl with no build step. Pages and the API run in a persistent FastCGI process `www/panel.fcgi` under
`mod_fcgid` (`libapache2-mod-fcgid`, `libfcgi-perl`); `login.pl`, `logout.pl`, `404.pl` are plain CGI (`cgid`).
Everything below is done by `deploy/install.sh`.

## Layout

```
/opt/dns-panel/www/              ← DocumentRoot (via the symlink /var/www/vhost/dns-panel)
├── panel.fcgi index.pl api.pl login.pl logout.pl 404.pl header.pl .htaccess
├── css/ js/ images/
└── include/ API/ pages/ mcp/    ← closed by .htaccess (403)
```

Configs, secrets, `bin/` and `docs/` live next to it, in `/opt/dns-panel`, outside the web root. The installer syncs
`www/` as a whole (`rsync --delete`), owner `root:www-data`, not group-writable.

## Apache vhost

`/opt/dns-panel/etc/apache/dns-panel.conf` → symlink `/etc/apache2/sites-available/dns-panel.conf`; the
`dns-panel` site is enabled, `000-default` is disabled. Modules: `cgid fcgid rewrite headers env`. The site itself
(`DocumentRoot`, `<Directory>`, FastCGI limits) is in `dns-panel-common.conf`, shared by the `:80` vhost and the `:443` one
that `deploy/tls.sh` writes (HTTPS below):

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

`+FollowSymLinks` is required: DocumentRoot is a symlink. Routes are in `www/.htaccess`: `/`, pages
(`/zones`, `/records`, …), `/ajax/*`, `/dns-api/*` and `/health/{live,ready}` go to `panel.fcgi`; the same file
closes `include/ API/ pages/ mcp/`, dot paths and `*.json|sql|pm|md` files.

After a code update the installer restarts Apache — the `panel.fcgi` process restarts along with it.

## etc/panel.toml

The only panel config on the node: database access, the PowerDNS API, the dns-agent and pulse-server sockets, the
`[ha] enabled` flag. The installer creates it once from `etc/panel.example.toml` (`root:www-data 0640`), and it is
not part of the repository. It contains no passwords — only paths to secret files in `etc/secrets/` (`*_file`). Everything
the administrator manages (sync timeouts, MCP policy, session lifetime) is in the `settings` table
and is edited in the panel.

Login is only through real sessions (bootstrap-admin → login + password + TOTP) or an mTLS certificate.

## HTTPS + mTLS (client certificate)

Put the certificates into `/opt/dns-panel/etc/tls/` and run `/opt/dns-panel/deploy/tls.sh` as root:

| File | |
|------|--|
| `server.crt`, `server.key` | the server certificate and key (it must name the address people open: the node, or the pair's service name) |
| `chain.crt` | intermediate certificates, if the CA needs them (optional) |
| `client-ca.crt` | CA of client certificates: enables sign-in by certificate (optional) |

`tls.sh` writes the `:443` vhost (`etc/apache/dns-panel-tls.conf`) and makes `:80` redirect to it, except `/health/`
(readiness probes of a pair stay on plain HTTP). A client certificate is asked for but not required
(`SSLVerifyClient optional`): people without one sign in with a password, API and MCP clients with a token. Without the
files it takes HTTPS down again. The installer runs it on every install and package upgrade, so the setup survives
upgrades; run it yourself after replacing the certificates. On a pair, put the same files on both nodes.

The panel accepts the certificate when `SSL_CLIENT_VERIFY=SUCCESS` and takes the CN from `SSL_CLIENT_S_DN_CN` →
`auth_identities`. User provisioning — [../../08-auth.md](../../08-auth.md).

## Check

```bash
curl -s  http://<node>/health/ready                     # → JSON, "ready":1 (no session)
curl -sI http://<node>/ | grep -E '^(HTTP|Location:)'   # no session → 302, Location: …/login
curl -sI http://<node>/login | head -1                  # → 200
curl -sI http://<node>/pages/zones.pl | head -1         # → 403 (auth bypass closed)
curl -sI http://<node>/include/functions.pm | head -1   # → 403
```
