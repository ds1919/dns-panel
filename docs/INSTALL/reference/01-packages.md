# 01 — OS packages

Ubuntu 24.04 (noble) or 26.04 (resolute). Everything is installed by `deploy/install.sh`; **Perl modules come as apt packages, not from CPAN.**

## What the installer installs

PowerDNS — from the official repository, branch `auth-51` ([03-powerdns.md](03-powerdns.md)). Everything else — from the
distribution:

```
perl libcgi-pm-perl libdbi-perl libdbd-mysql-perl libjson-perl libwww-perl
libcrypt-urandom-perl libcrypt-argon2-perl libcryptx-perl libauth-googleauth-perl libimager-qrcode-perl
apache2 libapache2-mod-fcgid libfcgi-perl bind9-dnsutils rsync
mariadb-server mariadb-client
pdns-server pdns-backend-mysql
```

`pdns-backend-bind` is removed (its `launch+=bind` conflicts with gmysql). Apache modules:
`a2enmod cgid fcgid rewrite headers env`.

## Panel Perl modules

| Module (in code) | apt package | Purpose |
|-----------------|-----------|-------|
| `FCGI` | `libfcgi-perl` | persistent `www/panel.fcgi` process under `mod_fcgid` |
| `CGI`, `CGI::Cookie` | `libcgi-pm-perl` | request parsing, cookie sessions |
| `DBI` | `libdbi-perl` | access to MariaDB (`dns_panel` + `pdns`) |
| `DBD::mysql` | `libdbd-mysql-perl` | driver (DSN `DBI:mysql:`), works with MariaDB |
| `JSON` | `libjson-perl` | API bodies, JSON embedded in pages |
| `LWP::UserAgent`, `HTTP::Request` | `libwww-perl` | PowerDNS HTTP API |
| `Crypt::URandom` | `libcrypt-urandom-perl` | cryptographically secure random (tokens/secrets) |
| `Crypt::Argon2` | `libcrypt-argon2-perl` | **Argon2id** — password hashing |
| `Crypt::AuthEnc::GCM` (CryptX) | `libcryptx-perl` | **AES-256-GCM** — encryption of TOTP secrets with the master key |
| `Auth::GoogleAuth` | `libauth-googleauth-perl` | **TOTP** (RFC 6238) |
| `Imager::QRCode` | `libimager-qrcode-perl` | **QR** for TOTP enrollment |
| `Digest::SHA`, `MIME::Base64`, `Socket`, `IO::Socket::UNIX`, `POSIX`, `FindBin`, … | Perl core | no separate installation needed |

The installer checks: `perl -MCGI -MDBI -MDBD::mysql -MJSON -MCrypt::Argon2 -MImager::QRCode -MFCGI -e 1`.

`bind9-dnsutils` — the external `dig`: dns-agent uses it to check SOA and to do AXFR from other servers.

## What is NOT needed

- CPAN.
- Go on the nodes: Go binaries come built in the release package (from source: `make build` / `make deb`).
- A frontend build: the panel has no build step.
