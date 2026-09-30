# 01 — Пакеты ОС

Ubuntu 24.04 (noble) или 26.04 (resolute). Всё ставит `deploy/install.sh`; **Perl-модули — пакетами apt, не CPAN.**

## Что ставит установщик

PowerDNS — из официального репозитория, ветка `auth-51` ([03-powerdns.md](03-powerdns.md)). Остальное — из
дистрибутива:

```
perl libcgi-pm-perl libdbi-perl libdbd-mysql-perl libjson-perl libwww-perl
libcrypt-urandom-perl libcrypt-argon2-perl libcryptx-perl libauth-googleauth-perl libimager-qrcode-perl
apache2 libapache2-mod-fcgid libfcgi-perl bind9-dnsutils rsync
mariadb-server mariadb-client
pdns-server pdns-backend-mysql
```

`pdns-backend-bind` удаляется (его `launch+=bind` конфликтует с gmysql). Модули Apache:
`a2enmod cgid fcgid rewrite headers env`.

## Perl-модули панели

| Модуль (в коде) | apt-пакет | Зачем |
|-----------------|-----------|-------|
| `FCGI` | `libfcgi-perl` | постоянный процесс `www/panel.fcgi` под `mod_fcgid` |
| `CGI`, `CGI::Cookie` | `libcgi-pm-perl` | разбор запроса, cookie-сессии |
| `DBI` | `libdbi-perl` | доступ к MariaDB (`dns_panel` + `pdns`) |
| `DBD::mysql` | `libdbd-mysql-perl` | драйвер (DSN `DBI:mysql:`), работает с MariaDB |
| `JSON` | `libjson-perl` | API-тела, встроенный JSON страниц |
| `LWP::UserAgent`, `HTTP::Request` | `libwww-perl` | HTTP API PowerDNS |
| `Crypt::URandom` | `libcrypt-urandom-perl` | криптостойкий random (токены/секреты) |
| `Crypt::Argon2` | `libcrypt-argon2-perl` | **Argon2id** — хэш паролей |
| `Crypt::AuthEnc::GCM` (CryptX) | `libcryptx-perl` | **AES-256-GCM** — шифрование TOTP-секретов master-key |
| `Auth::GoogleAuth` | `libauth-googleauth-perl` | **TOTP** (RFC 6238) |
| `Imager::QRCode` | `libimager-qrcode-perl` | **QR** для TOTP-enrollment |
| `Digest::SHA`, `MIME::Base64`, `Socket`, `IO::Socket::UNIX`, `POSIX`, `FindBin`, … | ядро Perl | отдельно ставить не нужно |

Установщик проверяет: `perl -MCGI -MDBI -MDBD::mysql -MJSON -MCrypt::Argon2 -MImager::QRCode -MFCGI -e 1`.

`bind9-dnsutils` — внешний `dig`: им dns-agent сверяет SOA и делает AXFR с других серверов.

## Что НЕ нужно

- CPAN.
- Go на узлах: Go-бинарники приходят собранными в пакете релиза (из исходников — `make build` / `make deb`).
- Сборка фронтенда: панель без сборки.
