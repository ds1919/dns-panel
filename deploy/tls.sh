#!/bin/sh
# HTTPS for the panel. Put the certificates into /opt/dns-panel/etc/tls/ and run this as root:
#
#   server.crt     the server certificate (it must name the address people open: the node, or a pair's service name)
#   server.key     its private key
#   chain.crt      intermediate certificates, if the CA needs them          (optional)
#   client-ca.crt  CA of client certificates: enables sign-in by certificate (optional)
#
# With server.crt and server.key a :443 vhost is set up and :80 redirects to it, except /health/ (readiness probes
# of a pair stay on plain HTTP). A client certificate is asked for but not required: people without one sign in with
# a password, API and MCP clients with a token (optional_no_ca: a certificate that fails the check still reaches the
# panel, which only trusts SUCCESS but can then say what is wrong). Without the files, HTTPS is taken down again. The installer runs
# this on every install and update, so the setup survives package upgrades; run it yourself after changing the files.
set -eu
PANEL=/opt/dns-panel
TLS=$PANEL/etc/tls
A=$PANEL/etc/apache
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
# 0755: the panel checks whether client-ca.crt is there (sign-in by certificate); server.key itself stays 0600.
install -d -m 0755 -o root -g root "$TLS"

if [ -s "$TLS/server.crt" ] && [ -s "$TLS/server.key" ]; then
    chmod 0600 "$TLS/server.key"
    chain=""; [ -s "$TLS/chain.crt" ] && chain="    SSLCertificateChainFile $TLS/chain.crt"
    client=""
    if [ -s "$TLS/client-ca.crt" ]; then
        client="    SSLCACertificateFile  $TLS/client-ca.crt
    SSLVerifyClient       optional_no_ca
    SSLVerifyDepth        3"
    fi
    cat > "$A/dns-panel-tls.conf" <<EOF
# Written by deploy/tls.sh from the files in $TLS — edit those and run it again, not this file.
<VirtualHost *:443>
    Include $A/dns-panel-common.conf
    SSLEngine on
    SSLCertificateFile    $TLS/server.crt
    SSLCertificateKeyFile $TLS/server.key
$chain
$client
    # The panel reads SSL_CLIENT_VERIFY / SSL_CLIENT_S_DN_CN (sign-in by certificate) and HTTPS (secure cookies).
    <Directory /var/www/vhost/dns-panel>
        SSLOptions +StdEnvVars +ExportCertData
    </Directory>
</VirtualHost>
EOF
    cat > "$A/dns-panel-tls-redirect.conf" <<'EOF'
# Written by deploy/tls.sh: HTTPS is set up, so plain HTTP goes there — except the readiness probes.
RewriteEngine On
# Only the request as it came in: .htaccess maps /health/ready to panel.fcgi by an internal redirect, and that
# second pass would otherwise no longer look like /health/.
RewriteCond %{ENV:REDIRECT_STATUS} ^$
RewriteCond %{REQUEST_URI} !^/health/
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
EOF
    a2enmod -q ssl rewrite >/dev/null
    ln -sf "$A/dns-panel-tls.conf" /etc/apache2/sites-available/dns-panel-tls.conf
    a2ensite -q dns-panel-tls >/dev/null
    what="HTTPS on :443$( [ -n "$client" ] && echo ', sign-in by client certificate' ), :80 redirects to it"
else
    a2dissite -q dns-panel-tls >/dev/null 2>&1 || true
    rm -f /etc/apache2/sites-available/dns-panel-tls.conf "$A/dns-panel-tls.conf" "$A/dns-panel-tls-redirect.conf"
    what="HTTP only (no certificates in $TLS)"
fi

if ! apache2ctl configtest >/dev/null 2>&1; then
    apache2ctl configtest >&2 || true
    echo "Apache refuses this configuration — check the files in $TLS" >&2; exit 1
fi
systemctl reload apache2 2>/dev/null || systemctl restart apache2
echo "$what"
