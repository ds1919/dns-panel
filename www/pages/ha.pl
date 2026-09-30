#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use JSON qw(encode_json);
use functions qw(json_for_html request_user has_capability ha_mode ha_node_id ha_manager_request ha_service_url
                 node_addresses node_ifaces ha_pair_address);

# HA page. Floating IP and Anycast are modes of the same pair mechanism (role switch, epoch, GTID drain,
# emergency promotion, reseed); only the publication primitive differs (VIP vs route announcement).
# The page holds no HA logic: it shows manager state and sends intents; the manager alone decides
# whether a switch is allowed now.

sub _esc { my ($s) = @_; return '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; return $s; }

my $USER    = request_user();
my $CAN_HA  = has_capability($USER, 'ha.manage')    ? 1 : 0;
my $CAN_EM  = has_capability($USER, 'ha.emergency') ? 1 : 0;
# Three distinct facts, each driving a different screen:
#	ha_mode()     the HA stack is installed on this node
#	$TRUSTED      nodes are paired (source of truth: pair_status)
#	$CONFIGURED   HA is enabled with an active revision (source of truth: status.pair.ha_configured)
# Screens:
#	!$TRUSTED                  -> Standalone [Pair with another node]
#	$TRUSTED && !$CONFIGURED   -> Paired, HA not configured [Configure HA] [Undo pairing]
#	$TRUSTED && $CONFIGURED    -> HA active, ACTIVE/STANDBY [Dismantle HA]
# Keep $TRUSTED and $CONFIGURED separate: a dismantled but still paired pair must not show the pairing screen.
my $MODE    = ha_mode();               # standalone | pair
my $NODE_ID = ha_node_id() || '';

# Initial state is embedded so the page is meaningful before the first poll; an unreachable manager
# shows an explicit "state unknown" status, not an empty page.
my ($status, $status_err, $ops, $ops_err, $pairing, $pairing_err, $config, $config_err);
my ($TRUSTED, $CONFIGURED) = (0, 0);
if ($MODE eq 'pair' && $CAN_HA) {
    ($status, $status_err) = ha_manager_request('status');
    ($pairing, $pairing_err) = ha_manager_request('pair_status');
    $pairing = (ref $pairing eq 'HASH' && ref $pairing->{result} eq 'HASH') ? $pairing->{result} : $pairing;
    # Both facts come from the responses above, not extra socket calls, so they cannot disagree.
    $TRUSTED    = (ref $pairing eq 'HASH' && ($pairing->{state} // '') eq 'trusted') ? 1 : 0;
    my $pv      = (ref $status eq 'HASH' && ref $status->{pair} eq 'HASH') ? $status->{pair} : undef;
    # Tri-state: 1 enabled, 0 provably disabled, undef unknown (manager unreachable or could not read
    # `dns_ha`). Collapsing undef to 0 would show "HA not configured" for a pair that may be running.
    my $hc      = $pv ? $pv->{ha_configured} : undef;
    $CONFIGURED = defined $hc ? ($hc ? 1 : 0) : undef;
    # Config and operations are fetched only when HA is provably enabled.
    if ($CONFIGURED) {
        ($ops, $ops_err) = ha_manager_request('operations', limit => 12);
        $ops = (ref $ops eq 'HASH' && ref $ops->{result} eq 'ARRAY') ? $ops->{result} : [];
        # Config is needed in the first frame: without node addresses and card order the page would
        # reorder the server cards once /ha/config arrives.
        ($config, $config_err) = ha_manager_request('config');
        $config = $config->{result} if ref $config eq 'HASH' && ref $config->{result} eq 'HASH';
    }
}

my $BOOT = json_for_html({
    mode        => $MODE,
    node_id     => $NODE_ID,
    node_ips    => [ node_addresses() ],
    pair_ip     => scalar((ha_pair_address())[0]),   # user-chosen pairing address, may be null
    node_ifaces => [ node_ifaces() ],
    service_url => ha_service_url(),
    can_manage  => $CAN_HA ? \1 : \0,
    can_emerg   => $CAN_EM ? \1 : \0,
    paired        => $TRUSTED    ? \1 : \0,
    # Unknown stays null so the UI shows "unknown", not "no".
    ha_configured => defined $CONFIGURED ? ($CONFIGURED ? \1 : \0) : undef,
    status      => $status,
    status_err  => $status_err,
    pairing     => $pairing,
    pairing_err => $pairing_err,
    operations  => $ops || [],
    ops_err     => $ops_err,
    config      => $config,
    config_err  => $config_err,
});

# No page header on purpose: the section is already highlighted in the side menu.
print qq{<script type="application/json" id="ha-data">$BOOT</script>\n};
print <<'HTML';
<div id="ha-body"></div>
HTML
