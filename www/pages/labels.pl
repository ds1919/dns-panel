#!/usr/bin/perl

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)';

use FindBin; use lib "$FindBin::RealBin/include";
use functions qw(label_categories_all request_user has_capability);

# Label taxonomy (Settings -> Labels): categories (single/multiple) with coloured values.
# Editing requires labels.manage.

my $USER = request_user();
my $CAN  = has_capability($USER, 'labels.manage') ? 1 : 0;
my $cats = label_categories_all();

sub _esc { my ($s) = @_; return '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; return $s; }

print <<HTML;
<div class="page-head">
    <div><h1>Labels</h1><div class="sub">Flexible zone classification (does not affect DNS)</div></div>
</div>
HTML

if (!$CAN) {
    print qq{<div class="card" style="margin-bottom:1rem;"><p class="text-dim" style="margin:0;">}
        . qq{View only — managing labels requires the <code>labels.manage</code> capability.</p></div>\n};
}

# Site-wide select component: a native <select> always opens a system-styled menu.
my $card_sel = functions::ui_select_html('lc-card',
    [ { value => 'multiple', label => 'multiple' }, { value => 'single', label => 'single' } ], 'multiple');
if ($CAN) {
    print <<HTML;
<div class="card lbl-newcat" style="margin-bottom:1.25rem;">
    <div class="lbl-newcat-row">
        <input type="text" id="lc-name" class="field-input" placeholder="New category name" autocomplete="off">
        $card_sel
        <button class="btn btn-primary" id="lc-add" type="button">+ Add category</button>
    </div>
</div>
HTML
}

print qq{<div class="lbl-cards">\n};

if (@$cats) {
    for my $c (@$cats) {
        my $cid  = _esc($c->{id});
        my $name = _esc($c->{name});
        my $card = _esc($c->{cardinality});
        my $del_cat = $CAN
            ? qq{<button class="lbl-cat-del" data-id="$cid" aria-label="Delete category">}
              . qq{<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2m-9 0v14a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V6M10 11v6M14 11v6"/></svg></button>}
            : '';
        print <<HTML;
    <div class="lbl-card" data-cat-id="$cid">
        <div class="lbl-card-head">
            <div><span class="lbl-card-title">$name</span> <span class="badge muted">$card</span></div>
            $del_cat
        </div>
        <div class="lbl-card-values">
HTML
        for my $v (@{ $c->{values} }) {
            my $vid = _esc($v->{id});
            my $vn  = _esc($v->{name});
            my $col = $v->{color} ? qq{ style="--c:} . _esc($v->{color}) . qq{"} : '';
            my $x = $CAN ? qq{ <button class="lbl-val-del" data-id="$vid" aria-label="Delete value">\x{00d7}</button>} : '';
            print qq{            <span class="lbl-tag"$col>$vn$x</span>\n};
        }
        print "        </div>\n";
        if ($CAN) {
            print <<HTML;
        <div class="lbl-addval">
            <input type="text" class="field-input lbl-val-name" placeholder="New value\x{2026}" autocomplete="off">
            <input type="color" class="lbl-val-color" value="#4bb3a5">
            <button class="btn btn-ghost lbl-val-add" type="button">+</button>
        </div>
HTML
        }
        print "    </div>\n";
    }
} else {
    print qq{    <div class="card"><p class="text-dim" style="margin:0;">No label categories yet.</p></div>\n};
}

print "</div>\n";
1;
