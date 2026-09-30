#!/usr/bin/env perl

use strict;
use warnings;

print "Status: 404 Not Found\n";
print "Content-Type: text/html; charset=utf-8\n\n";
print <<'HTML';
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="robots" content="noindex, nofollow">
    <title>DNS Panel | 404</title>
    <link rel="stylesheet" href="/css/main.css">
</head>
<body>
    <div class="login-wrap">
        <div class="flex flex-col items-center">
            <div style="font-size:56px;font-weight:700;line-height:1;">404</div>
            <p class="text-dim" style="margin:8px 0 20px;">Page not found.</p>
            <a href="/" class="btn btn-primary">Back to dashboard</a>
        </div>
    </div>
</body>
</html>
HTML
exit;
