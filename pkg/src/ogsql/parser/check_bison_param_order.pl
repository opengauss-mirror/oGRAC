#!/usr/bin/env perl

use strict;
use warnings;

sub read_table
{
    my ($file, $marker) = @_;

    open(my $input, '<', $file) or die qq|Could not open $file: $!\n|;
    local $/;
    my $content = <$input>;
    close($input);

    my $start = index($content, $marker);
    die qq|Could not find table marker "$marker" in $file\n| if $start < 0;

    my $table = substr($content, $start + length($marker));
    $table =~ /^(.*?)^\};/ms or die qq|Could not find the end of table "$marker" in $file\n|;
    return $1;
}

sub check_table_order
{
    my ($file, $marker, $entry_pattern) = @_;
    my $table = read_table($file, $marker);
    my @names = ($table =~ /$entry_pattern/g);

    die qq|No entries found in table "$marker" in $file\n| if scalar(@names) == 0;
    for my $i (0 .. $#names - 1) {
        my $previous = uc($names[$i]);
        my $current = uc($names[$i + 1]);
        if (($previous cmp $current) >= 0) {
            die qq|The entry "$names[$i + 1]" is out of order in $file\n|;
        }
    }
}

die "Usage: check_bison_param_order.pl <system source> <session source> <NLS source>\n" if scalar(@ARGV) != 3;

check_table_order($ARGV[0], 'static const sql_bison_sys_param_verifier_t g_bison_sys_param_verifiers[] = {',
    qr/SQL_BISON_PARAM(?:_RANGE)?\("([^"]+)"/);
check_table_order($ARGV[1], 'static const bison_altset_item_t g_bison_altsession_items[] = {',
    qr/\{\s*\{\s*"([^"]+)"/);
check_table_order($ARGV[2], 'const nlsparam_item_t g_nlsparam_items[] = {',
    qr/\[[A-Z0-9_]+\]\s*=\s*\{\s*[A-Z0-9_]+,\s*\{\s*"([^"]+)"/);
