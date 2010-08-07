#!/bin/sh
#
# Copyright (C) 2004-2010  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000-2003  Internet Software Consortium.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: conf.sh.in,v 1.43.8.3 2010/05/26 06:30:43 marka Exp $

#
# Common configuration data for system tests, to be sourced into
# other shell scripts.
#

# Find the top of the BIND9 tree.
TOP=${SYSTEMTESTTOP:=.}/../../..

# Make it absolute so that it continues to work after we cd.
TOP=`cd $TOP && pwd`

NAMED=$TOP/bin/named/named
# We must use "named -l" instead of "lwresd" because argv[0] is lost
# if the program is libtoolized.
LWRESD="$TOP/bin/named/named -l"
DIG=$TOP/bin/dig/dig
RNDC=$TOP/bin/rndc/rndc
NSUPDATE=$TOP/bin/nsupdate/nsupdate
DDNSCONFGEN=$TOP/bin/confgen/ddns-confgen
KEYGEN=$TOP/bin/dnssec/dnssec-keygen
SIGNER=$TOP/bin/dnssec/dnssec-signzone
REVOKE=$TOP/bin/dnssec/dnssec-revoke
SETTIME=$TOP/bin/dnssec/dnssec-settime
DSFROMKEY=$TOP/bin/dnssec/dnssec-dsfromkey
CHECKZONE=$TOP/bin/check/named-checkzone
CHECKCONF=$TOP/bin/check/named-checkconf

# The "stress" test is not run by default since it creates enough
# load on the machine to make it unusable to other users.
# v6synth
SUBDIRS="acl autosign cacheclean checkconf checknames dlv dnssec forward glue
    ixfr limits lwresd masterfile masterformat metadata notify nsupdate pending 
    resolver rrsetorder sortlist smartsign stub tkey unknown upforwd views
    xfer xferquota zonechecks"

# PERL will be an empty string if no perl interpreter was found.
PERL=/usr/bin/perl

export NAMED LWRESD DIG NSUPDATE KEYGEN SIGNER KEYSIGNER KEYSETTOOL PERL \
    SUBDIRS RNDC CHECKZONE
