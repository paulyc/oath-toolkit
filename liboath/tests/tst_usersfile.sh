#!/bin/sh
# tst_usersfile.sh - Invoke tst_usersfile and check output.
# Copyright (C) 2009, 2010, 2011 Simon Josefsson

# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

cp $srcdir/users.oath tmp.oath

TSTAMP=`datefudge "2006-09-23" date -u +%s`
if test "$TSTAMP" != "1158962400"; then
    echo "Cannot fake timestamps, please install datefudge to check better."
    ./tst_usersfile$EXEEXT
    rc=$?
else
    datefudge 2006-12-07 ./tst_usersfile$EXEEXT
    rc=$?
    diff -ur $srcdir/expect.oath tmp.oath || rc=1
fi

rm -f tmp.oath

exit $rc
