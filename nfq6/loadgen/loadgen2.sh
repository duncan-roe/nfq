#!/bin/bash -p
# Hide shell commands from expect \
#set -x;\
[ -n "$1" ] || { echo "first arg must be number of packets" >&2;exit 1; } ;\
exec expect -- "$0" "$@"
#exp_internal 1
incr argv 0                        ;# Check numeric
set failed 0
spawn /bin/sh
expect {$ }
log_user 0
for {set i $argv; set j 1} {$i} {incr j; incr i -1} \
{
  exp_send {nc -6 -u ::1 -q 0 1042 <bigpkt}
  exp_send \r
  expect {$ }
  if {!($j%5000)} {puts $j}
}                         ;# for {set i $argv; set j 1} {$i} {incr j; incr i -1}
log_user 1
if {!$failed} \
{
  exp_send "nc -6 -u ::1 -q 0 1042 <q\r"
  expect {$ }
  exp_send exit\r
  expect eof
  wait
}                                  ;# if {{!$failed}}
