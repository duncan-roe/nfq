#!/bin/bash -p
# Hide shell commands from expect \
#set -x;\
[ -n "$1" ] || { echo "first arg must be number of packets" >&2;exit 1; } ;\
exec expect -- "$0" "$@"
#exp_internal 1
incr argv 0                        ;# Check numeric
set send_human {.1 .1 100 .0002 .0002}
set failed 0
spawn /bin/sh
expect {$ }
exp_send "nc -6 -u ::1 1042\r"
expect \r\n
log_user 0
for {set i $argv; set j 1} {$i} {incr j; incr i -1} \
{
  exp_send -h $j\r
  expect {$ } {set failed 1; break} \r\n {}
  if {!($j%5000)} {puts $j}
}                         ;# for {set i $argv; set j 1} {$i} {incr j; incr i -1}
log_user 1
if {!$failed} \
{
  exp_send -h q\r
  expect \r\n
  exp_send \03
  expect {$ }
  exp_send exit\r
  expect eof
  wait
}                                  ;# if {{!$failed}}
