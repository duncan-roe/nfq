# nfq6
experimental vehicle for IPv6 libnetfilter\_queue helper functions and
documentation
<br />
nfq6 needs a recent version of libnetfilter\_queue, usually from the
[libnetfilter\_queue Git repository](https://git.netfilter.org/libnetfilter\_queue).
In addition, nfq6 may need uncommitted libnetfilter\_queue patches which have
been posted to mailing list _netfilter-devel@vger.kernel.org_ or you can get
them from the
[mailing list archive](http://www.spinics.net/lists/netfilter-devel/)
(in the browser, search for _libnetfilter\_queue_).
<br />
At time of writing (2020-04-13 11:08:06 +1000), you need
[this](https://www.spinics.net/lists/netfilter-devel/msg66710.html).

## nfq6 Invocation
The command `nfq6 -h` is always up to date. At time of writing, it gives

    Usage: nfq6 [-a <alt q #>] [-p passes] [-t <test #>],... queue_number
           nfq6 -h
      -a <n>: Alternate queue for test 4
      -h: give this Help and exit
      -p <n>: Time <n> passes of pktb_alloc2() or whatever on the first packet.
              Forces on t6. It's expected the 2nd packet will be "q"
      -t <n>: do Test <n>. Tests are:
        0: If packet mark is zero, set it to 0xbeef and give verdict NF_REPEAT
        1: If packet mark is not 0xfaceb00c, set it to that and give verdict NF_REPEAT
           If packet mark *is* 0xfaceb00c, give verdict NF_STOP
        2: Allow ENOBUFS to happen; treat as harmless when it does
        3: Configure NFQA_CFG_F_FAIL_OPEN
        4: Send packets to alternate -a queue
        5: Force on test 4 and specify BYPASS
        6: Exit nfq6 if incoming packet contains 'q'
        7: Use pktb_alloc2()
        8: Give pktb_alloc2() an odd address
        9: Replace 1st ASD by F
       10: Replace 1st QWE by RTYUIOP
       11: Replace 2nd ASD by G
       12: Replace 2nd QWE by MNBVCXZ
       13: Use TCP
       14: Report EINTR if we get it
       15: Log netlink packets with no checksum
       16: Log all netlink packets
       17: Replace 1st ZXC by VBN
       18: Replace 2nd ZXC by VBN
       19: Give pktb_alloc2 zero extra
       20: Set 16MB kernel socket buffer

## Useful command lines
Run each of these in a separate window

`nc -6 -u ::1 1042`
<br />
`nc -6 -u -l -k -p 1042`
<br />
`tcpdump -X -i lo ip6`
<br />
To test with a listening netcat on another system on the local LAN, look up its
IPv6 address via *ifconfig* then connect similarly to this:
<br />
`nc -6 -u fe80::1a60:24ff:febb:2d6%eth0 1042`
<br />
(you need to use another system to test checksums)

## nft ruleset
These rules are adequate for almost all nfq6 tests

    #!/usr/sbin/nft -f
    flush ruleset
    table ip6 IP6 \
    {
      # Test IPv6 mangling via local interface
      chain FILTER_INPUT{type filter hook input priority filter; policy accept;
        iif "lo" udp dport 1042 counter queue num 24 bypass
        iif "lo" tcp dport 1042 counter queue num 24 bypass;}
      # Test IPv6 mangling via eth0
       chain FILTER_OUTPUT_2{type filter hook output priority filter;policy accept
        oif "eth0" udp dport 1042 counter queue num 24 bypass
        oif "eth0" tcp dport 1042 counter queue num 24 bypass;}
    }
To verify that NF\_STOP bypasses subsequent rules using the input hook,
you also need these (udp only)

    chain FILTER_INPUT_1{type filter hook input priority filter+1; policy accept;
      iif "lo" udp dport 1042 counter;}
    chain FILTER_OUTPUT{type filter hook output priority filter; policy accept;
      udp dport 1042 counter queue num 24 bypass;}
    chain FILTER_OUTPUT_1{type filter hook output priority filter+1;policy accept
      udp dport 1042 counter;}
    chain FLTR_PST{type filter hook postrouting priority filter+2;policy accept;
      udp dport 1042 counter;}
