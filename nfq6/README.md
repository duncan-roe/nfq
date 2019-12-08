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
At time of writing (2019-12-08 13:20:32 +1100), there are no outstanding
patches.

## nfq6 Invocation
The command `nfq6 -h` is always up to date. At time of writing, it gives

    Usage: nfq6 [-TUh] [-t <test #>] queue_number
      -T: use TCP (not implemented yet)
      -U: use UDP (default
      -a: Alternate queue test 4 sends packets to
      -h: give this help
      -t <n>: Do test <n>. Tests are:
        0: If packet mark is zero, set it to 0xbeef and give verdict NF_REPEAT
        1: If packet mark is not 0xfaceb00c, set it to that and give verdict NF_REPEAT
           If packet mark *is* 0xfaceb00c, give verdict NF_STOP
        2: Allow ENOBUFS to happen; treat as harmless when it does
        3: Configure NFQA_CFG_F_FAIL_OPEN
        4: Send packets to alternate -a queue
        5: Force on test 4 and specify BYPASS
        6: Exit nfq6 if incoming packet contains 'q'

## Useful command lines
Run each of these in a separate window

`nc -6 -u ::1 1042`
<br />
`nc -6 -u -l -k -p 1042`
<br />
`tcpdump -X -i lo ip6`

## nft ruleset
nfq6 including all tests needs these rules

    #!/usr/sbin/nft -f
    flush ruleset
    table ip6 IP6 \
    {
      # A chain to test IPv6 mangling and different verdicts

      chain FILTER_INPUT \
      {
        type filter hook input priority filter; policy accept;
        iif "lo" meta l4proto udp udp dport 1042 counter queue num 24 bypass
      }

      # A chain to test verdict NF_STOP

      chain FILTER_INPUT_1 \
      {
        type filter hook input priority filter + 1; policy accept;
        iif "lo" meta l4proto udp udp dport 1042 counter
      }
    }
    list ruleset
