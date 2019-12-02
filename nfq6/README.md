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
At time of writing (2019-12-02 11:58:18 +1100), you need
[this one](https://www.spinics.net/lists/netfilter-devel/msg64152.html).

## nfq6 Invocation
The command `nfq6 -h` is always up to date. At time of writing, it gives

    Usage: nfq6 [-TUh] [-t <test #>] queue_number
      -T: use TCP (not implemented yet)
      -U: use UDP (default
      -h: give this help
      -t <n>: Do test <n>. Tests are:
        0: If packet mark is zero, set it to 0xbeef and give verdict NF_REPEAT
        1: If packet mark is not 0xfaceb00c, set it to that and give verdict NF_REPEAT
           If packet mark *is* 0xfaceb00c, give verdict NF_STOP

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
      # A chain to test IPv6 mangling

      chain FILTER_INPUT \
      {
    type filter hook input priority filter; policy accept;
    iif "lo" meta l4proto udp udp dport 1042 counter queue num 24 bypass
      }
    }
    list ruleset
