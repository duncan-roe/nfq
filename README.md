# nfq
nft-based URL moderator
<br />
nfq needs a recent version of libnetfilter\_queue. Best clone the
[libnetfilter\_queue Git repository](https://git.netfilter.org/libnetfilter\_queue)
## Use as an ad blocker
nfq can be used as an ad blocker, either on the device or the router.
To do this, it works in conjunction with an **nft**
ruleset and a locally-installed *Domain Name Server*.
<br />
The diagram below shows the general setup:

    DNS                        KERNEL (NFT RULESET)                         BROWSER
     |                                    |  QRY advert.some.com               |
     |                                    |<---<---<---<---<---<---<---<---<---|
     |                                   /|  UDP: dest port domain (53)        |
     |                                  / |                                    |
     |                                 NFQ|                                    |
     |                                  \ |                                    |
     |  QRY sysx.bogus.nit               \|                                    |
     |<---<---<---<---<---<---<---<---<---|                                    |
     |                                    |                                    |
     |  RSP sysx.bogus.nit is A.B.C.D     |                                    |
     |--->--->--->--->--->--->--->--->--->|                                    |
     |  UDP: source port domain (53)      |\                                   |
                                          | \                                  |
                                          |NFQ                                 |
                                          | /                                  |
                                          |/ RSP advert.some.com is A.B.C.D    |
                                          |--->--->--->--->--->--->--->--->--->|
                                          |                                    |
                                          |  CONNECT A.B.C.D                   |
                                          |<---<---<---<---<---<---<---<---<---|
                                          |                                    |
                                          |  REJECT (admin prohibited)         |
                                          |--->--->--->--->--->--->--->--->--->|
                                          |         (or port not assigned &c.) |

*nfq* is DNS-agnostic, but the configuration files supplied with it are for
**Bind 9**.
<br />
Two domains *bogus.nit* and *bogus.nut* are defined.
An attempt to connect to a *bogus.nit* address gets
*Host not avaiable (admin prohibited)*, while connections to *bogus.nut* get
*Connection refused*.
<br />
(*bogus.net* is a real domain).

(To be continued)
