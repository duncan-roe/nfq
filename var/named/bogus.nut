$ORIGIN .
$TTL 86400	; 1 day
bogus.nut		IN SOA	tallstar. fred_nerk.bogus.nut. (
				343	   ; serial
				10800	   ; refresh (3 hours)
				900	   ; retry (15 minutes)
				604800	   ; expire (1 week)
				86400	   ; minimum (1 day)
				)
			NS	tallstar.bogus.nut.
$ORIGIN bogus.nut.
$TTL 302400	; 3 days 12 hours
sys3			A	10.255.253.1
			A	10.255.253.2
			A	10.255.253.3
sys1			A	10.255.253.4
tallstar		A	10.255.253.6
sys2			A	10.255.253.7
			A	10.255.253.8
sys8			A	10.255.253.10
			A	10.255.253.11
			A	10.255.253.12
			A	10.255.253.13
			A	10.255.253.14
			A	10.255.253.15
			A	10.255.253.16
			A	10.255.253.17
sys5			A	10.255.253.18
			A	10.255.253.19
			A	10.255.253.20
			A	10.255.253.21
			A	10.255.253.22
sys4			A	10.255.253.23
			A	10.255.253.24
			A	10.255.253.25
			A	10.255.253.26
