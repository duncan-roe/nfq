$ORIGIN .
$TTL 86400	; 1 day
bogus.nit		IN SOA	tallstar. fred_nerk.bogus.nit. (
				343	   ; serial
				10800	   ; refresh (3 hours)
				900	   ; retry (15 minutes)
				604800	   ; expire (1 week)
				86400	   ; minimum (1 day)
				)
			NS	tallstar.bogus.nit.
$ORIGIN bogus.nit.
$TTL 302400	; 3 days 12 hours
sys3			A	10.255.254.1
			A	10.255.254.2
			A	10.255.254.3
sys1			A	10.255.254.4
tallstar		A	10.255.254.6
sys2			A	10.255.254.7
			A	10.255.254.8
sys8			A	10.255.254.10
			A	10.255.254.11
			A	10.255.254.12
			A	10.255.254.13
			A	10.255.254.14
			A	10.255.254.15
			A	10.255.254.16
			A	10.255.254.17
sys5			A	10.255.254.18
			A	10.255.254.19
			A	10.255.254.20
			A	10.255.254.21
			A	10.255.254.22
sys4			A	10.255.254.23
			A	10.255.254.24
			A	10.255.254.25
			A	10.255.254.26
