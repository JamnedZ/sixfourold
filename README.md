# sixfourold *(IPv6 for old apps)*

## A simple TCP/UDP local-to-remote proxy

(despite the name, it can proxy to IPv4 as well)

## Usage

```txt
$ sixfourold
- interactive mode

$ sixfourold -lp 10800 -ta 1234:2345:5f3::2 -tp 10800 -tcp -udp
- proxy tcp and udp traffic from localhost:10800 (127.0.0.1:10800) to [1234:2345:5f3::2]:10800

$ sixfourold -lp 25565 -ta smth.dynv6.com -tp 11037 -tcp -6
- proxy tcp traffic from localhost:25565 to smth.dynv6.com:11037, explicitly to IPv6

-6    Use only IPv6 for target (when using hostname)
-la string
    Local IP address to bind to (e.g., 0.0.0.0 for all interfaces) (default "127.0.0.1")
-lp string
    Local port the proxy will listen on (e.g., 7777)
-ta string
    Target port (e.g., 7777)
-tcp
    Enable the TCP proxy listener
-th string
    Target IP or hostname (e.g., 1234:5678::ef2 or myhost.ddns.net)
-udp
    Enable the UDP proxy listener
-h    Show help page
```

## Why

My mobile ISP provides me an IPv6 that is globally accessible, but some games are hardcoded to use IPv4, therefore I can't really host games like that, since I'm behind a CGNAT and people can't enter my IPv6 (or DDNS hostname, for that matter).

This little tool allows people who want to connect to me just to enter `127.0.0.1` with any port they wish (or the one the game requires) and it's like there was no problem at the first place.
