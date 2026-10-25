# Research notes for IP-FINDER tools 29–40

These notes explain implementation choices based on upstream documentation and are intentionally conservative. The software does not claim full security certification.

## DNS query comparison and batch DNS

The resolver comparison reuses the existing `PUBLIC_RESOLVERS` array rather than introducing another resolver provider. dnspython's resolver supports explicit resolver IPs via the `nameservers` attribute and bounded waits through `timeout`/`lifetime`; see the [dnspython resolver docs](https://dnspython.readthedocs.io/en/stable/resolver.html). The batch tool limits input to 50 unique names, uses up to four workers and performs only A/AAAA DNS lookups.

## TLS compatibility

Tool 32 makes a separate TLS handshake for each version it attempts; it does not submit HTTP requests. Python's `ssl` module is backed by the local OpenSSL build and its available protocol settings, and secure certificate validation remains the default in the existing certificate-inspection tool. The compatibility probe disables certificate verification only to isolate protocol negotiation, and states this plainly in its output. See the [official Python `ssl` documentation](https://docs.python.org/3/library/ssl.html).

A failed attempt is not proof that the remote endpoint does not support the protocol: local OpenSSL security policy, server configuration, a middlebox, or network filtering can cause failure.

## Certificate Transparency

Tool 24 continues to use the pre-existing `crt.sh` lookup. Certificate Transparency records public certificate issuance and can reveal names in certificates, but names found in the logs may be historical, expired or not currently resolvable. The client consumes at most 4 MiB of response data and returns at most 100 unique names to limit memory use. This is described in [Let's Encrypt's CT overview](https://letsencrypt.org/docs/ct-logs/).

## Route diagnostics on Termux

Tool 30 calls a locally installed command using an argument array (not a shell string), caps at 12 hops and enforces an 18-second process timeout. It accepts `traceroute` or `tracepath` on Unix-like systems, or `tracert` on Windows. Termux's package repository documents `traceroute` as an installable package; refer to the [Termux package system](https://github.com/termux/termux-packages/) and [package-management guide](https://github.com/termux/termux-packages/wiki/Package-Management).

## Repeated checks and local history

- TCP stability checks target one hostname/IP and one port, cap at 30 samples and use a short timeout.
- Uptime checks target one HTTP URL, cap at 30 requests and enforce a minimum 5-second interval.
- History stays in `~/.ip-finder/`; it is not committed to the repository. The application attempts owner-only directory/file permissions on platforms that support them.
- HTTP method inspection sends only OPTIONS. It does not try methods that create, change or delete remote data.

## Test evidence and remaining limits

The automated suite checks syntax, all numbered menu dispatch paths, success paths for tools 01–40, input limits, local history persistence and selected failure paths using mocked resolver, socket, TLS and HTTP behavior. It does not prove that every external provider is reachable from every network or that every operating system's traceroute flags behave identically. Perform real connectivity checks only with authorized targets and account for local firewall, DNS and OpenSSL behavior.
