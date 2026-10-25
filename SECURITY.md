# Security Policy

## Intended use

IP-FINDER is a network diagnostics and inventory utility for systems you own or are explicitly authorized to inspect. It is not a penetration-testing framework or load-testing tool.

## Reporting a problem

Please open a GitHub issue with a minimal reproduction and avoid posting API keys, private IP inventories, personal information, or full diagnostic exports. Redact sensitive targets and output before sharing.

## Built-in limits

- Route diagnostics caps the route at 12 hops and stops after 18 seconds.
- Connection stability checks cap at 30 samples to one host/port.
- Batch DNS checks accept at most 50 domains and perform DNS lookups only.
- Uptime checks cap at 30 HTTP requests and require at least a 5-second interval.
- HTTP method checking sends only `OPTIONS`.

These limits reduce unintended load but do not replace permission to test a target.
