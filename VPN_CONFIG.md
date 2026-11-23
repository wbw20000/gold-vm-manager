# Explicit guest VPN configuration

[The standalone parser](<vpn_config.py>) never imports legacy provisioning, reads host profiles/credentials, fetches subscriptions, or contacts the network. It normalizes **user-submitted** Clash/Mihomo nodes for a **new guest**. Storage/API/UI/runtime integration is deliberately outside this module.

## API

```python
from vpn_config import parse_submission, VPNConfigurationError

result = parse_submission({'input_mode': 'fields', 'nodes': node_dicts})
# Alternatively: {'input_mode': 'yaml', 'yaml_text': uploaded_text}
# Optional resolver(hostname) -> list/tuple of 1..16 public IPv4 strings.
```

`VPNConfiguration` is a frozen dataclass with a constant redacted repr:

- `private_config`: a JSON-compatible dictionary containing credentials.
- `private_json`: deterministic sorted compact JSON, also valid YAML; **private**.
- `endpoints`: sorted, deduplicated tuple of `(tcp|udp, public_ipv4, port)`; **private**. Shadowsocks permits TCP and, when enabled, UDP; TUIC/Hysteria2 use UDP; VLESS/Trojan use TCP.
- `summary`: only `node_count`, `endpoint_count`, sorted `protocols`, fixed-text `warnings`, and `normalization_required`. Safe to expose; no input names, endpoints, credentials or exception details.

A stored ticket is single-use and an unclaimed one expires after an hour, so a later VM cannot reuse the ticket itself. `vpn_store.store_saved(state_dir, private_config, endpoints)` issues a new ticket for a configuration the manager already validated and kept with one of its own VMs (read back by `preinstall_runtime.saved_private_config`). It accepts the configuration only if reparsing it here, without any resolver, reproduces it and its endpoints exactly; its summary carries no warnings because nothing is replaced.

`VPNConfigurationError` has constant sanitized text. Do not log submissions/private output or tracebacks with local variables. Frozen attributes do not deeply freeze dictionaries: never mutate a validated result before storage/use. The caller must privately store the exact validated config and corresponding fence atomically.

No resolver is created implicitly. Without an injected resolver, use literal global IPv4 and your operator's explicit TLS SNI (`servername` for VLESS, `sni` otherwise). With one, **all** answers must be public unicast IPv4; mixed private/IPv6 answers fail. The numerically smallest answer is pinned, DNS names are cached per submission, and explicit/default original TLS names are retained. Revalidate to refresh pins. IPv6, non-global/special-use IPv4 and endpoint port 53 are rejected.

## Reviewed subset

Both modes use the same Clash node keys and strict types (integer ports, real booleans). One to sixteen explicit nodes; optional names are discarded.

| Type | Supported |
| --- | --- |
| `tuic` | UUID/password, verified TLS SNI, ALPN, `cubic`/`new_reno`/`bbr`, `native`/`quic` relay; bounded integer timing/packet options |
| `vless` | Canonical nonzero UUID; `tls: true`, TCP only; optional `xtls-rprx-vision`, `xudp`, typed Reality public key/short ID, known browser fingerprints |
| `trojan` | Password, verified TLS SNI, TCP only, ALPN and known browser fingerprints |
| `ss` | Password; only `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`; optional UDP |
| `hysteria2` | Password, verified TLS SNI, optional integer Mbps `up`/`down`, optional `salamander` + `obfs-password` |

Unknown keys/types fail closed. No VMess, WS/gRPC, plugins, SSR, Shadowsocks 2022/legacy ciphers, Hysteria port hopping, custom trust certificates, insecure TLS, or disabled SNI. No providers, subscription downloads, scripts, YAML tags/anchors/aliases/merges/object construction, file/path directives or custom listeners. Rejected constructs are **not** silently adopted.

YAML mode requires **system `/usr/bin/ruby` with Psych/JSON** as a bootstrap prerequisite (no third-party dependency). A five-second subprocess receives only stdin, discards stderr, uses a minimal environment, and emits bounded JSON. Duplicate keys, multiple documents, non-string keys, non-JSON types, depth/node/size excesses fail. Limit: 256 KiB submitted/parsed data, depth 16, 8192 structural entries. Fields mode never launches Ruby.

## Owned policy and consent

Uploaded rules/DNS/TUN/controller/groups and allowlisted general settings are replaced, with fixed normalization warnings. Require **explicit normalization consent before creating a guest** whenever `summary.normalization_required` is true. Unknown top-level settings are rejected; submit only explicit nodes if a full config contains unsupported directives.

Output has silent logging, loopback-only local proxy/DNS, no controller API or controller secret, IPv6 disabled, owned TUN, no saved selection/history, generated `proxy-N` identities, a `PROXY` selector without DIRECT, and final `MATCH,PROXY`. DNS uses IP-literal DoH through `#PROXY`, including explicit bootstrap/proxy DNS, without plaintext bootstrap or fallback. Endpoint fence integration remains mandatory; normalization is not a substitute for the fence. Parent must check compatibility with its pinned Mihomo version.

**Initial user administrator consent is still required for guest service/TUN setup. Generated config is not evidence of installation, connection, isolation or readiness.** No runtime/native app/VM/disk execution is performed here.

## Nonfunctional templates and tests

The [Clash YAML template](<examples/vpn/clash.yaml>) has zero active nodes (`proxies: []`). In a copy outside version control, change that line to `proxies:`, then uncomment the matching protocol block below it and keep the indentation. Use your operator's actual endpoint, port, credentials and TLS name; leave certificate verification enabled. Enter only the filled copy's local path in the one-click form. The [parameter-form JSON](<examples/vpn/fields.json>) contains an empty `nodes` array. Neither template contains real endpoints or credentials, and both are deliberately rejected unchanged.

Run the fixture-only suite:

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p test_vpn_config.py -v
```

[Test fixtures](<tests/test_vpn_config.py>) use injected resolver/subprocess results; native Ruby tests use only explicit dummy strings and skip if Ruby is absent. No network, host profiles, temp-directory cleanup, VM/disk or native app operations.
