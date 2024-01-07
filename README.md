### acme-tls-alpn-01 &emsp; [![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![crates.io Version](https://img.shields.io/crates/v/acme-tls-alpn-01.svg)](https://crates.io/crates/acme-tls-alpn-01) [![Documentation](https://docs.rs/acme-tls-alpn-01/badge.svg)](https://docs.rs/acme-tls-alpn-01)

TLS certificate management using the [ACME (RFC 8555)](https://datatracker.ietf.org/doc/html/rfc8555) protocol,
using the [TLS-ALPN-01 (RFC 8737)](https://datatracker.ietf.org/doc/html/rfc8737) challenge.

Even though this should work with any ACME server, the emphasis is to have it work with the [Boulder](https://acme-v02.api.letsencrypt.org) implementation from [Let's Encrypt](https://letsencrypt.org), which can [diverge](https://github.com/letsencrypt/boulder/blob/main/docs/acme-divergences.md) slightly from the specs.

---

The [TLS-ALPN-01](https://datatracker.ietf.org/doc/html/rfc8737) challenge is validated by providing a self-signed certificate during the TLS handshake. The certificate must have an [`id-pe-acmeIdentifier` extension (id 31)](https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml#table-smi-numbers-1.3.6.1.5.5.7.1) that includes the authorization key.

This means that the library needs to interact with the server TLS acceptor.
