> **Retired (September 2026).** This fork carried the RA-TLS v1 intra-handshake attestation binder. RA-TLS v2 obtains evidence after the handshake through a TLS exporter that upstream already exposes, so the fork is no longer needed and this repository is archived. See the RA-TLS v2 specification: https://github.com/Privasys/ra-tls-clients/blob/main/docs/ratls-v2.md and the SDKs in https://github.com/Privasys/ra-tls-clients (v0.9.1 and later).

> [!IMPORTANT]
> **This is the Privasys fork of Go, not the Go project.** It adds the RA-TLS
> challenge extension (0xFFBB) and RA-TLS channel binding to `crypto/tls` for the
> [Privasys](https://privasys.org) confidential-computing platform; the Privasys
> changes live on the `release-branch.go1.N` branches and `privasys-v*` tags. For
> Go itself, go to https://github.com/golang/go. **Security reports for this fork
> go to Privasys, not to the Go security team**: see [SECURITY.md](SECURITY.md).

# Go — Privasys RA-TLS Fork

This is a fork of the [Go programming language](https://github.com/golang/go) maintained by [Privasys](https://privasys.org) to add **RA-TLS (Remote Attestation TLS)** support to `crypto/tls`: a challenge extension for challenge-response attestation, and a session channel binder that binds attestation quotes to the live TLS session.

## What this fork adds

### RA-TLS challenge extension (`0xFFBB`)

A custom TLS extension that carries a challenge nonce in the **ClientHello** and **CertificateRequest** messages:

1. A TLS **client** embeds a challenge nonce in the ClientHello extension (`Config.RATLSChallenge`); the server reads it via `ClientHelloInfo.RATLSChallenge` in its certificate callbacks and binds it into its attestation quote's `report_data`.
2. A TLS 1.3 **server** can send its own nonce in the CertificateRequest (`Config.RATLSChallenge` on the server config); the client receives it via `CertificateRequestInfo.RATLSChallenge`, for the mutual (client-certificate) attestation leg.
3. The verifier confirms the quote was freshly generated for that specific handshake.

### Session channel binding

A 32-byte channel binder derived from the TLS 1.3 key schedule:

```
binder = HKDF-Expand-Label(client_handshake_traffic_secret,
                           "privasys-ratls-binder-v1",
                           transcript_hash(ClientHello..ServerHello), 32)
```

Both peers compute the identical value, so folding it into a quote's `report_data` binds the attestation to this exact TLS session — a relayed quote fails closed against a binding-aware verifier. The derivation is byte-compatible with the [Privasys rustls fork](https://github.com/Privasys/rustls). Binding is systematic: no negotiation, a configured hook always binds.

- **Server leg**: `Config.RATLSBindCertificate` is called at the Certificate-emit seam (once the handshake secret exists) with the binder, and may return a re-minted leaf whose quote commits to the session. Servers that serve certificates through `GetCertificate` (e.g. behind certmagic/Caddy) instead get a second `GetCertificate` call with `ClientHelloInfo.RATLSChannelBinder` set — only for clients that sent the `0xFFBB` extension.
- **Mutual (client-cert) leg**: `CertificateRequestInfo.RATLSChannelBinder` hands the client the binder so its client certificate's quote can commit to the session (`nonce || binder`).
- `ConnectionState.RATLSChannelBinder` exposes the binder on both sides so verifiers can recompute channel-bound `report_data`.

### Changed files (relative to upstream `go1.26.5`)

| File | Change |
|------|--------|
| `src/crypto/tls/common.go` | `Config.RATLSChallenge`, `Config.RATLSBindCertificate`, `ClientHelloInfo.RATLSChallenge`/`.RATLSChannelBinder`, `CertificateRequestInfo.RATLSChallenge`/`.RATLSChannelBinder`, `ConnectionState.RATLSChannelBinder` |
| `src/crypto/tls/conn.go` | Populate `ConnectionState.RATLSChannelBinder` |
| `src/crypto/tls/handshake_client.go` | Copy `Config.RATLSChallenge` → `clientHelloMsg` |
| `src/crypto/tls/handshake_client_tls13.go` | Derive the client-side binder; propagate challenge + binder to `CertificateRequestInfo` |
| `src/crypto/tls/handshake_messages.go` | Marshal/unmarshal `extensionRATLS` in `clientHelloMsg` and `certificateRequestMsgTLS13` |
| `src/crypto/tls/handshake_server.go` | Propagate challenge from ClientHello to `ClientHelloInfo` |
| `src/crypto/tls/handshake_server_tls13.go` | Copy `Config.RATLSChallenge` to CertificateRequest; derive the binder at the Certificate-emit seam; `RATLSBindCertificate` hook + `GetCertificate` re-invocation |
| `src/crypto/tls/handshake_messages_test.go` | Marshal/unmarshal round-trip tests |
| `src/crypto/tls/handshake_test.go` | `TestRATLS*` runtime tests (binder equality, both challenge legs, re-mint, TLS 1.2 fail-closed) |
| `src/crypto/tls/tls_test.go` | Config clone coverage for the new fields |

### Usage

```go
import "crypto/tls"

// Client side: send a challenge nonce and read the session binder.
config := &tls.Config{
    RATLSChallenge:     nonce,       // 8–64 bytes
    InsecureSkipVerify: true,        // attestation replaces PKI
}
conn, err := tls.Dial("tcp", "enclave:443", config)
binder := conn.ConnectionState().RATLSChannelBinder // 32 bytes, TLS 1.3

// Server side (enclave): re-mint the leaf so its quote commits to the session.
config := &tls.Config{
    GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        // hello.RATLSChallenge      — the client's nonce (both calls)
        // hello.RATLSChannelBinder  — nil on the first call, the 32-byte
        //                             binder on the emit-seam re-invocation
        return mintAttestedCert(hello.RATLSChallenge, hello.RATLSChannelBinder)
    },
}

// Mutual leg (TEE client authenticating to a verifier):
config := &tls.Config{
    GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
        // cri.RATLSChallenge      — the server's nonce from CertificateRequest
        // cri.RATLSChannelBinder  — this session's binder
        return mintAttestedClientCert(cri.RATLSChallenge, cri.RATLSChannelBinder)
    },
}
```

### Tests

```sh
GOROOT=<this repo> go test crypto/tls -run 'TestRATLS' -count=1
```

CI (`.github/workflows/build.yml`) builds the toolchain with `make.bash`, runs the RA-TLS tests, and attaches a prebuilt linux-amd64 toolchain tarball (`go-ratls-<tag>-linux-amd64.tar.gz`) to tagged releases. Consumers build with `GOROOT=<extracted>/go-ratls go build -tags ratls`.

## Upstream

This fork is based on the `release-branch.go1.26` branch (tag `go1.26.5`) of the upstream Go repository at https://github.com/golang/go. Challenge-extension upstream PR: [golang/go#77714](https://github.com/golang/go/pull/77714).

Unless otherwise noted, the Go source files are distributed under the
BSD-style license found in the LICENSE file.
