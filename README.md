# klaps-direct-dns

A single Rust binary that does two things:

- **HTTP API**: a token yields a deterministic hash, then a Let's Encrypt certificate for `*.<hash>.klapz.direct` is issued and returned to the client.
- **Authoritative DNS** for `klapz.direct`, with answers computed on the fly:

| Name | Type | Answer |
|---|---|---|
| `192-168-1-12.<hash>.klapz.direct` | A | `192.168.1.12` |
| `2001-db8--1.<hash>.klapz.direct` | AAAA | `2001:db8::1` (`-` = `:`, `--` = `::`) |
| `_acme-challenge.<hash>.klapz.direct` | TXT | stored ACME challenge values |
| `klapz.direct` | SOA / NS | config |
| `ns1.klapz.direct` | A / AAAA | `DNS_NS_IPS` (glue) |

## Flow

1. `POST /certificate` with `Authorization: Bearer <token>`.
2. `hash = HMAC-SHA256(HASH_SECRET, token)`, truncated to `HASH_LENGTH` hex chars.
3. If `data/certs/ab/cd/<hash>.bin` holds a certificate valid for more than `RENEW_BEFORE_DAYS` days, it is returned right away.
4. Otherwise: ACME order, TXT value written to the `.bin` and to RAM (the DNS server serves it immediately), validation, then the certificate and key are added to the `.bin` and returned.

## API

```
GET  /subdomain        (Bearer)  -> {"hash","domain"}
POST /certificate      (Bearer)  -> {"hash","domain","names","not_after","certificate","private_key"}
GET  /txt/{hash}                 -> {"name","values"}
```

## Storage and performance

- One binary file per hash: `data/certs/ab/cd/<hash>.bin` (TXT + certificate + key + expiry). Atomic writes (tmp + rename), 0600 permissions.
- RAM cache bounded by `CACHE_MAX_MB` (50 MB by default), with usage-based eviction (moka, TinyLFU). Missing hashes are cached too.
- The certificate JSON response is serialized once and served as-is.
- DNS: one UDP socket per core (`SO_REUSEPORT`), A/AAAA answers with no disk access, plus TCP.
- mimalloc, LTO, `codegen-units = 1`.

## Running

```sh
cp .env.example .env   # then edit it
cargo build --release
set -a; . ./.env; set +a
sudo setcap 'cap_net_bind_service=+ep' target/release/klaps-direct-dns   # port 53 without root
./target/release/klaps-direct-dns
```

At the registrar: delegate `klapz.direct` to `ns1.klapz.direct`, with a glue record pointing to the server's IP. A second NS is recommended.

## Things to know

- **`token_is_valid`** (`src/api.rs`) accepts everything by default: wire it to your database, otherwise anyone can exhaust the Let's Encrypt quota.
- **Let's Encrypt quota**: 50 certificates per 7 days per registered domain (`klapz.direct`) in production. Test with `ACME_DIRECTORY=staging`, and request a rate limit override from Let's Encrypt before launch. The Public Suffix List is not an option: it explicitly rejects IP-in-name wildcard DNS services and requests made to work around rate limits.
- **Certificate Transparency**: every `<hash>.klapz.direct` is published. The HMAC prevents tracing a hash back to its token.
- **Private IPs**: some routers and resolvers with DNS rebinding protection block answers containing `192.168.x.x`, `10.x.x.x`, etc.
