# klaps-direct-dns

Un seul binaire Rust qui fait deux choses :

- **API HTTP** : un token donne un hash déterministe, puis un certificat Let's Encrypt pour `*.<hash>.klapz.direct`, renvoyé au client.
- **DNS faisant autorité** sur `klapz.direct`, avec des réponses calculées à la volée :

| Nom | Type | Réponse |
|---|---|---|
| `192-168-1-12.<hash>.klapz.direct` | A | `192.168.1.12` |
| `2001-db8--1.<hash>.klapz.direct` | AAAA | `2001:db8::1` (`-` = `:`, `--` = `::`) |
| `_acme-challenge.<hash>.klapz.direct` | TXT | valeurs du challenge ACME stockées |
| `klapz.direct` | SOA / NS | config |
| `ns1.klapz.direct` | A / AAAA | `DNS_NS_IPS` (glue) |

## Flux

1. `POST /certificate` avec `Authorization: Bearer <token>`.
2. `hash = HMAC-SHA256(HASH_SECRET, token)`, tronqué à `HASH_LENGTH` caractères hex.
3. Si `data/certs/ab/cd/<hash>.bin` contient un certificat valide pour plus de `RENEW_BEFORE_DAYS` jours, il est renvoyé directement.
4. Sinon : commande ACME, valeur TXT écrite dans le `.bin` et en RAM (le DNS la sert immédiatement), validation, puis certificat et clé ajoutés au `.bin` et renvoyés.

## API

```
GET  /subdomain        (Bearer)  -> {"hash","domain"}
POST /certificate      (Bearer)  -> {"hash","domain","names","not_after","certificate","private_key"}
GET  /txt/{hash}                 -> {"name","values"}
```

## Stockage et perf

- Un fichier binaire par hash : `data/certs/ab/cd/<hash>.bin` (TXT + certificat + clé + expiration). Écriture atomique (tmp + rename), permissions 0600.
- Cache RAM borné à `CACHE_MAX_MB` (50 Mo par défaut), avec éviction selon l'usage (moka, TinyLFU). Les hash absents sont aussi mis en cache.
- La réponse JSON du certificat est sérialisée une seule fois et resservie telle quelle.
- DNS : un socket UDP par cœur (`SO_REUSEPORT`), A/AAAA sans accès disque, plus TCP.
- mimalloc, LTO, `codegen-units = 1`.

## Lancer

```sh
cp .env.example .env   # puis éditer
cargo build --release
set -a; . ./.env; set +a
sudo setcap 'cap_net_bind_service=+ep' target/release/klaps-direct-dns   # port 53 sans root
./target/release/klaps-direct-dns
```

Côté registrar : déléguer `klapz.direct` à `ns1.klapz.direct`, avec un enregistrement glue vers l'IP du serveur. Idéalement, prévoir un deuxième NS.

## À savoir

- **`token_is_valid`** (`src/api.rs`) accepte tout par défaut : à brancher sur ta base, sinon n'importe qui peut épuiser les quotas Let's Encrypt.
- **Quotas Let's Encrypt** : 50 certificats par semaine et par domaine enregistré (`klapz.direct`) en production. Tester en `ACME_DIRECTORY=staging`. Au-delà, demander une hausse de limite ou faire ajouter le domaine à la Public Suffix List.
- **Certificate Transparency** : chaque `<hash>.klapz.direct` est publié. Le HMAC empêche de remonter au token.
- **IP privées** : certains routeurs et résolveurs, avec une protection anti DNS-rebinding, bloquent les réponses contenant `192.168.x.x`, `10.x.x.x`, etc.
