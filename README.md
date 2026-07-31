# moshpit-transport

Post-quantum authenticated transport for **native** Moshpit clients. No TLS, no
certificates, no certificate authority. Hybrid X25519 + ML-KEM-768 key
agreement, ML-DSA-65 identity, ChaCha20-Poly1305 records, over plain TCP.

Zero dependencies — every primitive comes from `node:crypto` on Node 24 with
OpenSSL 3.5.

## ⚠️ Read this before relying on it

**This is a bespoke protocol.** The primitives are standard and come from
OpenSSL, but the *composition* — the handshake, the key schedule, the record
layer — has not been through formal analysis, an external audit, or any
adversarial review beyond the tests in this repository.

Novel transport crypto is one of the easiest things in computing to get subtly,
catastrophically wrong, and the failure mode is silence: it works perfectly and
is broken anyway. If you need something battle-tested today, use TLS 1.3 with
raw public keys, or a reviewed Noise Protocol Framework implementation.

The honest reason to use this instead is that nothing off the shelf currently
gives you post-quantum *authentication* without a certificate chain, which is
exactly what a name-is-the-key namespace wants. Treat it as a working reference
implementation of that idea, not as a finished security product.

## Why this exists

The browser story (`moshpit-proxy`) has to bend around what browsers allow:
`https://`, a local CA to satisfy the certificate check, and TLS's key exchange.
Native clients have none of those constraints. So this is what the design looks
like when nothing forces a compromise:

|  | moshpit-proxy | moshpit-transport |
|---|---|---|
| Clients | browsers | native, CLI, SDK |
| Transport | TLS 1.3 | raw TCP |
| Confidentiality | `X25519MLKEM768` if the stack has it | hybrid, always |
| **Authentication** | **SHA-256 pin over a TLS SPKI** | **ML-DSA-65 signature, pin over its SPKI** |
| Certificates | self-signed, plus a local CA for the browser | none at all |

**Both use the same pin format** — `SHA-256(SubjectPublicKeyInfo)`, base64. One
registry field, `pins`, anchors both. A name can list a TLS pin and an ML-DSA
pin side by side, and a client picks whichever suits the transport it speaks.

## Protocol (MTP/1)

```
client -> server   ClientHello   ephemeral X25519 pub, ephemeral ML-KEM-768 pub, random
server -> client   ServerHello   ephemeral X25519 pub, ML-KEM ciphertext, random,
                                 static ML-DSA-65 pub, signature over the transcript
```

**Hybrid on purpose.** The session key is derived from an X25519 exchange *and*
an ML-KEM-768 encapsulation, concatenated before the KDF. Breaking one is not
enough — a quantum adversary who solves the discrete log still lacks the ML-KEM
secret, and a flaw found in ML-KEM still leaves X25519. Same reasoning as TLS's
`X25519MLKEM768`.

**Forward secrecy.** The static ML-DSA key only ever signs; it never
participates in key agreement. Stealing a server's long-term identity lets an
attacker impersonate it *from then on*, but decrypts nothing recorded earlier,
because those session keys came from ephemerals that no longer exist.

**Transcript binding.** The signature covers a hash of the whole ClientHello and
the ServerHello up to the signature field — both ephemerals, the KEM ciphertext,
both randoms, and the claimed identity. A recorded ServerHello cannot be spliced
onto a fresh ClientHello. Tested.

**The client checks the pin before verifying the signature**, so an unknown
identity is rejected without running verification against attacker-chosen key
material.

### Record layer

Length-framed ChaCha20-Poly1305. Nonces are implicit 64-bit counters, one per
direction, never sent on the wire — so a peer cannot choose our nonce, and the
two directions use different keys. Records cannot be reordered, replayed, or
truncated without failing the tag. The sealer refuses to wrap the counter rather
than reusing a nonce.

## Use

```sh
node bin/moshpit-keygen.ts scrambled.eggs
```

Writes the identity to `~/.moshpit/identities/` with mode 600 and prints the pin
to publish at [app.moshcode.sh/pit/dns](https://app.moshcode.sh/pit/dns).

```ts
import { createServer, connect, loadIdentity } from "./lib/index.ts";

// server
const identity = await loadIdentity("~/.moshpit/identities/scrambled.eggs.json");
const server = createServer({
  identity,
  onSession: (session) => {
    session.on("message", (data) => session.send(data));
  },
});
await server.listen(9443, "0.0.0.0");

// client — pins come from the registry
const session = await connect({ host, port: 9443, pins });
session.on("message", (data) => console.log(data.toString()));
session.send(Buffer.from("hello"));
```

`connect()` rejects if the pin set is empty. There is no unauthenticated mode
and no TOFU — a native client has no rollout excuse, since it ships with code
that can fetch the registry.

## What this does not do

- **Browsers.** Not reachable from one, and not fixable: `crypto.subtle` is
  undefined on insecure origins, and you cannot bootstrap trust from an
  unauthenticated channel. Use `moshpit-proxy`, or TronBrowser.
- **Client authentication.** The server does not authenticate the client. The
  handshake has room for it (the transcript is already there to sign); it isn't
  built because nothing needs it yet.
- **Rekeying.** One key per direction per connection. Fine at 2^64 records;
  worth revisiting for very long-lived sessions.
- **0-RTT / early data.** Deliberately absent. Early data is where replay
  vulnerabilities live, and there is no latency budget forcing the risk.
- **Padding or traffic shaping.** Record lengths are visible. An observer learns
  message sizes and timing.

## Tests

```sh
npm test        # node --test tests/*.test.ts
```

34 tests. The interesting ones are adversarial: tampered signatures, swapped
ephemeral keys, ServerHellos replayed from a different session, identities of
the wrong algorithm, reordered and replayed records.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
