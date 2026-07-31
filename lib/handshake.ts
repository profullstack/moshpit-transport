// MTP/1 handshake: hybrid key agreement, post-quantum identity, two messages.
//
//   client -> server   ClientHello   ephemeral X25519 pub, ephemeral ML-KEM pub, random
//   server -> client   ServerHello   ephemeral X25519 pub, ML-KEM ciphertext, random,
//                                    static ML-DSA pub, signature over the transcript
//
// Why hybrid. The session key is derived from *both* an X25519 exchange and an
// ML-KEM-768 encapsulation, concatenated before the KDF. Breaking one is not
// enough: a quantum adversary who solves the discrete log still lacks the
// ML-KEM secret, and a flaw discovered in ML-KEM still leaves X25519. This is
// the same reasoning behind TLS's X25519MLKEM768, and it is the reason not to
// ship ML-KEM alone despite it being the newer thing.
//
// Why the static key never participates in key agreement. It only signs. That
// separation is what gives forward secrecy: stealing a server's long-term
// identity key lets an attacker impersonate it *from then on*, but does not
// decrypt a single session recorded before the theft, because those session
// keys came from ephemerals that no longer exist.
//
// What the signature covers. The transcript is a hash of the whole ClientHello
// and of the ServerHello up to but excluding the signature field — so it binds
// both ephemerals, the KEM ciphertext, both randoms, and the server's claimed
// identity. An attacker cannot splice a recorded ServerHello onto a fresh
// ClientHello, because the client's ephemeral and random are inside the hash.
//
// ---------------------------------------------------------------------------
// This is a bespoke protocol. The primitives are standard and come from
// OpenSSL, but the composition has not been through formal analysis or an
// external review. See the warning in README.md before relying on it.
// ---------------------------------------------------------------------------

import {
  createHash,
  createPublicKey,
  decapsulate,
  diffieHellman,
  encapsulate,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import type { KeyObject } from "node:crypto";
import { Reader, Writer } from "./wire.ts";
import { pinFromSpkiDer, pinMatches, publicKeyFromSpkiDer } from "./identity.ts";
import type { Identity } from "./identity.ts";

export const MAGIC = Buffer.from("MTP1", "ascii");
export const CLIENT_HELLO = 0x01;
export const SERVER_HELLO = 0x02;

const KEM_ALGORITHM = "ml-kem-768";
const RANDOM_BYTES = 32;
const KEY_BYTES = 32;

export type SessionKeys = {
  /** Key for data the client sends. */
  clientToServer: Buffer;
  /** Key for data the server sends. */
  serverToClient: Buffer;
  /** A unique handle for this session, safe to log. */
  sessionId: string;
};

export type ClientHandshakeState = {
  message: Buffer;
  ephemeralX25519: KeyObject;
  ephemeralKem: KeyObject;
};

/** Step 1, client side. */
export function buildClientHello(): ClientHandshakeState {
  const x = generateKeyPairSync("x25519");
  const kem = generateKeyPairSync(KEM_ALGORITHM as "ed25519");

  const message = new Writer()
    .bytes(MAGIC)
    .u8(CLIENT_HELLO)
    .block(x.publicKey.export({ type: "spki", format: "der" }) as Buffer)
    .block(kem.publicKey.export({ type: "spki", format: "der" }) as Buffer)
    .bytes(randomBytes(RANDOM_BYTES))
    .build();

  return { message, ephemeralX25519: x.privateKey, ephemeralKem: kem.privateKey };
}

/** Step 2, server side: consume the ClientHello and answer it. */
export function buildServerHello(
  clientHello: Uint8Array,
  identity: Identity,
): { message: Buffer; keys: SessionKeys } {
  const reader = new Reader(clientHello);
  reader.expect(MAGIC, "protocol magic");
  if (reader.u8() !== CLIENT_HELLO) throw new Error("expected ClientHello");
  const clientX25519Der = reader.block();
  const clientKemDer = reader.block();
  reader.bytes(RANDOM_BYTES);
  reader.done();

  const serverX = generateKeyPairSync("x25519");
  const clientX = publicKeyOf(clientX25519Der, "x25519");
  const clientKem = publicKeyOf(clientKemDer, KEM_ALGORITHM);

  const { ciphertext, sharedKey } = encapsulate(clientKem);
  const classical = diffieHellman({ privateKey: serverX.privateKey, publicKey: clientX });

  // Everything except the signature, which cannot cover itself.
  const prefix = new Writer()
    .bytes(MAGIC)
    .u8(SERVER_HELLO)
    .block(serverX.publicKey.export({ type: "spki", format: "der" }) as Buffer)
    .block(ciphertext)
    .bytes(randomBytes(RANDOM_BYTES))
    .block(identity.publicKeyDer)
    .build();

  const transcript = hashTranscript(clientHello, prefix);
  const signature = sign(null, transcript, identity.privateKey);

  return {
    message: Buffer.concat([prefix, new Writer().block(signature).build()]),
    keys: deriveKeys(classical, Buffer.from(sharedKey), transcript),
  };
}

/** Step 3, client side: verify the server and finish. */
export function handleServerHello(
  serverHello: Uint8Array,
  state: ClientHandshakeState,
  allowedPins: readonly string[],
): { keys: SessionKeys; pin: string } {
  const reader = new Reader(serverHello);
  reader.expect(MAGIC, "protocol magic");
  if (reader.u8() !== SERVER_HELLO) throw new Error("expected ServerHello");
  const serverX25519Der = reader.block();
  const ciphertext = reader.block();
  reader.bytes(RANDOM_BYTES);
  const identityDer = reader.block();

  // The transcript is fixed at exactly this point, before the signature field.
  const prefix = reader.consumed();
  const signature = reader.block();
  reader.done();

  // The pin is checked before the signature, so an unknown identity is
  // rejected without ever running verification against attacker-chosen key
  // material.
  const pin = pinFromSpkiDer(identityDer);
  if (!allowedPins.length) throw new Error("no pins supplied; refusing to connect");
  if (!pinMatches(pin, allowedPins)) {
    throw new Error(`identity ${pin} is not in the pin set for this name`);
  }

  const identityKey = publicKeyFromSpkiDer(identityDer);
  const transcript = hashTranscript(state.message, prefix);
  if (!verify(null, transcript, identityKey, signature)) {
    throw new Error("server signature did not verify");
  }

  const serverX = publicKeyOf(serverX25519Der, "x25519");
  const classical = diffieHellman({ privateKey: state.ephemeralX25519, publicKey: serverX });
  const sharedKey = decapsulate(state.ephemeralKem, ciphertext);

  return { keys: deriveKeys(classical, Buffer.from(sharedKey), transcript), pin };
}

function hashTranscript(clientHello: Uint8Array, serverHelloPrefix: Uint8Array): Buffer {
  return createHash("sha256").update(clientHello).update(serverHelloPrefix).digest();
}

/**
 * Both secrets go into one KDF input rather than being XORed or hashed
 * separately, so the derived keys depend on the whole of each. The transcript
 * is the salt, which binds the keys to this exact exchange.
 */
function deriveKeys(classical: Uint8Array, postQuantum: Uint8Array, transcript: Buffer): SessionKeys {
  const ikm = Buffer.concat([Buffer.from(classical), Buffer.from(postQuantum)]);
  const expand = (label: string, length = KEY_BYTES) =>
    Buffer.from(hkdfSync("sha256", ikm, transcript, Buffer.from(label, "ascii"), length));

  return {
    clientToServer: expand("mtp1 c2s"),
    serverToClient: expand("mtp1 s2c"),
    sessionId: expand("mtp1 session id", 16).toString("hex"),
  };
}

/**
 * Parses a peer's SPKI and refuses it unless it is the algorithm this field is
 * supposed to carry. Without the check, a peer could offer a key of some other
 * type in the ephemeral slots and push the exchange somewhere unintended.
 */
function publicKeyOf(der: Uint8Array, expected: string): KeyObject {
  const key = createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
  if (key.asymmetricKeyType !== expected) {
    throw new Error(`expected ${expected} key, got ${key.asymmetricKeyType}`);
  }
  return key;
}
