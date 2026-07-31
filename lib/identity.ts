// A Moshpit identity: a long-term ML-DSA-65 keypair, and the pin that names it.
//
// The pin is SHA-256 over the SubjectPublicKeyInfo, base64 — byte-for-byte the
// same format `moshpit-proxy` publishes for TLS keys. That is the point of
// reusing it: one registry field, `pins`, anchors both transports. A name's
// entry can list a TLS SPKI pin and an ML-DSA SPKI pin side by side, and a
// client picks whichever matches the transport it speaks.
//
// ML-DSA-65 rather than Ed25519 because this is the half of the protocol that
// Shor's algorithm would otherwise break. Key agreement is protected by
// harvest-now-decrypt-later urgency; signatures are not, since a forgery in
// 2040 cannot retroactively open a session recorded today. But we control both
// ends here — there is no root program to wait for — so there is no reason to
// ship the weaker thing.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";

export const IDENTITY_ALGORITHM = "ml-dsa-65";

export type Identity = {
  publicKey: KeyObject;
  privateKey: KeyObject;
  /** SPKI DER, which is what goes on the wire and what the pin is taken over. */
  publicKeyDer: Buffer;
  pin: string;
};

export function generateIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPairSync(IDENTITY_ALGORITHM as "ed25519");
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return { publicKey, privateKey, publicKeyDer, pin: pinFromSpkiDer(publicKeyDer) };
}

export function pinFromSpkiDer(spki: Uint8Array): string {
  return createHash("sha256").update(spki).digest("base64");
}

/**
 * Rejects anything that is not an ML-DSA-65 key before it is ever used to
 * verify. Without this check a peer could offer, say, an Ed25519 key whose pin
 * an attacker had ground out, and the algorithm would silently downgrade.
 */
export function publicKeyFromSpkiDer(spki: Uint8Array): KeyObject {
  const key = createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  if (key.asymmetricKeyType !== IDENTITY_ALGORITHM) {
    throw new Error(`expected ${IDENTITY_ALGORITHM} identity, got ${key.asymmetricKeyType}`);
  }
  return key;
}

/** The on-disk shape written by `moshpit-keygen`. */
export type StoredIdentity = {
  name: string;
  algorithm: string;
  pin: string;
  publicKey: string;
  privateKey: string;
};

/**
 * Rebuilds an identity from what keygen wrote.
 *
 * The stored pin is recomputed rather than trusted. A file whose recorded pin
 * disagrees with its own key is either corrupt or edited, and serving under it
 * would advertise one identity while proving another — clients would fail to
 * connect with no indication of why.
 */
export function identityFromStored(stored: StoredIdentity): Identity {
  if (stored.algorithm !== IDENTITY_ALGORITHM) {
    throw new Error(`expected ${IDENTITY_ALGORITHM} identity, file says ${stored.algorithm}`);
  }

  const publicKeyDer = Buffer.from(stored.publicKey, "base64");
  const pin = pinFromSpkiDer(publicKeyDer);
  if (stored.pin && stored.pin !== pin) {
    throw new Error(`identity file is inconsistent: records pin ${stored.pin}, key hashes to ${pin}`);
  }

  const privateKey = createPrivateKey({
    key: Buffer.from(stored.privateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  if (privateKey.asymmetricKeyType !== IDENTITY_ALGORITHM) {
    throw new Error(`private key is ${privateKey.asymmetricKeyType}, not ${IDENTITY_ALGORITHM}`);
  }

  return { publicKey: publicKeyFromSpkiDer(publicKeyDer), privateKey, publicKeyDer, pin };
}

export async function loadIdentity(path: string): Promise<Identity> {
  return identityFromStored(JSON.parse(await readFile(path, "utf8")) as StoredIdentity);
}

/** Constant-time-ish membership test. Pins are public; the habit is cheap. */
export function pinMatches(presented: string, allowed: readonly string[]): boolean {
  let hit = false;
  for (const candidate of allowed) {
    if (candidate.length === presented.length && candidate === presented) hit = true;
  }
  return hit;
}
