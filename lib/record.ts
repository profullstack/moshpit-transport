// The record layer: length-framed ChaCha20-Poly1305, one counter per direction.
//
// Nonces are implicit. Each direction keeps a 64-bit counter that starts at
// zero and increments once per record, and the nonce is that counter big-endian
// in the low eight bytes of twelve. Nothing is sent on the wire, so a peer
// cannot choose our nonce, and the two directions use different keys so the
// same counter value in each is not a reuse.
//
// Reusing a nonce with ChaCha20-Poly1305 is catastrophic rather than merely
// bad: it leaks the XOR of two plaintexts and, worse, allows forgery by
// exposing the Poly1305 key. So the counter is checked for exhaustion and the
// sealer refuses to continue rather than wrapping. 2^64 records is not
// reachable in practice; the check is here because "not reachable in practice"
// is what everyone says before it happens.

import { createCipheriv, createDecipheriv } from "node:crypto";

export const MAX_PLAINTEXT = 64 * 1024;
export const TAG_BYTES = 16;
/** Room for the tag on top of a full-size plaintext, plus the 4-byte framing. */
export const MAX_FRAME = MAX_PLAINTEXT + TAG_BYTES;

const ALGORITHM = "chacha20-poly1305";
const NONCE_BYTES = 12;
const COUNTER_LIMIT = 0xffffffffffffffffn;

export type Sealer = { seal(plaintext: Uint8Array): Buffer; count(): bigint };
export type Opener = { open(record: Uint8Array): Buffer; count(): bigint };

function nonceFor(counter: bigint): Buffer {
  const nonce = Buffer.alloc(NONCE_BYTES);
  nonce.writeBigUInt64BE(counter, NONCE_BYTES - 8);
  return nonce;
}

export function createSealer(key: Uint8Array): Sealer {
  let counter = 0n;
  return {
    seal(plaintext: Uint8Array): Buffer {
      if (plaintext.length > MAX_PLAINTEXT) {
        throw new Error(`record of ${plaintext.length} exceeds ${MAX_PLAINTEXT}`);
      }
      if (counter === COUNTER_LIMIT) throw new Error("record counter exhausted");

      const cipher = createCipheriv(ALGORITHM, key, nonceFor(counter), { authTagLength: TAG_BYTES });
      const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      counter++;
      return Buffer.concat([body, cipher.getAuthTag()]);
    },
    count: () => counter,
  };
}

export function createOpener(key: Uint8Array): Opener {
  let counter = 0n;
  return {
    open(record: Uint8Array): Buffer {
      if (record.length < TAG_BYTES) throw new Error("record shorter than its tag");
      if (record.length > MAX_FRAME) throw new Error(`record of ${record.length} exceeds ${MAX_FRAME}`);
      if (counter === COUNTER_LIMIT) throw new Error("record counter exhausted");

      const body = Buffer.from(record.subarray(0, record.length - TAG_BYTES));
      const tag = Buffer.from(record.subarray(record.length - TAG_BYTES));

      const decipher = createDecipheriv(ALGORITHM, key, nonceFor(counter), { authTagLength: TAG_BYTES });
      decipher.setAuthTag(tag);
      // Throws on a bad tag, which is the only correct response: a record that
      // does not authenticate is not a corrupted record, it is an attack, and
      // the caller tears the connection down rather than resynchronising.
      const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
      counter++;
      return plaintext;
    },
    count: () => counter,
  };
}
