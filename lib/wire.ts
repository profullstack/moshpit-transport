// Wire encoding. Every variable field is length-prefixed rather than assumed
// to be a fixed size.
//
// The sizes here happen to be fixed today — ML-KEM-768 ciphertexts are 1088
// bytes, ML-DSA-65 signatures 3309 — but hardcoding them would make the parser
// silently wrong the day a parameter set changes, and a parser that is
// silently wrong about lengths is the classic way a protocol grows a memory
// bug. Length prefixes cost four bytes and remove the entire category.

export class Reader {
  #buf: Buffer;
  #offset = 0;

  constructor(buf: Uint8Array) {
    this.#buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  get remaining(): number {
    return this.#buf.length - this.#offset;
  }

  bytes(length: number): Buffer {
    if (length < 0 || this.remaining < length) {
      throw new Error(`truncated message: wanted ${length}, have ${this.remaining}`);
    }
    const slice = this.#buf.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    // Copied, not a view: callers keep these around and the backing buffer of a
    // socket chunk is reused.
    return Buffer.from(slice);
  }

  u8(): number {
    return this.bytes(1)[0]!;
  }

  u16(): number {
    return this.bytes(2).readUInt16BE(0);
  }

  /** A u16-length-prefixed field. */
  block(): Buffer {
    return this.bytes(this.u16());
  }

  expect(expected: Uint8Array, what: string): void {
    const actual = this.bytes(expected.length);
    if (!actual.equals(Buffer.from(expected))) {
      throw new Error(`bad ${what}`);
    }
  }

  /** Everything consumed so far, for transcript hashing. */
  consumed(): Buffer {
    return Buffer.from(this.#buf.subarray(0, this.#offset));
  }

  done(): void {
    if (this.remaining !== 0) {
      throw new Error(`trailing bytes: ${this.remaining}`);
    }
  }
}

export class Writer {
  #parts: Buffer[] = [];

  bytes(value: Uint8Array): this {
    this.#parts.push(Buffer.from(value));
    return this;
  }

  u8(value: number): this {
    const b = Buffer.allocUnsafe(1);
    b.writeUInt8(value, 0);
    return this.bytes(b);
  }

  u16(value: number): this {
    const b = Buffer.allocUnsafe(2);
    b.writeUInt16BE(value, 0);
    return this.bytes(b);
  }

  /** A u16-length-prefixed field. */
  block(value: Uint8Array): this {
    if (value.length > 0xffff) throw new Error(`field too long: ${value.length}`);
    return this.u16(value.length).bytes(value);
  }

  build(): Buffer {
    return Buffer.concat(this.#parts);
  }
}

/**
 * Splits a stream into u32-length-prefixed frames.
 *
 * Returned as a generator over whatever is complete, so a caller feeding it
 * socket chunks never has to think about message boundaries. The cap is what
 * stops a peer from announcing a 4 GiB frame and having us hold the buffer.
 */
export function createFramer(maxFrame: number) {
  let pending = Buffer.alloc(0);

  return function* push(chunk: Uint8Array): Generator<Buffer> {
    pending = pending.length ? Buffer.concat([pending, Buffer.from(chunk)]) : Buffer.from(chunk);

    for (;;) {
      if (pending.length < 4) return;
      const length = pending.readUInt32BE(0);
      if (length > maxFrame) throw new Error(`frame of ${length} exceeds max ${maxFrame}`);
      if (pending.length < 4 + length) return;

      yield Buffer.from(pending.subarray(4, 4 + length));
      pending = Buffer.from(pending.subarray(4 + length));
    }
  };
}

export function frame(payload: Uint8Array): Buffer {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, Buffer.from(payload)]);
}
