import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { MAX_PLAINTEXT, createOpener, createSealer } from "../lib/record.ts";
import { createFramer, frame } from "../lib/wire.ts";

const key = () => randomBytes(32);

describe("record layer", () => {
  test("round-trips", () => {
    const k = key();
    const sealer = createSealer(k);
    const opener = createOpener(k);

    assert.deepEqual(opener.open(sealer.seal(Buffer.from("hello"))), Buffer.from("hello"));
  });

  test("keeps a stream of records in step", () => {
    const k = key();
    const sealer = createSealer(k);
    const opener = createOpener(k);

    for (let i = 0; i < 50; i++) {
      const payload = Buffer.from(`record ${i}`);
      assert.deepEqual(opener.open(sealer.seal(payload)), payload);
    }
    assert.equal(sealer.count(), 50n);
    assert.equal(opener.count(), 50n);
  });

  test("a flipped bit fails authentication", () => {
    const k = key();
    const record = createSealer(k).seal(Buffer.from("hello"));
    record[0] ^= 0x01;

    assert.throws(() => createOpener(k).open(record));
  });

  test("a forged tag fails authentication", () => {
    const k = key();
    const record = createSealer(k).seal(Buffer.from("hello"));
    record[record.length - 1] ^= 0x01;

    assert.throws(() => createOpener(k).open(record));
  });

  test("records cannot be reordered", () => {
    const k = key();
    const sealer = createSealer(k);
    const opener = createOpener(k);

    const first = sealer.seal(Buffer.from("one"));
    const second = sealer.seal(Buffer.from("two"));

    // Nonces are implicit counters, so delivering the second record first
    // decrypts under the wrong nonce and fails the tag.
    assert.throws(() => opener.open(second));
    assert.doesNotThrow(() => createOpener(k).open(first));
  });

  test("a record cannot be replayed", () => {
    const k = key();
    const sealer = createSealer(k);
    const opener = createOpener(k);

    const record = sealer.seal(Buffer.from("once"));
    opener.open(record);

    assert.throws(() => opener.open(record));
  });

  test("a record sealed with a different key does not open", () => {
    const record = createSealer(key()).seal(Buffer.from("hello"));
    assert.throws(() => createOpener(key()).open(record));
  });

  test("oversized plaintext is refused before it is sealed", () => {
    assert.throws(
      () => createSealer(key()).seal(Buffer.alloc(MAX_PLAINTEXT + 1)),
      /exceeds/,
    );
  });

  test("a full-size record survives the round trip", () => {
    const k = key();
    const payload = randomBytes(MAX_PLAINTEXT);

    assert.deepEqual(createOpener(k).open(createSealer(k).seal(payload)), payload);
  });

  test("a record shorter than its tag is rejected", () => {
    assert.throws(() => createOpener(key()).open(Buffer.alloc(4)), /shorter than its tag/);
  });
});

describe("framing", () => {
  test("reassembles messages split across chunk boundaries", () => {
    const framer = createFramer(1024);
    const wire = Buffer.concat([frame(Buffer.from("alpha")), frame(Buffer.from("beta"))]);

    const out: Buffer[] = [];
    for (let i = 0; i < wire.length; i++) out.push(...framer(wire.subarray(i, i + 1)));

    assert.deepEqual(out.map((b) => b.toString()), ["alpha", "beta"]);
  });

  test("yields several messages from one chunk", () => {
    const framer = createFramer(1024);
    const wire = Buffer.concat([frame(Buffer.from("a")), frame(Buffer.from("b")), frame(Buffer.from("c"))]);

    assert.deepEqual([...framer(wire)].map((b) => b.toString()), ["a", "b", "c"]);
  });

  test("refuses a frame larger than the cap", () => {
    const framer = createFramer(16);
    assert.throws(() => [...framer(frame(Buffer.alloc(32)))], /exceeds max/);
  });

  test("holds an incomplete frame without emitting it", () => {
    const framer = createFramer(1024);
    const wire = frame(Buffer.from("incomplete"));

    assert.deepEqual([...framer(wire.subarray(0, 6))], []);
    assert.deepEqual([...framer(wire.subarray(6))].map((b) => b.toString()), ["incomplete"]);
  });
});
