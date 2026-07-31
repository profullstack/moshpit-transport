import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { buildClientHello, buildServerHello, handleServerHello } from "../lib/handshake.ts";
import { generateIdentity, pinFromSpkiDer } from "../lib/identity.ts";
import { Writer } from "../lib/wire.ts";

function completeHandshake(identity = generateIdentity(), pins?: string[]) {
  const state = buildClientHello();
  const server = buildServerHello(state.message, identity);
  const client = handleServerHello(server.message, state, pins ?? [identity.pin]);
  return { state, server, client, identity };
}

describe("handshake", () => {
  test("both sides derive the same keys", () => {
    const { server, client } = completeHandshake();

    assert.deepEqual(client.keys.clientToServer, server.keys.clientToServer);
    assert.deepEqual(client.keys.serverToClient, server.keys.serverToClient);
    assert.equal(client.keys.sessionId, server.keys.sessionId);
  });

  test("the two directions get different keys", () => {
    const { server } = completeHandshake();

    // Same key both ways would make the counter-based nonces collide across
    // directions, which is the reuse the record layer is built to avoid.
    assert.notDeepEqual(server.keys.clientToServer, server.keys.serverToClient);
  });

  test("every handshake is unique, so a recorded one cannot be replayed", () => {
    const identity = generateIdentity();
    const a = completeHandshake(identity);
    const b = completeHandshake(identity);

    assert.notDeepEqual(a.server.keys.clientToServer, b.server.keys.clientToServer);
    assert.notEqual(a.server.keys.sessionId, b.server.keys.sessionId);
  });

  test("the client reports the pin it actually verified", () => {
    const { client, identity } = completeHandshake();
    assert.equal(client.pin, identity.pin);
    assert.equal(client.pin, pinFromSpkiDer(identity.publicKeyDer));
  });

  test("an identity outside the pin set is refused", () => {
    const impostor = generateIdentity();
    const expected = generateIdentity();

    const state = buildClientHello();
    const server = buildServerHello(state.message, impostor);

    assert.throws(
      () => handleServerHello(server.message, state, [expected.pin]),
      /not in the pin set/,
    );
  });

  test("an empty pin set is refused rather than treated as 'anything goes'", () => {
    const identity = generateIdentity();
    const state = buildClientHello();
    const server = buildServerHello(state.message, identity);

    assert.throws(() => handleServerHello(server.message, state, []), /no pins supplied/);
  });

  test("a tampered signature does not verify", () => {
    const identity = generateIdentity();
    const state = buildClientHello();
    const server = buildServerHello(state.message, identity);

    const tampered = Buffer.from(server.message);
    tampered[tampered.length - 1] ^= 0x01;

    assert.throws(() => handleServerHello(tampered, state, [identity.pin]), /did not verify/);
  });

  test("swapping the server's ephemeral key breaks the transcript", () => {
    const identity = generateIdentity();
    const state = buildClientHello();
    const server = buildServerHello(state.message, identity);

    // An on-path attacker substituting its own X25519 share is the whole
    // reason the signature covers the transcript rather than just the identity.
    const attacker = generateKeyPairSync("x25519");
    const attackerDer = attacker.publicKey.export({ type: "spki", format: "der" }) as Buffer;

    const tampered = Buffer.from(server.message);
    // The ephemeral block starts after magic(4) + type(1) + u16 length(2).
    attackerDer.copy(tampered, 7);

    assert.throws(() => handleServerHello(tampered, state, [identity.pin]), /did not verify/);
  });

  test("a ServerHello bound to a different ClientHello is rejected", () => {
    const identity = generateIdentity();
    const victim = buildClientHello();
    const other = buildClientHello();

    // Recorded from someone else's session, replayed at us.
    const server = buildServerHello(other.message, identity);

    assert.throws(() => handleServerHello(server.message, victim, [identity.pin]), /did not verify/);
  });

  test("an identity of the wrong algorithm is refused", () => {
    const identity = generateIdentity();
    const state = buildClientHello();
    const server = buildServerHello(state.message, identity);

    // Replace the ML-DSA identity with an Ed25519 key and pin that instead.
    const ed = generateKeyPairSync("ed25519");
    const edDer = ed.publicKey.export({ type: "spki", format: "der" }) as Buffer;

    const magicAndType = 5;
    const view = Buffer.from(server.message);
    const ephLen = view.readUInt16BE(magicAndType);
    let cursor = magicAndType + 2 + ephLen;
    const ctLen = view.readUInt16BE(cursor);
    cursor += 2 + ctLen + 32;
    const idLen = view.readUInt16BE(cursor);

    const rebuilt = Buffer.concat([
      view.subarray(0, cursor),
      new Writer().block(edDer).build(),
      view.subarray(cursor + 2 + idLen),
    ]);

    assert.throws(
      () => handleServerHello(rebuilt, state, [pinFromSpkiDer(edDer)]),
      /expected ml-dsa-65/,
    );
  });

  test("a truncated ServerHello is rejected, not partially parsed", () => {
    const identity = generateIdentity();
    const state = buildClientHello();
    const server = buildServerHello(state.message, identity);

    assert.throws(() => handleServerHello(server.message.subarray(0, 40), state, [identity.pin]));
  });

  test("a ClientHello with bad magic is rejected", () => {
    const identity = generateIdentity();
    const state = buildClientHello();
    const tampered = Buffer.from(state.message);
    tampered.write("XXXX", 0, "ascii");

    assert.throws(() => buildServerHello(tampered, identity), /protocol magic/);
  });
});
