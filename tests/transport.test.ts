// End to end over a real TCP socket. These are the tests that check the claim:
// a pinned identity gets a session, anything else gets nothing.

import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { generateIdentity } from "../lib/identity.ts";
import { connect, createServer } from "../lib/transport.ts";
import type { Session, TransportServer } from "../lib/transport.ts";

const cleanup: Array<() => Promise<void>> = [];
after(async () => {
  for (const fn of cleanup.reverse()) await fn();
});

async function startServer(identity = generateIdentity(), onSession?: (s: Session) => void) {
  const server: TransportServer = createServer({
    identity,
    onSession: onSession ?? ((session) => {
      session.on("message", (data: Buffer) => session.send(Buffer.from(`echo:${data}`)));
    }),
  });
  const port = await server.listen(0, "127.0.0.1");
  cleanup.push(() => server.close());
  return { server, port, identity };
}

function exchange(session: Session, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), 8_000);
    session.once("message", (data: Buffer) => {
      clearTimeout(timer);
      resolve(data.toString());
    });
    session.once("error", (error: Error) => {
      clearTimeout(timer);
      reject(error);
    });
    session.send(Buffer.from(payload));
  });
}

describe("transport", () => {
  test("a pinned identity gets a working session", async () => {
    const { port, identity } = await startServer();
    const session = await connect({ host: "127.0.0.1", port, pins: [identity.pin] });

    assert.equal(await exchange(session, "hello"), "echo:hello");
    assert.equal(session.peerPin, identity.pin);
    assert.match(session.sessionId, /^[0-9a-f]{32}$/);
    session.close();
  });

  test("both sides agree on the session id", async () => {
    let serverSessionId = "";
    const identity = generateIdentity();
    const { port } = await startServer(identity, (session) => {
      serverSessionId = session.sessionId;
      session.on("message", (data: Buffer) => session.send(data));
    });

    const client = await connect({ host: "127.0.0.1", port, pins: [identity.pin] });
    await exchange(client, "ping");

    assert.equal(client.sessionId, serverSessionId);
    client.close();
  });

  test("an unpinned server is refused", async () => {
    const { port } = await startServer();
    const somebodyElse = generateIdentity();

    await assert.rejects(
      connect({ host: "127.0.0.1", port, pins: [somebodyElse.pin] }),
      /not in the pin set/,
    );
  });

  test("connecting with no pins is refused before a socket is opened", async () => {
    await assert.rejects(
      connect({ host: "127.0.0.1", port: 1, pins: [] }),
      /no pins supplied/,
    );
  });

  test("a rotating server is reachable on either of its published pins", async () => {
    const { port, identity } = await startServer();
    const previous = generateIdentity();

    // Both listed during a rotation window; the live key is the second.
    const session = await connect({
      host: "127.0.0.1", port, pins: [previous.pin, identity.pin],
    });

    assert.equal(session.peerPin, identity.pin);
    session.close();
  });

  test("many messages survive in order and in both directions", async () => {
    const { port, identity } = await startServer();
    const session = await connect({ host: "127.0.0.1", port, pins: [identity.pin] });

    const received: string[] = [];
    session.on("message", (data: Buffer) => received.push(data.toString()));

    for (let i = 0; i < 100; i++) session.send(Buffer.from(`msg-${i}`));
    await new Promise((r) => setTimeout(r, 500));

    assert.equal(received.length, 100);
    assert.equal(received[0], "echo:msg-0");
    assert.equal(received[99], "echo:msg-99");
    session.close();
  });

  test("a large payload survives the round trip", async () => {
    const { port, identity } = await startServer();
    const session = await connect({ host: "127.0.0.1", port, pins: [identity.pin] });

    const payload = "x".repeat(60_000);
    assert.equal(await exchange(session, payload), `echo:${payload}`);
    session.close();
  });

  test("closing is observable on the other side", async () => {
    const identity = generateIdentity();
    let closed = false;
    const { port } = await startServer(identity, (session) => {
      session.on("close", () => (closed = true));
    });

    const client = await connect({ host: "127.0.0.1", port, pins: [identity.pin] });
    client.close();
    await new Promise((r) => setTimeout(r, 300));

    assert.equal(closed, true);
  });
});
