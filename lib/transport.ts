// TCP wiring. Everything interesting is in handshake.ts and record.ts; this
// moves bytes and enforces the state machine around them.
//
// The rule that matters here: a connection is in one of two states, and no
// application data is emitted or accepted until the handshake has completed
// and — on the client — the server's identity has matched a pin. There is no
// "optimistic" path and no unauthenticated early data.

import { EventEmitter } from "node:events";
import { createServer as createTcpServer, connect as tcpConnect } from "node:net";
import type { Server as TcpServer, Socket } from "node:net";
import { buildClientHello, buildServerHello, handleServerHello } from "./handshake.ts";
import type { SessionKeys } from "./handshake.ts";
import { MAX_FRAME, MAX_PLAINTEXT, createOpener, createSealer } from "./record.ts";
import { createFramer, frame } from "./wire.ts";
import type { Identity } from "./identity.ts";

export type Session = EventEmitter & {
  send(data: Uint8Array): void;
  close(): void;
  readonly sessionId: string;
  /** The pin of the peer's static identity. Null on the server, which does not authenticate clients. */
  readonly peerPin: string | null;
};

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

/** Attaches the record layer to a socket once keys exist. */
function makeSession(
  socket: Socket,
  keys: SessionKeys,
  role: "client" | "server",
  peerPin: string | null,
  framer: ReturnType<typeof createFramer>,
  leftover: Buffer[],
): Session {
  const sealer = createSealer(role === "client" ? keys.clientToServer : keys.serverToClient);
  const opener = createOpener(role === "client" ? keys.serverToClient : keys.clientToServer);

  const session = new EventEmitter() as Session;
  Object.defineProperties(session, {
    sessionId: { value: keys.sessionId, enumerable: true },
    peerPin: { value: peerPin, enumerable: true },
  });

  let closed = false;
  const fail = (error: Error) => {
    if (closed) return;
    closed = true;
    socket.destroy();
    session.emit("error", error);
    session.emit("close");
  };

  const consume = (chunk: Uint8Array) => {
    try {
      for (const record of framer(chunk)) session.emit("message", opener.open(record));
    } catch (error) {
      fail(error as Error);
    }
  };

  // Bytes that arrived in the same TCP segment as the final handshake message.
  for (const chunk of leftover) consume(chunk);

  socket.on("data", consume);
  socket.on("error", fail);
  socket.on("close", () => {
    if (closed) return;
    closed = true;
    session.emit("close");
  });

  (session as { send: Session["send"] }).send = (data: Uint8Array) => {
    if (closed) throw new Error("session is closed");
    if (data.length > MAX_PLAINTEXT) throw new Error(`message exceeds ${MAX_PLAINTEXT} bytes`);
    socket.write(frame(sealer.seal(data)));
  };
  (session as { close: Session["close"] }).close = () => {
    if (closed) return;
    closed = true;
    socket.end();
    session.emit("close");
  };

  return session;
}

export type TransportServer = {
  listen(port?: number, host?: string): Promise<number>;
  close(): Promise<void>;
  port(): number;
};

export function createServer(options: {
  identity: Identity;
  onSession: (session: Session) => void;
  handshakeTimeoutMs?: number;
  onError?: (error: Error) => void;
}): TransportServer {
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  const onError = options.onError ?? (() => {});

  const server = createTcpServer((socket) => {
    const framer = createFramer(MAX_FRAME);
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) socket.destroy(new Error("handshake timeout"));
    }, handshakeTimeoutMs);

    const onData = (chunk: Buffer) => {
      if (settled) return;
      try {
        for (const message of framer(chunk)) {
          if (settled) {
            // Application data that shared a segment with the ClientHello.
            leftover.push(frame(message));
            continue;
          }
          const { message: serverHello, keys } = buildServerHello(message, options.identity);
          socket.write(frame(serverHello));
          settled = true;
          clearTimeout(timer);
          socket.off("data", onData);
          options.onSession(makeSession(socket, keys, "server", null, framer, leftover));
        }
      } catch (error) {
        clearTimeout(timer);
        socket.destroy();
        onError(error as Error);
      }
    };

    const leftover: Buffer[] = [];
    socket.on("data", onData);
    socket.on("error", (error) => {
      clearTimeout(timer);
      onError(error);
    });
  });

  return {
    listen(port = 0, host = "127.0.0.1") {
      return new Promise<number>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.removeListener("error", reject);
          resolve(portOf(server));
        });
      });
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    port: () => portOf(server),
  };
}

export function connect(options: {
  host: string;
  port: number;
  /** Accepted static identities for this name. An empty set is refused. */
  pins: readonly string[];
  handshakeTimeoutMs?: number;
}): Promise<Session> {
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;

  return new Promise<Session>((resolve, reject) => {
    if (!options.pins.length) {
      reject(new Error("no pins supplied; refusing to connect"));
      return;
    }

    const state = buildClientHello();
    const framer = createFramer(MAX_FRAME);
    const leftover: Buffer[] = [];
    let settled = false;

    const socket = tcpConnect({ host: options.host, port: options.port });
    const timer = setTimeout(() => {
      if (!settled) fail(new Error("handshake timeout"));
    }, handshakeTimeoutMs);

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(error);
    };

    socket.once("connect", () => socket.write(frame(state.message)));

    const onData = (chunk: Buffer) => {
      if (settled) return;
      try {
        for (const message of framer(chunk)) {
          if (settled) {
            leftover.push(frame(message));
            continue;
          }
          const { keys, pin } = handleServerHello(message, state, options.pins);
          settled = true;
          clearTimeout(timer);
          socket.off("data", onData);
          resolve(makeSession(socket, keys, "client", pin, framer, leftover));
        }
      } catch (error) {
        fail(error as Error);
      }
    };

    socket.on("data", onData);
    socket.on("error", fail);
    socket.on("close", () => fail(new Error("connection closed during handshake")));
  });
}

function portOf(server: TcpServer): number {
  const address = server.address();
  return typeof address === "object" && address ? address.port : 0;
}
