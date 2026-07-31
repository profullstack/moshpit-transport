#!/usr/bin/env node
// A tunnel pair, so an existing service can speak MTP/1 without being rewritten.
//
//   moshpit-transport serve   --identity id.json --forward 127.0.0.1:8080 --listen 9443
//   moshpit-transport forward --to host:9443 --pin <base64> --listen 1080
//
// `serve` runs beside whatever you already have — an HTTP server, a database,
// anything TCP — and exposes it over an authenticated post-quantum channel.
// `forward` is the other end: a local port that tunnels to it. Neither side
// needs to know it is being tunnelled, which is the point. Adopting this should
// not mean rewriting an application against a new socket API.

import { connect as tcpConnect, createServer as createTcpServer } from "node:net";
import type { Socket } from "node:net";
import { loadIdentity } from "../lib/identity.ts";
import { connect, createServer } from "../lib/transport.ts";
import type { Session } from "../lib/transport.ts";
import { MAX_PLAINTEXT } from "../lib/record.ts";

const [command, ...rest] = process.argv.slice(2);
const flags = parseFlags(rest);

try {
  if (command === "serve") await serve();
  else if (command === "forward") await forward();
  else usage(command ? `unknown command: ${command}` : undefined);
} catch (error) {
  console.error(`error: ${(error as Error).message}`);
  process.exit(1);
}

async function serve() {
  const identityPath = need("identity");
  const target = parseAddress(need("forward"));
  const listen = parseAddress(flags.listen ?? "0.0.0.0:9443", 9443);

  const identity = await loadIdentity(identityPath);

  const server = createServer({
    identity,
    onSession: (session) => {
      const upstream = tcpConnect({ host: target.host, port: target.port });
      bridge(session, upstream);
    },
    onError: (error) => log(`handshake failed: ${error.message}`),
  });

  await server.listen(listen.port, listen.host);
  log(`serving ${listen.host}:${listen.port} -> ${target.host}:${target.port}`);
  log(`identity ${identity.pin}`);
  log("clients need that pin; publish it at https://app.moshcode.sh/pit/dns");
  hold(() => server.close());
}

async function forward() {
  const remote = parseAddress(need("to"), 9443);
  const listen = parseAddress(flags.listen ?? "127.0.0.1:1080", 1080);
  const pins = (flags.pin ?? "").split(",").map((p) => p.trim()).filter(Boolean);
  if (!pins.length) throw new Error("--pin is required; there is no unauthenticated mode");

  const local = createTcpServer((socket) => {
    socket.pause();
    connect({ host: remote.host, port: remote.port, pins })
      .then((session) => {
        socket.resume();
        bridge(session, socket);
      })
      .catch((error) => {
        // A refused pin must not look like a working connection that went quiet.
        log(`refused: ${error.message}`);
        socket.destroy();
      });
  });

  await new Promise<void>((resolve) => local.listen(listen.port, listen.host, () => resolve()));
  log(`forwarding ${listen.host}:${listen.port} -> ${remote.host}:${remote.port} (mtp/1)`);
  log(`accepting ${pins.length} pin(s)`);
  hold(() => new Promise<void>((r) => local.close(() => r())));
}

/**
 * Joins an MTP session to a plain socket in both directions.
 *
 * Socket chunks are split to the record limit rather than rejected, because a
 * kernel is free to hand us more than 64 KiB at once and an application that
 * happened to write a large buffer should not see a tunnel error.
 */
function bridge(session: Session, socket: Socket) {
  let open = true;
  const shutdown = () => {
    if (!open) return;
    open = false;
    socket.destroy();
    session.close();
  };

  session.on("message", (data: Buffer) => {
    if (open) socket.write(data);
  });
  session.on("close", shutdown);
  session.on("error", (error: Error) => {
    log(`session error: ${error.message}`);
    shutdown();
  });

  socket.on("data", (chunk: Buffer) => {
    if (!open) return;
    for (let offset = 0; offset < chunk.length; offset += MAX_PLAINTEXT) {
      session.send(chunk.subarray(offset, Math.min(offset + MAX_PLAINTEXT, chunk.length)));
    }
  });
  socket.on("close", shutdown);
  socket.on("error", shutdown);
}

function parseFlags(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith("--")) continue;
    const [key, inline] = arg.slice(2).split("=", 2);
    out[key!] = inline ?? argv[++i] ?? "";
  }
  return out;
}

function need(name: string): string {
  const value = flags[name];
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

function parseAddress(value: string, defaultPort = 0): { host: string; port: number } {
  // Bare `:9443` means "every interface", and a bare number is a port.
  if (/^\d+$/.test(value)) return { host: "0.0.0.0", port: Number(value) };
  const index = value.lastIndexOf(":");
  if (index < 0) return { host: value, port: defaultPort };
  const port = Number(value.slice(index + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`bad port in "${value}"`);
  return { host: value.slice(0, index) || "0.0.0.0", port };
}

function hold(stop: () => Promise<void> | void) {
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, () => {
      log("shutting down");
      void Promise.resolve(stop()).then(() => process.exit(0));
    });
  }
}

function log(line: string) {
  console.error(`[mtp] ${line}`);
}

function usage(problem?: string) {
  if (problem) console.error(`${problem}\n`);
  console.error(`usage:
  moshpit-transport serve   --identity <file> --forward <host:port> [--listen 0.0.0.0:9443]
  moshpit-transport forward --to <host:port>  --pin <base64[,base64]> [--listen 127.0.0.1:1080]

  moshpit-keygen <name> [--out <file>]     generate a server identity`);
  process.exit(problem ? 2 : 0);
}
