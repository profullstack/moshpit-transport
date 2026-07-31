#!/usr/bin/env node
// Generate a static ML-DSA-65 identity for a Moshpit name, and print the pin
// to publish for it.
//
//   moshpit-keygen scrambled.eggs
//   moshpit-keygen scrambled.eggs --out ./identity.json
//
// The private key is written with mode 600 and never leaves the machine. The
// pin is the only part that goes anywhere — publish it at
// https://app.moshcode.sh/pit/dns alongside any TLS pin for the same name.

import { chmod, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { generateIdentity } from "../lib/identity.ts";

const args = process.argv.slice(2);
const name = args.find((a) => !a.startsWith("--"));
if (!name) {
  console.error("usage: moshpit-keygen <name> [--out <path>] [--force]");
  process.exit(2);
}

const outIndex = args.indexOf("--out");
const out = outIndex >= 0 ? args[outIndex + 1] : join(homedir(), ".moshpit", "identities", `${safe(name)}.json`);
const force = args.includes("--force");

if (!out) {
  console.error("--out needs a path");
  process.exit(2);
}
if (existsSync(out) && !force) {
  // Overwriting an identity silently would break every client that pinned the
  // old key, with no way to tell what happened.
  console.error(`${out} already exists. Pass --force only if you mean to rotate the key.`);
  console.error("Publish the new pin alongside the old one before you start serving it.");
  process.exit(1);
}

const identity = generateIdentity();

await mkdir(dirname(out), { recursive: true, mode: 0o700 });
await writeFile(
  out,
  `${JSON.stringify(
    {
      name,
      algorithm: "ml-dsa-65",
      pin: identity.pin,
      publicKey: identity.publicKeyDer.toString("base64"),
      privateKey: (identity.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64"),
      created: new Date().toISOString(),
    },
    null,
    2,
  )}\n`,
  { mode: 0o600 },
);
await chmod(out, 0o600);

console.log(identity.pin);
console.error("");
console.error(`identity for ${name} written to ${out} (mode 600, keep it there)`);
console.error("");
console.error("publish at https://app.moshcode.sh/pit/dns:");
console.error(`  { "pins": ["${identity.pin}"] }`);
console.error("");
console.error("when rotating, list the new pin alongside the old one until every");
console.error("client has seen it, then drop the old one.");

function safe(value: string): string {
  return value.replace(/[^a-z0-9._-]/gi, "_");
}
