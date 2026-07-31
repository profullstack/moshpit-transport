import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { generateIdentity, identityFromStored, loadIdentity, pinFromSpkiDer } from "../lib/identity.ts";
import { buildClientHello, buildServerHello, handleServerHello } from "../lib/handshake.ts";

const run = promisify(execFile);
const keygen = fileURLToPath(new URL("../bin/moshpit-keygen.ts", import.meta.url));

describe("identity", () => {
  test("the pin is the hash of the SPKI, not of anything else", () => {
    const identity = generateIdentity();
    assert.equal(identity.pin, pinFromSpkiDer(identity.publicKeyDer));
    assert.equal(identity.publicKeyDer.length, 1974); // ML-DSA-65
  });

  test("keygen writes a file that round-trips into a usable identity", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mt-id-"));
    const out = join(dir, "id.json");
    const { stdout } = await run("node", [keygen, "round.trip", "--out", out]);

    const loaded = await loadIdentity(out);
    assert.equal(loaded.pin, stdout.trim());

    // The real check: a key loaded from disk can actually complete a handshake.
    const state = buildClientHello();
    const server = buildServerHello(state.message, loaded);
    const client = handleServerHello(server.message, state, [loaded.pin]);
    assert.equal(client.pin, loaded.pin);
  });

  test("refuses to load a file whose recorded pin disagrees with its key", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mt-id-"));
    const out = join(dir, "id.json");
    await run("node", [keygen, "tampered", "--out", out]);

    const stored = JSON.parse(await readFile(out, "utf8"));
    stored.pin = generateIdentity().pin;

    assert.throws(() => identityFromStored(stored), /inconsistent/);
  });

  test("refuses an identity of the wrong algorithm", () => {
    const identity = generateIdentity();
    assert.throws(
      () => identityFromStored({
        name: "x", algorithm: "ed25519", pin: identity.pin,
        publicKey: identity.publicKeyDer.toString("base64"), privateKey: "",
      }),
      /expected ml-dsa-65/,
    );
  });

  test("keygen refuses to overwrite an identity without --force", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mt-id-"));
    const out = join(dir, "id.json");
    await run("node", [keygen, "once", "--out", out]);

    // Silent overwrite would break every client that pinned the old key.
    await assert.rejects(run("node", [keygen, "once", "--out", out]), /already exists/);
  });

  test("--force rotates to a genuinely different key", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mt-id-"));
    const out = join(dir, "id.json");
    const first = await run("node", [keygen, "rotate", "--out", out]);
    const second = await run("node", [keygen, "rotate", "--out", out, "--force"]);

    assert.notEqual(first.stdout.trim(), second.stdout.trim());
    assert.equal((await loadIdentity(out)).pin, second.stdout.trim());
  });
});
