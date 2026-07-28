import assert from "node:assert/strict";
import test from "node:test";

import {
  identifyCellIdentity,
  identifyCellManifest,
  verifyCellIdentity,
} from "../src/verify-cell-identity.mjs";

const capability = `ni:///sha-256;${"A".repeat(43)}`;
const sku = `ni:///sha-256;${"S".repeat(43)}`;
const controller = "did:pkh:eip155:5615610:0x1111111111111111111111111111111111111111";

function observer(evidence) {
  return ({ cell, controller: did }) => ({ cell, controller: did, evidence });
}

test("declared requirements, rather than a manifest-declared face vocabulary, determine admission", async () => {
  const result = await verifyCellIdentity({
    manifest: { type: "CapabilityCellManifest", version: 2, sku, capability, controller, faces: {} },
    requiredFaces: ["activitypub", "evm"],
  });
  assert.equal(result.profileDisposition, "refused");
  assert.deepEqual(result.faces, []);
  assert.deepEqual(result.missingRequiredBindings, ["activitypub", "evm"]);
});

test("a cell may bind any declared protocol faces", async () => {
  const manifest = {
    type: "CapabilityCellManifest",
    version: 2,
    sku,
    capability,
    controller,
    faces: {
      activitypub: { actor: "https://cell.example/actor" },
      evm: { account: "eip155:5615610:0x1111111111111111111111111111111111111111" },
      "webtransport-v2": { endpoint: "https://cell.example/wt" },
    },
  };
  const result = await verifyCellIdentity({
    manifest,
    requiredFaces: ["activitypub", "evm"],
    observers: {
      activitypub: observer({ signature: "activitypub-fixture" }),
      evm: observer({ erc1271: "fixture" }),
      "webtransport-v2": observer({ session: "fixture" }),
    },
  });
  assert.equal(result.profileDisposition, "admitted");
  assert.equal(result.faces.length, 3);
  assert.equal(result.faces.find(({ face }) => face === "activitypub").disposition, "bound");
  assert.equal(result.faces.find(({ face }) => face === "evm").disposition, "bound");
  assert.equal(result.faces.find(({ face }) => face === "webtransport-v2").disposition, "bound");
});

test("a claimed face is invalid when its observer is absent, refuses, or binds another cell identity", async () => {
  const manifest = {
    type: "CapabilityCellManifest",
    version: 2,
    sku,
    capability,
    controller,
    faces: {
      activitypub: { actor: "https://cell.example/actor" },
      evm: { account: "eip155:5615610:0x1111111111111111111111111111111111111111" },
      mcp: { endpoint: "https://cell.example/mcp" },
    },
  };
  const result = await verifyCellIdentity({
    manifest,
    requiredFaces: ["activitypub", "evm"],
    observers: {
      activitypub: async () => { throw new Error("signature failed"); },
      evm: ({ controller: did }) => ({
        cell: `ni:///sha-256;${"B".repeat(43)}`,
        controller: did,
      }),
    },
  });
  assert.equal(result.profileDisposition, "refused");
  assert.deepEqual(result.missingRequiredBindings, ["activitypub", "evm"]);
  assert.equal(result.faces.find(({ face }) => face === "activitypub").reason, "observer-refused");
  assert.equal(result.faces.find(({ face }) => face === "evm").reason, "identity-mismatch");
  assert.equal(result.faces.find(({ face }) => face === "mcp").reason, "observer-unavailable");
  assert.match(identifyCellManifest(manifest).id, /^ni:\/\/\/sha-256;[A-Za-z0-9_-]{43}$/u);
});

test("face address changes revise the manifest without mutating cell or SKU identity", () => {
  const first = {
    type: "CapabilityCellManifest",
    version: 2,
    sku,
    capability,
    controller,
    faces: { activitypub: { actor: "https://cell.example/actor" } },
  };
  const second = {
    ...first,
    faces: { activitypub: { actor: "https://cell.actions.561.group/actor" } },
  };
  assert.equal(identifyCellIdentity(first).id, identifyCellIdentity(second).id);
  assert.notEqual(identifyCellManifest(first).id, identifyCellManifest(second).id);
});

test("face composition can evolve without a new verifier release", async () => {
  const manifest = {
    type: "CapabilityCellManifest", version: 2, sku, capability, controller,
    faces: { "future-proof": { version: 1 } },
  };
  const result = await verifyCellIdentity({
    manifest,
    observers: { "future-proof": observer({ accepted: true }) },
    requiredFaces: ["future-proof"],
  });
  assert.equal(result.profileDisposition, "admitted");
  assert.deepEqual(result.missingRequiredBindings, []);
});
