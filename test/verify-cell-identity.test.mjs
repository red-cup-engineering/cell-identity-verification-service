import assert from "node:assert/strict";
import test from "node:test";

import {
  CELL_FACES,
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

test("a CapCell is refused when its ActivityPub and EVM bindings are absent", async () => {
  const result = await verifyCellIdentity({
    manifest: { type: "CapabilityCellManifest", version: 2, sku, capability, controller, faces: {} },
  });
  assert.equal(result.profileDisposition, "refused");
  assert.deepEqual(result.faces.map(({ disposition }) => disposition), CELL_FACES.map(() => "absent"));
  assert.deepEqual(result.missingRequiredBindings, ["activitypub", "evm"]);
});

test("a CapCell requires bound ActivityPub and EVM but no other face", async () => {
  const manifest = {
    type: "CapabilityCellManifest",
    version: 2,
    sku,
    capability,
    controller,
    faces: {
      activitypub: { actor: "https://cell.example/actor" },
      evm: { account: "eip155:5615610:0x1111111111111111111111111111111111111111" },
    },
  };
  const result = await verifyCellIdentity({
    manifest,
    observers: {
      activitypub: observer({ signature: "activitypub-fixture" }),
      evm: observer({ erc1271: "fixture" }),
    },
  });
  assert.equal(result.profileDisposition, "admitted");
  assert.equal(result.faces.find(({ face }) => face === "npm").disposition, "absent");
  assert.equal(result.faces.find(({ face }) => face === "activitypub").disposition, "bound");
  assert.equal(result.faces.find(({ face }) => face === "evm").disposition, "bound");
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

test("partial-cell profiles are refused rather than weakening CapCell", async () => {
  const manifest = { type: "CapabilityCellManifest", version: 2, sku, capability, controller, faces: {} };
  for (const profile of ["federated-capcell", "state-cell", "union-capcell"]) {
    await assert.rejects(
      verifyCellIdentity({manifest, profile}),
      /unsupported cell profile/u,
    );
  }
});
