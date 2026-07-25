import assert from "node:assert/strict";
import test from "node:test";

import {
  CELL_FACES,
  identifyCellManifest,
  verifyCellIdentity,
} from "../src/verify-cell-identity.mjs";

const capability = `ni:///sha-256;${"A".repeat(43)}`;
const controller = "did:pkh:eip155:5615610:0x1111111111111111111111111111111111111111";

function observer(evidence) {
  return ({ manifest, controller: did }) => ({ manifest, controller: did, evidence });
}

test("a generic CapCell admits seven absent optional faces", async () => {
  const result = await verifyCellIdentity({
    manifest: { type: "CapabilityCellManifest", version: 1, capability, controller, faces: {} },
  });
  assert.equal(result.profileDisposition, "admitted");
  assert.deepEqual(result.faces.map(({ disposition }) => disposition), CELL_FACES.map(() => "absent"));
  assert.deepEqual(result.missingRequiredBindings, []);
});

test("a UnionCapCell requires bound ActivityPub and EVM but no other face", async () => {
  const manifest = {
    type: "CapabilityCellManifest",
    version: 1,
    capability,
    controller,
    faces: {
      activitypub: { actor: "https://cell.example/actor" },
      evm: { account: "eip155:5615610:0x1111111111111111111111111111111111111111" },
    },
  };
  const result = await verifyCellIdentity({
    manifest,
    profile: "union-capcell",
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

test("a claimed face is invalid when its observer is absent, refuses, or binds another identity", async () => {
  const manifest = {
    type: "CapabilityCellManifest",
    version: 1,
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
    profile: "union-capcell",
    observers: {
      activitypub: async () => { throw new Error("signature failed"); },
      evm: ({ controller: did }) => ({
        manifest: `ni:///sha-256;${"B".repeat(43)}`,
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
