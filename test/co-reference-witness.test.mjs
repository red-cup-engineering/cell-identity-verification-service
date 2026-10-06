import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  deriveActorProtocolFaces,
  identifyActorCoReferenceWitness,
  normalizeActorCoReferenceWitness,
} from "../src/co-reference-witness.mjs";

const actor = "urn:561:actor:yanagi";

function witness(overrides = {}) {
  return {
    type: "ActorCoReferenceWitness",
    version: 1,
    canonicalActor: actor,
    externalIdentifier: "@example",
    protocol: "x",
    verificationMethod: "signed-profile-link",
    observedAt: "2026-10-06T00:00:00-05:00",
    evidence: ["receipt:fixture"],
    standing: "verified",
    ...overrides,
  };
}

test("co-reference witness is normalized and content-addressed", () => {
  const normalized = normalizeActorCoReferenceWitness(witness({ protocol: "X" }));
  assert.equal(normalized.protocol, "x");
  assert.equal(normalized.observedAt, "2026-10-06T05:00:00.000Z");
  assert.match(
    identifyActorCoReferenceWitness(normalized).id,
    /^ni:\/\/\/sha-256;[A-Za-z0-9_-]{43}$/u,
  );
});

test("only the latest verified standing is admitted as a current protocol face", () => {
  const result = deriveActorProtocolFaces({
    canonicalActor: actor,
    witnesses: [
      witness({ standing: "historical", observedAt: "2026-10-05T20:00:00Z" }),
      witness({ standing: "verified", observedAt: "2026-10-06T01:00:00Z" }),
    ],
  });
  assert.equal(result.faces.length, 1);
  assert.equal(result.faces[0].standing, "verified");
  assert.equal(result.faces[0].admitted, true);
  assert.equal(result.admittedFaces.length, 1);
});

test("later revocation removes a formerly verified face without erasing history", () => {
  const result = deriveActorProtocolFaces({
    canonicalActor: actor,
    witnesses: [
      witness({ standing: "verified", observedAt: "2026-10-06T01:00:00Z" }),
      witness({ standing: "revoked", observedAt: "2026-10-06T02:00:00Z" }),
    ],
  });
  assert.equal(result.faces[0].standing, "revoked");
  assert.equal(result.faces[0].admitted, false);
  assert.equal(result.faces[0].witnessHistory.length, 2);
  assert.deepEqual(result.admittedFaces, []);
});

test("contradictory equal-coordinate observations derive conflict rather than last-write-wins", () => {
  const result = deriveActorProtocolFaces({
    canonicalActor: actor,
    witnesses: [
      witness({ standing: "verified", evidence: ["receipt:a"] }),
      witness({ standing: "revoked", evidence: ["receipt:b"] }),
    ],
  });
  assert.equal(result.faces[0].standing, "conflicting");
  assert.equal(result.faces[0].admitted, false);
});

test("Yanagi candidate record preserves historical faces without promoting them to current", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("../content/yanagi-co-reference-candidates.json", import.meta.url), "utf8"),
  );
  const result = deriveActorProtocolFaces({
    canonicalActor: fixture.canonicalActor,
    witnesses: fixture.witnesses,
  });
  assert.equal(result.faces.length, 4);
  assert.ok(result.faces.every(({ standing }) => standing === "historical"));
  assert.deepEqual(result.admittedFaces, []);
});

test("witnesses for a different canonical actor are refused", () => {
  assert.throws(
    () => deriveActorProtocolFaces({
      canonicalActor: actor,
      witnesses: [witness({ canonicalActor: "urn:561:actor:someone-else" })],
    }),
    /canonicalActor/u,
  );
});
