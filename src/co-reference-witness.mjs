import {
  semanticAddress,
} from "@red-cup-engineering/computer-content-address-engineering-services-section/semiotic-content-address";

import { assertHistoricalIdentityData, assertOwnDataRecord, assertDenseDataArray } from "./historical-identity-admission.mjs";

const STANDINGS = new Set([
  "verified",
  "historical",
  "unresolved",
  "revoked",
  "conflicting",
]);

export class ActorCoReferenceWitnessError extends Error {
  constructor(message) {
    super(message);
    this.name = "ActorCoReferenceWitnessError";
    this.code = "ACTOR_COREFERENCE_WITNESS_INVALID";
  }
}

function object(value, label) {
  return assertOwnDataRecord(value, label, ActorCoReferenceWitnessError);
}

function text(value, label) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ActorCoReferenceWitnessError(`${label} must be non-empty text`);
  }
  return value.trim();
}

function timestamp(value) {
  const source = text(value, "observedAt");
  const millis = Date.parse(source);
  if (!Number.isFinite(millis)) {
    throw new ActorCoReferenceWitnessError("observedAt must be an offset-aware ISO timestamp");
  }
  if (!/(?:Z|[+-]\d\d:\d\d)$/u.test(source)) {
    throw new ActorCoReferenceWitnessError("observedAt must include Z or a numeric UTC offset");
  }
  return new Date(millis).toISOString();
}

function evidence(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new ActorCoReferenceWitnessError("evidence must be a non-empty array");
  }
  return Object.freeze(value.map((item, index) => text(item, `evidence[${index}]`)));
}

function continuity(value) {
  if (value === undefined) return undefined;
  const source = object(value, "continuity");
  const normalizedKeys = new Set();
  for (const key of Object.keys(source)) {
    const normalizedKey = text(key, "continuity key").normalize("NFC");
    if (normalizedKeys.has(normalizedKey)) throw new ActorCoReferenceWitnessError("continuity keys collide after trimming and NFC normalization");
    normalizedKeys.add(normalizedKey);
  }
  return Object.freeze(
    Object.fromEntries(
      Object.keys(source)
        .sort()
        .map((key) => [text(key, "continuity key"), text(source[key], `continuity.${key}`)]),
    ),
  );
}

export function normalizeActorCoReferenceWitness(source) {
  assertHistoricalIdentityData(source, "witness", ActorCoReferenceWitnessError, ["statementRef", "continuity"]);
  const witness = object(source, "witness");
  if (witness.type !== "ActorCoReferenceWitness" || witness.version !== 1) {
    throw new ActorCoReferenceWitnessError("witness must use ActorCoReferenceWitness version 1");
  }
  const standing = text(witness.standing, "standing");
  if (!STANDINGS.has(standing)) {
    throw new ActorCoReferenceWitnessError("standing must be verified, historical, unresolved, revoked, or conflicting");
  }
  const admittedContinuity = continuity(witness.continuity);
  const normalized = Object.freeze({
    type: "ActorCoReferenceWitness",
    version: 1,
    canonicalActor: text(witness.canonicalActor, "canonicalActor"),
    externalIdentifier: text(witness.externalIdentifier, "externalIdentifier"),
    protocol: text(witness.protocol, "protocol").toLowerCase(),
    verificationMethod: text(witness.verificationMethod, "verificationMethod"),
    observedAt: timestamp(witness.observedAt),
    evidence: evidence(witness.evidence),
    standing,
    ...(witness.statementRef === undefined
      ? {}
      : { statementRef: text(witness.statementRef, "statementRef") }),
    ...(admittedContinuity === undefined ? {} : { continuity: admittedContinuity }),
  });
  assertHistoricalIdentityData(normalized, "normalized witness", ActorCoReferenceWitnessError);
  return normalized;
}

export function identifyActorCoReferenceWitness(source) {
  const value = normalizeActorCoReferenceWitness(source);
  const { id, bytes } = semanticAddress(value);
  return Object.freeze({
    id,
    mediaType: "application/rmn+cbor",
    value,
    bytes,
  });
}

function latestStanding(group) {
  const newest = Math.max(...group.map(({ witness }) => Date.parse(witness.observedAt)));
  const latest = group.filter(({ witness }) => Date.parse(witness.observedAt) === newest);
  const standings = new Set(latest.map(({ witness }) => witness.standing));
  if (standings.size > 1) return "conflicting";
  return latest[0].witness.standing;
}

export function deriveActorProtocolFaces(input) {
  const { canonicalActor, witnesses } = object(input, "protocol-face request");
  assertHistoricalIdentityData(canonicalActor, "canonicalActor", ActorCoReferenceWitnessError);
  assertDenseDataArray(witnesses, "witnesses", ActorCoReferenceWitnessError);
  const actor = text(canonicalActor, "canonicalActor");
  if (!Array.isArray(witnesses)) {
    throw new ActorCoReferenceWitnessError("witnesses must be an array");
  }
  const identified = witnesses.map((source) => identifyActorCoReferenceWitness(source));
  for (const item of identified) {
    if (item.value.canonicalActor !== actor) {
      throw new ActorCoReferenceWitnessError("all witnesses must bind the requested canonicalActor");
    }
  }

  const groups = new Map();
  for (const item of identified) {
    const key = `${item.value.protocol}\u0000${item.value.externalIdentifier}`;
    const current = groups.get(key) ?? [];
    current.push(Object.freeze({ id: item.id, witness: item.value }));
    groups.set(key, current);
  }

  const faces = [...groups.values()]
    .map((group) => {
      const ordered = [...group].sort((a, b) =>
        a.witness.observedAt.localeCompare(b.witness.observedAt) || a.id.localeCompare(b.id));
      const latest = ordered[ordered.length - 1];
      const standing = latestStanding(ordered);
      return Object.freeze({
        protocol: latest.witness.protocol,
        externalIdentifier: latest.witness.externalIdentifier,
        standing,
        admitted: standing === "verified",
        latestObservedAt: latest.witness.observedAt,
        latestWitness: latest.id,
        witnessHistory: Object.freeze(ordered.map(({ id }) => id)),
      });
    })
    .sort((a, b) =>
      a.protocol.localeCompare(b.protocol)
      || a.externalIdentifier.localeCompare(b.externalIdentifier));

  const value = Object.freeze({
    type: "ActorProtocolFaceSet",
    version: 1,
    canonicalActor: actor,
    faces: Object.freeze(faces),
    admittedFaces: Object.freeze(
      faces
        .filter(({ admitted }) => admitted)
        .map(({ protocol, externalIdentifier, latestWitness }) =>
          Object.freeze({ protocol, externalIdentifier, witness: latestWitness })),
    ),
  });

  assertHistoricalIdentityData(value, "protocol faces", ActorCoReferenceWitnessError);
  const { id, bytes } = semanticAddress(value);
  return Object.freeze({ ...value, id, bytes });
}
