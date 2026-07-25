import {
  decodeSemantic,
  semanticBytes,
  semanticId,
} from "@emsenn/rmn-semantic-conformance-die";

export const CELL_FACES = Object.freeze([
  "npm",
  "github",
  "activitypub",
  "a2a",
  "mcp",
  "x402",
  "evm",
]);

export const CELL_PROFILES = Object.freeze({
  capcell: Object.freeze(["activitypub", "evm"]),
});

const NI = /^ni:\/\/\/sha-256;[A-Za-z0-9_-]{43}$/u;
const EVM_DID = /^did:pkh:(eip155:\d+):(0x[0-9a-fA-F]{40})$/u;

export class CellIdentityVerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "CellIdentityVerificationError";
    this.code = "CELL_IDENTITY_VERIFICATION_INVALID";
  }
}

function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CellIdentityVerificationError(`${label} must be an object`);
  }
  return value;
}

export function normalizeCellManifest(source) {
  const manifest = object(source, "manifest");
  if (manifest.type !== "CapabilityCellManifest" || manifest.version !== 2) {
    throw new CellIdentityVerificationError("manifest must use CapabilityCellManifest version 2");
  }
  if (typeof manifest.sku !== "string" || !NI.test(manifest.sku)) {
    throw new CellIdentityVerificationError("manifest sku must be one canonical RMN StockKeepingUnit identity");
  }
  if (typeof manifest.capability !== "string" || !NI.test(manifest.capability)) {
    throw new CellIdentityVerificationError("manifest capability must be one SHA-256 ni URI");
  }
  if (typeof manifest.controller !== "string" || !EVM_DID.test(manifest.controller)) {
    throw new CellIdentityVerificationError("manifest controller must be one did:pkh EVM account");
  }
  const faces = object(manifest.faces ?? {}, "manifest faces");
  const unknown = Object.keys(faces).filter((face) => !CELL_FACES.includes(face));
  if (unknown.length > 0) {
    throw new CellIdentityVerificationError(`manifest contains unknown faces: ${unknown.join(", ")}`);
  }
  const normalizedFaces = Object.fromEntries(
    CELL_FACES
      .filter((face) => Object.hasOwn(faces, face))
      .map((face) => [face, object(faces[face], `manifest face ${face}`)]),
  );
  return Object.freeze({
    type: "CapabilityCellManifest",
    version: 2,
    sku: manifest.sku,
    capability: manifest.capability,
    controller: manifest.controller,
    faces: Object.freeze(normalizedFaces),
  });
}

export function identifyCellIdentity(source) {
  const manifest = normalizeCellManifest(source);
  const value = Object.freeze({
    type: "CapabilityCellIdentity",
    version: 1,
    sku: manifest.sku,
    capability: manifest.capability,
    controller: manifest.controller,
  });
  const bytes = semanticBytes(value);
  return Object.freeze({
    id: semanticId(value),
    mediaType: "application/rmn+cbor",
    value: decodeSemantic(bytes),
    bytes,
  });
}

export function identifyCellManifest(source) {
  const value = normalizeCellManifest(source);
  const bytes = semanticBytes(value);
  return Object.freeze({
    id: semanticId(value),
    mediaType: "application/rmn+cbor",
    value: decodeSemantic(bytes),
    bytes,
  });
}

function invalid(face, claim, reason, evidence = undefined) {
  return Object.freeze({
    face,
    disposition: "invalid",
    claim,
    reason,
    ...(evidence === undefined ? {} : { evidence }),
  });
}

async function observeFace(face, claim, observer, cell, manifest, sku, capability, controller) {
  if (typeof observer !== "function") {
    return invalid(face, claim, "observer-unavailable");
  }
  let result;
  try {
    result = object(await observer(Object.freeze({
      face,
      claim,
      cell,
      manifest,
      sku,
      capability,
      controller,
    })), `${face} observer result`);
  } catch (error) {
    return invalid(face, claim, "observer-refused", {
      name: error?.name ?? "Error",
      message: error?.message ?? String(error),
    });
  }
  if (result.cell !== cell || result.controller !== controller) {
    return invalid(face, claim, "identity-mismatch", result.evidence);
  }
  return Object.freeze({
    face,
    disposition: "bound",
    claim,
    evidence: result.evidence ?? null,
  });
}

export async function verifyCellIdentity({ manifest, observers = {}, profile = "capcell" }) {
  const requiredFaces = CELL_PROFILES[profile];
  if (requiredFaces === undefined) {
    throw new CellIdentityVerificationError(`unsupported cell profile: ${profile}`);
  }
  object(observers, "observers");
  const identity = identifyCellIdentity(manifest);
  const manifestRecord = identifyCellManifest(manifest);
  const faces = [];
  for (const face of CELL_FACES) {
    const claim = manifestRecord.value.faces[face];
    faces.push(claim === undefined
      ? Object.freeze({ face, disposition: "absent" })
      : await observeFace(
        face,
        claim,
        observers[face],
        identity.id,
        manifestRecord.id,
        identity.value.sku,
        identity.value.capability,
        identity.value.controller,
      ));
  }
  const byFace = Object.fromEntries(faces.map((result) => [result.face, result]));
  const missing = requiredFaces.filter((face) => byFace[face].disposition !== "bound");
  const value = Object.freeze({
    type: "CellIdentityVerification",
    version: 2,
    cell: identity.id,
    manifest: manifestRecord.id,
    sku: identity.value.sku,
    capability: identity.value.capability,
    controller: identity.value.controller,
    profile,
    faces: Object.freeze(faces),
    profileDisposition: missing.length === 0 ? "admitted" : "refused",
    missingRequiredBindings: Object.freeze(missing),
  });
  return Object.freeze({
    ...value,
    id: semanticId(value),
    bytes: semanticBytes(value),
  });
}
