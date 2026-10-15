// Admission for this service's historical identity profile. This module does
// not normalize content, encode CBOR or derive identities; ContentAddress does.
import { types } from "node:util";
import { Buffer } from "node:buffer";

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length").get;
const byteBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer").get;

function refuse(ErrorType, label, reason) {
  throw new ErrorType(`${label} ${reason}`);
}

function admittedText(value) {
  return typeof value === "string" && value.isWellFormed() && !value.startsWith("\uFEFF");
}

function descriptors(value, label, ErrorType, prototype) {
  if (value === null || typeof value !== "object" || types.isProxy(value)
    || Object.getPrototypeOf(value) !== prototype) {
    refuse(ErrorType, label, "must be an ordinary non-Proxy data container");
  }
  const fields = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(fields)) {
    const field = fields[key];
    if (typeof key !== "string" || !("value" in field)) {
      refuse(ErrorType, label, "must not contain symbol keys or accessors");
    }
  }
  return fields;
}

export function assertOwnDataRecord(value, label, ErrorType) {
  const fields = descriptors(value, label, ErrorType, Object.prototype);
  const normalized = new Set();
  for (const key of Object.keys(fields)) {
    if (!fields[key].enumerable || !admittedText(key) || key === "__proto__") {
      refuse(ErrorType, label, "has a property outside the historical identity profile");
    }
    const normalizedKey = key.normalize("NFC");
    if (normalized.has(normalizedKey)) refuse(ErrorType, label, "has keys that collide after NFC normalization");
    normalized.add(normalizedKey);
  }
  return value;
}

export function assertDenseDataArray(value, label, ErrorType) {
  const fields = descriptors(value, label, ErrorType, Array.prototype);
  if (!Array.isArray(value) || !fields.length || !("value" in fields.length)) {
    refuse(ErrorType, label, "must be an ordinary dense array");
  }
  const length = fields.length.value;
  if (Object.keys(fields).length !== length + 1) refuse(ErrorType, label, "must not contain array holes or extra properties");
  for (const key of Object.keys(fields)) {
    if (key === "length") continue;
    const index = Number(key);
    if (!Number.isInteger(index) || index < 0 || index >= length || String(index) !== key || !fields[key].enumerable) {
      refuse(ErrorType, label, "must not contain array holes or extra properties");
    }
  }
  return value;
}

export function assertHistoricalIdentityData(value, label, ErrorType, optionalUndefinedKeys = []) {
  const pending = [{ value, label, root: true }], ancestors = new Set();
  while (pending.length) {
    const item = pending.pop(), member = item.value;
    if (item.exit) { ancestors.delete(member); continue; }
    if (member === null || typeof member === "boolean") continue;
    if (typeof member === "string") {
      if (!admittedText(member)) refuse(ErrorType, item.label, "must be well-formed text without a leading BOM");
      continue;
    }
    if (typeof member === "number") {
      if (!Number.isSafeInteger(member)) refuse(ErrorType, item.label, "must be a safe integer in the historical profile");
      continue;
    }
    if (typeof member === "bigint") {
      if (member < -18446744073709551616n || member > 18446744073709551615n) refuse(ErrorType, item.label, "is outside the CBOR integer range");
      continue;
    }
    if (typeof member !== "object" || types.isProxy(member)) refuse(ErrorType, item.label, "must be inert historical identity data");
    if (types.isUint8Array(member)) {
      const prototype = Object.getPrototypeOf(member);
      if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) refuse(ErrorType, item.label, "must be an ordinary byte string");
      const fields = descriptors(member, item.label, ErrorType, prototype), length = byteLength.call(member);
      if (types.isSharedArrayBuffer(byteBuffer.call(member))) refuse(ErrorType, item.label, "must not contain concurrently mutable shared bytes");
      for (const key of Object.keys(fields)) {
        const index = Number(key);
        if (!Number.isInteger(index) || index < 0 || index >= length || String(index) !== key || !fields[key].enumerable) refuse(ErrorType, item.label, "must not contain extra byte-string properties");
      }
      continue;
    }
    if (ancestors.has(member)) refuse(ErrorType, item.label, "must not be cyclic");
    if (Array.isArray(member)) assertDenseDataArray(member, item.label, ErrorType);
    else assertOwnDataRecord(member, item.label, ErrorType);
    ancestors.add(member); pending.push({ value: member, exit: true });
    for (const [key, field] of Object.entries(Object.getOwnPropertyDescriptors(member))) {
      if (Array.isArray(member) && key === "length") continue;
      if (item.root && field.value === undefined && optionalUndefinedKeys.includes(key)) continue;
      pending.push({ value: field.value, label: `${item.label}.${key}`, root: false });
    }
  }
  return value;
}

export function assertObserverRecord(value, label, ErrorType) {
  assertOwnDataRecord(value, label, ErrorType);
  for (const [key, member] of Object.entries(value)) {
    if (typeof member === "function") {
      if (types.isProxy(member)) refuse(ErrorType, `${label}.${key}`, "must not be a Proxy callback");
    } else if (member !== undefined) assertHistoricalIdentityData(member, `${label}.${key}`, ErrorType);
  }
  return value;
}

function inertErrorText(error, key, fallback) {
  let current = error;
  while (current !== null && (typeof current === "object" || typeof current === "function")) {
    if (types.isProxy(current)) return fallback;
    const field = Object.getOwnPropertyDescriptor(current, key);
    if (field) return "value" in field && admittedText(field.value) ? field.value : fallback;
    current = Object.getPrototypeOf(current);
  }
  return fallback;
}

export function observerRefusalEvidence(error) {
  const primitive = error === null || !["object", "function"].includes(typeof error);
  const message = primitive && admittedText(String(error)) ? String(error) : "observer refused";
  return {
    name: inertErrorText(error, "name", "Error"),
    message: inertErrorText(error, "message", message),
  };
}
