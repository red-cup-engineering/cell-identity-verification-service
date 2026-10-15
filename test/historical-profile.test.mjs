import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import * as candidate from '../src/verify-cell-identity.mjs';
import * as candidateActor from '../src/co-reference-witness.mjs';
const historical = JSON.parse(readFileSync(new URL('./fixtures/historical-identities.json', import.meta.url), 'utf8'));

const sku = `ni:///sha-256;${'S'.repeat(43)}`;
const capability = `ni:///sha-256;${'A'.repeat(43)}`;
const controller = 'did:pkh:eip155:5615610:0x1111111111111111111111111111111111111111';
const manifest = (claim = {}) => ({ type: 'CapabilityCellManifest', version: 2, sku, capability, controller, faces: { example: claim } });
const witness = (overrides = {}) => ({ type: 'ActorCoReferenceWitness', version: 1, canonicalActor: 'urn:fixture:actor', externalIdentifier: '@fixture', protocol: 'EXAMPLE', verificationMethod: 'signed-profile-link', observedAt: '2026-10-06T00:00:00-05:00', evidence: ['receipt:fixture'], standing: 'verified', ...overrides });
const equalIdentity = (a, b) => {
  assert.equal(a.id, b.id);
  assert.equal(Buffer.from(a.bytes).toString('hex'), b.bytesHex);
};

test('I1-I3 historical admitted manifest bytes, NI and cell/face distinction', () => {
  const shared = { normalized: 'e\u0301', bytes: new Uint8Array([0, 255]) };
  const values = [null, true, false, -0, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, -18446744073709551616n, -9007199254740992n, 18446744073709551615n, 'cafe\u0301', new Uint8Array([1, 2]), [shared, shared], { ['a'.repeat(23)]: 1, ['b'.repeat(24)]: 2, ['\u00e9'.repeat(255)]: 3, ['c'.repeat(256)]: 4 }];
  for (const [index, value] of values.entries()) {
    const input = manifest({ value });
    equalIdentity(candidate.identifyCellIdentity(input), historical.manifests[index].cell);
    equalIdentity(candidate.identifyCellManifest(input), historical.manifests[index].manifest);
    assert.equal(candidate.identifyCellManifest(input).mediaType, 'application/rmn+cbor');
  }
  assert.equal(candidate.identifyCellIdentity(manifest({ endpoint: 'a' })).id, candidate.identifyCellIdentity(manifest({ endpoint: 'b' })).id);
  assert.notEqual(candidate.identifyCellManifest(manifest({ endpoint: 'a' })).id, candidate.identifyCellManifest(manifest({ endpoint: 'b' })).id);
  for (const faces of [null, undefined]) equalIdentity(candidate.identifyCellManifest({ ...manifest(), faces }), historical.emptyManifest);
});

test('H excludes unsupported or ambiguous data without normalizing it away', () => {
  const cycle = {}; cycle.self = cycle;
  const sparse = []; sparse.length = 1;
  const extra = []; extra.extra = 1;
  const hidden = {}; Object.defineProperty(hidden, 'hidden', { value: 1 });
  class Bytes extends Uint8Array {}
  for (const value of [undefined, 1.5, 9007199254740992, NaN, Infinity, 18446744073709551616n, -18446744073709551617n, '\ud800', '\ufeffa', () => {}, Symbol('x'), new Date(0), Object.create(null), JSON.parse('{"__proto__":1}'), { '\u00e9': 1, 'e\u0301': 2 }, { [Symbol('x')]: 1 }, hidden, sparse, extra, cycle, new Bytes([1]), new Uint8Array(new SharedArrayBuffer(1))]) {
    assert.throws(() => candidate.identifyCellManifest(manifest({ value })), error => error.code === 'CELL_IDENTITY_VERIFICATION_INVALID');
  }
});

test('H never invokes accessors or Proxy traps during admission', () => {
  let executions = 0;
  const getter = Object.defineProperty({}, 'secret', { enumerable: true, get() { executions++; return 1; } });
  const proxy = new Proxy({}, { get() { executions++; return 1; }, getPrototypeOf() { executions++; return Object.prototype; }, ownKeys() { executions++; return []; } });
  for (const input of [manifest(getter), manifest({ nested: proxy }), proxy, Object.defineProperty(manifest(), 'type', { get() { executions++; return 'CapabilityCellManifest'; }, enumerable: true })]) {
    assert.throws(() => candidate.identifyCellManifest(input));
  }
  assert.equal(executions, 0);
});

test('I4 preserves ordinary observer profiles and exact verification identities', async () => {
  const examples = [
    {},
    { example: () => { throw new Error('fixture refusal'); } },
    { example: () => ({ cell: capability, controller, evidence: { invalid: true } }) },
    { example: ({ cell }) => ({ cell, controller, evidence: { admitted: true } }) },
  ];
  for (const [index, observers] of examples.entries()) for (const requiredFaces of [[], ['example']]) {
    const input = { manifest: manifest({ endpoint: 'https://fixture.invalid' }), observers, requiredFaces };
    const actual = await candidate.verifyCellIdentity(input), expected = historical.verifications[index * 2 + (requiredFaces.length ? 1 : 0)];
    equalIdentity(actual, expected);
    assert.equal(actual.profileDisposition, expected.profileDisposition);
    assert.deepEqual(actual.missingRequiredBindings, expected.missingRequiredBindings);
  }
});

test('I4-I7 outer observer shape is a face refusal; malformed inert evidence refuses the operation', async () => {
  let executions = 0;
  for (const requiredFaces of [[], ['example']]) {
    const result = await candidate.verifyCellIdentity({ manifest: manifest(), requiredFaces, observers: { example: () => Object.defineProperty({}, 'evidence', { enumerable: true, get() { executions++; return {}; } }) } });
    assert.equal(result.faces[0].reason, 'observer-refused');
    assert.equal(result.profileDisposition, requiredFaces.length ? 'refused' : 'admitted');
    for (const matches of [true, false]) await assert.rejects(candidate.verifyCellIdentity({ manifest: manifest(), requiredFaces, observers: { example: ({ cell }) => ({ cell: matches ? cell : capability, controller, evidence: { hidden: undefined } }) } }), error => error.code === 'CELL_IDENTITY_VERIFICATION_INVALID');
  }
  const thrown = Object.defineProperties({}, { name: { get() { executions++; return 'Unsafe'; } }, message: { get() { executions++; return 'Unsafe'; } } });
  const result = await candidate.verifyCellIdentity({ manifest: manifest(), observers: { example: () => { throw thrown; } } });
  assert.equal(result.faces[0].reason, 'observer-refused');
  assert.equal(executions, 0);
});

test('I4 uses own observer functions and rejects executable request structure before invocation', async () => {
  let executions = 0;
  const proxy = new Proxy({}, { get() { executions++; throw Error('trap'); }, ownKeys() { executions++; throw Error('trap'); } });
  await assert.rejects(candidate.verifyCellIdentity(proxy));
  await assert.rejects(candidate.verifyCellIdentity({ manifest: manifest(), observers: Object.defineProperty({}, 'example', { enumerable: true, get() { executions++; return () => {}; } }) }));
  const result = await candidate.verifyCellIdentity({ manifest: { ...manifest(), faces: { toString: {} } } });
  assert.equal(result.faces[0].reason, 'observer-unavailable');
  assert.equal(executions, 0);
});

test('I4 retains caller-owned thenable and native Promise subclass resolution', async () => {
  let resolutions = 0;
  class ObserverPromise extends Promise {}
  for (const kind of ['thenable', 'promise-subclass']) {
    const example = ({ cell }) => {
      const binding = { cell, controller, evidence: { admitted: true } };
      if (kind === 'promise-subclass') return new ObserverPromise(resolve => resolve(binding));
      return Object.defineProperty({}, 'then', { get() {
        resolutions++;
        return resolve => resolve(binding);
      } });
    };
    const actual = await candidate.verifyCellIdentity({ manifest: manifest({ endpoint: 'https://fixture.invalid' }), observers: { example } });
    equalIdentity(actual, historical.verifications[6]);
    assert.equal(actual.profileDisposition, 'admitted');
  }
  assert.equal(resolutions, 1);
});

test('I5-I6 witness normalization and synthetic histories preserve every original identity', () => {
  const cases = [
    [witness({ standing: 'historical' })],
    [witness({ standing: 'unresolved' })],
    [witness({ standing: 'historical', observedAt: '2026-10-05T00:00:00Z' }), witness()],
    [witness(), witness({ standing: 'revoked', observedAt: '2026-10-07T00:00:00Z' })],
    [witness(), witness({ standing: 'revoked', evidence: ['receipt:conflict'] })],
    [witness({ protocol: ' EXAMPLE ', statementRef: ' receipt:statement ', continuity: { ' prior ': ' receipt:prior ' } })],
    [witness({ continuity: undefined, statementRef: undefined })],
  ];
  for (const [caseIndex, witnesses] of cases.entries()) {
    for (const [witnessIndex, input] of witnesses.entries()) {
      equalIdentity(candidateActor.identifyActorCoReferenceWitness(input), historical.histories[caseIndex].witnesses[witnessIndex]);
      assert.deepEqual(candidateActor.normalizeActorCoReferenceWitness(input), historical.histories[caseIndex].witnesses[witnessIndex].normalized);
    }
    const input = { canonicalActor: 'urn:fixture:actor', witnesses };
    const actual = candidateActor.deriveActorProtocolFaces(input), expected = historical.histories[caseIndex].result;
    equalIdentity(actual, expected);
    assert.deepEqual(actual.faces, expected.faces);
    assert.deepEqual(actual.admittedFaces, expected.admittedFaces);
  }
  assert.throws(() => candidateActor.deriveActorProtocolFaces({ canonicalActor: 'urn:other', witnesses: [witness()] }));
});

test('I5 continuity collisions and executable witness containers refuse', () => {
  for (const continuity of [{ ' a ': 'x', a: 'y' }, { '\u00e9': 'x', 'e\u0301': 'y' }, { ' __proto__ ': 'x' }]) assert.throws(() => candidateActor.identifyActorCoReferenceWitness(witness({ continuity })));
  let executions = 0;
  const input = witness(); Object.defineProperty(input, 'canonicalActor', { enumerable: true, get() { executions++; return 'urn:fixture:actor'; } });
  assert.throws(() => candidateActor.identifyActorCoReferenceWitness(input));
  const proxy = new Proxy([], { get() { executions++; return []; } });
  assert.throws(() => candidateActor.deriveActorProtocolFaces({ canonicalActor: 'urn:fixture:actor', witnesses: proxy }));
  assert.equal(executions, 0);
});

test('M1-M3 production uses the one canonical provider and retains historical metadata and Node contract', () => {
  for (const name of ['verify-cell-identity.mjs', 'co-reference-witness.mjs']) {
    const source = readFileSync(new URL(`../src/${name}`, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /relation-model-notation-runtime/);
    assert.match(source, /computer-content-address-engineering-services-section\/semiotic-content-address/);
    assert.match(source, /semanticAddress/);
    assert.doesNotMatch(source, /semanticBytes|semanticId/);
  }
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.engines.node, '>=22');
  assert.ok(!('@red-cup-engineering/relation-model-notation-runtime' in pkg.dependencies));
});
