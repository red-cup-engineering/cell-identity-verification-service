export type CellFace = "npm" | "github" | "activitypub" | "a2a" | "mcp" | "x402" | "evm";
export type CellFaceDisposition = "bound" | "absent" | "invalid";
export type CellProfile = "capcell";

export interface CapabilityCellManifest {
  type: "CapabilityCellManifest";
  version: 2;
  sku: `ni:///sha-256;${string}`;
  capability: `ni:///sha-256;${string}`;
  controller: `did:pkh:eip155:${string}:0x${string}`;
  faces: Partial<Record<CellFace, Readonly<Record<string, unknown>>>>;
}

export interface CellFaceBinding {
  face: CellFace;
  disposition: CellFaceDisposition;
  claim?: Readonly<Record<string, unknown>>;
  reason?: string;
  evidence?: unknown;
}

export declare const CELL_FACES: readonly CellFace[];
export declare const CELL_PROFILES: Readonly<Record<CellProfile, readonly CellFace[]>>;
export declare function normalizeCellManifest(source: unknown): CapabilityCellManifest;
export declare function identifyCellIdentity(source: unknown): {
  id: `ni:///sha-256;${string}`;
  mediaType: "application/rmn+cbor";
  value: {
    type: "CapabilityCellIdentity";
    version: 1;
    sku: `ni:///sha-256;${string}`;
    capability: `ni:///sha-256;${string}`;
    controller: `did:pkh:eip155:${string}:0x${string}`;
  };
  bytes: Uint8Array;
};
export declare function identifyCellManifest(source: unknown): {
  id: `ni:///sha-256;${string}`;
  mediaType: "application/rmn+cbor";
  value: CapabilityCellManifest;
  bytes: Uint8Array;
};
export declare function verifyCellIdentity(input: {
  manifest: CapabilityCellManifest;
  profile?: CellProfile;
  observers?: Partial<Record<CellFace, (request: {
    face: CellFace;
    claim: Readonly<Record<string, unknown>>;
    cell: `ni:///sha-256;${string}`;
    manifest: `ni:///sha-256;${string}`;
    sku: `ni:///sha-256;${string}`;
    capability: `ni:///sha-256;${string}`;
    controller: `did:pkh:eip155:${string}:0x${string}`;
  }) => unknown | Promise<unknown>>>;
}): Promise<{
  id: `ni:///sha-256;${string}`;
  bytes: Uint8Array;
  cell: `ni:///sha-256;${string}`;
  manifest: `ni:///sha-256;${string}`;
  sku: `ni:///sha-256;${string}`;
  capability: `ni:///sha-256;${string}`;
  controller: string;
  profile: CellProfile;
  faces: readonly CellFaceBinding[];
  profileDisposition: "admitted" | "refused";
  missingRequiredBindings: readonly CellFace[];
}>;
