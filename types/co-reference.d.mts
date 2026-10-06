export type ActorCoReferenceStanding =
  | "verified"
  | "historical"
  | "unresolved"
  | "revoked"
  | "conflicting";

export interface ActorCoReferenceWitness {
  type: "ActorCoReferenceWitness";
  version: 1;
  canonicalActor: string;
  externalIdentifier: string;
  protocol: string;
  verificationMethod: string;
  observedAt: string;
  evidence: readonly string[];
  standing: ActorCoReferenceStanding;
  statementRef?: string;
  continuity?: Readonly<Record<string, string>>;
}

export interface ActorProtocolFaceReading {
  protocol: string;
  externalIdentifier: string;
  standing: ActorCoReferenceStanding;
  admitted: boolean;
  latestObservedAt: string;
  latestWitness: `ni:///sha-256;${string}`;
  witnessHistory: readonly `ni:///sha-256;${string}`[];
}

export declare function normalizeActorCoReferenceWitness(source: unknown): ActorCoReferenceWitness;

export declare function identifyActorCoReferenceWitness(source: unknown): {
  id: `ni:///sha-256;${string}`;
  mediaType: "application/rmn+cbor";
  value: ActorCoReferenceWitness;
  bytes: Uint8Array;
};

export declare function deriveActorProtocolFaces(input: {
  canonicalActor: string;
  witnesses: readonly ActorCoReferenceWitness[];
}): {
  type: "ActorProtocolFaceSet";
  version: 1;
  canonicalActor: string;
  faces: readonly ActorProtocolFaceReading[];
  admittedFaces: readonly {
    protocol: string;
    externalIdentifier: string;
    witness: `ni:///sha-256;${string}`;
  }[];
  id: `ni:///sha-256;${string}`;
  bytes: Uint8Array;
};
