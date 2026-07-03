import { SpiffeAuthorizationError } from "../errors";
import type { SpiffeId } from "../spiffe/spiffe-id";

export type PeerAuthorizationInput = {
  peerId: SpiffeId;
  targetId: SpiffeId;
  action: string;
};

export type PeerAuthorizationDecision = {
  allowed: boolean;
  reason: string;
};

export type PeerPolicyRule = {
  sourceId: SpiffeId;
  targetIds: ReadonlySet<SpiffeId>;
  actions: ReadonlySet<string>;
};

export interface PeerAuthorizer {
  authorize(input: PeerAuthorizationInput): PeerAuthorizationDecision;
  assertAuthorized(input: PeerAuthorizationInput): void;
}

export class StaticPeerPolicy implements PeerAuthorizer {
  constructor(private readonly rules: readonly PeerPolicyRule[]) {}

  authorize(input: PeerAuthorizationInput): PeerAuthorizationDecision {
    const matchingRule = this.rules.find((rule) => {
      const sourceMatches = rule.sourceId === input.peerId;
      const targetMatches = rule.targetIds.has(input.targetId) || rule.targetIds.has("*" as SpiffeId);
      const actionMatches = rule.actions.has(input.action) || rule.actions.has("*");
      return sourceMatches && targetMatches && actionMatches;
    });

    if (!matchingRule) {
      return {
        allowed: false,
        reason: `No policy rule allows ${input.peerId} to perform ${input.action} on ${input.targetId}`,
      };
    }

    return { allowed: true, reason: "Matched static peer policy" };
  }

  assertAuthorized(input: PeerAuthorizationInput): void {
    const decision = this.authorize(input);
    if (!decision.allowed) {
      throw new SpiffeAuthorizationError("SPIFFE peer is not authorized", { ...input, reason: decision.reason });
    }
  }
}

export function allowListedClientsPolicy(allowedClientIds: ReadonlySet<SpiffeId>): StaticPeerPolicy {
  return new StaticPeerPolicy(
    [...allowedClientIds].map((sourceId) => ({
      sourceId,
      targetIds: new Set<SpiffeId>(["*" as SpiffeId]),
      actions: new Set<string>(["*"]),
    })),
  );
}