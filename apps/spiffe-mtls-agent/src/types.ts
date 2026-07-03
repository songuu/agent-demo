import type { IncomingHttpHeaders } from "node:http";
import type { SpiffeId } from "./spiffe/spiffe-id";

export type SpiffeTlsMaterial = {
  spiffeId: SpiffeId;
  cert: string;
  key: string;
  ca: string[];
  expiresAt?: Date;
};

export type AgentRequestOptions = {
  method?: string;
  body?: string | Buffer;
  headers?: Record<string, string>;
};

export type AuthenticatedPeer = {
  spiffeId: SpiffeId;
  authorizedAt: Date;
  certificateExpiresAt?: Date;
};

export type AgentRequestContext = {
  localSpiffeId: SpiffeId;
  peer: AuthenticatedPeer;
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: Buffer;
};

export type AgentHandler = (context: AgentRequestContext) => Promise<unknown> | unknown;