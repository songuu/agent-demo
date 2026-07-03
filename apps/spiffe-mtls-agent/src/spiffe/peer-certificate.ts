import type tls from "node:tls";
import { SpiffeAuthorizationError, SpiffeError } from "../errors";
import { assertSpiffeId, type SpiffeId } from "./spiffe-id";

type NodeCheckServerIdentity = (host: string, cert: tls.PeerCertificate) => Error | undefined;

function parseSubjectAlternativeNameEntries(subjectAlternativeName?: string): string[] {
  if (!subjectAlternativeName) return [];

  const entries: string[] = [];
  let current = "";
  let inJsonString = false;
  let escaped = false;

  for (const character of subjectAlternativeName) {
    if (character === "\\" && inJsonString) {
      escaped = !escaped;
      current += character;
      continue;
    }

    if (character === '"' && !escaped) {
      inJsonString = !inJsonString;
      current += character;
      continue;
    }

    escaped = false;

    if (character === "," && !inJsonString) {
      entries.push(current.trim());
      current = "";
      continue;
    }

    current += character;
  }

  if (current.trim()) entries.push(current.trim());
  return entries;
}

function decodeNodeSubjectAlternativeNameValue(value: string): string {
  const trimmed = value.trim();
  if (!trimmed.startsWith('"')) return trimmed;

  try {
    return JSON.parse(trimmed) as string;
  } catch (error) {
    throw new SpiffeError("Could not decode URI SAN JSON string", { value, cause: error });
  }
}

export function extractSpiffeIdFromPeerCertificate(peerCertificate: tls.PeerCertificate): SpiffeId {
  const uriSans = parseSubjectAlternativeNameEntries(peerCertificate.subjectaltname)
    .filter((entry) => entry.startsWith("URI:"))
    .map((entry) => decodeNodeSubjectAlternativeNameValue(entry.slice("URI:".length)));

  if (uriSans.length !== 1) {
    throw new SpiffeAuthorizationError("Peer certificate must contain exactly one SPIFFE URI SAN", {
      subjectaltname: peerCertificate.subjectaltname,
      uriSanCount: uriSans.length,
    });
  }

  return assertSpiffeId(uriSans[0], "peer certificate URI SAN");
}

export function checkExpectedServerSpiffeId(expectedServerId: SpiffeId): NodeCheckServerIdentity {
  return (_host, peerCertificate) => {
    try {
      const actualServerId = extractSpiffeIdFromPeerCertificate(peerCertificate);
      if (actualServerId !== expectedServerId) {
        return new SpiffeAuthorizationError("Unexpected server SPIFFE ID", {
          expectedServerId,
          actualServerId,
        });
      }
      return undefined;
    } catch (error) {
      return error instanceof Error ? error : new SpiffeError("Unknown SPIFFE server identity failure", { error });
    }
  };
}