import { SpiffeError } from "../errors";

export type SpiffeId = `spiffe://${string}`;

export function assertSpiffeId(value: string, label = "SPIFFE ID"): SpiffeId {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "spiffe:" || !parsed.hostname) {
      throw new SpiffeError(`${label} must use the spiffe:// trust-domain/path format`, { value });
    }
    if (parsed.search || parsed.hash || parsed.username || parsed.password || parsed.port) {
      throw new SpiffeError(`${label} must not include authority credentials, port, query, or fragment`, { value });
    }
    return value as SpiffeId;
  } catch (error) {
    if (error instanceof SpiffeError) throw error;
    throw new SpiffeError(`${label} is not a valid SPIFFE ID`, { value, cause: error });
  }
}

export function trustDomainFromSpiffeId(spiffeId: SpiffeId): string {
  return new URL(spiffeId).hostname;
}

export function pathSegmentsFromSpiffeId(spiffeId: SpiffeId): string[] {
  return new URL(spiffeId).pathname.split("/").filter(Boolean);
}

export function spiffeSetFromCsv(value: string): ReadonlySet<SpiffeId> {
  return new Set(
    value
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => assertSpiffeId(entry, "SPIFFE allow-list entry")),
  );
}