import { EventEmitter } from "node:events";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { SpiffeError } from "../errors";
import type { SpiffeTlsMaterial } from "../types";
import { bufferFromGrpcBytes, derCertificatesToPem, derToPem, firstCertificateExpiresAt } from "./der";
import { checkExpectedServerSpiffeId } from "./peer-certificate";
import { assertSpiffeId, type SpiffeId } from "./spiffe-id";
import { WORKLOAD_API_PROTO } from "./workload-api-proto";

type X509SvidWire = {
  spiffe_id: string;
  x509_svid: Buffer | Uint8Array;
  x509_svid_key: Buffer | Uint8Array;
  bundle: Buffer | Uint8Array;
  hint?: string;
};

type X509SvidResponseWire = {
  svids?: X509SvidWire[];
  federated_bundles?: Record<string, Buffer | Uint8Array>;
};

export type WorkloadApiX509SourceOptions = {
  spiffeEndpointSocket?: string;
  spiffeId?: SpiffeId;
  timeoutMs?: number;
};

function endpointToGrpcTarget(endpoint: string): string {
  try {
    const parsedEndpoint = new URL(endpoint);

    if (parsedEndpoint.protocol === "unix:") {
      if (!parsedEndpoint.pathname) {
        throw new SpiffeError("SPIFFE unix endpoint must include an absolute socket path", { endpoint });
      }
      return `unix:${parsedEndpoint.pathname}`;
    }

    if (parsedEndpoint.protocol === "tcp:") {
      if (!parsedEndpoint.hostname || !parsedEndpoint.port) {
        throw new SpiffeError("SPIFFE tcp endpoint must include host and port", { endpoint });
      }
      return `${parsedEndpoint.hostname}:${parsedEndpoint.port}`;
    }
  } catch (error) {
    if (error instanceof SpiffeError) throw error;
    throw new SpiffeError("Invalid SPIFFE endpoint URI", { endpoint, cause: error });
  }

  throw new SpiffeError("Unsupported SPIFFE endpoint scheme", { endpoint });
}

function materialProtoPath(): string {
  const protoPath = path.join(os.tmpdir(), "spiffe-workloadapi-x509.proto");
  fs.writeFileSync(protoPath, WORKLOAD_API_PROTO, { encoding: "utf8", mode: 0o600 });
  return protoPath;
}

async function waitForFirstMaterial(source: WorkloadApiX509Source, timeoutMs: number): Promise<SpiffeTlsMaterial> {
  const currentMaterial = source.current();
  if (currentMaterial) return currentMaterial;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new SpiffeError("Timed out waiting for SPIFFE X509-SVID", { timeoutMs }));
    }, timeoutMs);

    const onUpdate = (material: SpiffeTlsMaterial) => {
      cleanup();
      resolve(material);
    };

    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };

    const cleanup = () => {
      clearTimeout(timeout);
      source.off("update", onUpdate);
      source.off("error", onError);
    };

    source.once("update", onUpdate);
    source.once("error", onError);
  });
}

export class WorkloadApiX509Source extends EventEmitter {
  private material?: SpiffeTlsMaterial;
  private stream?: grpc.ClientReadableStream<X509SvidResponseWire>;

  async start(options: WorkloadApiX509SourceOptions = {}): Promise<void> {
    const endpoint = options.spiffeEndpointSocket ?? process.env.SPIFFE_ENDPOINT_SOCKET;
    if (!endpoint) {
      throw new SpiffeError("SPIFFE_ENDPOINT_SOCKET is required, e.g. unix:///run/spire/sockets/agent.sock");
    }

    const packageDefinition = protoLoader.loadSync(materialProtoPath(), {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });

    const loadedPackage = grpc.loadPackageDefinition(packageDefinition) as Record<string, unknown>;
    const WorkloadApiClient = loadedPackage.SpiffeWorkloadAPI as grpc.ServiceClientConstructor | undefined;
    if (!WorkloadApiClient) {
      throw new SpiffeError("Could not load SpiffeWorkloadAPI client from embedded proto");
    }

    const client = new WorkloadApiClient(endpointToGrpcTarget(endpoint), grpc.credentials.createInsecure());
    const workloadApiClient = client as grpc.Client & Record<string, unknown>;
    const metadata = new grpc.Metadata();
    metadata.set("workload.spiffe.io", "true");

    const fetchMethod = (workloadApiClient.FetchX509SVID ?? workloadApiClient.fetchX509SVID) as
      | ((request: Record<string, never>, metadata: grpc.Metadata) => grpc.ClientReadableStream<X509SvidResponseWire>)
      | undefined;
    if (!fetchMethod) {
      throw new SpiffeError("SpiffeWorkloadAPI client does not expose FetchX509SVID");
    }

    this.stream = fetchMethod.call(client, {}, metadata);
    this.stream.on("data", (message) => {
      try {
        this.updateMaterial(message, options.spiffeId);
      } catch (error) {
        this.emit("error", error instanceof Error ? error : new SpiffeError("Unknown SPIFFE material update error", { error }));
      }
    });
    this.stream.on("error", (error) => this.emit("error", new SpiffeError("SPIFFE Workload API stream error", { cause: error })));
    this.stream.on("end", () => this.emit("end"));

    await waitForFirstMaterial(this, options.timeoutMs ?? 10_000);
  }

  stop(): void {
    this.stream?.cancel();
    this.stream = undefined;
  }

  current(): SpiffeTlsMaterial | undefined {
    return this.material;
  }

  required(): SpiffeTlsMaterial {
    if (!this.material) {
      throw new SpiffeError("SPIFFE X509-SVID material is not loaded");
    }
    return this.material;
  }

  createSecureContext(): tls.SecureContext {
    const material = this.required();
    return tls.createSecureContext({
      key: material.key,
      cert: material.cert,
      ca: material.ca,
      minVersion: "TLSv1.2",
    });
  }

  createHttpsAgent(expectedServerId: SpiffeId): https.Agent {
    const material = this.required();
    return new https.Agent({
      key: material.key,
      cert: material.cert,
      ca: material.ca,
      keepAlive: true,
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
      checkServerIdentity: checkExpectedServerSpiffeId(expectedServerId),
    });
  }

  private updateMaterial(message: X509SvidResponseWire, requestedSpiffeId?: SpiffeId): void {
    const svids = message.svids ?? [];
    const selectedSvid = requestedSpiffeId ? svids.find((svid) => svid.spiffe_id === requestedSpiffeId) : svids[0];
    if (!selectedSvid) {
      throw new SpiffeError("No authorized X509-SVID returned by Workload API", {
        requestedSpiffeId,
        returnedIds: svids.map((svid) => svid.spiffe_id),
      });
    }

    const certificatePem = derCertificatesToPem(bufferFromGrpcBytes(selectedSvid.x509_svid));
    const federatedBundles = Object.values(message.federated_bundles ?? {}).map((bundle) =>
      derCertificatesToPem(bufferFromGrpcBytes(bundle)),
    );

    this.material = {
      spiffeId: assertSpiffeId(selectedSvid.spiffe_id, "selected SVID"),
      cert: certificatePem,
      key: derToPem(bufferFromGrpcBytes(selectedSvid.x509_svid_key), "PRIVATE KEY"),
      ca: [derCertificatesToPem(bufferFromGrpcBytes(selectedSvid.bundle)), ...federatedBundles],
      expiresAt: firstCertificateExpiresAt(certificatePem),
    };

    this.emit("update", this.material);
  }
}