import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { SpiffeAuthorizationError } from "../errors";
import type { PeerAuthorizer } from "../policy/peer-policy";
import { extractSpiffeIdFromPeerCertificate } from "../spiffe/peer-certificate";
import type { SpiffeId } from "../spiffe/spiffe-id";
import type { WorkloadApiX509Source } from "../spiffe/workload-x509-source";
import type { AgentHandler, AuthenticatedPeer, SpiffeTlsMaterial } from "../types";

function readRequestBody(request: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function writeJson(response: http.ServerResponse, statusCode: number, body: unknown): void {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function defaultAgentHandler(context: Parameters<AgentHandler>[0]): unknown {
  return {
    ok: true,
    serverId: context.localSpiffeId,
    clientId: context.peer.spiffeId,
    method: context.method,
    url: context.url,
  };
}

export class SpiffeMtlsAgentServer {
  private server?: https.Server;

  private readonly updateSecureContext = (updatedMaterial: SpiffeTlsMaterial) => {
    this.server?.setSecureContext({
      key: updatedMaterial.key,
      cert: updatedMaterial.cert,
      ca: updatedMaterial.ca,
    });
  };

  constructor(
    private readonly source: WorkloadApiX509Source,
    private readonly authorizer: PeerAuthorizer,
    private readonly handler: AgentHandler = defaultAgentHandler,
  ) {}

  async listen(port: number, host = "0.0.0.0"): Promise<https.Server> {
    const material = this.source.required();
    this.server = https.createServer(
      {
        key: material.key,
        cert: material.cert,
        ca: material.ca,
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
      },
      async (request, response) => {
        try {
          const peer = this.authorizeClient(request.socket as tls.TLSSocket, "agent:http");
          const body = await readRequestBody(request);
          const result = await this.handler({
            localSpiffeId: this.source.required().spiffeId,
            peer,
            method: request.method ?? "GET",
            url: request.url ?? "/",
            headers: request.headers,
            body,
          });
          writeJson(response, 200, result);
        } catch (error) {
          const statusCode = error instanceof SpiffeAuthorizationError ? 403 : 500;
          const message = error instanceof Error ? error.message : String(error);
          writeJson(response, statusCode, { ok: false, error: message });
        }
      },
    );

    this.source.on("update", this.updateSecureContext);

    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, host, () => {
        this.server!.off("error", reject);
        resolve();
      });
    });

    return this.server;
  }

  async close(): Promise<void> {
    this.source.off("update", this.updateSecureContext);
    if (!this.server) return;
    await new Promise<void>((resolve, reject) => {
      this.server!.close((error) => (error ? reject(error) : resolve()));
    });
  }

  private authorizeClient(socket: tls.TLSSocket, action: string): AuthenticatedPeer {
    if (!socket.authorized) {
      throw new SpiffeAuthorizationError("TLS client certificate was not authorized", {
        authorizationError: socket.authorizationError,
      });
    }

    const certificate = socket.getPeerCertificate();
    if (!certificate || Object.keys(certificate).length === 0) {
      throw new SpiffeAuthorizationError("TLS peer certificate is missing");
    }

    const peerId = extractSpiffeIdFromPeerCertificate(certificate);
    const targetId: SpiffeId = this.source.required().spiffeId;
    this.authorizer.assertAuthorized({ peerId, targetId, action });

    return {
      spiffeId: peerId,
      authorizedAt: new Date(),
      certificateExpiresAt: certificate.valid_to ? new Date(certificate.valid_to) : undefined,
    };
  }
}