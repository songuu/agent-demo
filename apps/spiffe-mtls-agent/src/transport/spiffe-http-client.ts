import https from "node:https";
import { SpiffeError } from "../errors";
import type { SpiffeId } from "../spiffe/spiffe-id";
import type { WorkloadApiX509Source } from "../spiffe/workload-x509-source";
import type { AgentRequestOptions } from "../types";

export class SpiffeMtlsAgentClient {
  constructor(private readonly source: WorkloadApiX509Source) {}

  async requestJson<TResponse = unknown>(
    url: URL,
    expectedServerId: SpiffeId,
    options: AgentRequestOptions = {},
  ): Promise<TResponse> {
    const agent = this.source.createHttpsAgent(expectedServerId);
    const body = options.body;

    return new Promise((resolve, reject) => {
      const request = https.request(
        url,
        {
          method: options.method ?? "GET",
          agent,
          headers: {
            ...(body ? { "content-length": String(Buffer.byteLength(body)) } : {}),
            ...(options.headers ?? {}),
          },
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
          response.on("end", () => {
            const responseBody = Buffer.concat(chunks).toString("utf8");
            if (!response.statusCode || response.statusCode >= 400) {
              reject(new SpiffeError("Agent request failed", { statusCode: response.statusCode, responseBody }));
              return;
            }

            try {
              resolve(JSON.parse(responseBody) as TResponse);
            } catch (error) {
              reject(new SpiffeError("Agent response is not valid JSON", { responseBody, cause: error }));
            }
          });
        },
      );

      request.on("error", reject);
      if (body) request.write(body);
      request.end();
    });
  }
}