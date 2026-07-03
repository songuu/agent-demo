import { X509Certificate } from "node:crypto";
import { SpiffeError } from "../errors";

export function bufferFromGrpcBytes(value: Buffer | Uint8Array): Buffer {
  return Buffer.isBuffer(value) ? value : Buffer.from(value);
}

export function splitConcatenatedDer(input: Buffer): Buffer[] {
  const blocks: Buffer[] = [];
  let offset = 0;

  while (offset < input.length) {
    if (input[offset] !== 0x30) {
      throw new SpiffeError("Invalid DER: expected ASN.1 SEQUENCE", { offset });
    }

    const lengthByte = input[offset + 1];
    if (lengthByte === undefined) {
      throw new SpiffeError("Invalid DER: truncated length", { offset });
    }

    let payloadLength = 0;
    let headerLength = 2;

    if ((lengthByte & 0x80) === 0) {
      payloadLength = lengthByte;
    } else {
      const lengthByteCount = lengthByte & 0x7f;
      if (lengthByteCount === 0 || lengthByteCount > 4) {
        throw new SpiffeError("Invalid DER: unsupported length encoding", { offset, lengthByteCount });
      }
      headerLength = 2 + lengthByteCount;
      if (offset + headerLength > input.length) {
        throw new SpiffeError("Invalid DER: truncated long length", { offset, lengthByteCount });
      }
      for (let index = 0; index < lengthByteCount; index += 1) {
        payloadLength = (payloadLength << 8) + input[offset + 2 + index];
      }
    }

    const end = offset + headerLength + payloadLength;
    if (end > input.length) {
      throw new SpiffeError("Invalid DER: block exceeds input length", { offset, end, inputLength: input.length });
    }

    blocks.push(input.subarray(offset, end));
    offset = end;
  }

  return blocks;
}

export function derToPem(der: Buffer, label: "CERTIFICATE" | "PRIVATE KEY"): string {
  const body = der.toString("base64").match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

export function derCertificatesToPem(derChain: Buffer): string {
  return splitConcatenatedDer(derChain)
    .map((der) => derToPem(der, "CERTIFICATE"))
    .join("");
}

export function firstCertificateExpiresAt(certificatePem: string): Date | undefined {
  const firstCertificate = certificatePem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0];
  if (!firstCertificate) return undefined;

  try {
    const validTo = new X509Certificate(firstCertificate).validTo;
    return validTo ? new Date(validTo) : undefined;
  } catch {
    return undefined;
  }
}