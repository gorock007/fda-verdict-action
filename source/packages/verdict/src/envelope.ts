import {
  createHash,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import {
  VERDICT_MAX_CONFIG_BYTES,
  VERDICT_MAX_ENVELOPE_BYTES,
  VERDICT_SCHEMA_VERSION,
  VERDICT_SIGNING_CONTEXT,
  verdictConfigSchema,
  verdictEnvelopeSchema,
  verdictPayloadSchema,
  type VerdictConfig,
  type VerdictEnvelope,
  type VerdictPayload,
} from "@fda/contracts";

// Decision 0027: `.fda/verdict.json` is a detached Ed25519 signature over
// `UTF8("fda-verdict/v1\n") || payload bytes`. The verifier checks those
// exact bytes before it parses the payload, so no side relies on canonical
// JSON. Ed25519 is fixed: nothing in the file selects an algorithm.

/** A refusal the verifier reports as a reason; never carries secrets. */
export class VerdictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerdictError";
  }
}

const CONTEXT = Buffer.from(VERDICT_SIGNING_CONTEXT, "utf8");
const MAX_JSON_DEPTH = 32;

export function sha256Hex(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeUtf8(bytes: Uint8Array, what: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch {
    throw new VerdictError(`${what} is not valid UTF-8`);
  }
}

/**
 * Checks `text` is one RFC 8259 JSON value with no repeated object key at
 * any depth (`JSON.parse` keeps the last one silently), then parses it.
 */
export function parseStrictJson(text: string, what = "JSON"): unknown {
  let i = 0;
  const fail = (problem: string): never => {
    throw new VerdictError(`${what} ${problem} at offset ${i}`);
  };
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i]!)) i++;
  };
  const string = (): string => {
    const start = i;
    i++;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return JSON.parse(text.slice(start, i)) as string;
      }
      if (c < 0x20) fail("has a control character in a string");
      if (c === 0x5c) {
        const next = text[i + 1];
        if (next === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) {
            fail("has a bad \\u escape");
          }
          i += 6;
          continue;
        }
        if (next === undefined || !'"\\/bfnrt'.includes(next)) {
          fail("has a bad escape");
        }
        i += 2;
        continue;
      }
      i++;
    }
    return fail("has an unterminated string");
  };
  const value = (depth: number): void => {
    if (depth > MAX_JSON_DEPTH) fail("is nested too deeply");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const keys = new Set<string>();
      ws();
      if (text[i] === "}") {
        i++;
        return;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected a key");
        const key = string();
        if (keys.has(key)) fail(`repeats the key ${JSON.stringify(key)}`);
        keys.add(key);
        ws();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        value(depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return;
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      ws();
      if (text[i] === "]") {
        i++;
        return;
      }
      for (;;) {
        value(depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return;
        }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') {
      string();
      return;
    }
    const literal =
      /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        text.slice(i, i + 400),
      );
    if (!literal) fail("has an unexpected token");
    i += literal![0].length;
  };
  value(0);
  ws();
  if (i !== text.length) fail("has trailing data");
  return JSON.parse(text);
}

function publicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** The raw 32-byte public key, base64, as `.fda/verdict-config.json` holds it. */
export function publicKeyB64(key: KeyObject): string {
  const publicKey = key.type === "private" ? createPublicKey(key) : key;
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new VerdictError("verdict keys are Ed25519");
  }
  const { x } = publicKey.export({ format: "jwk" });
  return Buffer.from(x!, "base64url").toString("base64");
}

/** The payload bytes Namlo signs: the schema-checked payload as JSON. */
export function encodePayload(payload: VerdictPayload): Buffer {
  return Buffer.from(
    JSON.stringify(verdictPayloadSchema.parse(payload)),
    "utf8",
  );
}

export interface SigningKey {
  keyId: string;
  privateKey: KeyObject;
}

export interface SignedEnvelope {
  envelope: VerdictEnvelope;
  /** The exact bytes of `.fda/verdict.json`. */
  bytes: Buffer;
  /** SHA-256 of `bytes`, recorded on the issuance before pushing. */
  digest: string;
}

/**
 * Signs a payload with a key object. Pure: key storage, unwrapping and
 * choosing the payload's fields are the service's job, never a caller's
 * free-form input.
 */
export function signEnvelope(
  payload: VerdictPayload,
  key: SigningKey,
): SignedEnvelope {
  if (key.privateKey.type !== "private") {
    throw new VerdictError("signing needs a private key");
  }
  if (key.privateKey.asymmetricKeyType !== "ed25519") {
    throw new VerdictError("verdict keys are Ed25519");
  }
  if (payload.key_id !== key.keyId) {
    throw new VerdictError("the payload names a different key");
  }
  const payloadBytes = encodePayload(payload);
  const signature = sign(
    null,
    Buffer.concat([CONTEXT, payloadBytes]),
    key.privateKey,
  );
  const envelope = verdictEnvelopeSchema.parse({
    schema_version: VERDICT_SCHEMA_VERSION,
    key_id: key.keyId,
    payload_b64: payloadBytes.toString("base64"),
    signature_b64: signature.toString("base64"),
  });
  const bytes = Buffer.from(`${JSON.stringify(envelope)}\n`, "utf8");
  return { envelope, bytes, digest: sha256Hex(bytes) };
}

/** Parses `.fda/verdict-config.json` strictly (no repeated keys, no extras). */
export function parseVerdictConfig(bytes: Uint8Array): VerdictConfig {
  if (bytes.length > VERDICT_MAX_CONFIG_BYTES) {
    throw new VerdictError("verification config is too large");
  }
  const parsed = verdictConfigSchema.safeParse(
    parseStrictJson(
      decodeUtf8(bytes, "verification config"),
      "verification config",
    ),
  );
  if (!parsed.success) {
    throw new VerdictError("verification config does not match its schema");
  }
  return parsed.data;
}

export interface VerifiedEnvelope {
  envelope: VerdictEnvelope;
  payload: VerdictPayload;
  digest: string;
}

/**
 * Verifies the exact file bytes against the trusted config's keys, then
 * parses the payload strictly. Throws `VerdictError` for a malformed file,
 * an unknown key, a bad signature or a payload outside its schema.
 */
export function verifyEnvelope(
  bytes: Uint8Array,
  config: VerdictConfig,
): VerifiedEnvelope {
  if (bytes.length > VERDICT_MAX_ENVELOPE_BYTES) {
    throw new VerdictError("envelope is too large");
  }
  const outer = verdictEnvelopeSchema.safeParse(
    parseStrictJson(decodeUtf8(bytes, "envelope"), "envelope"),
  );
  if (!outer.success) {
    throw new VerdictError("envelope does not match its schema");
  }
  const envelope = outer.data;
  const key = config.keys.find(({ key_id }) => key_id === envelope.key_id);
  if (!key) {
    throw new VerdictError(
      `envelope key ${envelope.key_id} is not trusted by this repository`,
    );
  }
  const payloadBytes = Buffer.from(envelope.payload_b64, "base64");
  const signature = Buffer.from(envelope.signature_b64, "base64");
  const valid = verify(
    null,
    Buffer.concat([CONTEXT, payloadBytes]),
    publicKeyFromRaw(Buffer.from(key.public_key_b64, "base64")),
    signature,
  );
  if (!valid) throw new VerdictError("envelope signature does not verify");
  const payload = verdictPayloadSchema.safeParse(
    parseStrictJson(decodeUtf8(payloadBytes, "payload"), "payload"),
  );
  if (!payload.success) {
    throw new VerdictError("signed payload does not match its schema");
  }
  if (payload.data.key_id !== envelope.key_id) {
    throw new VerdictError("signed payload names a different key");
  }
  return { envelope, payload: payload.data, digest: sha256Hex(bytes) };
}

/** What the verifier knows independently of the envelope. */
export interface PayloadExpectations {
  config: VerdictConfig;
  repository: { github_id: number; full_name: string };
  headBranch: string;
  baseBranch: string;
  defaultBranch: string;
  /** The release (`W`) of the running reusable workflow. */
  releaseWorkflowSha: string;
  gateRevision: string;
  now: Date;
}

/** Tolerated clock skew between Namlo and the runner. */
const CLOCK_SKEW_MS = 5 * 60_000;

/**
 * Why a verified payload doesn't bind to this repository, PR, branch and
 * release. Empty means it binds.
 */
export function payloadBindingIssues(
  payload: VerdictPayload,
  expected: PayloadExpectations,
): string[] {
  const issues: string[] = [];
  const { config } = expected;
  if (
    payload.repository.github_id !== expected.repository.github_id ||
    payload.repository.github_id !== config.repository.github_id
  ) {
    issues.push("envelope is for a different repository");
  }
  if (
    payload.repository.full_name !== expected.repository.full_name ||
    config.repository.full_name !== expected.repository.full_name
  ) {
    issues.push("envelope names a different repository");
  }
  if (
    payload.organization_id !== config.organization_id ||
    payload.repository.fda_id !== config.repository.fda_id
  ) {
    issues.push("envelope is for a different Namlo organization or repository");
  }
  if (payload.head_branch !== expected.headBranch) {
    issues.push("envelope is for a different head branch");
  }
  if (
    payload.base_branch !== expected.baseBranch ||
    payload.default_branch !== expected.defaultBranch
  ) {
    issues.push("envelope is for a different base or default branch");
  }
  if (
    payload.release.workflow_sha !== expected.releaseWorkflowSha ||
    config.release.workflow_sha !== expected.releaseWorkflowSha
  ) {
    issues.push("envelope or config names a different verifier release");
  }
  if (payload.gate_revision !== expected.gateRevision) {
    issues.push(`unsupported gate revision ${payload.gate_revision}`);
  }
  const now = expected.now.getTime();
  if (Date.parse(payload.issued_at) - CLOCK_SKEW_MS > now) {
    issues.push("envelope is issued in the future");
  }
  if (Date.parse(payload.expires_at) <= now) {
    issues.push("envelope has expired");
  }
  return issues;
}
