import { z } from "zod";

import {
  gitShaSchema,
  pathGlobSchema,
  policyVersionSchema,
  repoPathSchema,
  riskSchema,
  scopeSchema,
} from "./common.js";
import {
  acceptanceSpecIdSchema,
  customerIdSchema,
  intentIdSchema,
  organizationIdSchema,
  repositoryIdSchema,
  requestIdSchema,
  taskIdSchema,
} from "./ids.js";
import { ACCEPTANCE_SPEC_KINDS, SPEC_POLARITIES } from "./intent.js";
import { sensitiveAreasSchema } from "./policy.js";
import { branchNameSchema, workBranchSchema } from "./task.js";
import { fdaInitiativeSchema } from "./widget-install.js";

// Decision 0027: a customer-repository verdict check. Namlo signs a bounded
// envelope bound to the code commit `P`; the customer's Actions verify it with
// the public keys on the default branch, re-run the shared gate and the
// signed specs, and report back. These are the shapes every side shares. They
// are strict on purpose: the verifier rejects unknown fields and versions
// instead of guessing.

/** The carrier file on the PR head `H`; its only change from `P`. */
export const VERDICT_ENVELOPE_PATH = ".fda/verdict.json";
/** The trusted key configuration, read at the default-branch revision only. */
export const VERDICT_CONFIG_PATH = ".fda/verdict-config.json";
/** The customer workflow that calls the pinned reusable workflow. */
export const VERDICT_WORKFLOW_PATH = ".github/workflows/fda-verdict.yml";
/** The App-owned required check. */
export const VERDICT_CHECK_NAME = "FDA / verdict";
/** The OIDC audience the report job asks GitHub for. */
export const VERDICT_REPORT_AUDIENCE = "fda-verdict-report";

/** Prefix of the signed bytes: `UTF8(context) || payload bytes`. */
export const VERDICT_SIGNING_CONTEXT = "fda-verdict/v1\n";
export const VERDICT_SCHEMA_VERSION = 1;
export const VERDICT_MAX_PAYLOAD_BYTES = 256 * 1024;
/** The outer file holds the base64 payload plus a few hundred bytes. */
export const VERDICT_MAX_ENVELOPE_BYTES = 360 * 1024;
export const VERDICT_MAX_CONFIG_BYTES = 16 * 1024;
export const VERDICT_MAX_SPECS = 20;
export const VERDICT_ISSUANCE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** Received pack cap for the customer-CI fetch (v1). */
export const VERDICT_PACK_CAP_BYTES = 512 * 1024 * 1024;
/** Hard total execution deadline in the customer's container. */
export const VERDICT_MAX_EXECUTION_SECONDS = 20 * 60;

export const VERDICT_ARGV_MAX_ITEMS = 64;
export const VERDICT_ARG_MAX_CHARS = 1_000;

const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Standard padded base64 with nothing a decoder would silently fix up: no
 * whitespace, no URL-safe letters, correct padding and zero pad bits. A
 * value passes only if decoding and re-encoding it gives the same text.
 */
export function isCanonicalBase64(value: string): boolean {
  if (value.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    return false;
  if (value.endsWith("==")) {
    return (BASE64_ALPHABET.indexOf(value.at(-3)!) & 0b1111) === 0;
  }
  if (value.endsWith("=")) {
    return (BASE64_ALPHABET.indexOf(value.at(-2)!) & 0b11) === 0;
  }
  return true;
}

/** Decoded length of a canonical base64 string. */
export function base64DecodedLength(value: string): number {
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

function canonicalBase64Schema(bytes: { exact?: number; max?: number }) {
  const maxChars =
    bytes.exact !== undefined
      ? Math.ceil(bytes.exact / 3) * 4
      : Math.ceil((bytes.max ?? 0) / 3) * 4;
  return z
    .string()
    .max(maxChars)
    .refine(isCanonicalBase64, "expected canonical padded base64")
    .refine(
      (value) =>
        bytes.exact !== undefined
          ? base64DecodedLength(value) === bytes.exact
          : base64DecodedLength(value) <= (bytes.max ?? 0),
      bytes.exact !== undefined
        ? `expected ${bytes.exact} decoded bytes`
        : `decoded value exceeds ${bytes.max} bytes`,
    );
}

export const sha256HexSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, "expected a lowercase SHA-256 hex digest");

export const verdictKeyIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/, "expected a key id");

/** `owner/name` as GitHub spells it. */
export const repositoryFullNameSchema = z
  .string()
  .max(200)
  .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "expected owner/name");

/**
 * A repo path in normal form: what Git stores in a tree. No empty, `.` or
 * `..` segment, no leading or trailing slash, no backslash or control
 * character.
 */
export const normalizedRepoPathSchema = repoPathSchema.refine(
  (path) =>
    !path.endsWith("/") &&
    path.split("/").every((segment) => segment !== "" && segment !== ".") &&
    !/[\u0000-\u001f\u007f]/.test(path),
  "expected a normalized repo path",
);

/** One command as argv: never a shell string. */
export const verdictArgvSchema = z
  .array(
    z
      .string()
      .max(VERDICT_ARG_MAX_CHARS)
      .refine((arg) => !arg.includes("\0"), "argv may not contain NUL"),
  )
  .min(1)
  .max(VERDICT_ARGV_MAX_ITEMS)
  .refine((argv) => argv[0] !== "", "argv[0] may not be empty");

const githubRepositorySchema = z.strictObject({
  /** GitHub's stable numeric repository id. */
  github_id: z.int().positive(),
  full_name: repositoryFullNameSchema,
});

const repositoryBindingSchema = githubRepositorySchema.extend({
  /** Namlo's repository id. */
  fda_id: repositoryIdSchema,
});

/** The published reusable-workflow release (`W`) a payload or config names. */
const releaseRefSchema = z.strictObject({ workflow_sha: gitShaSchema });

const globList = z.array(pathGlobSchema).max(200);

/**
 * Exactly what `evaluatePatch` consumes, as signed schema projections of the
 * task and the build's effective repository policy; never a whole `Task` or
 * org policy.
 */
export const verdictGateProjectionSchema = z.strictObject({
  task: z.strictObject({
    allowed_paths: globList.min(1),
    protected_paths: globList,
    target_scope: scopeSchema,
    risk: riskSchema.exclude(["blocked"]),
    policy_version: policyVersionSchema,
    security_test_updates: z.array(repoPathSchema).max(20).optional(),
    fda_initiative: fdaInitiativeSchema.optional(),
  }),
  repository: z.strictObject({
    allowed_paths: globList,
    protected_paths: globList,
    max_files: z.int().min(1),
    max_changed_lines: z.int().min(1),
    allow_dependency_changes: z.boolean(),
  }),
  /** The org policy version number the build loaded. */
  org_policy_version: z.int().min(1),
  sensitive_areas: sensitiveAreasSchema,
});

export const verdictSpecSchema = z.strictObject({
  id: acceptanceSpecIdSchema,
  path: normalizedRepoPathSchema,
  /** SHA-256 of the spec's exact UTF-8 bytes; CI hashes the blob at `P`. */
  sha256: sha256HexSchema,
  kind: z.enum(ACCEPTANCE_SPEC_KINDS),
  polarity: z.enum(SPEC_POLARITIES),
  /** Opaque: which customer the spec is for. */
  customer_id: customerIdSchema,
  must_fail_before: z.literal(true),
  argv: verdictArgvSchema,
});

export const verdictExecutionSchema = z.strictObject({
  setup: z.array(verdictArgvSchema).max(20),
  /** Runner/image compatibility version the release must support. */
  runner_version: z.int().min(1),
  limits: z.strictObject({
    total_seconds: z.int().min(1).max(VERDICT_MAX_EXECUTION_SECONDS),
    command_seconds: z.int().min(1).max(VERDICT_MAX_EXECUTION_SECONDS),
  }),
});

const isoTimestamp = z.iso.datetime({ offset: false });

/**
 * The signed payload, built from authoritative records after the final gate.
 * It names `B` and `P` (never `H`, which carries it) and no PR number (the PR
 * doesn't exist yet; the issuance record binds it).
 */
export const verdictPayloadSchema = z
  .strictObject({
    schema_version: z.literal(VERDICT_SCHEMA_VERSION),
    issuance_id: z.uuid(),
    key_id: verdictKeyIdSchema,
    gate_revision: z.string().min(1).max(50),
    release: releaseRefSchema,
    issued_at: isoTimestamp,
    expires_at: isoTimestamp,
    organization_id: organizationIdSchema,
    repository: repositoryBindingSchema,
    task_id: taskIdSchema,
    request_id: requestIdSchema,
    intent_id: intentIdSchema,
    intent_version: z.int().min(1),
    head_branch: workBranchSchema,
    default_branch: branchNameSchema,
    base_branch: branchNameSchema,
    /** `B`: the task's recorded base commit. */
    base_sha: gitShaSchema,
    /** `P`: the final code commit after every gate. */
    code_sha: gitShaSchema,
    /** `P`'s tree id. */
    code_tree: gitShaSchema,
    gate: verdictGateProjectionSchema,
    specs: z.array(verdictSpecSchema).min(1).max(VERDICT_MAX_SPECS),
    execution: verdictExecutionSchema,
  })
  .superRefine((payload, ctx) => {
    const issued = Date.parse(payload.issued_at);
    const expires = Date.parse(payload.expires_at);
    if (!(expires > issued) || expires - issued > VERDICT_ISSUANCE_TTL_MS) {
      ctx.addIssue({
        code: "custom",
        message: "expires_at must be after issued_at and within 30 days",
        path: ["expires_at"],
      });
    }
    if (payload.base_branch !== payload.default_branch) {
      ctx.addIssue({
        code: "custom",
        message: "v1 verifies PRs that target the default branch only",
        path: ["base_branch"],
      });
    }
    const ids = payload.specs.map((spec) => spec.id);
    const paths = payload.specs.map((spec) => spec.path);
    if (new Set(ids).size !== ids.length) {
      ctx.addIssue({
        code: "custom",
        message: "spec ids repeat",
        path: ["specs"],
      });
    }
    if (new Set(paths).size !== paths.length) {
      ctx.addIssue({
        code: "custom",
        message: "spec paths repeat",
        path: ["specs"],
      });
    }
  });

/** `.fda/verdict.json`: a detached Ed25519 signature over the payload bytes. */
export const verdictEnvelopeSchema = z.strictObject({
  schema_version: z.literal(VERDICT_SCHEMA_VERSION),
  key_id: verdictKeyIdSchema,
  payload_b64: canonicalBase64Schema({ max: VERDICT_MAX_PAYLOAD_BYTES }),
  signature_b64: canonicalBase64Schema({ exact: 64 }),
});

export const VERDICT_KEY_STATES = ["active", "next"] as const;

/**
 * `.fda/verdict-config.json` on the default branch: the org's active public
 * key and at most one next key, the repository binding and the release.
 */
export const verdictConfigSchema = z
  .strictObject({
    schema_version: z.literal(VERDICT_SCHEMA_VERSION),
    organization_id: organizationIdSchema,
    repository: repositoryBindingSchema,
    release: releaseRefSchema,
    keys: z
      .array(
        z.strictObject({
          key_id: verdictKeyIdSchema,
          state: z.enum(VERDICT_KEY_STATES),
          /** Raw 32-byte Ed25519 public key. */
          public_key_b64: canonicalBase64Schema({ exact: 32 }),
        }),
      )
      .min(1)
      .max(2),
  })
  .superRefine((config, ctx) => {
    const active = config.keys.filter((key) => key.state === "active");
    const ids = config.keys.map((key) => key.key_id);
    const keys = config.keys.map((key) => key.public_key_b64);
    if (active.length !== 1) {
      ctx.addIssue({
        code: "custom",
        message: "exactly one active key",
        path: ["keys"],
      });
    }
    if (
      new Set(ids).size !== ids.length ||
      new Set(keys).size !== keys.length
    ) {
      ctx.addIssue({
        code: "custom",
        message: "key ids and keys must be distinct",
        path: ["keys"],
      });
    }
  });

export const VERDICT_PREPARE_OUTCOMES = [
  "passed",
  "failed",
  "not_applicable",
  "unsupported",
] as const;
export const VERDICT_RESULT_OUTCOMES = [
  "passed",
  "failed",
  "timed_out",
  "skipped",
  "missing",
] as const;
export const VERDICT_RUNTIMES = ["runsc", "runc"] as const;

const boundedReason = z.string().min(1).max(500);

/**
 * What the report job sends Namlo: bounded data derived from trusted job
 * outputs. Namlo checks every claim against its own records and GitHub.
 */
export const verdictReportSchema = z
  .strictObject({
    schema_version: z.literal(VERDICT_SCHEMA_VERSION),
    repository: githubRepositorySchema,
    pr_number: z.int().positive(),
    head_sha: gitShaSchema,
    code_sha: gitShaSchema.optional(),
    issuance_id: z.uuid().optional(),
    run: z.strictObject({
      id: z.int().positive(),
      attempt: z.int().min(1),
    }),
    prepare: z.strictObject({
      outcome: z.enum(VERDICT_PREPARE_OUTCOMES),
      /** SHA-256 of prepare's canonical outcome record. */
      digest: sha256HexSchema,
      /** SHA-256 of `.fda/verdict.json` at `H`. */
      envelope_digest: sha256HexSchema.optional(),
      reasons: z.array(boundedReason).max(50),
    }),
    result: z
      .strictObject({
        outcome: z.enum(VERDICT_RESULT_OUTCOMES),
        /** SHA-256 of the result artifact, compared with GitHub's. */
        artifact_digest: sha256HexSchema.optional(),
        runtime: z.enum(VERDICT_RUNTIMES).optional(),
        specs: z
          .array(
            z.strictObject({
              id: acceptanceSpecIdSchema,
              exit_code: z.int().nullable(),
              timed_out: z.boolean(),
              duration_ms: z.int().min(0),
            }),
          )
          .max(VERDICT_MAX_SPECS),
      })
      .optional(),
  })
  .superRefine((report, ctx) => {
    if (
      report.prepare.outcome === "passed" &&
      (report.issuance_id === undefined ||
        report.code_sha === undefined ||
        report.prepare.envelope_digest === undefined)
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "a passed prepare names the issuance, code commit and envelope digest",
        path: ["prepare"],
      });
    }
    if (
      report.result?.outcome === "passed" &&
      (report.prepare.outcome !== "passed" ||
        report.result.artifact_digest === undefined ||
        report.result.runtime === undefined)
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "a passed result needs a passed prepare, an artifact digest and a runtime",
        path: ["result"],
      });
    }
  });

export type VerdictGateProjection = z.infer<typeof verdictGateProjectionSchema>;
export type VerdictSpec = z.infer<typeof verdictSpecSchema>;
export type VerdictExecution = z.infer<typeof verdictExecutionSchema>;
export type VerdictPayload = z.infer<typeof verdictPayloadSchema>;
export type VerdictEnvelope = z.infer<typeof verdictEnvelopeSchema>;
export type VerdictConfig = z.infer<typeof verdictConfigSchema>;
export type VerdictReport = z.infer<typeof verdictReportSchema>;
export type VerdictPrepareOutcome = (typeof VERDICT_PREPARE_OUTCOMES)[number];
export type VerdictRuntime = (typeof VERDICT_RUNTIMES)[number];
