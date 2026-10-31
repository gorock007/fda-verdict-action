import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  gitShaSchema,
  sha256HexSchema,
  verdictEnvelopeSchema,
  verdictPayloadSchema,
  verdictReportSchema,
  type VerdictReport,
} from "@fda/contracts";

import { parseStrictJson, sha256Hex, VerdictError } from "./envelope.js";
import type { PrepareResult } from "./prepare.js";

// Decision 0027, the hand-off between the jobs. `execute` writes the one-file
// result record; the report job reads it back as data and builds the body
// Namlo's `POST /api/v1/verdict/reports` parses with `verdictReportSchema`.

/** Each artifact holds exactly one JSON file of at most this many bytes. */
export const VERDICT_ARTIFACT_MAX_BYTES = 1024 * 1024;
export const VERDICT_PREPARE_FILE = "prepare.json";
export const VERDICT_RESULT_FILE = "result.json";
/** The route's body cap. */
export const VERDICT_REPORT_MAX_BYTES = 64 * 1024;

/**
 * The supervisor's fixed-schema record, uploaded as `result.json`. It can't
 * hold its own archive's digest, so `result.artifact_digest` stays absent;
 * the report carries it. Built by extending a strict contracts schema
 * because this package has no direct zod dependency (the boundary test pins
 * its three dependencies).
 */
export const verdictExecutionRecordSchema = verdictEnvelopeSchema
  .pick({ schema_version: true })
  .extend({
    issuance_id: verdictPayloadSchema.shape.issuance_id,
    head_sha: gitShaSchema,
    code_sha: gitShaSchema,
    run: verdictReportSchema.shape.run,
    prepare_digest: sha256HexSchema,
    result: verdictReportSchema.shape.result.unwrap(),
  });
export type VerdictExecutionRecord = ReturnType<
  typeof verdictExecutionRecordSchema.parse
>;

export interface VerdictRun {
  id: number;
  attempt: number;
}

/** Names include the run and attempt; nothing is searched for by a bare name. */
export function verdictArtifactName(
  kind: "prepare" | "result",
  run: VerdictRun,
): string {
  verdictReportSchema.shape.run.parse(run);
  return `fda-verdict-${kind}-${run.id}-${run.attempt}`;
}

/** The exact bytes of `result.json`. */
export function encodeExecutionRecord(record: VerdictExecutionRecord): Buffer {
  const bytes = Buffer.from(
    JSON.stringify(verdictExecutionRecordSchema.parse(record)),
  );
  if (bytes.length > VERDICT_ARTIFACT_MAX_BYTES) {
    throw new VerdictError("the result record exceeds 1 MiB");
  }
  return bytes;
}

/** Reads `result.json` as data: bounded, strict JSON, strict schema. */
export function parseExecutionRecord(
  bytes: Uint8Array,
): VerdictExecutionRecord {
  if (bytes.length > VERDICT_ARTIFACT_MAX_BYTES) {
    throw new VerdictError("the result record exceeds 1 MiB");
  }
  const parsed = verdictExecutionRecordSchema.safeParse(
    parseStrictJson(Buffer.from(bytes).toString("utf8"), "result record"),
  );
  if (!parsed.success) {
    throw new VerdictError("the result record does not match its schema");
  }
  return parsed.data;
}

export interface WrittenRecord {
  path: string;
  /** SHA-256 of the file's bytes, for the job output. */
  sha256: string;
  bytes: number;
}

/**
 * Writes `result.json` into `dir`, a directory only the host can write:
 * never one a container mounts. Refuses to replace an existing file.
 */
export async function writeExecutionRecord(
  dir: string,
  record: VerdictExecutionRecord,
): Promise<WrittenRecord> {
  const bytes = encodeExecutionRecord(record);
  const path = join(dir, VERDICT_RESULT_FILE);
  await writeFile(path, bytes, { flag: "wx", mode: 0o644 });
  return { path, sha256: sha256Hex(bytes), bytes: bytes.length };
}

export interface ReportInput {
  repository: { github_id: number; full_name: string };
  prNumber: number;
  run: VerdictRun;
  prepare: PrepareResult;
  /**
   * The result artifact of this run and attempt, as the trusted job outputs
   * name it, with the SHA-256 of its ZIP. A record bound to another run,
   * attempt, issuance or commit is ignored, which reports `missing`.
   */
  result?: { record: VerdictExecutionRecord; artifactDigest: string };
}

function recordMatches(
  record: VerdictExecutionRecord,
  input: ReportInput,
): boolean {
  const { prepare, run } = input;
  return (
    record.run.id === run.id &&
    record.run.attempt === run.attempt &&
    record.issuance_id === prepare.issuance_id &&
    record.head_sha === prepare.head_sha &&
    record.code_sha === prepare.code_sha &&
    record.prepare_digest === prepare.digest &&
    record.result.artifact_digest === undefined &&
    // The route refuses a pass with no runtime; report it as missing instead.
    (record.result.outcome !== "passed" || record.result.runtime !== undefined)
  );
}

/**
 * The report body. Only a passed prepare carries a result, and only a
 * matching record can make it anything but `missing`. The body is parsed
 * with the route's own schema before it is returned.
 */
export function buildVerdictReport(input: ReportInput): VerdictReport {
  const { prepare } = input;
  let result: VerdictReport["result"];
  if (prepare.outcome === "passed") {
    const supplied = input.result;
    result =
      supplied &&
      recordMatches(supplied.record, input) &&
      sha256HexSchema.safeParse(supplied.artifactDigest).success
        ? {
            ...supplied.record.result,
            artifact_digest: supplied.artifactDigest,
          }
        : { outcome: "missing", specs: [] };
  }
  const body: VerdictReport = {
    schema_version: 1,
    repository: input.repository,
    pr_number: input.prNumber,
    head_sha: prepare.head_sha,
    ...(prepare.code_sha !== undefined && { code_sha: prepare.code_sha }),
    ...(prepare.issuance_id !== undefined && {
      issuance_id: prepare.issuance_id,
    }),
    run: { id: input.run.id, attempt: input.run.attempt },
    prepare: {
      outcome: prepare.outcome,
      digest: prepare.digest,
      ...(prepare.envelope_digest !== undefined && {
        envelope_digest: prepare.envelope_digest,
      }),
      reasons: prepare.reasons,
    },
    ...(result && { result }),
  };
  const parsed = verdictReportSchema.parse(body);
  if (Buffer.byteLength(JSON.stringify(parsed)) > VERDICT_REPORT_MAX_BYTES) {
    throw new VerdictError("the report body exceeds 64 KiB");
  }
  return parsed;
}
