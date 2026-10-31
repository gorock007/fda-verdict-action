import { lstat, mkdir, readdir, symlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import {
  branchNameSchema,
  gitShaSchema,
  normalizedRepoPathSchema,
  VERDICT_CONFIG_PATH,
  VERDICT_ENVELOPE_PATH,
  VERDICT_PACK_CAP_BYTES,
  VERDICT_SCHEMA_VERSION,
  type VerdictConfig,
  type VerdictPayload,
  type VerdictPrepareOutcome,
} from "@fda/contracts";
import { specDigest, type SpecObservation } from "@fda/policy";
import {
  fetchVerified,
  git,
  GitFetchError,
  initObjectStore,
  isAncestor,
  listTree,
  mergeBases,
  OBJECT_STORE_CONFIG,
  readCommit,
  readObjects,
  type GitContext,
  type TreeEntry,
} from "@fda/sandbox/git";
import { collectCommittedPatch } from "@fda/sandbox/patch";
import type { GitAuth } from "@fda/sandbox";

import {
  parseVerdictConfig,
  payloadBindingIssues,
  sha256Hex,
  VerdictError,
  verifyEnvelope,
} from "./envelope.js";
import { gateVerdictPatch, VERDICT_GATE_REVISION } from "./gate.js";

// Decision 0027, job `prepare`: reads Git objects only. It fetches into a
// fresh bare store (object checking, pack cap), proves the carrier's shape,
// verifies the envelope with the default branch's keys, checks the
// ancestry, gates `B..P` and exports `P` as files and links for the
// execution job. No install, test, hook, filter or checkout runs here.

export const VERDICT_EXPORT_MAX_FILES = 100_000;
export const VERDICT_EXPORT_MAX_BYTES = 1024 * 1024 * 1024;
const MAX_REASONS = 50;
const MAX_REASON_CHARS = 500;
const READ_BATCH = 256;

export interface PrepareInput {
  /** An empty directory for the bare object store. */
  storeDir: string;
  /** An empty directory `P`'s tree is exported into. */
  exportDir: string;
  remoteUrl: string;
  auth?: GitAuth;
  signal?: AbortSignal;
  repository: { github_id: number; full_name: string };
  pullRequest: {
    number: number;
    /** `pull_request.head.sha`, validated through GitHub's API: `H`. */
    headSha: string;
    /** The head branch name, e.g. `fda/abc123-v1`. */
    headRef: string;
    baseRef: string;
    /** The ref to fetch `H` from, e.g. `refs/pull/7/head`. */
    fetchRef: string;
    sameRepository: boolean;
    appAuthored: boolean;
  };
  defaultBranch: string;
  /** The default-branch commit the trusted workflow runs at (`GITHUB_SHA`). */
  trustedSha: string;
  /** The running reusable-workflow release (`W`). */
  releaseWorkflowSha: string;
  packCapBytes?: number;
  exportLimits?: { maxFiles: number; maxBytes: number };
  now?: Date;
}

export interface ExecutionPlan {
  setup: string[][];
  specs: Array<{ id: string; path: string; argv: string[] }>;
  runner_version: number;
  limits: VerdictPayload["execution"]["limits"];
}

export interface ExportSummary {
  files: number;
  symlinks: number;
  bytes: number;
}

/** Prepare's bounded outcome; its digest goes to the report. */
export interface PrepareRecord {
  schema_version: typeof VERDICT_SCHEMA_VERSION;
  outcome: VerdictPrepareOutcome;
  reasons: string[];
  head_sha: string;
  default_sha?: string;
  base_sha?: string;
  code_sha?: string;
  issuance_id?: string;
  envelope_digest?: string;
  plan?: ExecutionPlan;
  export?: ExportSummary;
}

export interface PrepareResult extends PrepareRecord {
  /** SHA-256 of the record's JSON. */
  digest: string;
}

function finish(record: PrepareRecord): PrepareResult {
  const reasons = record.reasons
    .slice(0, MAX_REASONS)
    .map((reason) =>
      reason.length > MAX_REASON_CHARS
        ? `${reason.slice(0, MAX_REASON_CHARS - 1)}…`
        : reason,
    );
  const bounded = { ...record, reasons };
  return { ...bounded, digest: sha256Hex(JSON.stringify(bounded)) };
}

async function resolveRef(
  ctx: GitContext,
  ref: string,
): Promise<string | undefined> {
  const out = await git(
    ctx,
    ["rev-parse", "--verify", "--quiet", "--end-of-options", `${ref}^{commit}`],
    { config: OBJECT_STORE_CONFIG, check: false },
  );
  return out.code === 0 ? out.stdout.trim() : undefined;
}

async function entryAt(
  ctx: GitContext,
  commit: string,
  path: string,
): Promise<TreeEntry | undefined> {
  const entries = await listTree(ctx, commit, { paths: [path] });
  return entries.find((entry) => entry.path === path);
}

async function readBlob(ctx: GitContext, oid: string, maxBytes: number) {
  const object = (await readObjects(ctx, [oid], { maxBytes })).get(oid);
  if (!object || object.type !== "blob") {
    throw new VerdictError(`object ${oid} is not a readable blob`);
  }
  return object.bytes;
}

const REGULAR_MODES = new Set(["100644", "100755"]);

/**
 * What sits at each spec path at `P`: a spec file and every directory on
 * its path must be a regular blob or tree; a link anywhere on the path makes
 * it `not_regular`, never followed.
 */
export async function observeSpecs(
  ctx: GitContext,
  tree: ReadonlyMap<string, TreeEntry>,
  paths: readonly string[],
): Promise<Map<string, SpecObservation>> {
  const observed = new Map<string, SpecObservation>();
  const toRead = new Map<string, string>();
  for (const path of paths) {
    const segments = path.split("/");
    let parentProblem: SpecObservation | undefined;
    for (let depth = 1; depth < segments.length; depth++) {
      const dir = tree.get(segments.slice(0, depth).join("/"));
      if (!dir) {
        parentProblem = { kind: "missing" };
        break;
      }
      if (dir.type !== "tree") {
        parentProblem = { kind: "not_regular" };
        break;
      }
    }
    const leaf = tree.get(path);
    if (parentProblem) observed.set(path, parentProblem);
    else if (!leaf) observed.set(path, { kind: "missing" });
    else if (leaf.type !== "blob" || !REGULAR_MODES.has(leaf.mode)) {
      observed.set(path, { kind: "not_regular" });
    } else toRead.set(path, leaf.oid);
  }
  if (toRead.size > 0) {
    const blobs = await readObjects(ctx, [...new Set(toRead.values())], {
      maxBytes: 64 * 1024 * 1024,
    });
    for (const [path, oid] of toRead) {
      const blob = blobs.get(oid);
      observed.set(
        path,
        blob
          ? { kind: "file", sha256: specDigest(blob.bytes) }
          : { kind: "missing" },
      );
    }
  }
  return observed;
}

function exportPathIssue(path: string): string | undefined {
  if (!normalizedRepoPathSchema.safeParse(path).success || path.includes("�")) {
    return `${path}: unsupported path in the source tree`;
  }
  if (path.split("/").some((segment) => segment.toLowerCase() === ".git")) {
    return `${path}: a .git entry in the source tree`;
  }
  return undefined;
}

async function assertPlainDir(dir: string): Promise<void> {
  const stat = await lstat(dir);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new VerdictError("export parent is not a plain directory");
  }
}

/**
 * Writes `commit`'s tree into the empty `outDir` from Git objects: files
 * with their bytes and exec bit, links as links (their target is never
 * read or followed), no gitlinks. Every write is exclusive and checks its
 * parent is a directory this export made, so a duplicate or case-folded
 * entry fails instead of landing through a link.
 */
export async function exportTree(
  ctx: GitContext,
  commit: string,
  outDir: string,
  limits = {
    maxFiles: VERDICT_EXPORT_MAX_FILES,
    maxBytes: VERDICT_EXPORT_MAX_BYTES,
  },
): Promise<ExportSummary> {
  if ((await readdir(outDir)).length > 0) {
    throw new VerdictError("export directory is not empty");
  }
  const entries = await listTree(ctx, commit);
  const blobs: TreeEntry[] = [];
  for (const entry of entries) {
    const issue = exportPathIssue(entry.path);
    if (issue) throw new VerdictError(issue);
    if (entry.type === "commit" || entry.mode === "160000") {
      throw new VerdictError(`${entry.path}: gitlinks are not supported`);
    }
    if (entry.type === "tree") continue;
    if (!REGULAR_MODES.has(entry.mode) && entry.mode !== "120000") {
      throw new VerdictError(`${entry.path}: unsupported mode ${entry.mode}`);
    }
    blobs.push(entry);
  }
  if (blobs.length > limits.maxFiles) {
    throw new VerdictError(
      `source tree has more than ${limits.maxFiles} files`,
    );
  }
  const summary: ExportSummary = { files: 0, symlinks: 0, bytes: 0 };
  for (const entry of entries) {
    if (entry.type !== "tree") continue;
    const target = join(outDir, ...entry.path.split("/"));
    await assertPlainDir(dirname(target));
    await mkdir(target);
  }
  for (let start = 0; start < blobs.length; start += READ_BATCH) {
    const batch = blobs.slice(start, start + READ_BATCH);
    const objects = await readObjects(
      ctx,
      [...new Set(batch.map((entry) => entry.oid))],
      { maxBytes: limits.maxBytes - summary.bytes },
    );
    for (const entry of batch) {
      const object = objects.get(entry.oid);
      if (!object || object.type !== "blob") {
        throw new VerdictError(`${entry.path}: blob is missing`);
      }
      summary.bytes += object.bytes.length;
      if (summary.bytes > limits.maxBytes) {
        throw new VerdictError(`source tree exceeds ${limits.maxBytes} bytes`);
      }
      const target = join(outDir, ...entry.path.split("/"));
      await assertPlainDir(dirname(target));
      if (entry.mode === "120000") {
        await symlink(object.bytes.toString("utf8"), target);
        summary.symlinks++;
      } else {
        await writeFile(target, object.bytes, {
          flag: "wx",
          mode: entry.mode === "100755" ? 0o755 : 0o644,
        });
        summary.files++;
      }
    }
  }
  return summary;
}

const FETCH_REF = /^refs\/[A-Za-z0-9._/-]+$/;

/**
 * The prepare job: everything that decides the gate and signature outcome,
 * from Git objects and the trusted default-branch config. Never throws for
 * a bad repository: the outcome and reasons say what failed.
 */
export async function prepare(input: PrepareInput): Promise<PrepareResult> {
  const H = input.pullRequest.headSha;
  const base = { schema_version: VERDICT_SCHEMA_VERSION, head_sha: H } as const;
  const failed = (reasons: string[], extra: Partial<PrepareRecord> = {}) =>
    finish({ ...base, ...extra, outcome: "failed", reasons });

  if (
    !gitShaSchema.safeParse(H).success ||
    !gitShaSchema.safeParse(input.trustedSha).success ||
    !gitShaSchema.safeParse(input.releaseWorkflowSha).success ||
    !branchNameSchema.safeParse(input.defaultBranch).success ||
    !FETCH_REF.test(input.pullRequest.fetchRef)
  ) {
    return failed(["the event's commits or refs are malformed"]);
  }

  let ctx: GitContext;
  try {
    ctx = await initObjectStore(join(input.storeDir, "objects.git"));
    await fetchVerified(
      ctx,
      input.remoteUrl,
      [
        `+refs/heads/${input.defaultBranch}:refs/fda-verdict/default`,
        `+${input.pullRequest.fetchRef}:refs/fda-verdict/head`,
      ],
      {
        auth: input.auth,
        signal: input.signal,
        packCapBytes: input.packCapBytes ?? VERDICT_PACK_CAP_BYTES,
      },
    );
  } catch (error) {
    return failed([
      error instanceof GitFetchError
        ? error.message
        : "could not fetch the repository",
    ]);
  }

  const fetchedHead = await resolveRef(ctx, "refs/fda-verdict/head");
  const D = await resolveRef(ctx, "refs/fda-verdict/default");
  if (fetchedHead !== H) {
    return failed(["the fetched PR head is not the head GitHub reported"]);
  }
  if (!D || !(await readCommit(ctx, input.trustedSha))) {
    return failed(["the default branch or the workflow's commit is missing"]);
  }
  const atDefault = { default_sha: D };

  const carrierEntry = await entryAt(ctx, H, VERDICT_ENVELOPE_PATH);
  const candidate =
    input.pullRequest.headRef.startsWith("fda/") ||
    input.pullRequest.appAuthored ||
    carrierEntry !== undefined;
  if (!candidate) {
    return finish({
      ...base,
      ...atDefault,
      outcome: "not_applicable",
      reasons: [],
    });
  }
  if (!input.pullRequest.sameRepository) {
    return finish({
      ...base,
      ...atDefault,
      outcome: "unsupported",
      reasons: ["a PR from a fork can't carry a Namlo change"],
    });
  }
  if (input.pullRequest.baseRef !== input.defaultBranch) {
    return finish({
      ...base,
      ...atDefault,
      outcome: "unsupported",
      reasons: ["the PR does not target the default branch"],
    });
  }

  let config: VerdictConfig;
  try {
    const entry = await entryAt(ctx, input.trustedSha, VERDICT_CONFIG_PATH);
    if (!entry || entry.type !== "blob" || entry.mode !== "100644") {
      throw new VerdictError(
        "verification config is missing on the default branch",
      );
    }
    config = parseVerdictConfig(await readBlob(ctx, entry.oid, 64 * 1024));
  } catch (error) {
    return failed(
      [reasonOf(error, "verification config is unreadable")],
      atDefault,
    );
  }

  if (!carrierEntry) {
    return failed(["the Namlo change has no verdict envelope"], atDefault);
  }
  if (carrierEntry.type !== "blob" || carrierEntry.mode !== "100644") {
    return failed(
      [`${VERDICT_ENVELOPE_PATH} is not a regular non-executable file`],
      atDefault,
    );
  }
  let payload: VerdictPayload;
  let envelopeDigest: string;
  try {
    const verified = verifyEnvelope(
      await readBlob(ctx, carrierEntry.oid, 512 * 1024),
      config,
    );
    payload = verified.payload;
    envelopeDigest = verified.digest;
  } catch (error) {
    return failed([reasonOf(error, "envelope is unreadable")], atDefault);
  }
  const signed = {
    ...atDefault,
    base_sha: payload.base_sha,
    code_sha: payload.code_sha,
    issuance_id: payload.issuance_id,
    envelope_digest: envelopeDigest,
  };
  const binding = payloadBindingIssues(payload, {
    config,
    repository: input.repository,
    headBranch: input.pullRequest.headRef,
    baseBranch: input.pullRequest.baseRef,
    defaultBranch: input.defaultBranch,
    releaseWorkflowSha: input.releaseWorkflowSha,
    gateRevision: VERDICT_GATE_REVISION,
    now: input.now ?? new Date(),
  });
  if (binding.length > 0) return failed(binding, signed);

  const B = payload.base_sha;
  const P = payload.code_sha;
  const reasons: string[] = [];
  try {
    // The carrier: H's only parent is P, P's tree is the signed tree, and
    // P..H changes exactly the envelope file.
    const head = await readCommit(ctx, H);
    const code = await readCommit(ctx, P);
    if (!head || head.parents.length !== 1 || head.parents[0] !== P) {
      return failed(
        [
          "the PR head is not exactly one carrier commit on the signed code commit",
        ],
        signed,
      );
    }
    if (!code || code.tree !== payload.code_tree) {
      return failed(["the code commit's tree is not the signed tree"], signed);
    }
    const carrier = await collectCommittedPatch(ctx, P, H);
    const [only, ...others] = carrier.manifest.files;
    if (
      others.length > 0 ||
      !only ||
      only.path !== VERDICT_ENVELOPE_PATH ||
      only.from !== undefined ||
      (only.status !== "added" && only.status !== "modified") ||
      only.mode !== "100644"
    ) {
      return failed(
        [
          `the carrier commit may change only ${VERDICT_ENVELOPE_PATH}; it changes ${carrier.manifest.files.map((file) => file.path).join(", ")}`,
        ],
        signed,
      );
    }

    // Ancestry: B under both P and the current default branch, and the
    // only merge base of the two.
    if (!(await readCommit(ctx, B))) {
      return failed(["the signed base commit is missing from history"], signed);
    }
    if (!(await isAncestor(ctx, B, P))) {
      reasons.push("the signed base is not an ancestor of the code commit");
    }
    if (!(await isAncestor(ctx, B, D))) {
      reasons.push("the signed base is not on the default branch");
    }
    const bases = await mergeBases(ctx, D, P);
    if (bases.length !== 1 || bases[0] !== B) {
      reasons.push(
        "the code commit's merge base with the default branch is not the signed base",
      );
    }

    // The gate over the complete B..P diff, with the specs as they are at P.
    const patch = await collectCommittedPatch(ctx, B, P);
    // The whole listing, so a link on a spec's parent path shows up.
    const tree = new Map(
      (await listTree(ctx, P)).map((entry) => [entry.path, entry]),
    );
    const observed = await observeSpecs(
      ctx,
      tree,
      payload.specs.map((spec) => spec.path),
    );
    const gate = gateVerdictPatch(patch.manifest, payload, observed);
    if (!gate.allowed) reasons.push(...gate.reasons);
  } catch (error) {
    reasons.push(reasonOf(error, "could not read the signed commits"));
  }
  if (reasons.length > 0) return failed(reasons, signed);

  let exported: ExportSummary;
  try {
    exported = await exportTree(ctx, P, input.exportDir, input.exportLimits);
  } catch (error) {
    return failed([reasonOf(error, "could not export the source")], signed);
  }
  return finish({
    ...base,
    ...signed,
    outcome: "passed",
    reasons: [],
    plan: {
      setup: payload.execution.setup,
      specs: payload.specs.map(({ id, path, argv }) => ({ id, path, argv })),
      runner_version: payload.execution.runner_version,
      limits: payload.execution.limits,
    },
    export: exported,
  });
}

function reasonOf(error: unknown, fallback: string): string {
  if (error instanceof VerdictError) return error.message;
  if (error instanceof Error && error.name === "SandboxError") {
    return `${fallback}: ${error.message}`;
  }
  return fallback;
}
