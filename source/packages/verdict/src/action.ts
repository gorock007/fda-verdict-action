import { createHash, randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  readlink,
  symlink,
  appendFile,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { isAbsolute, join, posix } from "node:path";

import {
  branchNameSchema,
  gitShaSchema,
  repositoryFullNameSchema,
  sha256HexSchema,
  VERDICT_PREPARE_OUTCOMES,
  VERDICT_REPORT_AUDIENCE,
  VERDICT_WORKFLOW_PATH,
  type VerdictReport,
} from "@fda/contracts";

import { parseStrictJson, sha256Hex, VerdictError } from "./envelope.js";
import {
  EgressFirewall,
  execute,
  hostIptables,
  neutralizeWorkflowCommands,
  runCommand,
  type CommandRunner,
  type ExecuteOptions,
  type ExecuteResult,
} from "./execute.js";
import {
  prepare,
  VERDICT_EXPORT_MAX_BYTES,
  VERDICT_EXPORT_MAX_FILES,
  type PrepareInput,
  type PrepareResult,
} from "./prepare.js";
import {
  buildVerdictReport,
  parseExecutionRecord,
  VERDICT_ARTIFACT_MAX_BYTES,
  VERDICT_PREPARE_FILE,
  VERDICT_RESULT_FILE,
  verdictArtifactName,
  writeExecutionRecord,
  type ReportInput,
  type VerdictRun,
} from "./report.js";

// Decision 0027, the bundled Action the reusable workflow runs in each of
// its three jobs (`mode: prepare | execute | report`). It derives every
// fact from the runner's environment, GitHub's API and this run's own
// artifacts, which it selects by run and attempt and checks against the
// digests the trusted jobs output. Only `report` asks for an OIDC token.

/** The fixed Namlo endpoint; the release pins it, nothing configures it. */
export const VERDICT_REPORT_URL = "https://app.namlo.si/api/v1/verdict/reports";
export const VERDICT_ACTION_REPOSITORY = "gorock007/fda-verdict-action";
export const VERDICT_REUSABLE_WORKFLOW = `${VERDICT_ACTION_REPOSITORY}/.github/workflows/verdict.yml`;
/** The signed `execution.runner_version` this release runs (pipeline signs 1). */
export const VERDICT_SUPPORTED_RUNNER_VERSION = 1;
export const VERDICT_SOURCE_FILE = "source.tar";
/** Under `RUNNER_TEMP`: what a job uploads, and where the workflow downloads to. */
export const VERDICT_OUT_DIR = "fda-verdict/out";
export const VERDICT_IN_DIR = "fda-verdict/in";

const MAX_EVENT_BYTES = 8 * 1024 * 1024;
const MAX_WORKFLOW_BYTES = 64 * 1024;
const MAX_GVISOR_BYTES = 512 * 1024 * 1024;
const REPORT_ATTEMPTS = 3;
const FETCH_TIMEOUT_MS = 30_000;
const GVISOR_DIR = "/opt/fda-gvisor";
const APP_SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const OUTPUT_VALUE = /^[A-Za-z0-9._:@/+-]{0,200}$/;

/** Prepare's source export travels as its own artifact of this run and attempt. */
export function verdictSourceArtifactName(run: VerdictRun): string {
  return verdictArtifactName("prepare", run).replace(
    "fda-verdict-prepare-",
    "fda-verdict-source-",
  );
}

export type ActionEnv = Readonly<Record<string, string | undefined>>;

export interface ActionDeps {
  env: ActionEnv;
  fetch: typeof fetch;
  /** One line of job log. */
  log: (line: string) => void;
  runner?: CommandRunner;
  sleep?: (ms: number) => Promise<void>;
  prepare?: (input: PrepareInput) => Promise<PrepareResult>;
  execute?: (options: ExecuteOptions) => Promise<ExecuteResult>;
}

// ---------------------------------------------------------------- runner I/O

/** A `with:` input, as the runner passes it (`INPUT_<NAME>`). */
export function actionInput(env: ActionEnv, name: string): string {
  return (env[`INPUT_${name.toUpperCase()}`] ?? "").trim();
}

/** Appends one job-step output; values are plain tokens, never free text. */
export async function setOutput(
  env: ActionEnv,
  name: string,
  value: string,
): Promise<void> {
  const file = env.GITHUB_OUTPUT;
  if (!file || !isAbsolute(file)) {
    throw new VerdictError("GITHUB_OUTPUT is not set");
  }
  if (!/^[a-z][a-z0-9-]*$/.test(name) || !OUTPUT_VALUE.test(value)) {
    throw new VerdictError(`refusing to write output ${name}`);
  }
  await appendFile(file, `${name}=${value}\n`);
}

/** Escapes a message for an `::error::` line (the runner's own encoding). */
export function commandData(text: string): string {
  return text.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

interface JobContext {
  run: VerdictRun;
  repository: { github_id: number; full_name: string };
  temp: string;
}

function positiveInt(value: string | undefined, what: string): number {
  if (!value || !/^[1-9][0-9]{0,15}$/.test(value)) {
    throw new VerdictError(`${what} is missing or malformed`);
  }
  return Number(value);
}

export function jobContext(env: ActionEnv): JobContext {
  const fullName = env.GITHUB_REPOSITORY ?? "";
  if (!repositoryFullNameSchema.safeParse(fullName).success) {
    throw new VerdictError("GITHUB_REPOSITORY is missing or malformed");
  }
  const temp = env.RUNNER_TEMP ?? "";
  if (!isAbsolute(temp)) throw new VerdictError("RUNNER_TEMP is not set");
  return {
    run: {
      id: positiveInt(env.GITHUB_RUN_ID, "GITHUB_RUN_ID"),
      attempt: positiveInt(env.GITHUB_RUN_ATTEMPT, "GITHUB_RUN_ATTEMPT"),
    },
    repository: {
      github_id: positiveInt(env.GITHUB_REPOSITORY_ID, "GITHUB_REPOSITORY_ID"),
      full_name: fullName,
    },
    temp,
  };
}

export interface PullRequestEvent {
  number: number;
  headSha: string;
  baseRepositoryId: number;
}

function record(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new VerdictError(`${what} is not an object`);
  }
  return value as Record<string, unknown>;
}

/** The `pull_request_target` event this run was started by. */
export async function readPullRequestEvent(
  env: ActionEnv,
): Promise<PullRequestEvent> {
  if (env.GITHUB_EVENT_NAME !== "pull_request_target") {
    throw new VerdictError("the verdict runs only on pull_request_target");
  }
  const path = env.GITHUB_EVENT_PATH ?? "";
  if (!isAbsolute(path)) throw new VerdictError("GITHUB_EVENT_PATH is not set");
  const bytes = await readFile(path);
  if (bytes.length > MAX_EVENT_BYTES) {
    throw new VerdictError("the event payload is too large");
  }
  const event = record(JSON.parse(bytes.toString("utf8")), "the event");
  const pr = record(event.pull_request, "pull_request");
  const head = record(pr.head, "pull_request.head");
  const base = record(pr.base, "pull_request.base");
  const baseRepo = record(base.repo, "pull_request.base.repo");
  if (
    typeof pr.number !== "number" ||
    !Number.isSafeInteger(pr.number) ||
    pr.number < 1 ||
    typeof head.sha !== "string" ||
    !gitShaSchema.safeParse(head.sha).success ||
    typeof baseRepo.id !== "number"
  ) {
    throw new VerdictError("the pull_request event is malformed");
  }
  return {
    number: pr.number,
    headSha: head.sha,
    baseRepositoryId: baseRepo.id,
  };
}

function withTimeout(init: RequestInit = {}): RequestInit {
  return {
    redirect: "error",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    ...init,
  };
}

async function githubGet(
  deps: ActionDeps,
  token: string,
  path: string,
  accept = "application/vnd.github+json",
): Promise<Response> {
  const api = new URL(deps.env.GITHUB_API_URL ?? "https://api.github.com");
  if (api.protocol !== "https:")
    throw new VerdictError("GITHUB_API_URL must be https");
  const url = new URL(`${api.pathname.replace(/\/$/, "")}${path}`, api);
  const response = await deps.fetch(
    url,
    withTimeout({
      headers: {
        accept,
        authorization: `Bearer ${token}`,
        "user-agent": "fda-verdict-action",
        "x-github-api-version": "2022-11-28",
      },
    }),
  );
  if (!response.ok) {
    throw new VerdictError(
      `GitHub answered ${response.status} for ${url.pathname}`,
    );
  }
  return response;
}

/**
 * The release `W` the trusted caller workflow pins: exactly one `uses:` of
 * the reusable workflow at a full commit SHA. `GITHUB_SHA` is the
 * default-branch commit GitHub ran that file from.
 */
export function callerReleaseSha(workflowText: string): string {
  const refs: string[] = [];
  for (const line of workflowText.split("\n")) {
    const match = /^\s*(?:-\s+)?uses:\s*["']?([^\s"'#]+)["']?\s*(?:#.*)?$/.exec(
      line,
    );
    if (match?.[1]?.startsWith(`${VERDICT_REUSABLE_WORKFLOW}@`)) {
      refs.push(match[1].slice(VERDICT_REUSABLE_WORKFLOW.length + 1));
    }
  }
  if (refs.length !== 1 || !gitShaSchema.safeParse(refs[0]).success) {
    throw new VerdictError(
      "the default branch's verdict workflow must call the release at exactly one full commit SHA",
    );
  }
  return refs[0]!;
}

// ---------------------------------------------------------------- source archive

// A deterministic tar of prepare's export: sorted entries, mode 0644/0755
// files, 0755 directories, links kept as links, zero owners and mtimes, and
// PAX records for long or non-ASCII names. The reader accepts only that
// shape: no `..`, absolute or duplicate path, nothing under a link, nothing
// but files, directories and links, and the export's count and byte caps.

const BLOCK = 512;
const CHUNK = 1024 * 1024;

type TarType = "file" | "dir" | "symlink";
interface TarEntry {
  path: string;
  type: TarType;
  mode: number;
  size: number;
  link?: string;
}

function asciiField(
  buffer: Buffer,
  offset: number,
  width: number,
  text: string,
) {
  buffer.write(text, offset, width, "ascii");
}

function octalField(
  buffer: Buffer,
  offset: number,
  width: number,
  value: number,
) {
  asciiField(
    buffer,
    offset,
    width,
    `${value.toString(8).padStart(width - 1, "0")}\0`,
  );
}

function paxRecord(key: string, value: string): string {
  const body = ` ${key}=${value}\n`;
  let length = Buffer.byteLength(body);
  while (String(length).length + Buffer.byteLength(body) !== length) {
    length = String(length).length + Buffer.byteLength(body);
  }
  return `${length}${body}`;
}

const PLAIN_NAME = /^[\x20-\x7e]{1,99}$/;

function tarHeader(
  name: string,
  flag: string,
  mode: number,
  size: number,
  link = "",
): Buffer {
  const header = Buffer.alloc(BLOCK);
  asciiField(header, 0, 100, name);
  octalField(header, 100, 8, mode);
  octalField(header, 108, 8, 0);
  octalField(header, 116, 8, 0);
  octalField(header, 124, 12, size);
  octalField(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  asciiField(header, 156, 1, flag);
  asciiField(header, 157, 100, link);
  asciiField(header, 257, 8, "ustar\u000000");
  let sum = 0;
  for (const byte of header) sum += byte;
  asciiField(header, 148, 8, `${sum.toString(8).padStart(6, "0")}\0 `);
  return header;
}

function entryHeaders(entry: TarEntry): Buffer[] {
  const flag = { file: "0", dir: "5", symlink: "2" }[entry.type];
  const name = entry.type === "dir" ? `${entry.path}/` : entry.path;
  const link = entry.link ?? "";
  let pax = "";
  if (!PLAIN_NAME.test(name)) pax += paxRecord("path", name);
  if (link !== "" && !PLAIN_NAME.test(link)) pax += paxRecord("linkpath", link);
  const headers: Buffer[] = [];
  if (pax !== "") {
    const data = Buffer.from(pax);
    headers.push(tarHeader("PaxHeader", "x", 0o644, data.length));
    headers.push(Buffer.concat([data, padding(data.length)]));
  }
  headers.push(
    tarHeader(
      PLAIN_NAME.test(name) ? name : "entry",
      flag,
      entry.mode,
      entry.size,
      PLAIN_NAME.test(link) ? link : "",
    ),
  );
  return headers;
}

function padding(size: number): Buffer {
  return Buffer.alloc((BLOCK - (size % BLOCK)) % BLOCK);
}

async function treeEntries(root: string): Promise<TarEntry[]> {
  const entries: TarEntry[] = [];
  const walk = async (rel: string) => {
    const names = (await readdir(join(root, rel))).sort();
    for (const name of names) {
      const path = rel === "" ? name : `${rel}/${name}`;
      const info = await lstat(join(root, path));
      if (info.isDirectory()) {
        entries.push({ path, type: "dir", mode: 0o755, size: 0 });
        await walk(path);
      } else if (info.isSymbolicLink()) {
        const link = await readlink(join(root, path));
        entries.push({ path, type: "symlink", mode: 0o777, size: 0, link });
      } else if (info.isFile()) {
        const mode = info.mode & 0o111 ? 0o755 : 0o644;
        entries.push({ path, type: "file", mode, size: info.size });
      } else {
        throw new VerdictError(`${path}: not a file, directory or link`);
      }
    }
  };
  await walk("");
  return entries;
}

/** Writes `dir` as a deterministic tar at `file`; returns its SHA-256. */
export async function packTree(
  dir: string,
  file: string,
): Promise<{ sha256: string; entries: number; bytes: number }> {
  const entries = await treeEntries(dir);
  const hash = createHash("sha256");
  const out = await open(file, "wx", 0o644);
  let bytes = 0;
  const write = async (chunk: Buffer) => {
    hash.update(chunk);
    bytes += chunk.length;
    await out.write(chunk);
  };
  try {
    for (const entry of entries) {
      for (const header of entryHeaders(entry)) await write(header);
      if (entry.type !== "file") continue;
      const data = await readFile(join(dir, entry.path));
      if (data.length !== entry.size) {
        throw new VerdictError(`${entry.path} changed while it was archived`);
      }
      await write(data);
      await write(padding(data.length));
    }
    await write(Buffer.alloc(BLOCK * 2));
  } finally {
    await out.close();
  }
  return { sha256: hash.digest("hex"), entries: entries.length, bytes };
}

async function readExactly(
  handle: FileHandle,
  length: number,
): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      length - offset,
      null,
    );
    if (bytesRead === 0)
      throw new VerdictError("the source archive is truncated");
    offset += bytesRead;
  }
  return buffer;
}

function headerString(header: Buffer, offset: number, width: number): string {
  const field = header.subarray(offset, offset + width);
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? width : end).toString("utf8");
}

function headerNumber(header: Buffer, offset: number, width: number): number {
  const text = headerString(header, offset, width).trim();
  if (!/^[0-7]{1,12}$/.test(text))
    throw new VerdictError("malformed tar number");
  return parseInt(text, 8);
}

function parsePax(data: Buffer): Record<string, string> {
  const records: Record<string, string> = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const length = Number(data.subarray(offset, space).toString("ascii"));
    if (space === -1 || !Number.isSafeInteger(length) || length <= 0) {
      throw new VerdictError("malformed PAX record");
    }
    const text = data.subarray(space + 1, offset + length).toString("utf8");
    const eq = text.indexOf("=");
    if (eq === -1 || !text.endsWith("\n"))
      throw new VerdictError("malformed PAX record");
    const key = text.slice(0, eq);
    if (key !== "path" && key !== "linkpath") {
      throw new VerdictError(`unexpected PAX record ${JSON.stringify(key)}`);
    }
    records[key] = text.slice(eq + 1, -1);
    offset += length;
  }
  return records;
}

function archivePathIssue(path: string): string | undefined {
  if (
    path === "" ||
    path.length > 4096 ||
    path.startsWith("/") ||
    path.includes("\0") ||
    path.includes("\\") ||
    path.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    return `unsafe archive path ${JSON.stringify(path.slice(0, 200))}`;
  }
  return undefined;
}

/**
 * Extracts a `packTree` archive into the empty `dir`. Every entry's parent
 * must be a directory this archive created, so nothing lands through a link.
 */
export async function unpackTree(
  file: string,
  dir: string,
  limits = {
    maxFiles: VERDICT_EXPORT_MAX_FILES,
    maxBytes: VERDICT_EXPORT_MAX_BYTES,
  },
): Promise<{ files: number; symlinks: number; bytes: number }> {
  if ((await readdir(dir)).length > 0) {
    throw new VerdictError("the export directory is not empty");
  }
  const handle = await open(file, "r");
  const dirs = new Set<string>();
  const seen = new Set<string>();
  const summary = { files: 0, symlinks: 0, bytes: 0 };
  try {
    let pax: Record<string, string> | undefined;
    for (;;) {
      const header = await readExactly(handle, BLOCK);
      if (header.every((byte) => byte === 0)) {
        const second = await readExactly(handle, BLOCK);
        if (!second.every((byte) => byte === 0) || pax) {
          throw new VerdictError("malformed end of the source archive");
        }
        break;
      }
      const stored = headerNumber(header, 148, 8);
      header.fill(0x20, 148, 156);
      let sum = 0;
      for (const byte of header) sum += byte;
      if (sum !== stored || headerString(header, 257, 6) !== "ustar") {
        throw new VerdictError("a source archive header is corrupt");
      }
      const flag = headerString(header, 156, 1);
      const size = headerNumber(header, 124, 12);
      const mode = headerNumber(header, 100, 8);
      if (flag === "x") {
        if (pax || size > 64 * 1024)
          throw new VerdictError("malformed PAX header");
        pax = parsePax(await readExactly(handle, size));
        await readExactly(handle, padding(size).length);
        continue;
      }
      let path = pax?.path ?? headerString(header, 0, 100);
      const link = pax?.linkpath ?? headerString(header, 157, 100);
      pax = undefined;
      if (flag === "5" && path.endsWith("/")) path = path.slice(0, -1);
      const issue = archivePathIssue(path);
      if (issue) throw new VerdictError(issue);
      if (seen.has(path)) throw new VerdictError(`${path} appears twice`);
      seen.add(path);
      const parent = posix.dirname(path);
      if (parent !== "." && !dirs.has(parent)) {
        throw new VerdictError(
          `${path} is not inside a directory of the archive`,
        );
      }
      const target = join(dir, ...path.split("/"));
      if (flag === "5") {
        if (size !== 0)
          throw new VerdictError(`${path}: a directory with data`);
        await mkdir(target, { mode: 0o755 });
        dirs.add(path);
      } else if (flag === "2") {
        if (size !== 0 || link === "" || link.includes("\0")) {
          throw new VerdictError(`${path}: malformed link`);
        }
        await symlink(link, target);
        summary.symlinks++;
      } else if (flag === "0") {
        if (mode !== 0o644 && mode !== 0o755) {
          throw new VerdictError(
            `${path}: unexpected mode ${mode.toString(8)}`,
          );
        }
        summary.files++;
        summary.bytes += size;
        if (summary.files + summary.symlinks > limits.maxFiles) {
          throw new VerdictError(
            `the source has more than ${limits.maxFiles} files`,
          );
        }
        if (summary.bytes > limits.maxBytes) {
          throw new VerdictError(`the source exceeds ${limits.maxBytes} bytes`);
        }
        const out = await open(target, "wx", mode);
        try {
          for (let left = size; left > 0; left -= CHUNK) {
            await out.write(await readExactly(handle, Math.min(left, CHUNK)));
          }
        } finally {
          await out.close();
        }
        await chmod(target, mode);
        await readExactly(handle, padding(size).length);
      } else {
        throw new VerdictError(
          `${path}: unsupported archive entry type ${JSON.stringify(flag)}`,
        );
      }
    }
  } finally {
    await handle.close();
  }
  return summary;
}

async function fileSha256(file: string): Promise<string> {
  const hash = createHash("sha256");
  const handle = await open(file, "r");
  try {
    const buffer = Buffer.alloc(CHUNK);
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, CHUNK, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    await handle.close();
  }
  return hash.digest("hex");
}

// ---------------------------------------------------------------- artifacts

/**
 * The one file of this run and attempt's artifact, which the workflow
 * downloads into `<root>/<name>/`. Nothing else under `root` is looked at,
 * so another name or an older attempt is ignored; the artifact's own
 * directory must hold exactly that regular file. Absent artifact: undefined.
 */
export async function selectArtifactFile(
  root: string,
  name: string,
  file: string,
  maxBytes: number,
): Promise<string | undefined> {
  const dir = join(root, name);
  let info;
  try {
    info = await lstat(dir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (!info.isDirectory())
    throw new VerdictError(`artifact ${name} is not a directory`);
  const names = await readdir(dir);
  if (names.length !== 1 || names[0] !== file) {
    throw new VerdictError(`artifact ${name} must hold exactly ${file}`);
  }
  const path = join(dir, file);
  const fileInfo = await lstat(path);
  if (!fileInfo.isFile())
    throw new VerdictError(`${name}/${file} is not a regular file`);
  if (fileInfo.size > maxBytes)
    throw new VerdictError(`${name}/${file} is too large`);
  return path;
}

const PREPARE_OUTCOMES: readonly string[] = VERDICT_PREPARE_OUTCOMES;

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}

function planShapeIssue(plan: unknown): boolean {
  if (typeof plan !== "object" || plan === null) return true;
  const p = plan as Record<string, unknown>;
  const limits = p.limits as Record<string, unknown> | undefined;
  return !(
    Array.isArray(p.setup) &&
    p.setup.every(isStringArray) &&
    Array.isArray(p.specs) &&
    p.specs.every(
      (spec: Record<string, unknown>) =>
        typeof spec?.id === "string" &&
        typeof spec.path === "string" &&
        isStringArray(spec.argv),
    ) &&
    typeof p.runner_version === "number" &&
    typeof limits?.total_seconds === "number" &&
    typeof limits.command_seconds === "number"
  );
}

/**
 * This run's `prepare.json`, accepted only when its recomputed digest is
 * the one the prepare job output: that job ran no customer code.
 */
export async function readPrepareArtifact(
  root: string,
  run: VerdictRun,
  digest: string,
): Promise<PrepareResult> {
  if (!sha256HexSchema.safeParse(digest).success) {
    throw new VerdictError("the prepare job output no digest");
  }
  const name = verdictArtifactName("prepare", run);
  const path = await selectArtifactFile(
    root,
    name,
    VERDICT_PREPARE_FILE,
    VERDICT_ARTIFACT_MAX_BYTES,
  );
  if (!path) throw new VerdictError(`artifact ${name} is missing`);
  const parsed = record(
    parseStrictJson(
      (await readFile(path)).toString("utf8"),
      "preparation record",
    ),
    "the preparation record",
  );
  const { digest: claimed, ...rest } = parsed;
  if (claimed !== digest || sha256Hex(JSON.stringify(rest)) !== digest) {
    throw new VerdictError(
      "the preparation record does not match the prepare job's digest",
    );
  }
  if (
    rest.schema_version !== 1 ||
    typeof rest.outcome !== "string" ||
    !PREPARE_OUTCOMES.includes(rest.outcome) ||
    !gitShaSchema.safeParse(rest.head_sha).success ||
    !isStringArray(rest.reasons) ||
    (rest.plan !== undefined && planShapeIssue(rest.plan))
  ) {
    throw new VerdictError("the preparation record is malformed");
  }
  return parsed as unknown as PrepareResult;
}

/** This run's result record and its ZIP digest, or undefined (`missing`). */
export async function readResultArtifact(
  deps: Pick<ActionDeps, "log">,
  root: string,
  run: VerdictRun,
  artifactDigest: string,
): Promise<ReportInput["result"]> {
  try {
    if (!sha256HexSchema.safeParse(artifactDigest).success) {
      throw new VerdictError("the execute job output no result digest");
    }
    const name = verdictArtifactName("result", run);
    const path = await selectArtifactFile(
      root,
      name,
      VERDICT_RESULT_FILE,
      VERDICT_ARTIFACT_MAX_BYTES,
    );
    if (!path) throw new VerdictError(`artifact ${name} is missing`);
    return {
      record: parseExecutionRecord(await readFile(path)),
      artifactDigest,
    };
  } catch (error) {
    deps.log(neutralizeWorkflowCommands(`No usable result: ${message(error)}`));
    return undefined;
  }
}

async function freshDir(path: string): Promise<string> {
  await mkdir(join(path, ".."), { recursive: true });
  await mkdir(path);
  return path;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------- prepare

interface ApiRepository {
  id: number;
  full_name: string;
  default_branch: string;
}

interface ApiPullRequest {
  head: { sha: string; ref: string; repo: { id: number } | null };
  base: { ref: string };
  user: { login: string; type: string } | null;
}

/**
 * Job `prepare` (`contents: read`, `pull-requests: read`): resolves the PR
 * through GitHub's API, runs `prepare` over Git objects only, and writes
 * `prepare.json` plus, when it passed, the source archive.
 */
export async function runPrepare(deps: ActionDeps): Promise<boolean> {
  const { env } = deps;
  const job = jobContext(env);
  const event = await readPullRequestEvent(env);
  const token = actionInput(env, "token");
  const appSlug = actionInput(env, "app-slug");
  if (!token) throw new VerdictError("prepare needs the job's read-only token");
  if (!APP_SLUG.test(appSlug))
    throw new VerdictError("the release names no App slug");
  const full = job.repository.full_name;

  const repo = (await (
    await githubGet(deps, token, `/repos/${full}`)
  ).json()) as ApiRepository;
  if (repo.id !== job.repository.github_id || repo.full_name !== full) {
    throw new VerdictError(
      "GitHub's repository is not the one this run belongs to",
    );
  }
  if (event.baseRepositoryId !== repo.id) {
    throw new VerdictError(
      "the event's base repository is not this repository",
    );
  }
  if (!branchNameSchema.safeParse(repo.default_branch).success) {
    throw new VerdictError("the default branch name is malformed");
  }
  if (
    env.GITHUB_WORKFLOW_REF !==
    `${full}/${VERDICT_WORKFLOW_PATH}@refs/heads/${repo.default_branch}`
  ) {
    throw new VerdictError(
      `the verdict must be called from ${VERDICT_WORKFLOW_PATH} on the default branch`,
    );
  }
  const pr = (await (
    await githubGet(deps, token, `/repos/${full}/pulls/${event.number}`)
  ).json()) as ApiPullRequest;
  if (pr.head.sha !== event.headSha) {
    throw new VerdictError(
      "the PR head moved after this event; the run for the new head checks it",
    );
  }
  const trustedSha = env.GITHUB_SHA ?? "";
  if (!gitShaSchema.safeParse(trustedSha).success) {
    throw new VerdictError("GITHUB_SHA is missing or malformed");
  }
  const workflow = await githubGet(
    deps,
    token,
    `/repos/${full}/contents/${VERDICT_WORKFLOW_PATH}?ref=${trustedSha}`,
    "application/vnd.github.raw+json",
  );
  const workflowBytes = Buffer.from(await workflow.arrayBuffer());
  if (workflowBytes.length > MAX_WORKFLOW_BYTES) {
    throw new VerdictError("the verdict workflow file is too large");
  }
  const releaseWorkflowSha = callerReleaseSha(workflowBytes.toString("utf8"));

  const out = join(job.temp, VERDICT_OUT_DIR);
  const prepareDir = await freshDir(join(out, "prepare"));
  const server = env.GITHUB_SERVER_URL ?? "https://github.com";
  if (!server.startsWith("https://"))
    throw new VerdictError("GITHUB_SERVER_URL must be https");
  const storeDir = await mkdtemp(join(job.temp, "fda-verdict-store-"));
  const exportDir = await mkdtemp(join(job.temp, "fda-verdict-export-"));
  const result = await (deps.prepare ?? prepare)({
    storeDir,
    exportDir,
    remoteUrl: `${server}/${full}.git`,
    auth: { token, username: "x-access-token" },
    repository: job.repository,
    pullRequest: {
      number: event.number,
      headSha: event.headSha,
      headRef: pr.head.ref,
      baseRef: pr.base.ref,
      fetchRef: `refs/pull/${event.number}/head`,
      sameRepository: pr.head.repo?.id === repo.id,
      appAuthored:
        pr.user?.type === "Bot" && pr.user.login === `${appSlug}[bot]`,
    },
    defaultBranch: repo.default_branch,
    trustedSha,
    releaseWorkflowSha,
  });
  // 2b's route reads these exact bytes back: `JSON.stringify(result)`.
  await writeFile(
    join(prepareDir, VERDICT_PREPARE_FILE),
    JSON.stringify(result),
    {
      flag: "wx",
      mode: 0o644,
    },
  );
  let sourceDigest = "";
  if (result.outcome === "passed") {
    const sourceDir = await freshDir(join(out, "source"));
    const packed = await packTree(
      exportDir,
      join(sourceDir, VERDICT_SOURCE_FILE),
    );
    sourceDigest = packed.sha256;
    deps.log(
      `Exported ${packed.entries} entries (${packed.bytes} archive bytes) of ${result.code_sha}.`,
    );
  }
  deps.log(
    `Preparation ${result.outcome} for ${event.headSha} (release ${releaseWorkflowSha}).`,
  );
  for (const reason of result.reasons)
    deps.log(neutralizeWorkflowCommands(reason));
  await setOutput(env, "outcome", result.outcome);
  await setOutput(env, "digest", result.digest);
  await setOutput(env, "source-digest", sourceDigest);
  return true;
}

// ---------------------------------------------------------------- execute

export interface GvisorPin {
  url: string;
  sha256: string;
}

/** A dated gVisor release tarball; `latest` would be a moving ref. */
export const VERDICT_GVISOR_URL =
  /^https:\/\/storage\.googleapis\.com\/gvisor\/releases\/release\/[0-9]{8}(?:\.[0-9]+)?\/x86_64\/gvisor\.tar\.bz2$/;

/**
 * Installs the release's pinned gVisor before any customer code runs and
 * registers `runsc` with Docker. Anything short of that leaves `runc`,
 * which the record then names; an unverified download never runs.
 */
export async function installGvisor(
  deps: ActionDeps,
  pin: GvisorPin,
  dir: string,
): Promise<boolean> {
  const run = deps.runner ?? runCommand;
  try {
    if (
      !VERDICT_GVISOR_URL.test(pin.url) ||
      !sha256HexSchema.safeParse(pin.sha256).success
    ) {
      throw new VerdictError("the release's gVisor pin is malformed");
    }
    const response = await deps.fetch(pin.url, {
      redirect: "error",
      signal: AbortSignal.timeout(120_000),
    });
    if (!response.ok)
      throw new VerdictError(`the gVisor download answered ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX_GVISOR_BYTES || sha256Hex(bytes) !== pin.sha256) {
      throw new VerdictError(
        "the gVisor download does not match the release's digest",
      );
    }
    const file = join(dir, "gvisor.tar.bz2");
    await writeFile(file, bytes, { flag: "wx", mode: 0o644 });
    const steps: string[][] = [
      ["mkdir", "-p", GVISOR_DIR],
      ["tar", "-xjf", file, "-C", GVISOR_DIR, "--no-same-owner"],
      [`${GVISOR_DIR}/runsc`, "install"],
      ["systemctl", "restart", "docker"],
    ];
    for (const step of steps) {
      const result = await run("sudo", ["-n", ...step], { timeoutMs: 120_000 });
      if (result.code !== 0) {
        throw new VerdictError(`${step[0]} failed while installing gVisor`);
      }
    }
    // The supervisor's first `docker info` must not race the restart.
    const sleep =
      deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
    for (let attempt = 0; attempt < 30; attempt++) {
      const info = await run(
        "docker",
        ["info", "--format", "{{json .Runtimes}}"],
        {
          timeoutMs: 10_000,
        },
      );
      if (info.code === 0 && info.stdout.includes('"runsc"')) {
        deps.log("gVisor installed; customer code runs under runsc.");
        return true;
      }
      await sleep(1_000);
    }
    throw new VerdictError("Docker did not come back with runsc registered");
  } catch (error) {
    deps.log(
      `::warning::${commandData(`gVisor is unavailable (${message(error)}); customer code runs under runc, and the result says so.`)}`,
    );
    return false;
  }
}

function printExecution(deps: ActionDeps, result: ExecuteResult): void {
  // Output is already neutralized; stopping command processing is a second fence.
  const stop = randomBytes(16).toString("hex");
  deps.log(`::stop-commands::${stop}`);
  for (const step of result.logs) {
    const exit = step.timedOut ? "timed out" : `exit ${step.exitCode}`;
    deps.log(
      neutralizeWorkflowCommands(
        `${step.kind} ${step.label}: ${exit} in ${step.durationMs} ms`,
      ),
    );
    deps.log(step.output);
  }
  for (const reason of result.reasons)
    deps.log(neutralizeWorkflowCommands(reason));
  deps.log(`::${stop}::`);
}

/**
 * Job `execute` (`permissions: {}`): checks this run's preparation and
 * source against the prepare job's digests, then runs the signed plan under
 * the host supervisor and writes the result record outside every container.
 * Returns false (a red job) for anything but a passing result.
 */
export async function runExecute(deps: ActionDeps): Promise<boolean> {
  const { env } = deps;
  const job = jobContext(env);
  const root = join(job.temp, VERDICT_IN_DIR);
  const prepared = await readPrepareArtifact(
    root,
    job.run,
    actionInput(env, "prepare-digest"),
  );
  if (prepared.outcome !== "passed" || !prepared.plan) {
    throw new VerdictError("preparation did not pass, so nothing runs");
  }
  if (prepared.plan.runner_version !== VERDICT_SUPPORTED_RUNNER_VERSION) {
    throw new VerdictError(
      `runner version ${prepared.plan.runner_version} is not supported by this release`,
    );
  }
  const sourceDigest = actionInput(env, "source-digest");
  const name = verdictSourceArtifactName(job.run);
  const archive = await selectArtifactFile(
    root,
    name,
    VERDICT_SOURCE_FILE,
    VERDICT_EXPORT_MAX_BYTES * 2,
  );
  if (!archive) throw new VerdictError(`artifact ${name} is missing`);
  if (
    !sha256HexSchema.safeParse(sourceDigest).success ||
    (await fileSha256(archive)) !== sourceDigest
  ) {
    throw new VerdictError(
      "the source archive does not match the prepare job's digest",
    );
  }
  const exportDir = await mkdtemp(join(job.temp, "fda-verdict-export-"));
  await unpackTree(archive, exportDir);

  const gvisorUrl = actionInput(env, "gvisor-url");
  if (gvisorUrl) {
    const scratch = await mkdtemp(join(job.temp, "fda-verdict-gvisor-"));
    await installGvisor(
      deps,
      { url: gvisorUrl, sha256: actionInput(env, "gvisor-sha256") },
      scratch,
    );
  }
  const result = await (deps.execute ?? execute)({
    prepare: prepared,
    run: job.run,
    exportDir,
    image: actionInput(env, "image"),
    firewall: new EgressFirewall(hostIptables(deps.runner)),
    workRoot: job.temp,
    ...(deps.runner && { runner: deps.runner }),
  });
  printExecution(deps, result);
  if (!result.record) throw new VerdictError("the supervisor wrote no result");
  const outDir = await freshDir(join(job.temp, VERDICT_OUT_DIR, "result"));
  const written = await writeExecutionRecord(outDir, result.record);
  const outcome = result.record.result.outcome;
  deps.log(
    `Result ${outcome} under ${result.record.result.runtime ?? "no runtime"}; result.json sha256 ${written.sha256}.`,
  );
  await setOutput(env, "outcome", outcome);
  await setOutput(env, "runtime", result.record.result.runtime ?? "");
  await setOutput(env, "result-written", "true");
  return outcome === "passed";
}

// ---------------------------------------------------------------- report

/** The report job's GitHub OIDC token for Namlo's audience. */
export async function requestOidcToken(
  deps: Pick<ActionDeps, "env" | "fetch">,
  audience = VERDICT_REPORT_AUDIENCE,
): Promise<string> {
  const url = deps.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const token = deps.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !token) {
    throw new VerdictError(
      "no OIDC token is available: the report job needs id-token: write",
    );
  }
  const request = new URL(url);
  if (request.protocol !== "https:")
    throw new VerdictError("the OIDC endpoint must be https");
  request.searchParams.set("audience", audience);
  const response = await deps.fetch(
    request,
    withTimeout({
      headers: { authorization: `bearer ${token}`, accept: "application/json" },
    }),
  );
  if (!response.ok)
    throw new VerdictError(`the OIDC endpoint answered ${response.status}`);
  const body = (await response.json()) as { value?: unknown };
  if (typeof body.value !== "string" || body.value.split(".").length !== 3) {
    throw new VerdictError("the OIDC endpoint returned no token");
  }
  return body.value;
}

/** POSTs the report; a 5xx or network failure is retried, a refusal is not. */
export async function postReport(
  deps: ActionDeps,
  jwt: string,
  body: VerdictReport,
): Promise<void> {
  const sleep =
    deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  for (let attempt = 1; ; attempt++) {
    let response: Response;
    try {
      response = await deps.fetch(
        VERDICT_REPORT_URL,
        withTimeout({
          method: "POST",
          headers: {
            authorization: `Bearer ${jwt}`,
            "content-type": "application/json",
            "user-agent": "fda-verdict-action",
          },
          body: JSON.stringify(body),
        }),
      );
    } catch (error) {
      if (attempt >= REPORT_ATTEMPTS) {
        throw new VerdictError(`Namlo could not be reached: ${message(error)}`);
      }
      await sleep(2_000 * attempt);
      continue;
    }
    const text = (await response.text()).slice(0, 2_000);
    let code = "";
    try {
      const parsed = JSON.parse(text) as { error?: unknown };
      if (typeof parsed.error === "string") code = parsed.error.slice(0, 64);
    } catch {
      // Not JSON: the status says enough.
    }
    if (response.ok) {
      deps.log(`Namlo accepted the report (${response.status}).`);
      return;
    }
    if (response.status >= 500 && attempt < REPORT_ATTEMPTS) {
      await sleep(2_000 * attempt);
      continue;
    }
    throw new VerdictError(
      `Namlo refused the report (${response.status}${code ? ` ${code}` : ""}); FDA / verdict stays as it was`,
    );
  }
}

/**
 * Job `report` (`id-token: write` only; runs `always()`): reads the small
 * prepare and result records as data, builds the bounded report and sends
 * it with this job's OIDC token. Without a preparation record there is
 * nothing to report, and the required check stays pending.
 */
export async function runReport(deps: ActionDeps): Promise<boolean> {
  const { env } = deps;
  const job = jobContext(env);
  const event = await readPullRequestEvent(env);
  const root = join(job.temp, VERDICT_IN_DIR);
  let prepared: PrepareResult;
  try {
    prepared = await readPrepareArtifact(
      root,
      job.run,
      actionInput(env, "prepare-digest"),
    );
  } catch (error) {
    throw new VerdictError(
      `preparation did not complete (${message(error)}); nothing is reported and FDA / verdict stays pending`,
    );
  }
  if (prepared.head_sha !== event.headSha) {
    throw new VerdictError("the preparation record names another head");
  }
  const result =
    prepared.outcome === "passed"
      ? await readResultArtifact(
          deps,
          root,
          job.run,
          actionInput(env, "result-digest"),
        )
      : undefined;
  const body = buildVerdictReport({
    repository: job.repository,
    prNumber: event.number,
    run: job.run,
    prepare: prepared,
    ...(result && { result }),
  });
  deps.log(
    `Reporting prepare ${body.prepare.outcome}, result ${body.result?.outcome ?? "none"} (execute job: ${neutralizeWorkflowCommands(actionInput(env, "execute-result") || "not run")}).`,
  );
  await postReport(deps, await requestOidcToken(deps), body);
  return true;
}

// ---------------------------------------------------------------- entry

export function defaultDeps(): ActionDeps {
  return {
    env: process.env,
    fetch: globalThis.fetch,
    log: (line) => process.stdout.write(`${line}\n`),
  };
}

/** The bundle's entry point: runs one mode and returns the exit code. */
export async function main(deps: ActionDeps = defaultDeps()): Promise<number> {
  const mode = actionInput(deps.env, "mode");
  const modes = { prepare: runPrepare, execute: runExecute, report: runReport };
  try {
    if (!Object.hasOwn(modes, mode)) {
      throw new VerdictError(
        `unknown mode ${JSON.stringify(mode.slice(0, 40))}`,
      );
    }
    return (await modes[mode as keyof typeof modes](deps)) ? 0 : 1;
  } catch (error) {
    deps.log(`::error::${commandData(message(error))}`);
    return 1;
  }
}
