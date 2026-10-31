import { spawn } from "node:child_process";
import {
  chmod,
  lstat,
  mkdtemp,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runProcess, type RunResult } from "./process.js";
import { redact } from "./redact.js";
import type { GitAuth } from "./types.js";
import { SandboxError, type Workspace } from "./types.js";

const SHA_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const DEFAULT_GIT_TIMEOUT_MS = 10 * 60_000;
const MAX_GIT_STDOUT_BYTES = 64 * 1024 * 1024;

export function assertSha(sha: string): void {
  if (!SHA_PATTERN.test(sha)) {
    throw new SandboxError(`sha must be a full lowercase commit id: ${sha}`);
  }
}

export interface ParsedCloneUrl {
  /** URL with any user:password removed; safe to store in `.git/config` and logs. */
  safeUrl: string;
  /** Credentials found in the URL, moved to an in-memory header instead. */
  auth?: GitAuth;
}

/**
 * Accepts `https:` always and `file:` only when allowed (tests and local
 * fixtures). Credentials embedded in the URL are lifted out so they never
 * reach disk.
 */
export function parseCloneUrl(
  cloneUrl: string,
  { allowFileProtocol = false } = {},
): ParsedCloneUrl {
  let url: URL;
  try {
    url = new URL(cloneUrl);
  } catch {
    throw new SandboxError("cloneUrl is not a valid URL");
  }
  if (url.protocol === "file:") {
    if (!allowFileProtocol) {
      throw new SandboxError("file: clone URLs are disabled");
    }
    return { safeUrl: url.toString() };
  }
  if (url.protocol !== "https:") {
    throw new SandboxError(`unsupported clone URL protocol: ${url.protocol}`);
  }
  let auth: GitAuth | undefined;
  if (url.password) {
    auth = {
      token: decodeURIComponent(url.password),
      username: decodeURIComponent(url.username) || undefined,
    };
  } else if (url.username) {
    auth = { token: decodeURIComponent(url.username) };
  }
  url.username = "";
  url.password = "";
  return { safeUrl: url.toString(), auth };
}

export function authHeader(auth: GitAuth): string {
  const user = auth.username ?? "x-access-token";
  const basic = Buffer.from(`${user}:${auth.token}`).toString("base64");
  return `Authorization: Basic ${basic}`;
}

/**
 * Host git environment: no system/global config (a developer's url rewrites,
 * hooks or credential helpers must not apply), no prompts, and optional
 * auth passed as in-memory `GIT_CONFIG_*` entries — not argv, which `ps`
 * shows, and not `.git/config`.
 */
export function gitEnv(
  auth?: GitAuth,
  extraConfig: ReadonlyArray<readonly [string, string]> = [],
): NodeJS.ProcessEnv {
  const config: (readonly [string, string])[] = [
    ["credential.helper", ""],
    ["core.fsmonitor", "false"],
    ["core.hooksPath", "/dev/null"],
    ["protocol.allow", "never"],
    ["protocol.https.allow", "always"],
    ["protocol.file.allow", "always"],
    // Keep command-capable nested-repository settings disabled in child gits.
    ["submodule.recurse", "false"],
    ["diff.ignoreSubmodules", "all"],
    ["status.submoduleSummary", "false"],
    ["core.sshCommand", "false"],
    ["diff.external", ""],
  ];
  if (auth) config.push(["http.extraHeader", authHeader(auth)]);
  config.push(...extraConfig);
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    LANG: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "",
    SSH_ASKPASS: "",
    GIT_CONFIG_COUNT: String(config.length),
    // Next.js types make NODE_ENV a required key; a fresh git env has none.
  } as Partial<NodeJS.ProcessEnv> as NodeJS.ProcessEnv;
  config.forEach(([key, value], index) => {
    env[`GIT_CONFIG_KEY_${index}`] = key;
    env[`GIT_CONFIG_VALUE_${index}`] = value;
  });
  return env;
}

export interface GitContext {
  gitDir: string;
  /** Absent for a bare object store (decision 0027's verdict check). */
  workTree?: string;
}

export interface GitRunOptions {
  auth?: GitAuth;
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Throw on a non-zero exit (default true). */
  check?: boolean;
  /** More in-memory `GIT_CONFIG_*` entries, after the defaults. */
  config?: ReadonlyArray<readonly [string, string]>;
  /** `GIT_EXEC_PATH` for this command and the gits it starts. */
  execPath?: string;
}

export async function git(
  ctx: GitContext,
  args: readonly string[],
  options: GitRunOptions = {},
): Promise<RunResult> {
  const result = await runProcess(
    "git",
    [
      `--git-dir=${ctx.gitDir}`,
      ...(ctx.workTree === undefined ? [] : [`--work-tree=${ctx.workTree}`]),
      ...args,
    ],
    {
      env: {
        ...gitEnv(options.auth, options.config),
        ...(options.execPath && { GIT_EXEC_PATH: options.execPath }),
      },
      signal: options.signal,
      timeoutMs: options.timeoutMs ?? DEFAULT_GIT_TIMEOUT_MS,
      fullStdoutBytes: MAX_GIT_STDOUT_BYTES,
    },
  );
  if (options.check !== false && result.code !== 0) {
    const secrets = options.auth ? [options.auth.token] : [];
    const reason = result.aborted
      ? "cancelled"
      : result.timedOut
        ? "timed out"
        : redact(result.stderr.trim(), secrets).slice(0, 2_000);
    throw new SandboxError(`git ${args[0] ?? ""} failed: ${reason}`);
  }
  return result;
}

export interface CheckoutInput extends GitContext {
  safeUrl: string;
  sha: string;
  auth?: GitAuth;
  signal?: AbortSignal;
}

async function fetchSha(
  ctx: GitContext,
  safeUrl: string,
  sha: string,
  options: Pick<GitRunOptions, "auth" | "signal">,
  fallbackRefspecs: readonly string[],
): Promise<boolean> {
  assertSha(sha);
  const shallow = await git(
    ctx,
    ["fetch", "--quiet", "--no-tags", "--depth=1", safeUrl, sha],
    { ...options, check: false },
  );
  if (shallow.code === 0) {
    const present = await git(ctx, ["cat-file", "-e", `${sha}^{commit}`], {
      signal: options.signal,
      check: false,
    });
    if (present.code === 0) return true;
  }
  if (shallow.aborted) throw new SandboxError("git fetch cancelled");
  for (const refspec of fallbackRefspecs) {
    const fallback = await git(
      ctx,
      ["fetch", "--quiet", "--no-tags", safeUrl, refspec],
      { ...options, check: false },
    );
    if (fallback.aborted) throw new SandboxError("git fetch cancelled");
  }
  const present = await git(ctx, ["cat-file", "-e", `${sha}^{commit}`], {
    signal: options.signal,
    check: false,
  });
  return present.code === 0;
}

/** Fetches exact commits into an existing workspace without writing auth to disk. */
export async function fetchCommits(
  workspace: Pick<Workspace, "gitDir" | "dir" | "cloneUrl">,
  auth: GitAuth | undefined,
  shas: readonly string[],
  options: { signal?: AbortSignal; pullRequestNumber?: number } = {},
): Promise<{ missing: string[] }> {
  const ctx = { gitDir: workspace.gitDir, workTree: workspace.dir };
  const fallbackRefspecs = [
    "+refs/heads/*:refs/fda-seed/*",
    ...(options.pullRequestNumber
      ? [
          `+refs/pull/${options.pullRequestNumber}/head:refs/fda-seed/pull/${options.pullRequestNumber}`,
        ]
      : []),
  ];
  const missing: string[] = [];
  for (const sha of new Set(shas)) {
    if (
      !(await fetchSha(
        ctx,
        workspace.cloneUrl,
        sha,
        { auth, signal: options.signal },
        fallbackRefspecs,
      ))
    ) {
      missing.push(sha);
    }
  }
  return { missing };
}

/**
 * Fetches exactly `sha` into a git dir kept outside the work tree and checks
 * it out detached. Falls back to a full fetch for servers that refuse
 * fetch-by-sha. Throws unless HEAD ends up at `sha`.
 */
export async function checkoutAtSha(input: CheckoutInput): Promise<void> {
  const { auth, signal, sha } = input;
  assertSha(sha);
  await git(input, ["init", "--quiet"], { signal });
  await git(input, ["config", "core.bare", "false"], { signal });
  await git(input, ["remote", "add", "origin", input.safeUrl], { signal });
  if (
    !(await fetchSha(input, "origin", sha, { auth, signal }, [
      "+refs/heads/*:refs/fda-seed/*",
    ]))
  ) {
    throw new SandboxError(`git fetch did not provide commit ${sha}`);
  }
  await git(
    input,
    ["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", sha],
    { signal },
  );
  const head = await git(input, ["rev-parse", "HEAD"], { signal });
  if (head.stdout.trim() !== sha) {
    throw new SandboxError(
      `checkout landed on ${head.stdout.trim()}, not ${sha}`,
    );
  }
}

// --- Read-only object stores (decision 0027) --------------------------------
// The customer-CI verifier reads an untrusted repository as data: a bare
// store with no checkout, index, hooks, filters, attributes or submodules,
// fetched with object checking and a size cap, and read through plumbing.

/** Git's empty tree, used as the attribute source so a tree's `.gitattributes` never applies. */
export const EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/** Config for every command on an untrusted object store. */
export const OBJECT_STORE_CONFIG: ReadonlyArray<readonly [string, string]> = [
  ["attr.tree", EMPTY_TREE_SHA],
  ["core.attributesFile", "/dev/null"],
  ["core.bare", "true"],
  ["gc.auto", "0"],
  ["maintenance.auto", "false"],
  ["fetch.writeCommitGraph", "false"],
  ["fetch.recurseSubmodules", "false"],
  ["transfer.fsckObjects", "true"],
  ["fetch.fsckObjects", "true"],
  // Keep every received pack whole: one index-pack, so one capped stream.
  ["fetch.unpackLimit", "1"],
  ["transfer.unpackLimit", "1"],
];

export type GitFetchErrorKind = "malformed_object" | "pack_cap" | "failed";

export class GitFetchError extends SandboxError {
  readonly kind: GitFetchErrorKind;

  constructor(kind: GitFetchErrorKind, message: string) {
    super(message);
    this.name = "GitFetchError";
    this.kind = kind;
  }
}

/** A fresh bare store: no templates (so no sample hooks), no work tree. */
export async function initObjectStore(gitDir: string): Promise<GitContext> {
  const ctx: GitContext = { gitDir };
  await git(ctx, ["init", "--bare", "--quiet", "--template="], {
    config: OBJECT_STORE_CONFIG,
  });
  return ctx;
}

async function treeBytes(dir: string): Promise<number> {
  let total = 0;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw error;
  }
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) total += await treeBytes(path);
    else {
      try {
        total += (await lstat(path)).size;
      } catch (error) {
        // A temporary pack renamed between readdir and lstat.
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
  return total;
}

export interface VerifiedFetchOptions {
  auth?: GitAuth;
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Fail once the store's objects exceed this many bytes. */
  packCapBytes: number;
  /** How often the backstop poll checks the store while receiving (ms). */
  pollMs?: number;
}

const PACK_TOO_LARGE = /^fatal: pack exceeds maximum allowed size/m;

/**
 * `git fetch` gives no way to bound the pack it receives, but the
 * `index-pack` it pipes the pack into does: `--max-input-size` dies as soon as
 * the stream passes N bytes, before more than one 4 KiB read reaches disk.
 * Fetch starts index-pack as `$GIT_EXEC_PATH/git index-pack ...`, so a private
 * exec dir — the real one's helpers linked in, and a `git` that adds the flag
 * to index-pack — makes the cap hard for every transport.
 */
async function cappedExecPath(maxInputBytes: number): Promise<string> {
  const real = (
    await runProcess("git", ["--exec-path"], { env: gitEnv() })
  ).stdout.trim();
  if (!real.startsWith("/")) throw new SandboxError("git exec path not found");
  const dir = await mkdtemp(join(tmpdir(), "fda-git-exec-"));
  try {
    for (const name of await readdir(real)) {
      if (name !== "git") await symlink(join(real, name), join(dir, name));
    }
    const binary = `'${join(real, "git").replaceAll("'", `'\\''`)}'`;
    await writeFile(
      join(dir, "git"),
      [
        "#!/bin/sh",
        `if [ "$1" = index-pack ]; then shift; exec ${binary} index-pack --max-input-size=${maxInputBytes} "$@"; fi`,
        `exec ${binary} "$@"`,
        "",
      ].join("\n"),
    );
    await chmod(join(dir, "git"), 0o700);
    return dir;
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}

const MALFORMED_OBJECT =
  /fsck|error in (?:commit|tree|blob|tag)|bad (?:object|tree|commit)|malformed|did not pass|invalid object|index-pack failed/i;

/**
 * Fetches `refspecs` with full history into an object store, checking every
 * received object (`transfer.fsckObjects`) and capping the received bytes.
 * A malformed object or a pack over the cap throws `GitFetchError` before
 * any caller reads a tree. The cap is hard: index-pack dies once the pack
 * stream passes what the store has left (`cappedExecPath`). A poll of the
 * store and a final size check stay as backstops, and catch the pack index.
 */
export async function fetchVerified(
  ctx: GitContext,
  url: string,
  refspecs: readonly string[],
  options: VerifiedFetchOptions,
): Promise<void> {
  const objects = join(ctx.gitDir, "objects");
  const cap = `received objects exceed the ${options.packCapBytes}-byte cap`;
  const remaining = options.packCapBytes - (await treeBytes(objects));
  // `--max-input-size=0` means unlimited, so a full store refuses up front.
  if (remaining < 1)
    throw new GitFetchError("pack_cap", `git fetch refused: ${cap}`);
  const execPath = await cappedExecPath(remaining);
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  options.signal?.addEventListener("abort", onAbort, { once: true });
  let overCap = false;
  let polling = false;
  const timer = setInterval(() => {
    if (polling) return;
    polling = true;
    treeBytes(objects)
      .then((bytes) => {
        if (bytes > options.packCapBytes) {
          overCap = true;
          controller.abort();
        }
      })
      .catch(() => undefined)
      .finally(() => {
        polling = false;
      });
  }, options.pollMs ?? 25);
  let result: RunResult;
  try {
    result = await git(
      ctx,
      [
        "fetch",
        "--quiet",
        "--no-tags",
        "--no-write-fetch-head",
        "--no-recurse-submodules",
        "--",
        url,
        ...refspecs,
      ],
      {
        auth: options.auth,
        signal: controller.signal,
        timeoutMs: options.timeoutMs,
        config: OBJECT_STORE_CONFIG,
        check: false,
        execPath,
      },
    );
  } finally {
    clearInterval(timer);
    options.signal?.removeEventListener("abort", onAbort);
    await rm(execPath, { recursive: true, force: true });
  }
  if (overCap || (result.code !== 0 && PACK_TOO_LARGE.test(result.stderr)))
    throw new GitFetchError("pack_cap", `git fetch stopped: ${cap}`);
  if (result.aborted) throw new GitFetchError("failed", "git fetch cancelled");
  if (result.code !== 0) {
    const stderr = redact(
      result.stderr.trim(),
      options.auth ? [options.auth.token] : [],
    ).slice(0, 2_000);
    throw new GitFetchError(
      MALFORMED_OBJECT.test(stderr) ? "malformed_object" : "failed",
      `git fetch failed: ${result.timedOut ? "timed out" : stderr}`,
    );
  }
  if ((await treeBytes(objects)) > options.packCapBytes) {
    throw new GitFetchError("pack_cap", `git fetch refused: ${cap}`);
  }
}

export interface GitObject {
  type: "blob" | "tree" | "commit" | "tag";
  bytes: Buffer;
}

/**
 * Reads objects as raw bytes (`git cat-file --batch`), never through a
 * checkout, filter or text conversion. A missing object is absent from the
 * result. Throws once their total size exceeds `maxBytes`.
 */
export function readObjects(
  ctx: GitContext,
  oids: readonly string[],
  { maxBytes }: { maxBytes: number },
): Promise<Map<string, GitObject>> {
  for (const oid of oids) assertSha(oid);
  return new Promise((resolve, reject) => {
    const child = spawn(
      "git",
      [`--git-dir=${ctx.gitDir}`, "cat-file", "--batch"],
      {
        env: gitEnv(undefined, OBJECT_STORE_CONFIG),
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    const chunks: Buffer[] = [];
    let received = 0;
    let failed = false;
    const fail = (error: Error) => {
      if (failed) return;
      failed = true;
      child.kill("SIGKILL");
      reject(error);
    };
    child.stdout.on("data", (chunk: Buffer) => {
      received += chunk.length;
      // Headers and separators add a little to the content itself.
      if (received > maxBytes + oids.length * 128) {
        fail(new SandboxError(`objects exceed ${maxBytes} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    child.stderr.resume();
    child.on("error", fail);
    child.on("close", (code) => {
      if (failed) return;
      if (code !== 0) {
        reject(new SandboxError(`git cat-file failed (${code})`));
        return;
      }
      try {
        resolve(parseBatch(Buffer.concat(chunks), maxBytes));
      } catch (error) {
        reject(error as Error);
      }
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(oids.map((oid) => `${oid}\n`).join(""));
  });
}

function parseBatch(output: Buffer, maxBytes: number): Map<string, GitObject> {
  const objects = new Map<string, GitObject>();
  let offset = 0;
  let total = 0;
  while (offset < output.length) {
    const newline = output.indexOf(0x0a, offset);
    if (newline < 0) throw new SandboxError("truncated cat-file output");
    const header = output.subarray(offset, newline).toString("utf8");
    offset = newline + 1;
    if (/^[0-9a-f]+ missing$/.test(header)) continue;
    const match = /^([0-9a-f]+) (blob|tree|commit|tag) (\d+)$/.exec(header);
    if (!match) throw new SandboxError(`unexpected cat-file header: ${header}`);
    const size = Number(match[3]);
    total += size;
    if (total > maxBytes) {
      throw new SandboxError(`objects exceed ${maxBytes} bytes`);
    }
    if (offset + size + 1 > output.length) {
      throw new SandboxError("truncated cat-file output");
    }
    objects.set(match[1]!, {
      type: match[2] as GitObject["type"],
      bytes: Buffer.from(output.subarray(offset, offset + size)),
    });
    offset += size + 1;
  }
  return objects;
}

export interface TreeEntry {
  mode: string;
  type: "blob" | "tree" | "commit";
  oid: string;
  path: string;
}

/**
 * Every entry of a commit's tree, recursively, including the trees
 * themselves (`ls-tree -r -t -z --full-tree`). With `paths`, only the
 * entries on those literal paths (and the trees above them).
 */
export async function listTree(
  ctx: GitContext,
  commit: string,
  options: Pick<GitRunOptions, "signal"> & { paths?: readonly string[] } = {},
): Promise<TreeEntry[]> {
  assertSha(commit);
  const out = await git(
    ctx,
    [
      "--literal-pathspecs",
      "ls-tree",
      "-r",
      "-t",
      "-z",
      "--full-tree",
      commit,
      ...(options.paths ? ["--", ...options.paths] : []),
    ],
    { signal: options.signal, config: OBJECT_STORE_CONFIG },
  );
  return out.stdout
    .split("\0")
    .filter((record) => record !== "")
    .map((record) => {
      const match =
        /^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40,64})\t(.*)$/s.exec(record);
      if (!match) throw new SandboxError(`unexpected ls-tree record`);
      return {
        mode: match[1]!,
        type: match[2] as TreeEntry["type"],
        oid: match[3]!,
        path: match[4]!,
      };
    });
}

export interface CommitInfo {
  tree: string;
  parents: string[];
}

/** A commit's tree and parents, from its object header. */
export async function readCommit(
  ctx: GitContext,
  sha: string,
): Promise<CommitInfo | undefined> {
  assertSha(sha);
  const out = await git(ctx, ["cat-file", "commit", sha], {
    config: OBJECT_STORE_CONFIG,
    check: false,
  });
  if (out.code !== 0) return undefined;
  const header = out.stdout.slice(0, out.stdout.indexOf("\n\n"));
  const lines = header.split("\n");
  const tree = /^tree ([0-9a-f]{40,64})$/.exec(lines[0] ?? "")?.[1];
  if (!tree) throw new SandboxError(`commit ${sha} has no tree line`);
  const parents = lines
    .slice(1)
    .flatMap((line) => /^parent ([0-9a-f]{40,64})$/.exec(line)?.[1] ?? []);
  return { tree, parents };
}

/** Whether `ancestor` is an ancestor of (or equal to) `descendant`. */
export async function isAncestor(
  ctx: GitContext,
  ancestor: string,
  descendant: string,
): Promise<boolean> {
  assertSha(ancestor);
  assertSha(descendant);
  const out = await git(
    ctx,
    ["merge-base", "--is-ancestor", ancestor, descendant],
    { config: OBJECT_STORE_CONFIG, check: false },
  );
  if (out.code === 0) return true;
  if (out.code === 1) return false;
  throw new SandboxError(`git merge-base failed: ${out.stderr.slice(0, 500)}`);
}

/** Every best common ancestor of two commits (`merge-base --all`). */
export async function mergeBases(
  ctx: GitContext,
  a: string,
  b: string,
): Promise<string[]> {
  assertSha(a);
  assertSha(b);
  const out = await git(ctx, ["merge-base", "--all", a, b], {
    config: OBJECT_STORE_CONFIG,
    check: false,
  });
  if (out.code === 1) return [];
  if (out.code !== 0) {
    throw new SandboxError(
      `git merge-base failed: ${out.stderr.slice(0, 500)}`,
    );
  }
  return out.stdout.split("\n").filter((line) => line !== "");
}
