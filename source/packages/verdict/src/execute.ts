import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  cp,
  lstat,
  mkdtemp,
  readdir,
  readFile,
  readlink,
  realpath,
  rm,
  statfs,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";

import {
  VERDICT_SCHEMA_VERSION,
  type VERDICT_RESULT_OUTCOMES,
  type VerdictRuntime,
} from "@fda/contracts";
import {
  assertArgv,
  currentOwner,
  OWNER_FILE,
  OWNER_LABEL,
  SANDBOX_LABEL,
  sanitizeOutput,
  WORKSPACE_LABEL,
} from "@fda/sandbox";

import { VerdictError } from "./envelope.js";
import type { PrepareResult } from "./prepare.js";
import {
  verdictExecutionRecordSchema,
  type VerdictExecutionRecord,
  type VerdictRun,
} from "./report.js";

// Decision 0027, job `execute`: the host supervisor. Customer code (setup
// and the signed specs) runs only in fresh containers from a pinned image:
// non-root, read-only root, no capabilities, no-new-privileges, bounded
// CPU/memory/PIDs/tmp, one container per command, removed in `finally`.
// Setup reaches the internet through a per-run bridge whose host, private,
// link-local and metadata destinations are dropped by host firewall rules
// installed first; specs run with `--network=none`. The container sees a
// copy of the export; the pristine export never gets mounted, and after
// setup and each spec the host compares every tracked path with it, by
// lstat. Only this process writes the result record.

export type VerdictResultOutcome = (typeof VERDICT_RESULT_OUTCOMES)[number];

const CONTAINER_WORKDIR = "/workspace";
const DOCKER_CLI_TIMEOUT_MS = 60_000;
// After `docker rm -f`, how long `docker start --attach` gets before we kill the CLI.
const KILL_GRACE_MS = 10_000;
const MAX_TREE_REASONS = 20;
const DIGEST_IMAGE = /^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$/;

/** Public resolvers for setup: the runner's own resolver is on a blocked address. */
export const VERDICT_SETUP_DNS = ["1.1.1.1", "8.8.8.8"] as const;

/**
 * Destinations setup may not reach (stricter than 0027, by ruling): link-local
 * and cloud metadata, Azure's wire server (GitHub-hosted runners are Azure
 * VMs), RFC 1918 and CGNAT (Alibaba's metadata address). The host itself,
 * the bridge gateway included, is dropped on INPUT. IPv6 is off.
 */
export const VERDICT_BLOCKED_IPV4 = [
  "169.254.0.0/16",
  "168.63.129.16/32",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
] as const;

export interface ExecutionLimits {
  cpus: number;
  memory: string;
  pidsLimit: number;
  shmSize: string;
  /** tmpfs size for /tmp, which also holds HOME. */
  tmpSize: string;
  /** Growth allowed on the filesystem under the workspace. */
  workspaceBytes: number;
  /** How often that growth is sampled. */
  pollMs: number;
}

export const VERDICT_EXECUTION_LIMITS: ExecutionLimits = {
  cpus: 2,
  memory: "4g",
  pidsLimit: 1024,
  shmSize: "1g",
  tmpSize: "2g",
  workspaceBytes: 8 * 1024 * 1024 * 1024,
  pollMs: 1_000,
};

// ---------------------------------------------------------------- processes

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export type CommandRunner = (
  file: string,
  args: readonly string[],
  options?: { timeoutMs?: number; signal?: AbortSignal },
) => Promise<RunResult>;

const CAPTURE_HEAD = 16 * 1024;
const CAPTURE_TAIL = 48 * 1024;

/** Holds the first and last bytes of a stream, never the whole of it. */
class Capture {
  private head = Buffer.alloc(0);
  private tail: Buffer[] = [];
  private tailBytes = 0;
  private dropped = 0;

  push(chunk: Buffer): void {
    if (this.head.length < CAPTURE_HEAD) {
      const take = CAPTURE_HEAD - this.head.length;
      this.head = Buffer.concat([this.head, chunk.subarray(0, take)]);
      chunk = chunk.subarray(take);
    }
    if (chunk.length === 0) return;
    this.tail.push(chunk);
    this.tailBytes += chunk.length;
    if (this.tailBytes > CAPTURE_TAIL * 2) {
      const joined = Buffer.concat(this.tail);
      const kept = joined.subarray(joined.length - CAPTURE_TAIL);
      this.dropped += joined.length - kept.length;
      this.tail = [Buffer.from(kept)];
      this.tailBytes = kept.length;
    }
  }

  toString(): string {
    let tail = Buffer.concat(this.tail);
    let dropped = this.dropped;
    if (tail.length > CAPTURE_TAIL) {
      dropped += tail.length - CAPTURE_TAIL;
      tail = tail.subarray(tail.length - CAPTURE_TAIL);
    }
    const gap = dropped > 0 ? `\n[… ${dropped} bytes dropped …]\n` : "";
    return `${this.head.toString("utf8")}${gap}${tail.toString("utf8")}`;
  }
}

/** Runs a host program from argv, never a shell, holding bounded output. */
export const runCommand: CommandRunner = (file, args, options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(file, [...args], {
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = new Capture();
    const stderr = new Capture();
    let timedOut = false;
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    const kill = () => child.kill("SIGKILL");
    const timer =
      options.timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            kill();
          }, options.timeoutMs);
    options.signal?.addEventListener("abort", kill, { once: true });
    if (options.signal?.aborted) kill();
    const done = () => {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", kill);
    };
    child.on("error", (error) => {
      done();
      reject(error);
    });
    child.on("close", (code, signal) => {
      done();
      resolve({
        code: code ?? (signal ? 137 : 1),
        stdout: stdout.toString(),
        stderr: stderr.toString(),
        timedOut,
      });
    });
  });

// ---------------------------------------------------------------- log text

/**
 * Makes captured text inert in an Actions log: every line gets a `| `
 * prefix, and the `::` and `##[` that open workflow commands get a
 * zero-width space, wherever they appear. Run after `sanitizeOutput`.
 */
export function neutralizeWorkflowCommands(text: string): string {
  return text
    .split("\n")
    .map((line) => `| ${line.replace(/::/g, ":​:").replace(/##\[/g, "##​[")}`)
    .join("\n");
}

/** ANSI stripped, tokens redacted, bounded, then neutralized. */
export function escapeCommandOutput(text: string): string {
  return neutralizeWorkflowCommands(sanitizeOutput(text).text);
}

// ---------------------------------------------------------------- firewall

/** Runs iptables argv lists (no program name) in the Docker host's namespace. */
export type IptablesExec = (
  commands: readonly (readonly string[])[],
  options: { tolerateFailure: boolean },
) => Promise<string>;

const BRIDGE_NAME = /^fdav[0-9a-f]{10}$/;
const RULE_TAG = /^fda-verdict-[0-9a-f]{12}$/;

/** The drop rules for one run's bridge, each tagged with the run's comment. */
export function egressRules(bridge: string, tag: string): string[][] {
  if (!BRIDGE_NAME.test(bridge) || !RULE_TAG.test(tag)) {
    throw new VerdictError("unexpected bridge name or rule tag");
  }
  const comment = ["-m", "comment", "--comment", tag];
  return [
    ["INPUT", "-i", bridge, ...comment, "-j", "DROP"],
    ...VERDICT_BLOCKED_IPV4.map((cidr) => [
      "FORWARD",
      "-i",
      bridge,
      "-d",
      cidr,
      ...comment,
      "-j",
      "DROP",
    ]),
  ];
}

export interface Firewall {
  install(bridge: string, tag: string): Promise<void>;
  /** Removes exactly the rules `install` added; throws if any remain. */
  remove(bridge: string, tag: string): Promise<void>;
}

export class EgressFirewall implements Firewall {
  constructor(private readonly exec: IptablesExec) {}

  async install(bridge: string, tag: string): Promise<void> {
    await this.exec(
      egressRules(bridge, tag).map(([chain, ...rule]) => [
        "-I",
        chain!,
        "1",
        ...rule,
      ]),
      { tolerateFailure: false },
    );
  }

  async remove(bridge: string, tag: string): Promise<void> {
    const listing = await this.exec(
      [
        ...egressRules(bridge, tag).map(([chain, ...rule]) => [
          "-D",
          chain!,
          ...rule,
        ]),
        ["-S", "INPUT"],
        ["-S", "FORWARD"],
      ],
      { tolerateFailure: true },
    );
    if (!/-A FORWARD/.test(listing)) {
      throw new VerdictError("could not list the firewall after cleanup");
    }
    if (listing.includes(tag)) {
      throw new VerdictError(`firewall rules tagged ${tag} remain`);
    }
  }
}

/** Production: `sudo -n iptables` on the runner, one command at a time. */
export function hostIptables(
  runner: CommandRunner = runCommand,
  prefix: readonly string[] = ["sudo", "-n", "iptables"],
): IptablesExec {
  return async (commands, { tolerateFailure }) => {
    let out = "";
    for (const command of commands) {
      const result = await runner(
        prefix[0]!,
        [...prefix.slice(1), ...command],
        {
          timeoutMs: DOCKER_CLI_TIMEOUT_MS,
        },
      );
      if (result.code !== 0 && !tolerateFailure) {
        throw new VerdictError(
          `iptables ${command[0]} failed: ${sanitizeOutput(result.stderr).text.slice(0, 500)}`,
        );
      }
      out += result.stdout;
    }
    return out;
  };
}

// ---------------------------------------------------------------- containers

/** gVisor when the daemon has it (or `runc` when asked), else `runc`. */
export async function detectRuntime(
  run: CommandRunner,
  docker: string,
  preference: "auto" | VerdictRuntime = "auto",
): Promise<VerdictRuntime> {
  const info = await run(docker, ["info", "--format", "{{json .Runtimes}}"], {
    timeoutMs: DOCKER_CLI_TIMEOUT_MS,
  });
  if (info.code !== 0) throw new VerdictError("docker is not available");
  if (preference === "runc") return "runc";
  let runtimes: string[] = [];
  try {
    runtimes = Object.keys(
      (JSON.parse(info.stdout) as Record<string, unknown> | null) ?? {},
    );
  } catch {
    throw new VerdictError("could not read docker's runtimes");
  }
  if (runtimes.includes("runsc")) return "runsc";
  if (preference === "runsc") {
    throw new VerdictError("gVisor (runsc) is not installed");
  }
  return "runc";
}

export interface ContainerArgsInput {
  name: string;
  image: string;
  /** Labels the container for this run's cleanup and the sandbox janitor. */
  workspaceId: string;
  owner: string;
  hostDir: string;
  /** Supervisor-owned resolver file, outside the workspace; required for setup. */
  resolvConf?: string;
  user: string;
  runtime: VerdictRuntime;
  limits: ExecutionLimits;
  /** A per-run bridge network for setup, `none` for specs. */
  network: string;
  argv: readonly string[];
}

/** `docker create` arguments; argv follows the image, where flags stop. */
export function containerArgs(input: ContainerArgsInput): string[] {
  assertArgv(input.argv);
  const [program, ...args] = input.argv;
  if (!DIGEST_IMAGE.test(input.image)) {
    throw new VerdictError("the image must be pinned by sha256 digest");
  }
  // --mount is comma-separated CSV; a comma or quote in the path would inject options.
  if (!input.hostDir.startsWith("/") || /[,"\n]/.test(input.hostDir)) {
    throw new VerdictError(`unsafe workspace path: ${input.hostDir}`);
  }
  const { limits } = input;
  const online = input.network !== "none";
  if (
    online &&
    (!input.resolvConf?.startsWith("/") || /[,"\r\n]/.test(input.resolvConf))
  ) {
    throw new VerdictError("setup needs a safe absolute resolver file path");
  }
  return [
    "create",
    `--name=${input.name}`,
    `--label=${SANDBOX_LABEL}=1`,
    `--label=${WORKSPACE_LABEL}=${input.workspaceId}`,
    `--label=${OWNER_LABEL}=${input.owner}`,
    `--runtime=${input.runtime}`,
    `--network=${input.network}`,
    ...(online
      ? [
          ...VERDICT_SETUP_DNS.map((ip) => `--dns=${ip}`),
          "--sysctl=net.ipv6.conf.all.disable_ipv6=1",
        ]
      : []),
    `--user=${input.user}`,
    "--init",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    `--cpus=${limits.cpus}`,
    `--memory=${limits.memory}`,
    `--memory-swap=${limits.memory}`,
    `--pids-limit=${limits.pidsLimit}`,
    `--shm-size=${limits.shmSize}`,
    `--tmpfs=/tmp:rw,exec,nosuid,nodev,mode=1777,size=${limits.tmpSize}`,
    `--mount=type=bind,source=${input.hostDir},target=${CONTAINER_WORKDIR}`,
    // --dns only sets Docker's upstreams on a user-defined bridge: it still
    // writes 127.0.0.11, which runsc's isolated netstack cannot reach. Mount
    // public resolvers directly; their packets still cross our host firewall.
    ...(online
      ? [
          `--mount=type=bind,source=${input.resolvConf},target=/etc/resolv.conf,readonly`,
        ]
      : []),
    `--workdir=${CONTAINER_WORKDIR}`,
    // Nothing is inherited: only public test-only values.
    "--env=CI=1",
    "--env=HOME=/tmp/home",
    `--entrypoint=${program}`,
    input.image,
    ...args,
  ];
}

// ---------------------------------------------------------------- source tree

type TreeEntry =
  | { kind: "dir" }
  | { kind: "file"; exec: boolean; sha256: string }
  | { kind: "link"; target: string };

async function hashFile(path: string): Promise<string> {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

/** Every path under `root`, by lstat: links are read, never followed. */
export async function snapshotTree(
  root: string,
): Promise<Map<string, TreeEntry>> {
  const tree = new Map<string, TreeEntry>();
  const walk = async (rel: string): Promise<void> => {
    for (const entry of await readdir(join(root, rel), {
      withFileTypes: true,
    })) {
      const path = rel === "" ? entry.name : posix.join(rel, entry.name);
      const abs = join(root, path);
      if (entry.isSymbolicLink()) {
        tree.set(path, { kind: "link", target: await readlink(abs) });
      } else if (entry.isDirectory()) {
        tree.set(path, { kind: "dir" });
        await walk(path);
      } else if (entry.isFile()) {
        const stat = await lstat(abs);
        tree.set(path, {
          kind: "file",
          exec: (stat.mode & 0o111) !== 0,
          sha256: await hashFile(abs),
        });
      } else {
        throw new VerdictError(`${path}: unsupported file type in the export`);
      }
    }
  };
  await walk("");
  return tree;
}

/**
 * Tracked paths whose workspace copy no longer matches the pristine export:
 * changed, removed, retyped or turned into a link. Untracked additions are
 * ignored. Run only while no container is running; a changed directory
 * hides its children, so nothing is read through a planted link.
 */
export async function changedPaths(
  pristine: ReadonlyMap<string, TreeEntry>,
  root: string,
): Promise<string[]> {
  const depth = (path: string) => path.split("/").length;
  const paths = [...pristine.keys()].sort(
    (a, b) => depth(a) - depth(b) || (a < b ? -1 : a > b ? 1 : 0),
  );
  const changed: string[] = [];
  const bad = new Set<string>();
  for (const path of paths) {
    const segments = path.split("/");
    if (
      segments.some((_, i) => i > 0 && bad.has(segments.slice(0, i).join("/")))
    ) {
      continue;
    }
    const want = pristine.get(path)!;
    const abs = join(root, path);
    const stat = await lstat(abs).catch(() => undefined);
    let same = false;
    if (stat) {
      if (want.kind === "dir") same = stat.isDirectory();
      else if (want.kind === "link") {
        same =
          stat.isSymbolicLink() &&
          (await readlink(abs).catch(() => undefined)) === want.target;
      } else {
        same =
          stat.isFile() &&
          ((stat.mode & 0o111) !== 0) === want.exec &&
          (await hashFile(abs).catch(() => undefined)) === want.sha256;
      }
    }
    if (!same) {
      changed.push(path);
      bad.add(path);
    }
  }
  return changed;
}

// ---------------------------------------------------------------- execute

export interface ExecuteOptions {
  /** Prepare's record; only a passed one with a plan runs anything. */
  prepare: PrepareResult;
  run: VerdictRun;
  /** Prepare's export of `P`: copied, never mounted or written. */
  exportDir: string;
  /** The audited image, pinned as `name@sha256:<digest>`. */
  image: string;
  /** Required when the plan has setup commands. */
  firewall?: Firewall;
  runtime?: "auto" | VerdictRuntime;
  limits?: Partial<ExecutionLimits>;
  /** Parent of the run's work root (default `os.tmpdir()`). */
  workRoot?: string;
  /** Container `uid:gid` (default the host's; never root). */
  user?: string;
  dockerBin?: string;
  runner?: CommandRunner;
  signal?: AbortSignal;
}

export interface StepLog {
  kind: "setup" | "spec";
  /** `setup 1`, or the spec id. */
  label: string;
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  /** Escaped with `escapeCommandOutput`: safe to print in a job log. */
  output: string;
}

export interface ExecuteResult {
  /** Absent when prepare did not pass: nothing ran. */
  record?: VerdictExecutionRecord;
  /** The supervisor's own reasons, for the job log. */
  reasons: string[];
  logs: StepLog[];
  /** The run's id: its containers' workspace label, bridge and rule tag. */
  runId: string;
}

type SpecResult = VerdictExecutionRecord["result"]["specs"][number];

/** Only every planned spec exiting 0, with nothing else wrong, passes. */
export function executionOutcome(input: {
  planned: number;
  specs: readonly Pick<SpecResult, "exit_code" | "timed_out">[];
  timedOut: boolean;
  reasons: readonly string[];
}): VerdictResultOutcome {
  if (input.timedOut || input.specs.some((spec) => spec.timed_out)) {
    return "timed_out";
  }
  if (
    input.planned === 0 ||
    input.reasons.length > 0 ||
    input.specs.length !== input.planned ||
    input.specs.some((spec) => spec.exit_code !== 0)
  ) {
    return "failed";
  }
  return "passed";
}

function hostUser(): string {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) {
    throw new VerdictError("cannot infer the host uid; pass `user`");
  }
  return `${uid}:${gid}`;
}

async function freeBytes(path: string): Promise<number> {
  const stats = await statfs(path);
  return stats.bavail * stats.bsize;
}

interface StepContext {
  run: CommandRunner;
  docker: string;
  id: string;
  owner: string;
  image: string;
  user: string;
  runtime: VerdictRuntime;
  limits: ExecutionLimits;
  workspace: string;
  resolvConf?: string;
  deadline: number;
  commandMs: number;
  baselineFree: number;
  signal?: AbortSignal;
}

interface StepOutcome {
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  /** Set when the step failed for a reason other than its exit code. */
  error?: string;
  output: string;
}

async function removeContainer(ctx: StepContext, name: string): Promise<void> {
  await ctx
    .run(ctx.docker, ["rm", "-f", name], { timeoutMs: DOCKER_CLI_TIMEOUT_MS })
    .catch(() => undefined);
}

async function runStep(
  ctx: StepContext,
  network: string,
  argv: readonly string[],
): Promise<StepOutcome> {
  const started = Date.now();
  const remaining = ctx.deadline - started;
  if (remaining <= 0) {
    return { exitCode: null, timedOut: true, durationMs: 0, output: "" };
  }
  if (ctx.signal?.aborted) {
    return {
      exitCode: null,
      timedOut: false,
      durationMs: 0,
      error: "the run was cancelled",
      output: "",
    };
  }
  const name = `fda-sbx-${ctx.id}-${randomBytes(4).toString("hex")}`;
  const created = await ctx.run(
    ctx.docker,
    containerArgs({
      name,
      image: ctx.image,
      workspaceId: ctx.id,
      owner: ctx.owner,
      hostDir: ctx.workspace,
      resolvConf: ctx.resolvConf,
      user: ctx.user,
      runtime: ctx.runtime,
      limits: ctx.limits,
      network,
      argv,
    }),
    { timeoutMs: DOCKER_CLI_TIMEOUT_MS },
  );
  if (created.code !== 0) {
    await removeContainer(ctx, name);
    return {
      exitCode: null,
      timedOut: false,
      durationMs: Date.now() - started,
      error: "the container could not be created",
      output: escapeCommandOutput(created.stderr),
    };
  }

  let timedOut = false;
  let overflow = false;
  let cancelled = false;
  const stopAttached = new AbortController();
  const kill = () => {
    void removeContainer(ctx, name);
    setTimeout(() => stopAttached.abort(), KILL_GRACE_MS).unref();
  };
  const timer = setTimeout(
    () => {
      timedOut = true;
      kill();
    },
    Math.min(ctx.commandMs, remaining),
  );
  const poll = setInterval(() => {
    void freeBytes(ctx.workspace).then(
      (free) => {
        if (!overflow && ctx.baselineFree - free > ctx.limits.workspaceBytes) {
          overflow = true;
          kill();
        }
      },
      () => undefined,
    );
  }, ctx.limits.pollMs);
  const onAbort = () => {
    cancelled = true;
    kill();
  };
  ctx.signal?.addEventListener("abort", onAbort, { once: true });
  try {
    const attached = await ctx.run(ctx.docker, ["start", "--attach", name], {
      signal: stopAttached.signal,
    });
    const output = [
      escapeCommandOutput(attached.stdout),
      escapeCommandOutput(attached.stderr),
    ]
      .filter((text) => text !== "| ")
      .join("\n");
    const error = overflow
      ? `the workspace grew past ${ctx.limits.workspaceBytes} bytes`
      : cancelled
        ? "the run was cancelled"
        : undefined;
    return {
      exitCode: timedOut || error ? null : attached.code,
      timedOut,
      durationMs: Date.now() - started,
      ...(error && { error }),
      output,
    };
  } finally {
    clearTimeout(timer);
    clearInterval(poll);
    ctx.signal?.removeEventListener("abort", onAbort);
    await removeContainer(ctx, name);
  }
}

function treeReasons(
  changed: readonly string[],
  phase: string,
  specPaths: ReadonlySet<string>,
): string[] {
  const reasons = changed
    .slice(0, MAX_TREE_REASONS)
    .map((path) =>
      specPaths.has(path)
        ? `spec ${path} was changed during ${phase}`
        : `${path} was changed during ${phase}`,
    );
  if (changed.length > MAX_TREE_REASONS) {
    reasons.push(`and ${changed.length - MAX_TREE_REASONS} more paths`);
  }
  return reasons;
}

/**
 * Runs prepare's plan: setup online behind the egress firewall, then each
 * spec offline, checking the source tree after setup and after every spec.
 * Never throws for customer behaviour; the record says what happened.
 */
export async function execute(options: ExecuteOptions): Promise<ExecuteResult> {
  const { prepare } = options;
  const id = randomBytes(6).toString("hex");
  const logs: StepLog[] = [];
  const plan = prepare.plan;
  if (
    prepare.outcome !== "passed" ||
    !plan ||
    !prepare.issuance_id ||
    !prepare.code_sha
  ) {
    return {
      reasons: ["preparation did not pass, so nothing ran"],
      logs,
      runId: id,
    };
  }
  if (!DIGEST_IMAGE.test(options.image)) {
    throw new VerdictError("the image must be pinned by sha256 digest");
  }
  if (plan.setup.length > 0 && !options.firewall) {
    throw new VerdictError("setup needs the egress firewall");
  }
  const user = options.user ?? hostUser();
  if (user === "root" || user === "0" || user.startsWith("0:")) {
    throw new VerdictError("refusing to run customer code as root");
  }
  const run = options.runner ?? runCommand;
  const docker = options.dockerBin ?? "docker";
  const limits = { ...VERDICT_EXECUTION_LIMITS, ...options.limits };
  const specPaths = new Set(plan.specs.map((spec) => spec.path));
  const network = `fda-verdict-${id}`;
  const bridge = `fdav${id.slice(0, 10)}`;
  const tag = `fda-verdict-${id}`;
  const owner = currentOwner();

  const reasons: string[] = [];
  const specs: SpecResult[] = [];
  let timedOut = false;
  let runtime: VerdictRuntime | undefined;
  let networkCreated = false;
  let firewallTouched = false;
  // The janitor's `fda-sbx-<12 hex>-` pattern and owner file: a run whose
  // host process dies is swept like any sandbox workspace.
  const root = await realpath(
    await mkdtemp(join(options.workRoot ?? tmpdir(), `fda-sbx-${id}-`)),
  );
  const workspace = join(root, "work");

  try {
    await writeFile(join(root, OWNER_FILE), `${owner}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    const pristine = await snapshotTree(options.exportDir);
    await cp(options.exportDir, workspace, {
      recursive: true,
      verbatimSymlinks: true,
      errorOnExist: true,
      force: false,
    });
    if ((await changedPaths(pristine, workspace)).length > 0) {
      throw new VerdictError("the workspace copy differs from the export");
    }
    // Customer code can write the workspace, but never this sibling file.
    // It contains no host resolver/search domains and is removed with root.
    const resolvConf =
      plan.setup.length > 0 ? join(root, "resolv.conf") : undefined;
    if (resolvConf) {
      await writeFile(
        resolvConf,
        VERDICT_SETUP_DNS.map((ip) => `nameserver ${ip}\n`).join(""),
        { flag: "wx", mode: 0o444 },
      );
    }
    runtime = await detectRuntime(run, docker, options.runtime);
    const started = Date.now();
    const ctx: StepContext = {
      run,
      docker,
      id,
      owner,
      image: options.image,
      user,
      runtime,
      limits,
      workspace,
      resolvConf,
      deadline: started + plan.limits.total_seconds * 1_000,
      commandMs: plan.limits.command_seconds * 1_000,
      baselineFree: await freeBytes(workspace),
      signal: options.signal,
    };
    const record = (kind: StepLog["kind"], label: string, step: StepOutcome) =>
      logs.push({
        kind,
        label,
        exitCode: step.exitCode,
        timedOut: step.timedOut,
        durationMs: step.durationMs,
        output: step.output,
      });

    if (plan.setup.length > 0) {
      const createdNetwork = await run(
        docker,
        [
          "network",
          "create",
          "--driver=bridge",
          `--opt=com.docker.network.bridge.name=${bridge}`,
          `--label=${SANDBOX_LABEL}=1`,
          `--label=${OWNER_LABEL}=${owner}`,
          network,
        ],
        { timeoutMs: DOCKER_CLI_TIMEOUT_MS },
      );
      if (createdNetwork.code !== 0) {
        throw new VerdictError("the setup network could not be created");
      }
      networkCreated = true;
      firewallTouched = true;
      await options.firewall!.install(bridge, tag);
      for (const [index, argv] of plan.setup.entries()) {
        const label = `setup ${index + 1}`;
        const step = await runStep(ctx, network, argv);
        record("setup", label, step);
        if (step.timedOut) {
          timedOut = true;
          reasons.push(`${label} timed out`);
        } else if (step.error) reasons.push(`${label}: ${step.error}`);
        else if (step.exitCode !== 0) {
          reasons.push(`${label} exited with ${step.exitCode}`);
        }
        if (reasons.length > 0) break;
      }
      if (reasons.length === 0) {
        reasons.push(
          ...treeReasons(
            await changedPaths(pristine, workspace),
            "setup",
            specPaths,
          ),
        );
      }
    }

    if (reasons.length === 0) {
      for (const spec of plan.specs) {
        const step = await runStep(ctx, "none", spec.argv);
        record("spec", spec.id, step);
        specs.push({
          // Branded by the record's schema when it is parsed below.
          id: spec.id as SpecResult["id"],
          exit_code: step.exitCode,
          timed_out: step.timedOut,
          duration_ms: step.durationMs,
        });
        if (step.timedOut) {
          timedOut = true;
          reasons.push(`spec ${spec.id} timed out`);
        } else if (step.error) reasons.push(`spec ${spec.id}: ${step.error}`);
        else if (step.exitCode !== 0) {
          reasons.push(`spec ${spec.id} exited with ${step.exitCode}`);
        }
        const changed = treeReasons(
          await changedPaths(pristine, workspace),
          `spec ${spec.id}`,
          specPaths,
        );
        reasons.push(...changed);
        if (changed.length > 0 || step.error || Date.now() >= ctx.deadline) {
          break;
        }
      }
    }
  } catch (error) {
    reasons.push(
      error instanceof VerdictError
        ? error.message
        : "the supervisor could not run the plan",
    );
  }

  reasons.push(
    ...(await cleanUp({
      run,
      docker,
      id,
      network: networkCreated ? network : undefined,
      firewall: firewallTouched ? options.firewall : undefined,
      bridge,
      tag,
      root,
    })),
  );

  const result = {
    outcome: executionOutcome({
      planned: plan.specs.length,
      specs,
      timedOut,
      reasons,
    }),
    ...(runtime && { runtime }),
    specs,
  };
  return {
    record: verdictExecutionRecordSchema.parse({
      schema_version: VERDICT_SCHEMA_VERSION,
      issuance_id: prepare.issuance_id,
      head_sha: prepare.head_sha,
      code_sha: prepare.code_sha,
      run: { id: options.run.id, attempt: options.run.attempt },
      prepare_digest: prepare.digest,
      result,
    }),
    reasons,
    logs,
    runId: id,
  };
}

/**
 * Removes the run's containers, network and firewall rules, then its work
 * root. A container, network or rule left behind fails the run.
 */
async function cleanUp(input: {
  run: CommandRunner;
  docker: string;
  id: string;
  network?: string;
  firewall?: Firewall;
  bridge: string;
  tag: string;
  root: string;
}): Promise<string[]> {
  const { run, docker } = input;
  const reasons: string[] = [];
  const opts = { timeoutMs: DOCKER_CLI_TIMEOUT_MS };
  try {
    const listed = await run(
      docker,
      ["ps", "-aq", "--filter", `label=${WORKSPACE_LABEL}=${input.id}`],
      opts,
    );
    const ids = listed.stdout.split(/\s+/).filter(Boolean);
    if (ids.length > 0) await run(docker, ["rm", "-f", ...ids], opts);
    const left = await run(
      docker,
      ["ps", "-aq", "--filter", `label=${WORKSPACE_LABEL}=${input.id}`],
      opts,
    );
    if (listed.code !== 0 || left.code !== 0 || left.stdout.trim() !== "") {
      reasons.push("a container of this run could not be removed");
    }
  } catch {
    reasons.push("a container of this run could not be removed");
  }
  if (input.network) {
    const removed = await run(docker, ["network", "rm", input.network], opts)
      .then((result) => result.code === 0)
      .catch(() => false);
    if (!removed) reasons.push("the setup network could not be removed");
  }
  if (input.firewall) {
    try {
      await input.firewall.remove(input.bridge, input.tag);
    } catch {
      reasons.push("the setup firewall rules could not be removed");
    }
  }
  // Left to the janitor when this fails; the owner file names this process.
  await rm(input.root, { recursive: true, force: true }).catch(() => undefined);
  return reasons;
}
