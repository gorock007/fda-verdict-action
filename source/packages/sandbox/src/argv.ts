import { posix } from "node:path";

import type { ExecPhase } from "./types.js";
import { SandboxError } from "./types.js";

export const CONTAINER_WORKDIR = "/workspace";
export const SANDBOX_LABEL = "fda.sandbox";
export const WORKSPACE_LABEL = "fda.sandbox.workspace";
/** `<hostname>:<pid>:<process start ms>` of the host process (see owner.ts). */
export const OWNER_LABEL = "fda.sandbox.owner";

export interface ContainerLimits {
  cpus: number;
  memory: string;
  pidsLimit: number;
  shmSize: string;
  /** tmpfs size for /tmp, which also holds HOME. */
  tmpSize: string;
}

export const DEFAULT_LIMITS: ContainerLimits = {
  cpus: 2,
  memory: "4g",
  pidsLimit: 512,
  shmSize: "1g",
  tmpSize: "2g",
};

/** Rejects anything that is not a plain argv array; commands never pass through a shell. */
export function assertArgv(cmd: unknown): asserts cmd is readonly string[] {
  if (!Array.isArray(cmd) || cmd.length === 0) {
    throw new SandboxError("command must be a non-empty argv array");
  }
  for (const arg of cmd) {
    if (typeof arg !== "string") {
      throw new SandboxError("every argv element must be a string");
    }
    if (arg.includes("\0")) {
      throw new SandboxError("argv elements must not contain NUL bytes");
    }
  }
  const program = cmd[0] as string;
  if (program.length === 0 || program.startsWith("-")) {
    throw new SandboxError("argv[0] must name a program");
  }
}

/** Resolves a workspace-relative cwd to its container path, refusing escapes. */
export function containerCwd(cwd: string | undefined): string {
  if (cwd === undefined || cwd === "" || cwd === ".") return CONTAINER_WORKDIR;
  if (cwd.includes("\0") || cwd.includes("\\") || posix.isAbsolute(cwd)) {
    throw new SandboxError(`cwd must be a relative POSIX path: ${cwd}`);
  }
  const normalized = posix.normalize(cwd);
  if (normalized === ".." || normalized.startsWith("../")) {
    throw new SandboxError(`cwd escapes the workspace: ${cwd}`);
  }
  return posix.join(CONTAINER_WORKDIR, normalized).replace(/\/+$/, "");
}

export interface CreateArgsInput {
  name: string;
  image: string;
  workspaceId: string;
  /** The creating host process, for the janitor (`currentOwner()`). */
  owner: string;
  hostDir: string;
  phase: ExecPhase;
  /** `uid:gid` or a user name present in the image. */
  user: string;
  limits: ContainerLimits;
  cmd: readonly string[];
  cwd?: string;
  /** Explicit values added to the sandbox's fixed environment. */
  env?: Readonly<Record<string, string>>;
}

/**
 * Arguments for `docker create`. The program is set with `--entrypoint` so an
 * image ENTRYPOINT cannot wrap it in a shell, and the rest of argv follows the
 * image name, where docker stops parsing flags.
 */
export function buildCreateArgs(input: CreateArgsInput): string[] {
  assertArgv(input.cmd);
  const [program, ...args] = input.cmd;
  const { limits } = input;
  // --mount is comma-separated CSV; a comma or quote in the path would inject options.
  if (!input.hostDir.startsWith("/") || /[,"\n]/.test(input.hostDir)) {
    throw new SandboxError(`unsafe workspace path: ${input.hostDir}`);
  }
  const environment = Object.entries(input.env ?? {}).flatMap(
    ([key, value]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
        throw new SandboxError(`invalid environment variable name: ${key}`);
      }
      if (typeof value !== "string") {
        throw new SandboxError(`environment variable ${key} must be a string`);
      }
      if (value.includes("\0")) {
        throw new SandboxError(
          `environment variable ${key} contains a NUL byte`,
        );
      }
      return [`--env=${key}=${value}`];
    },
  );
  return [
    "create",
    `--name=${input.name}`,
    `--label=${SANDBOX_LABEL}=1`,
    `--label=${WORKSPACE_LABEL}=${input.workspaceId}`,
    `--label=${OWNER_LABEL}=${input.owner}`,
    `--network=${input.phase === "install" ? "bridge" : "none"}`,
    `--user=${input.user}`,
    "--init",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    `--cpus=${limits.cpus}`,
    `--memory=${limits.memory}`,
    `--memory-swap=${limits.memory}`,
    `--pids-limit=${limits.pidsLimit}`,
    `--shm-size=${limits.shmSize}`,
    `--tmpfs=/tmp:rw,exec,mode=1777,size=${limits.tmpSize}`,
    `--mount=type=bind,source=${input.hostDir},target=${CONTAINER_WORKDIR}`,
    `--workdir=${containerCwd(input.cwd)}`,
    // The fixed environment plus explicitly supplied values; nothing is inherited.
    "--env=CI=1",
    "--env=HOME=/tmp/home",
    ...environment,
    `--entrypoint=${program}`,
    input.image,
    ...args,
  ];
}
