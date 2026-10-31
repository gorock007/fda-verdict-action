export type ExecPhase = "install" | "run";

/** Credentials for the host-side clone. Never written to disk or passed to a container. */
export interface GitAuth {
  token: string;
  /** Basic-auth user name; GitHub accepts `x-access-token` for App and PAT tokens. */
  username?: string;
}

export interface PrepareInput {
  cloneUrl: string;
  /** Full commit sha the workspace is pinned to (40 or 64 hex chars). */
  sha: string;
  auth?: GitAuth;
  cancelSignal?: AbortSignal;
}

export interface Workspace {
  id: string;
  /** Host directory holding the checked-out tree; bind-mounted into containers. */
  dir: string;
  /** Host-only git dir, kept outside `dir` so container code cannot rewrite git config or hooks. */
  gitDir: string;
  sha: string;
  /** Clone URL with any credentials removed; this is what `origin` points at. */
  cloneUrl: string;
}

export interface ExecOptions {
  phase: ExecPhase;
  timeoutMs: number;
  cancelSignal?: AbortSignal;
  /** Working directory relative to the workspace root (POSIX, no `..`). */
  cwd?: string;
  /**
   * Explicit environment values added to the isolated container environment.
   * Host environment variables are never inherited.
   */
  env?: Readonly<Record<string, string>>;
}

export interface ExecResult {
  /** Container exit code; 124 when timed out, 130 when cancelled. */
  exitCode: number;
  /** ANSI-stripped, redacted, capped at 64 KB. */
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  cancelled: boolean;
  /** True when stdout or stderr was cut to the cap. */
  truncated: boolean;
}

export interface Sandbox {
  /**
   * True when state outside the workspace (`HOME`, temp dirs) survives from
   * one exec to the next, as in a long-lived VM. A caller that must keep
   * commands from influencing each other then gives each group its own
   * `HOME` and `TMPDIR` through `ExecOptions.env`. Absent: every exec starts
   * from a fresh environment (Docker: a new container, `HOME` on a new tmpfs).
   */
  readonly persistentHome?: boolean;
  prepare(input: PrepareInput): Promise<Workspace>;
  exec(
    workspace: Workspace,
    cmd: readonly string[],
    options: ExecOptions,
  ): Promise<ExecResult>;
  dispose(workspace: Workspace): Promise<void>;
}

export class SandboxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SandboxError";
  }
}
