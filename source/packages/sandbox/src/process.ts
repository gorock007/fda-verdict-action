import { spawn } from "node:child_process";

import { BoundedOutput } from "./redact.js";

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  signal?: AbortSignal;
  /**
   * Keep stdout whole (up to this many bytes, else reject) instead of the
   * default head/tail window. For git output we must parse in full.
   */
  fullStdoutBytes?: number;
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  aborted: boolean;
}

/**
 * Runs a host program from an argv array (never through a shell). Output is
 * held in bounded buffers and returned raw; callers sanitize what they expose.
 */
export function runProcess(
  file: string,
  args: readonly string[],
  options: RunOptions = {},
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      resolve({
        code: 130,
        stdout: "",
        stderr: "",
        timedOut: false,
        aborted: true,
      });
      return;
    }
    const child = spawn(file, [...args], {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const kill = () => child.kill("SIGKILL");
    const stdout =
      options.fullStdoutBytes === undefined
        ? new BoundedOutput()
        : new FullOutput(options.fullStdoutBytes, kill);
    const stderr = new BoundedOutput();
    let timedOut = false;
    let aborted = false;
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

    const timer =
      options.timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            kill();
          }, options.timeoutMs);
    const onAbort = () => {
      aborted = true;
      kill();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    child.on("error", (error) => {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      reject(error);
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      if (stdout instanceof FullOutput && stdout.overflowed) {
        reject(new Error(`${file} output exceeded ${stdout.limit} bytes`));
        return;
      }
      resolve({
        code: code ?? (timedOut ? 124 : aborted ? 130 : 1),
        stdout: stdout.toString(),
        stderr: stderr.toString(),
        timedOut,
        aborted,
      });
    });
  });
}

class FullOutput {
  private readonly chunks: Buffer[] = [];
  private bytes = 0;
  overflowed = false;

  constructor(
    readonly limit: number,
    private readonly onOverflow: () => void,
  ) {}

  push(chunk: Buffer): void {
    if (this.overflowed) return;
    this.bytes += chunk.length;
    if (this.bytes > this.limit) {
      this.overflowed = true;
      this.onOverflow();
      return;
    }
    this.chunks.push(chunk);
  }

  toString(): string {
    return Buffer.concat(this.chunks).toString("utf8");
  }
}
