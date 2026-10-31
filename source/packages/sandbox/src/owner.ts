// Which host process owns a sandbox container or workspace, so the janitor
// can tell leftovers of a dead process from live work. The owner string is
// `<hostname>:<pid>:<start>`; the start catches pid reuse. A wrong "dead"
// deletes live work, so the start is never measured against the current
// clock, which NTP or a VM resume can step:
// - Linux: `b<ms after boot>` from /proc/<pid>/stat, compared exactly. Both
//   sides are the kernel's boot-relative start, which clock steps don't move.
// - elsewhere: epoch ms, compared with the start the kernel recorded
//   (`ps -o lstart`), an absolute time ps prints without reading "now".
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";

/** Beside `work/` in the workspace root, outside the bind mount. */
export const OWNER_FILE = "owner";

/** How a process start is recorded; `boot` values are exact, `epoch` ones to the second. */
export interface ProcessStart {
  kind: "boot" | "epoch";
  ms: number;
}

// lstart has whole seconds and our own epoch start is computed at load.
const EPOCH_TOLERANCE_MS = 5_000;

// `process.uptime()` is process-wide, so this is right in worker threads too
// (`performance.timeOrigin` is per thread).
const PROCESS_START: ProcessStart = (process.platform === "linux" &&
  bootStart(process.pid)) || {
  kind: "epoch",
  ms: Math.round(Date.now() - process.uptime() * 1_000),
};

export interface Owner {
  host: string;
  pid: number;
  start: ProcessStart;
}

export function formatStart(start: ProcessStart): string {
  return `${start.kind === "boot" ? "b" : ""}${start.ms}`;
}

export function currentOwner(): string {
  return `${hostname()}:${process.pid}:${formatStart(PROCESS_START)}`;
}

export function parseOwner(value: string | undefined): Owner | undefined {
  // Hostnames have no colons.
  const match = /^([^:]+):(\d+):(b?)(\d+)$/.exec(value?.trim() ?? "");
  if (!match) return undefined;
  const pid = Number(match[2]);
  const ms = Number(match[4]);
  if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
  if (!Number.isSafeInteger(ms)) return undefined;
  return {
    host: match[1] as string,
    pid,
    start: { kind: match[3] ? "boot" : "epoch", ms },
  };
}

/**
 * - `live`: this host, the pid exists and started when the owner says (or
 *   its start can't be read, which counts as live).
 * - `dead`: this host, and the pid is gone or now belongs to another process.
 * - `foreign`: another host; its processes can't be checked from here.
 * - `unknown`: no owner, or not one we wrote.
 */
export type OwnerStatus = "live" | "dead" | "foreign" | "unknown";

export function ownerStatus(
  value: string | undefined,
  host = hostname(),
): OwnerStatus {
  const owner = parseOwner(value);
  if (!owner) return "unknown";
  if (owner.host !== host) return "foreign";
  try {
    process.kill(owner.pid, 0);
  } catch (error) {
    // EPERM: the pid exists but belongs to another user.
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return "dead";
  }
  const started = processStart(owner.pid, owner.start.kind);
  if (started === undefined) return "live";
  const tolerance = owner.start.kind === "boot" ? 0 : EPOCH_TOLERANCE_MS;
  return Math.abs(started.ms - owner.start.ms) > tolerance ? "dead" : "live";
}

/** When `pid` started, in the given terms; undefined when it can't be read. */
export function processStart(
  pid: number,
  kind: ProcessStart["kind"],
): ProcessStart | undefined {
  if (pid === process.pid && kind === PROCESS_START.kind) return PROCESS_START;
  return kind === "boot" ? bootStart(pid) : epochStart(pid);
}

// Field 22 of /proc/<pid>/stat: the start in clock ticks after boot (USER_HZ
// is 100 on Linux). /proc works in slim images that have no `ps`.
function bootStart(pid: number): ProcessStart | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    // comm (field 2) is parenthesised and may hold spaces or parens.
    const ticks = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19]);
    return Number.isSafeInteger(ticks)
      ? { kind: "boot", ms: ticks * 10 }
      : undefined;
  } catch {
    return undefined;
  }
}

function epochStart(pid: number): ProcessStart | undefined {
  const result = spawnSync("ps", ["-o", "lstart=", "-p", String(pid)], {
    encoding: "utf8",
    timeout: 5_000,
    // lstart is local time, in the C locale's `Tue Oct 27 17:15:03 2026`.
    env: { ...process.env, LC_ALL: "C" },
  });
  const ms = Date.parse(result.stdout?.trim() ?? "");
  return result.status === 0 && Number.isFinite(ms)
    ? { kind: "epoch", ms }
    : undefined;
}

/** Records this process as the owner of a fresh workspace root. */
export async function writeOwnerFile(root: string): Promise<void> {
  await writeFile(join(root, OWNER_FILE), `${currentOwner()}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

/** The owner a workspace root names; undefined when there is no regular, small owner file. */
export async function readOwnerFile(root: string): Promise<string | undefined> {
  const path = join(root, OWNER_FILE);
  try {
    const stat = await lstat(path);
    if (!stat.isFile() || stat.size > 1_024) return undefined;
    return (await readFile(path, "utf8")).trim();
  } catch {
    return undefined;
  }
}
