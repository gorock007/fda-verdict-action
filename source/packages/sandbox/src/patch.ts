import { posix } from "node:path";

import {
  patchManifestSchema,
  type DependencyChange,
  type PatchFile,
  type PatchManifest,
} from "@fda/contracts";

import { assertSha, git, type GitContext, type GitRunOptions } from "./git.js";
import { SandboxError, type Workspace } from "./types.js";

export type { PatchFile, PatchManifest } from "@fda/contracts";
export type PatchFileStatus = PatchFile["status"];

export interface CollectedPatch {
  diff: string;
  manifest: PatchManifest;
}

export const LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
]);

const DEPENDENCY_FIELDS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
  "bundleDependencies",
  "bundledDependencies",
  "overrides",
  "resolutions",
] as const;

export interface RawEntry {
  status: PatchFileStatus;
  path: string;
  from?: string;
  oldMode: string;
  newMode: string;
}

const STATUS_LETTERS: Record<string, PatchFileStatus> = {
  A: "added",
  C: "added",
  M: "modified",
  T: "modified",
  D: "deleted",
  R: "renamed",
};

/** Parses `git diff --raw -z` (`:old new sha sha STATUS\0path\0[path\0]`). */
export function parseRawZ(output: string): RawEntry[] {
  const fields = output.split("\0");
  const entries: RawEntry[] = [];
  let i = 0;
  while (i < fields.length) {
    const header = fields[i++];
    if (!header) continue;
    const match = /^:(\d{6}) (\d{6}) [0-9a-f]+ [0-9a-f]+ ([A-Z])\d*$/.exec(
      header,
    );
    if (!match) throw new Error(`unexpected git --raw record: ${header}`);
    const [, oldMode, newMode, letter] = match as unknown as [
      string,
      string,
      string,
      string,
    ];
    const status = STATUS_LETTERS[letter];
    if (!status) throw new Error(`unsupported git status ${letter}`);
    const first = fields[i++] ?? "";
    if (letter === "R" || letter === "C") {
      const second = fields[i++] ?? "";
      entries.push(
        letter === "R"
          ? { status, path: second, from: first, oldMode, newMode }
          : { status, path: second, oldMode, newMode },
      );
    } else {
      entries.push({ status, path: first, oldMode, newMode });
    }
  }
  return entries;
}

export interface NumstatEntry {
  path: string;
  from?: string;
  additions: number;
  deletions: number;
  binary: boolean;
}

/** Parses `git diff --numstat -z`; renames are `a\td\t\0from\0to\0`, binaries count `-`. */
export function parseNumstatZ(output: string): NumstatEntry[] {
  const fields = output.split("\0");
  const entries: NumstatEntry[] = [];
  let i = 0;
  while (i < fields.length) {
    const record = fields[i++];
    if (!record) continue;
    const match = /^(\d+|-)\t(\d+|-)\t(.*)$/s.exec(record);
    if (!match) throw new Error(`unexpected git --numstat record: ${record}`);
    const [, added, deleted, inlinePath] = match as unknown as [
      string,
      string,
      string,
      string,
    ];
    const binary = added === "-" || deleted === "-";
    const counts = {
      additions: binary ? 0 : Number(added),
      deletions: binary ? 0 : Number(deleted),
      binary,
    };
    if (inlinePath === "") {
      const from = fields[i++] ?? "";
      const to = fields[i++] ?? "";
      entries.push({ path: to, from, ...counts });
    } else {
      entries.push({ path: inlinePath, ...counts });
    }
  }
  return entries;
}

export function isLockfile(path: string): boolean {
  return LOCKFILE_NAMES.has(posix.basename(path));
}

export function isPackageManifest(path: string): boolean {
  return posix.basename(path) === "package.json";
}

function dependencySnapshot(source: string | undefined): string | undefined {
  if (source === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(source);
    if (!parsed || typeof parsed !== "object") return source;
    const record = parsed as Record<string, unknown>;
    const picked: Record<string, unknown> = {};
    for (const field of DEPENDENCY_FIELDS) {
      if (record[field] !== undefined) picked[field] = record[field];
    }
    return stableStringify(picked);
  } catch {
    // Unparseable manifests compare as raw text, so any edit counts as a change.
    return source;
  }
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * True when a package.json change touches dependency maps. `before`/`after`
 * are file contents (undefined when the file did not exist on that side).
 */
export function manifestDependenciesChanged(
  before: string | undefined,
  after: string | undefined,
): boolean {
  const empty = stableStringify({});
  return (
    (dependencySnapshot(before) ?? empty) !==
    (dependencySnapshot(after) ?? empty)
  );
}

export function buildManifest(
  raw: readonly RawEntry[],
  numstat: readonly NumstatEntry[],
  dependencyChanges: readonly DependencyChange[],
): PatchManifest {
  const counts = new Map(numstat.map((entry) => [entry.path, entry]));
  const files = raw.map((entry): PatchFile => {
    const count = counts.get(entry.path);
    const file: PatchFile = {
      path: entry.path,
      status: entry.status,
      additions: count?.additions ?? 0,
      deletions: count?.deletions ?? 0,
      mode: entry.status === "deleted" ? entry.oldMode : entry.newMode,
    };
    if (entry.from !== undefined) file.from = entry.from;
    return file;
  });
  return patchManifestSchema.parse({
    files,
    dependency_changes: [...dependencyChanges],
    total_lines: files.reduce((sum, f) => sum + f.additions + f.deletions, 0),
  });
}

function dependencyEntries(
  source: string | undefined,
): Map<string, { name: string; value: string }> | undefined {
  if (source === undefined) return new Map();
  try {
    const parsed: unknown = JSON.parse(source);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return undefined;
    }
    const entries = new Map<string, { name: string; value: string }>();
    for (const field of DEPENDENCY_FIELDS) {
      const dependencies = (parsed as Record<string, unknown>)[field];
      if (
        !dependencies ||
        typeof dependencies !== "object" ||
        Array.isArray(dependencies)
      ) {
        continue;
      }
      for (const [name, value] of Object.entries(
        dependencies as Record<string, unknown>,
      )) {
        entries.set(`${field}\0${name}`, {
          name,
          value: typeof value === "string" ? value : stableStringify(value),
        });
      }
    }
    return entries;
  } catch {
    return undefined;
  }
}

function manifestDependencyChanges(
  path: string,
  before: string | undefined,
  after: string | undefined,
): DependencyChange[] {
  if (!manifestDependenciesChanged(before, after)) return [];
  const oldEntries = dependencyEntries(before);
  const newEntries = dependencyEntries(after);
  if (!oldEntries || !newEntries) return [{ path, kind: "manifest" }];

  const keys = new Set([...oldEntries.keys(), ...newEntries.keys()]);
  return [...keys].sort().flatMap((key): DependencyChange[] => {
    const oldEntry = oldEntries.get(key);
    const newEntry = newEntries.get(key);
    if (oldEntry?.value === newEntry?.value) return [];
    const name = oldEntry?.name ?? newEntry?.name;
    if (!name) return [{ path, kind: "manifest" }];
    return [
      {
        path,
        kind: "manifest",
        name,
        ...(oldEntry ? { from: oldEntry.value } : {}),
        ...(newEntry ? { to: newEntry.value } : {}),
      },
    ];
  });
}

// Shared by the workspace collector and the committed-tree collector, so
// both normalize a diff the same way (decision 0027).
const DIFF_OPTIONS = [
  "-M",
  "--no-color",
  "--no-ext-diff",
  "--no-textconv",
  "--ignore-submodules=none",
  "--submodule=short",
] as const;

async function readBlob(
  ctx: GitContext,
  spec: string,
  options: GitRunOptions = {},
): Promise<string | undefined> {
  const result = await git(ctx, ["show", spec], { ...options, check: false });
  return result.code === 0 ? result.stdout : undefined;
}

interface DiffSides {
  /** What `git diff` compares: `--cached <sha>` or `<base> <head>`. */
  args: readonly string[];
  /** Object spec of a path on the old side and on the new side. */
  before: (path: string) => string;
  after: (path: string) => string;
}

async function collectDiff(
  ctx: GitContext,
  sides: DiffSides,
  options: GitRunOptions = {},
): Promise<CollectedPatch> {
  const diffArgs = (...format: string[]) => [
    "diff",
    ...DIFF_OPTIONS,
    ...format,
    ...sides.args,
  ];
  const [diff, rawOut, numstatOut] = await Promise.all([
    git(ctx, diffArgs(), options),
    git(ctx, diffArgs("--raw", "-z", "--no-abbrev"), options),
    git(ctx, diffArgs("--numstat", "-z"), options),
  ]);
  const raw = parseRawZ(rawOut.stdout);
  const dependencyChanges: DependencyChange[] = [];
  for (const entry of raw) {
    if (isLockfile(entry.path) || (entry.from && isLockfile(entry.from))) {
      dependencyChanges.push({ path: entry.path, kind: "lockfile" });
    } else if (
      isPackageManifest(entry.path) ||
      (entry.from && isPackageManifest(entry.from))
    ) {
      const before =
        entry.status === "added"
          ? undefined
          : await readBlob(
              ctx,
              sides.before(entry.from ?? entry.path),
              options,
            );
      const after =
        entry.status === "deleted" || !isPackageManifest(entry.path)
          ? undefined
          : await readBlob(ctx, sides.after(entry.path), options);
      dependencyChanges.push(
        ...manifestDependencyChanges(entry.path, before, after),
      );
    }
  }
  return {
    diff: diff.stdout,
    manifest: buildManifest(
      raw,
      parseNumstatZ(numstatOut.stdout),
      dependencyChanges,
    ),
  };
}

/**
 * Stages everything (`git add -A`, so files the agent created are included —
 * the Wishcraft `git diff <base>` bug) and diffs the index against the pinned
 * commit. Binary files appear as "Binary files differ" in `diff` with 0/0 counts.
 */
export async function collectPatch(
  workspace: Workspace,
): Promise<CollectedPatch> {
  const ctx: GitContext = { gitDir: workspace.gitDir, workTree: workspace.dir };
  await git(ctx, ["add", "-A"]);
  const staged = await git(ctx, ["ls-files", "--stage", "-z"]);
  const gitlinks = staged.stdout.split("\0").flatMap((record) => {
    const match = /^160000 [0-9a-f]+ [0-3]\t(.*)$/s.exec(record);
    return match?.[1] === undefined ? [] : [match[1]];
  });
  if (gitlinks.length > 0) {
    throw new SandboxError(
      `nested git repository at ${gitlinks.join(", ")}; refusing to collect patch`,
    );
  }
  return collectDiff(ctx, {
    args: ["--cached", workspace.sha],
    before: (path) => `${workspace.sha}:${path}`,
    after: (path) => `:${path}`,
  });
}

/**
 * The patch between two commits, read from Git objects only: no work tree,
 * index or checkout. Normalized exactly as `collectPatch` (decision 0027), so
 * the verdict check gates `B..P` with the manifest the build gated. Gitlinks
 * and symlinks appear with their modes and `evaluatePatch` denies them.
 */
export async function collectCommittedPatch(
  ctx: GitContext,
  base: string,
  head: string,
  options: GitRunOptions = {},
): Promise<CollectedPatch> {
  assertSha(base);
  assertSha(head);
  return collectDiff(
    ctx,
    {
      args: [base, head],
      before: (path) => `${base}:${path}`,
      after: (path) => `${head}:${path}`,
    },
    options,
  );
}
