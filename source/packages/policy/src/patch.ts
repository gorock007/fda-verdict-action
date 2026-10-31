import {
  patchManifestSchema,
  repositoryPolicySchema,
  sensitiveAreaReason,
  type HardBlock,
  type PatchManifest,
  type RepositoryPolicy,
  type Task,
} from "@fda/contracts";

import { matchesAny, matchesGlob, pathScopeIssues } from "./paths.js";
import { makeVerdict, splitHardBlocks } from "./verdict.js";
import {
  isInitiativeFile,
  WIDGET_INSTALL_AREA,
  WIDGET_INSTALL_REASON,
  widgetInstallPatchIssues,
} from "./widget-install.js";

const CAPITALS = [..."ABCDEFGHIJKLMNOPQRSTUVWXYZ"];

/**
 * Globs for a file or directory named for one of `spellings` as a whole word,
 * anywhere in the tree. A lowercase spelling matches at the start of a name
 * or after `.`, `-`, `_` or `(`, followed by the end, `.`, `-`, `_`, `)` or
 * (at the start) a capital: `auth`, `auth.ts`, `auth-actions.ts`,
 * `user_auth.py`, `(auth)` (a Next.js route group), `authActions.ts`. A
 * capitalised spelling matches anywhere followed by the end, a separator or a
 * capital: `useAuth.ts`, `AuthProvider.tsx`, `ACLService.ts`. Neither matches
 * `author.ts` or `AuthorCard.tsx`. The matcher has no character classes (they
 * would break Next.js `[slug]` globs in repository policies), so each capital
 * is spelled out.
 */
function wordGlobs(spellings: readonly string[]): string[] {
  const after = ["", ".*", "-*", "_*", ")*"];
  const segments = spellings.flatMap((word) =>
    word[0] === word[0]?.toLowerCase()
      ? [
          ...["", "*.", "*-", "*_", "*("].flatMap((pre) =>
            after.map((post) => `${pre}${word}${post}`),
          ),
          ...CAPITALS.map((capital) => `${word}${capital}*`),
        ]
      : [
          ...after.map((post) => `*${word}${post}`),
          ...CAPITALS.map((capital) => `*${word}${capital}*`),
        ],
  );
  return segments.flatMap((segment) => [`**/${segment}`, `**/${segment}/**`]);
}

/** Globs for a file or directory whose name contains one of `fragments`. */
function fragmentGlobs(fragments: readonly string[]): string[] {
  return fragments.flatMap((fragment) => [
    `**/*${fragment}*`,
    `**/*${fragment}*/**`,
  ]);
}

/**
 * Auth-named files and directories (decision 0022): `auth-actions.ts`,
 * `auth.ts`, `authz.ts`, `oauth/…`, `AuthProvider.tsx`, `authenticate.ts`,
 * `authorization.ts`, RBAC, permission and ACL modules; not `author.ts`,
 * `AuthorCard.tsx`, `authoring/`, `Authority.ts`, `coauthor.ts` or
 * `authenticity.ts`. `middleware.*` files are deliberately not here: too many
 * legitimate edits.
 */
const AUTH_NAME_GLOBS: readonly string[] = [
  ...wordGlobs([
    "auth",
    "Auth",
    "AUTH",
    "oauth",
    "oauth2",
    "OAuth",
    "OAuth2",
    "Oauth",
    "OAUTH",
    "acl",
    "acls",
    "Acl",
    "Acls",
    "ACL",
    "ACLS",
  ]),
  ...fragmentGlobs([
    "authn",
    "Authn",
    "authz",
    "Authz",
    "authenticat",
    "Authenticat",
    "authoriz",
    "Authoriz",
    "authoris",
    "Authoris",
    "rbac",
    "Rbac",
    "RBAC",
    "permission",
    "Permission",
  ]),
];

export const HARD_BLOCK_PATHS: ReadonlyArray<{
  globs: readonly string[];
  block: HardBlock;
}> = [
  { globs: ["**/*session*", ...AUTH_NAME_GLOBS], block: "impact_auth" },
  {
    globs: ["**/billing/**", "**/payments/**"],
    block: "impact_billing",
  },
  {
    globs: ["**/migrations/**", "**/*.sql"],
    block: "impact_database",
  },
  {
    globs: [".github/**", "**/Dockerfile", "**/infra/**", "**/terraform/**"],
    block: "impact_infrastructure",
  },
  {
    globs: ["**/.env*", "**/*.pem", "**/*.key"],
    block: "secrets",
  },
];

// Package manifests and package-manager config change what `npm ci` installs
// or runs, so they are denied anywhere in the tree unless the repository
// policy allows dependency changes.
const PACKAGE_MANIFEST_GLOBS: readonly string[] = [
  "**/package.json",
  "**/.npmrc",
  "**/.yarnrc*",
  "**/.pnpmfile.cjs",
  "**/pnpm-workspace.yaml",
  "**/bunfig.toml",
  "**/package-lock.json",
  "**/npm-shrinkwrap.json",
  "**/yarn.lock",
  "**/pnpm-lock.yaml",
  "**/bun.lock",
  "**/bun.lockb",
];

export const TEST_FILE_GLOBS: readonly string[] = [
  "**/*.test.*",
  "**/*.spec.*",
  "**/*_test.*",
  "**/test_*.py",
  "**/__tests__/**",
  "**/test/**",
  "**/tests/**",
  "**/e2e/**",
  "**/spec/**",
  "**/specs/**",
  "**/cypress/**",
];

/** Names that make a test a security test (decision 0022). */
const SECURITY_TEST_NAME_GLOBS: readonly string[] = [
  ...AUTH_NAME_GLOBS,
  ...wordGlobs([
    "tenant",
    "tenants",
    "tenancy",
    "multitenant",
    "Tenant",
    "Tenants",
    "Tenancy",
    "TENANT",
    "isolation",
    "Isolation",
    "cross-org",
    "cross_org",
    "crossorg",
    "crossOrg",
    "CrossOrg",
    "CROSS_ORG",
    "rls",
    "Rls",
    "RLS",
    "security",
    "Security",
    "SECURITY",
  ]),
];

/**
 * Whether `path` is a test whose name says it guards security: tenant
 * isolation, cross-org access, RLS, auth, permissions, RBAC, ACLs. Any file
 * under a test directory counts, helpers included, when a segment of its path
 * is so named.
 */
export function isSecurityTestPath(path: string): boolean {
  return (
    matchesAny(path, TEST_FILE_GLOBS) &&
    matchesAny(path, SECURITY_TEST_NAME_GLOBS)
  );
}

export interface SecurityTestEdit {
  /** The existing test's path (a rename's old path). */
  path: string;
  change: "modified" | "deleted" | "renamed";
  /** The approved intent names it as an update (decision 0024). */
  approved: boolean;
}

/**
 * The existing security tests a patch may not touch: every one it modifies,
 * deletes or renames away, except a modification of one the approved intent
 * names (`approved`, the task's `security_test_updates`; decision 0024).
 * Adding one is not an edit: specs and reproductions do that.
 */
export function securityTestEdits(
  manifest: PatchManifest,
  approved: readonly string[] = [],
): SecurityTestEdit[] {
  const listed = new Set(approved);
  return manifest.files.flatMap((file): SecurityTestEdit[] => {
    if (file.status === "added") return [];
    const path = file.status === "renamed" ? file.from : file.path;
    if (path === undefined || !isSecurityTestPath(path)) return [];
    const isListed = listed.has(path);
    return isListed && file.status === "modified"
      ? []
      : [{ path, change: file.status, approved: isListed }];
  });
}

/**
 * The existing security tests a patch modifies because the approved intent
 * names them (decision 0024): allowed by the gate, judged by the reviewer.
 */
export function approvedSecurityTestEdits(
  manifest: PatchManifest,
  approved: readonly string[] = [],
): string[] {
  const listed = new Set(approved);
  return manifest.files.flatMap((file) =>
    file.status === "modified" &&
    listed.has(file.path) &&
    isSecurityTestPath(file.path)
      ? [file.path]
      : [],
  );
}

/** The patch gate's reason for one security-test edit. */
export function securityTestReason(edit: SecurityTestEdit): string {
  return edit.approved
    ? `${edit.path}: existing security test was ${edit.change}; the approved intent names it as an update, which allows modifying it, never deleting or renaming it (decision 0024)`
    : `${edit.path}: existing security test was ${edit.change}; a build may modify one only when the approved intent names it, and never delete or rename one (decisions 0022, 0024)`;
}

/**
 * The task fields `evaluatePatch` reads. A build passes its whole `Task`;
 * the verdict check (decision 0027) passes the signed projection of them.
 */
export type PatchTask = Pick<
  Task,
  | "allowed_paths"
  | "protected_paths"
  | "risk"
  | "security_test_updates"
  | "fda_initiative"
>;

export interface PatchContext {
  repository: RepositoryPolicy;
  task: PatchTask;
  policyVersionNumber: number;
  /**
   * The hard blocks the org allows with approval (decision 0025), from the
   * policy the build loaded; its paths pass with `sensitiveAreaReason`.
   * Absent means none: a caller that forgets it fails closed.
   */
  allowedAreas?: ReadonlySet<HardBlock>;
  /**
   * The acceptance spec files the build wrote (decision 0026): a
   * widget-install task may add these, its identity route and modify its
   * layout, and touch nothing else. Absent means no spec may be added.
   */
  specPaths?: readonly string[];
}

/** The hard blocks `HARD_BLOCK_PATHS` gives one path. */
export function hardBlockForPath(path: string): HardBlock[] {
  return HARD_BLOCK_PATHS.filter(({ globs }) => matchesAny(path, globs)).map(
    ({ block }) => block,
  );
}

function modeIsExecutable(mode: string): boolean {
  return [...mode.slice(-3)].some((digit) => (Number(digit) & 1) === 1);
}

export function evaluatePatch(manifestInput: PatchManifest, ctx: PatchContext) {
  const repository = repositoryPolicySchema.parse(ctx.repository);
  const rawFiles = Array.isArray((manifestInput as { files?: unknown }).files)
    ? (
        manifestInput as {
          files: Array<{ path?: unknown; from?: unknown }>;
        }
      ).files
    : [];
  const rawPaths = rawFiles.flatMap((file) =>
    [file.path, file.from].filter(
      (path): path is string => typeof path === "string",
    ),
  );
  const allowedAreas = ctx.allowedAreas ?? new Set<HardBlock>();
  const parsed = patchManifestSchema.safeParse(manifestInput);
  if (!parsed.success) {
    const { blocked } = splitHardBlocks(
      rawPaths.flatMap(hardBlockForPath),
      allowedAreas,
    );
    return makeVerdict({
      policyVersionNumber: ctx.policyVersionNumber,
      subject: "patch",
      allowed: false,
      effectiveDecision: "escalate",
      baselineDecision: "propose_change",
      reasons: ["patch manifest is invalid or contains an unsafe path"],
      hardBlocks: blocked,
      requiredApprovals: 0,
      riskFloor: blocked.length > 0 ? "blocked" : "high",
    });
  }

  const manifest = parsed.data;
  const reasons: string[] = [];
  const hardBlocks = new Set<HardBlock>();
  const allProtectedPaths = [
    ...repository.protected_paths,
    ...ctx.task.protected_paths,
  ];
  const allPaths = manifest.files.flatMap((file) =>
    file.from ? [file.path, file.from] : [file.path],
  );

  // Decision 0026: on FDA's own widget install, `impact_auth` is lifted for
  // exactly the two files the task names; every other path keeps the org's
  // own setting.
  const initiative = ctx.task.fda_initiative;
  let initiativeAuth = false;
  for (const path of allPaths) {
    reasons.push(
      ...pathScopeIssues(path, repository.allowed_paths, allProtectedPaths),
    );
    if (!matchesAny(path, ctx.task.allowed_paths)) {
      reasons.push(`${path}: path is outside task allowed paths`);
    }
    for (const block of hardBlockForPath(path)) {
      if (
        initiative &&
        block === WIDGET_INSTALL_AREA &&
        isInitiativeFile(initiative, path)
      ) {
        initiativeAuth = true;
        continue;
      }
      hardBlocks.add(block);
    }
  }
  if (initiative) {
    reasons.push(
      ...widgetInstallPatchIssues(
        manifest,
        initiative,
        new Set(ctx.specPaths ?? []),
      ),
    );
  }

  for (const file of manifest.files) {
    if (file.mode === "120000")
      reasons.push(`${file.path}: symlinks are denied`);
    if (file.mode === "160000")
      reasons.push(`${file.path}: gitlinks are denied`);
    if (
      file.status === "added" &&
      modeIsExecutable(file.mode) &&
      !matchesGlob(file.path, "scripts/**")
    ) {
      reasons.push(
        `${file.path}: executable additions are limited to scripts/**`,
      );
    }
  }

  for (const edit of securityTestEdits(
    manifest,
    ctx.task.security_test_updates,
  )) {
    reasons.push(securityTestReason(edit));
  }

  if (!repository.allow_dependency_changes) {
    for (const path of new Set(allPaths)) {
      if (matchesAny(path, PACKAGE_MANIFEST_GLOBS)) {
        reasons.push(`package manifest change: ${path}`);
      }
    }
  }

  if (manifest.files.length > repository.max_files) {
    reasons.push(`patch exceeds max_files (${repository.max_files})`);
  }
  if (manifest.total_lines > repository.max_changed_lines) {
    reasons.push(
      `patch exceeds max_changed_lines (${repository.max_changed_lines})`,
    );
  }
  if (
    manifest.dependency_changes.length > 0 &&
    !repository.allow_dependency_changes
  ) {
    reasons.push("dependency changes are not allowed");
  }
  for (const change of manifest.dependency_changes) {
    reasons.push(
      ...pathScopeIssues(
        change.path,
        repository.allowed_paths,
        allProtectedPaths,
      ),
    );
    if (!matchesAny(change.path, ctx.task.allowed_paths)) {
      reasons.push(
        `${change.path}: dependency path is outside task allowed paths`,
      );
    }
    for (const block of hardBlockForPath(change.path)) hardBlocks.add(block);
  }
  // Decision 0025: a path in an area the org allows is not a hard block. The
  // security-test, manifest, symlink and scope rules above still apply to it.
  const split = splitHardBlocks(hardBlocks, allowedAreas);
  if (split.blocked.length > 0) {
    reasons.push("patch touches a hard-block path this organization blocks");
  }
  const noted = [
    ...split.allowed.map(sensitiveAreaReason),
    ...(initiativeAuth && !split.allowed.includes(WIDGET_INSTALL_AREA)
      ? [sensitiveAreaReason(WIDGET_INSTALL_AREA)]
      : []),
    ...(initiative ? [WIDGET_INSTALL_REASON] : []),
  ];

  const allowed = reasons.length === 0;
  return makeVerdict({
    policyVersionNumber: ctx.policyVersionNumber,
    subject: "patch",
    allowed,
    effectiveDecision: allowed ? "propose_change" : "escalate",
    baselineDecision: "propose_change",
    reasons: [...noted, ...reasons],
    hardBlocks: split.blocked,
    requiredApprovals: 0,
    riskFloor:
      split.blocked.length > 0
        ? "blocked"
        : allowed
          ? noted.length > 0
            ? "high"
            : ctx.task.risk
          : "high",
  });
}
