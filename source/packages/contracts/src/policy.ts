import { z } from "zod";

import {
  RISK_LEVELS,
  decisionSchema,
  impactSchema,
  pathGlobSchema,
  policyVersionSchema,
  riskSchema,
  type Decision,
  type Impact,
  type PolicyVersion,
  type Risk,
} from "./common.js";
import { organizationIdSchema, repositoryIdSchema } from "./ids.js";

// Hard blocks are code (PRD §6): what each one catches is fixed here and in
// @fda/policy. Decision 0025: an org's owner may set any of them to "approve"
// (`sensitive_areas`), which turns that block into a high-risk reason that
// waits for human approvals; it never auto-builds. Bump HARD_BLOCKS_VERSION
// whenever their meaning changes, so the policy_version stamped on audits
// changes too.
export const HARD_BLOCKS_VERSION = 2;

export const HARD_BLOCK_IMPACTS = [
  "auth",
  "billing",
  "database",
  "infrastructure",
] as const satisfies readonly Impact[];

export const HARD_BLOCKS = [
  "impact_auth",
  "impact_billing",
  "impact_database",
  "impact_infrastructure",
  "secrets",
  "destructive_migration",
  "data_export",
  "cross_tenant_read",
  "missing_tenant_isolation",
] as const;
export const hardBlockSchema = z.enum(HARD_BLOCKS);
export type HardBlock = z.infer<typeof hardBlockSchema>;

export function isHardBlockImpact(impact: Impact): boolean {
  return (HARD_BLOCK_IMPACTS as readonly Impact[]).includes(impact);
}

// --- sensitive areas (decision 0025) ----------------------------------------

/** Per hard block: `block` (the default) or `approve`, allow with approval. */
export const SENSITIVE_AREA_MODES = ["block", "approve"] as const;
export const sensitiveAreaModeSchema = z.enum(SENSITIVE_AREA_MODES);
export type SensitiveAreaMode = z.infer<typeof sensitiveAreaModeSchema>;

export const sensitiveAreasSchema = z.strictObject(
  Object.fromEntries(
    HARD_BLOCKS.map((block) => [
      block,
      sensitiveAreaModeSchema.default("block"),
    ]),
  ) as Record<HardBlock, z.ZodDefault<typeof sensitiveAreaModeSchema>>,
);
export type SensitiveAreas = z.infer<typeof sensitiveAreasSchema>;

export function defaultSensitiveAreas(): SensitiveAreas {
  return Object.fromEntries(
    HARD_BLOCKS.map((block) => [block, "block"]),
  ) as SensitiveAreas;
}

/**
 * The hard blocks an org allows with approval. A missing or malformed
 * `sensitive_areas` allows nothing.
 */
export function allowedSensitiveAreas(policy: {
  sensitive_areas?: Partial<Record<HardBlock, SensitiveAreaMode>>;
}): ReadonlySet<HardBlock> {
  const areas = policy.sensitive_areas ?? {};
  return new Set(HARD_BLOCKS.filter((block) => areas[block] === "approve"));
}

/**
 * For each area the newest version allows, the first version of its unbroken
 * run of `approve`: "allowed with approval since org-vN". `versions` is the
 * org's policy history in any order.
 */
export function sensitiveAreasSince(
  versions: ReadonlyArray<{
    version: number;
    policy: { sensitive_areas?: Partial<Record<HardBlock, SensitiveAreaMode>> };
  }>,
): Partial<Record<HardBlock, number>> {
  const newestFirst = [...versions].sort((a, b) => b.version - a.version);
  const since: Partial<Record<HardBlock, number>> = {};
  for (const block of allowedSensitiveAreas(newestFirst[0]?.policy ?? {})) {
    for (const entry of newestFirst) {
      if (entry.policy.sensitive_areas?.[block] !== "approve") break;
      since[block] = entry.version;
    }
  }
  return since;
}

/** The verdict reason a gate gives an allowed area instead of a hard block. */
export const SENSITIVE_AREA_REASON_PREFIX = "sensitive_area_allowed:";

export function sensitiveAreaReason(block: HardBlock): string {
  return `${SENSITIVE_AREA_REASON_PREFIX}${block}`;
}

/** The allowed sensitive areas a verdict's reasons name, in order, once each. */
export function sensitiveAreasInReasons(
  reasons: readonly string[],
): HardBlock[] {
  const found = new Set<HardBlock>();
  for (const reason of reasons) {
    if (!reason.startsWith(SENSITIVE_AREA_REASON_PREFIX)) continue;
    const block = reason.slice(SENSITIVE_AREA_REASON_PREFIX.length);
    if ((HARD_BLOCKS as readonly string[]).includes(block)) {
      found.add(block as HardBlock);
    }
  }
  return [...found];
}

export function formatPolicyVersion(orgPolicyVersion: number): PolicyVersion {
  return `org-v${orgPolicyVersion}+hb-${HARD_BLOCKS_VERSION}`;
}

// --- orderings -------------------------------------------------------------

/** Ordered low < medium < high < blocked. */
export function compareRisk(a: Risk, b: Risk): number {
  return RISK_LEVELS.indexOf(a) - RISK_LEVELS.indexOf(b);
}

export function maxRisk(first: Risk, ...rest: Risk[]): Risk {
  return rest.reduce(
    (max, risk) => (compareRisk(risk, max) > 0 ? risk : max),
    first,
  );
}

export const DECISION_CONSERVATIVENESS = [
  "answer",
  "clarify",
  "propose_change",
  "escalate",
  "decline",
] as const satisfies readonly Decision[];

// A Record, so adding a decision without ranking it is a type error.
const DECISION_RANK: Record<Decision, number> = {
  answer: 0,
  clarify: 1,
  propose_change: 2,
  escalate: 3,
  decline: 4,
};

/** The more conservative of two decisions. */
export function moreConservative(a: Decision, b: Decision): Decision {
  return DECISION_RANK[b] > DECISION_RANK[a] ? b : a;
}

/** True when `candidate` is equal to or more conservative than `baseline`. */
export function isAtLeastAsConservative(
  candidate: Decision,
  baseline: Decision,
): boolean {
  return DECISION_RANK[candidate] >= DECISION_RANK[baseline];
}

// --- verdict ---------------------------------------------------------------

export const POLICY_SUBJECTS = ["triage", "intent", "patch", "budget"] as const;
export const policySubjectSchema = z.enum(POLICY_SUBJECTS);
export type PolicySubject = z.infer<typeof policySubjectSchema>;

export const policyVerdictSchema = z
  .strictObject({
    policy_version: policyVersionSchema,
    subject: policySubjectSchema,
    allowed: z.boolean(),
    /** Equal to or more conservative than the model's decision. */
    effective_decision: decisionSchema,
    reasons: z.array(z.string().min(1).max(1_000)),
    hard_blocks: z.array(hardBlockSchema),
    required_approvals: z.int().min(0).max(10),
    risk_floor: riskSchema,
  })
  .refine((verdict) => verdict.hard_blocks.length === 0 || !verdict.allowed, {
    message: "a verdict with hard blocks cannot be allowed",
    path: ["allowed"],
  });

// --- org policy ------------------------------------------------------------

/** Impacts a client may allow to be built; hard-block impacts never are. */
const buildableImpactSchema = impactSchema.refine(
  (impact) => impact !== "unknown" && !isHardBlockImpact(impact),
  "hard-block and unknown impacts cannot be allowed change types",
);

export const DEFAULT_REPOSITORY_POLICY = {
  // Empty means no path is allowed: fail closed until the client sets it.
  allowed_paths: [] as string[],
  protected_paths: [] as string[],
  max_files: 20,
  max_changed_lines: 500,
  allow_dependency_changes: false,
  setup_commands: [] as string[],
  check_commands: [] as string[],
  product_constraints: "",
  allowed_change_types: ["ui", "backend"] as Impact[],
};

export const repositoryPolicySchema = z.strictObject({
  repository_id: repositoryIdSchema,
  allowed_paths: z
    .array(pathGlobSchema)
    .default(() => [...DEFAULT_REPOSITORY_POLICY.allowed_paths]),
  protected_paths: z
    .array(pathGlobSchema)
    .default(() => [...DEFAULT_REPOSITORY_POLICY.protected_paths]),
  max_files: z.int().min(1).default(DEFAULT_REPOSITORY_POLICY.max_files),
  max_changed_lines: z
    .int()
    .min(1)
    .default(DEFAULT_REPOSITORY_POLICY.max_changed_lines),
  allow_dependency_changes: z
    .boolean()
    .default(DEFAULT_REPOSITORY_POLICY.allow_dependency_changes),
  setup_commands: z
    .array(z.string().min(1).max(1_000))
    .default(() => [...DEFAULT_REPOSITORY_POLICY.setup_commands]),
  check_commands: z
    .array(z.string().min(1).max(1_000))
    .default(() => [...DEFAULT_REPOSITORY_POLICY.check_commands]),
  product_constraints: z
    .string()
    .max(10_000)
    .default(DEFAULT_REPOSITORY_POLICY.product_constraints),
  allowed_change_types: z
    .array(buildableImpactSchema)
    .default(() => [...DEFAULT_REPOSITORY_POLICY.allowed_change_types]),
});

// Testing phase (2026-10-30): high-risk changes need one approval by default.
// An org can raise it in Settings; raise this back to 2 when design partners
// run FDA on their own.
export const DEFAULT_REQUIRED_APPROVALS = { low: 1, medium: 1, high: 1 };
export const MAX_REPAIR_ATTEMPTS = 3;
export const DEFAULT_BUDGETS = {
  per_task_usd: 5,
  monthly_usd: 200,
  max_repair_attempts: 2,
  max_concurrent_tasks: 2,
};

export const requiredApprovalsSchema = z
  .strictObject({
    low: z.int().min(1).max(10).default(DEFAULT_REQUIRED_APPROVALS.low),
    medium: z.int().min(1).max(10).default(DEFAULT_REQUIRED_APPROVALS.medium),
    high: z.int().min(1).max(10).default(DEFAULT_REQUIRED_APPROVALS.high),
  })
  .refine((a) => a.low <= a.medium && a.medium <= a.high, {
    message: "required approvals must not decrease as risk rises",
  });

export const orgBudgetsSchema = z
  .strictObject({
    per_task_usd: z.number().positive().default(DEFAULT_BUDGETS.per_task_usd),
    monthly_usd: z.number().positive().default(DEFAULT_BUDGETS.monthly_usd),
    max_repair_attempts: z
      .int()
      .min(0)
      .max(MAX_REPAIR_ATTEMPTS)
      .default(DEFAULT_BUDGETS.max_repair_attempts),
    max_concurrent_tasks: z
      .int()
      .min(1)
      .default(DEFAULT_BUDGETS.max_concurrent_tasks),
  })
  .refine((b) => b.per_task_usd <= b.monthly_usd, {
    message: "per-task budget cannot exceed the monthly budget",
    path: ["per_task_usd"],
  });

export const orgPolicySchema = z.strictObject({
  organization_id: organizationIdSchema,
  version: z.int().min(1),
  repositories: z.array(repositoryPolicySchema).default(() => []),
  required_approvals: requiredApprovalsSchema.default(() => ({
    ...DEFAULT_REQUIRED_APPROVALS,
  })),
  budgets: orgBudgetsSchema.default(() => ({ ...DEFAULT_BUDGETS })),
  auto_build_reconciler_repairs: z.boolean().default(false),
  /** Decision 0015: FDA approves low-risk intents itself and builds them. */
  auto_build_low_risk: z.boolean().default(false),
  /** Decision 0025: per hard block, block (default) or allow with approval. */
  sensitive_areas: sensitiveAreasSchema.default(defaultSensitiveAreas),
});

export type PolicyVerdict = z.infer<typeof policyVerdictSchema>;
export type RepositoryPolicy = z.infer<typeof repositoryPolicySchema>;
export type RequiredApprovals = z.infer<typeof requiredApprovalsSchema>;
export type OrgBudgets = z.infer<typeof orgBudgetsSchema>;
export type OrgPolicy = z.infer<typeof orgPolicySchema>;
/** Input shape: every field with a default may be omitted. */
export type OrgPolicyInput = z.input<typeof orgPolicySchema>;
