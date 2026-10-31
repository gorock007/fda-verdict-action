import { z } from "zod";

import {
  gitShaSchema,
  pathGlobSchema,
  policyVersionSchema,
  repoPathSchema,
  riskSchema,
  scopeSchema,
} from "./common.js";
import {
  customerIdSchema,
  intentIdSchema,
  organizationIdSchema,
  repositoryIdSchema,
  requestIdSchema,
  taskIdSchema,
} from "./ids.js";
import { MAX_REPAIR_ATTEMPTS } from "./policy.js";
import { fdaInitiativeSchema } from "./widget-install.js";

/** FDA pushes only `fda/<request-short-id>-v<intent-version>` branches. */
export const WORK_BRANCH_PATTERN = /^fda\/[a-z0-9-]+$/;
export const workBranchSchema = z
  .string()
  .max(200)
  .regex(WORK_BRANCH_PATTERN, "expected fda/<lowercase-slug>");

/** A plain git branch name (no `..`, spaces, control chars or leading `-`). */
export const branchNameSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(/^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]+$/, "expected a git branch name");

export const TASK_KINDS = ["build", "repair"] as const;

export const taskBudgetSchema = z.strictObject({
  max_usd: z.number().positive().max(1_000),
  max_minutes: z.int().min(1).max(1_440),
  max_repair_attempts: z.int().min(0).max(MAX_REPAIR_ATTEMPTS),
});

/**
 * The PRD §7 task contract. Validated before dispatch; the coding agent gets
 * a rendered, read-only copy.
 */
export const taskSchema = z
  .strictObject({
    task_id: taskIdSchema,
    idempotency_key: z.string().min(1).max(200),
    organization_id: organizationIdSchema,
    repository_id: repositoryIdSchema,
    customer_ids: z.array(customerIdSchema),
    request_id: requestIdSchema,
    intent_id: intentIdSchema,
    intent_version: z.int().min(1),
    kind: z.enum(TASK_KINDS),
    base_branch: branchNameSchema,
    base_sha: gitShaSchema,
    work_branch: workBranchSchema,
    allowed_paths: z.array(pathGlobSchema).min(1),
    protected_paths: z.array(pathGlobSchema),
    /**
     * Existing security tests the approved intent names (decision 0024): the
     * patch gate lets the build modify exactly these, never delete or rename
     * them. Absent on tasks built before it.
     */
    security_test_updates: z.array(repoPathSchema).max(20).optional(),
    /**
     * Decision 0026: copied from the approved intent. The patch gate then
     * allows `impact_auth` paths only for its two files and refuses every
     * other file but the acceptance specs. Absent on every other task.
     */
    fda_initiative: fdaInitiativeSchema.optional(),
    target_scope: scopeSchema,
    risk: riskSchema,
    policy_version: policyVersionSchema,
    budget: taskBudgetSchema,
    acceptance_commands: z.array(z.string().min(1).max(1_000)).min(1),
    artifact_prefix: z.string().min(1).max(500),
    cancellation_token: z.string().min(1).max(200),
  })
  .refine((task) => task.risk !== "blocked", {
    message: "a blocked-risk task is never dispatched",
    path: ["risk"],
  });

export type TaskKind = (typeof TASK_KINDS)[number];
export type TaskBudget = z.infer<typeof taskBudgetSchema>;
export type Task = z.infer<typeof taskSchema>;
