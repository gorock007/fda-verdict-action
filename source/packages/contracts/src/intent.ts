import { z } from "zod";

import {
  gitShaSchema,
  impactSchema,
  repoPathSchema,
  riskSchema,
  scopeSchema,
} from "./common.js";
import {
  acceptanceSpecIdSchema,
  customerIdSchema,
  intentIdSchema,
  requestIdSchema,
  type CustomerId,
} from "./ids.js";
import { fdaInitiativeSchema } from "./widget-install.js";

export const ACCEPTANCE_SPEC_KINDS = ["unit", "e2e"] as const;
export const SPEC_POLARITIES = ["positive", "negative"] as const;
export const VARIANT_MECHANISMS = ["config", "flag", "module"] as const;
export const INTENT_SOURCES = ["request", "reconciler", "operator"] as const;
export const INTENT_APPROVAL_STATES = [
  "draft",
  "approved",
  "rejected",
  "superseded",
] as const;

const shortText = z.string().min(1).max(500);

/**
 * An acceptance spec as the drafting model returns it (no `id`). Negative
 * specs prove a non-target customer does NOT get the change (M9).
 */
export const acceptanceSpecDraftSchema = z.strictObject({
  kind: z.enum(ACCEPTANCE_SPEC_KINDS),
  path: repoPathSchema,
  contents: z.string().min(1).max(200_000),
  /** How the client's runner runs only this spec. */
  command: z.string().min(1).max(1_000),
  customer_id: customerIdSchema,
  polarity: z.enum(SPEC_POLARITIES),
  must_fail_before: z.literal(true),
});

export const acceptanceSpecSchema = acceptanceSpecDraftSchema.extend({
  id: acceptanceSpecIdSchema,
});

export const variantSchema = z.strictObject({
  flag_key: z
    .string()
    .regex(/^[a-z0-9][a-z0-9_.-]{0,99}$/, "expected a lowercase flag key"),
  mechanism: z.enum(VARIANT_MECHANISMS),
  description: z.string().min(1).max(2_000),
});

/**
 * An existing security test the change must update (decision 0024), with why.
 * Approving the intent approves modifying it; never deleting or renaming it.
 */
export const existingTestUpdateSchema = z.strictObject({
  path: repoPathSchema,
  reason: shortText,
});

const intentBodyShape = {
  scope: scopeSchema,
  title: z.string().min(1).max(200),
  problem: z.string().min(1).max(4_000),
  desired_behavior: z.string().min(1).max(4_000),
  non_goals: z.array(shortText).max(20),
  acceptance_criteria: z.array(shortText).min(1).max(20),
  variant: variantSchema.optional(),
  affected_files: z.array(repoPathSchema).max(100),
  risk: riskSchema,
  impact: z.array(impactSchema).min(1),
  unknowns: z.array(shortText).max(20),
  rationale: z.string().min(1).max(4_000),
  /** Decision 0024; absent on intents drafted before it. */
  existing_test_updates: z
    .array(existingTestUpdateSchema)
    .max(20)
    .refine(
      (updates) => new Set(updates.map((u) => u.path)).size === updates.length,
      "each existing test is listed once",
    )
    .optional(),
};

/**
 * What the drafting model returns. Ids, version, target customers, source,
 * author and approval state are set by code — no tenant ids from a model.
 */
export const intentDraftSchema = z.strictObject({
  ...intentBodyShape,
  acceptance_specs: z.array(acceptanceSpecDraftSchema).min(1).max(20),
});

/** The customers a request's specs may name. */
export interface SpecCustomerSet {
  /** Customers the change is for; positive specs must name one of these. */
  targets: readonly CustomerId[];
  /** Other customers of the org offered to the drafter for negative specs. */
  others: readonly CustomerId[];
}

/**
 * Problems with the customers named by acceptance specs: a customer outside
 * the request's set, a positive spec on a non-target, or a negative spec on
 * a target. Empty when the specs are consistent.
 */
export function specCustomerIssues(
  specs: readonly { customer_id: CustomerId; polarity: string }[],
  customers: SpecCustomerSet,
): string[] {
  const targets = new Set<string>(customers.targets);
  const known = new Set<string>([...customers.targets, ...customers.others]);
  const issues: string[] = [];
  specs.forEach((spec, index) => {
    if (!known.has(spec.customer_id)) {
      issues.push(
        `acceptance_specs[${index}]: customer is not in this request's customer set`,
      );
    } else if (spec.polarity === "positive" && !targets.has(spec.customer_id)) {
      issues.push(
        `acceptance_specs[${index}]: positive spec must name a target customer`,
      );
    } else if (spec.polarity === "negative" && targets.has(spec.customer_id)) {
      issues.push(
        `acceptance_specs[${index}]: negative spec must name a non-target customer`,
      );
    }
  });
  return issues;
}

/** `intentDraftSchema` plus the spec-customer check for one request. */
export function intentDraftSchemaFor(customers: SpecCustomerSet) {
  return intentDraftSchema.superRefine((draft, ctx) => {
    for (const message of specCustomerIssues(
      draft.acceptance_specs,
      customers,
    )) {
      ctx.addIssue({ code: "custom", message, path: ["acceptance_specs"] });
    }
  });
}

/** For LLM structured output. */
export const intentDraftJsonSchema = z.toJSONSchema(intentDraftSchema);

/**
 * The pull request a version rebuilds after the client's CI failed on it
 * (decision 0011). A pointer only: the CI text stays on that PR's row.
 */
export const rebuildOfSchema = z.strictObject({
  pull_request_id: z.uuid(),
  pr_number: z.int().min(1),
  head_sha: gitShaSchema,
});

/** A stored intent version; prior versions are immutable. */
export const intentSchema = z
  .strictObject({
    ...intentBodyShape,
    intent_id: intentIdSchema,
    version: z.int().min(1),
    request_id: requestIdSchema,
    /** Target customers; empty only for a global change. */
    customer_ids: z.array(customerIdSchema),
    acceptance_specs: z.array(acceptanceSpecSchema),
    source: z.enum(INTENT_SOURCES),
    /** Operator user id, or an agent/system identifier. */
    created_by: z.string().min(1).max(200),
    approval_state: z.enum(INTENT_APPROVAL_STATES),
    /** Set by code, never by the drafting model (not in `intentBodyShape`). */
    rebuild_of: rebuildOfSchema.optional(),
    /**
     * Decision 0026: FDA's own widget install, set by code from the request
     * (never by the model or an operator; carried over edits like
     * `rebuild_of`). Opens `impact_auth` for exactly its two files.
     */
    fda_initiative: fdaInitiativeSchema.optional(),
  })
  .superRefine((intent, ctx) => {
    if (intent.scope !== "global" && intent.customer_ids.length === 0) {
      ctx.addIssue({
        code: "custom",
        message: "a non-global intent needs target customers",
        path: ["customer_ids"],
      });
    }
    if (intent.customer_ids.length === 0) return;
    const targets = new Set<string>(intent.customer_ids);
    intent.acceptance_specs.forEach((spec, index) => {
      if ((spec.polarity === "positive") !== targets.has(spec.customer_id)) {
        ctx.addIssue({
          code: "custom",
          message: `${spec.polarity} spec names the wrong customer`,
          path: ["acceptance_specs", index, "customer_id"],
        });
      }
    });
  });

export type AcceptanceSpecDraft = z.infer<typeof acceptanceSpecDraftSchema>;
export type AcceptanceSpec = z.infer<typeof acceptanceSpecSchema>;
export type Variant = z.infer<typeof variantSchema>;
export type ExistingTestUpdate = z.infer<typeof existingTestUpdateSchema>;
export type IntentDraft = z.infer<typeof intentDraftSchema>;
export type RebuildOf = z.infer<typeof rebuildOfSchema>;
export type Intent = z.infer<typeof intentSchema>;
