import { z } from "zod";

// Enums shared by triage, policy, intent and task. They live here rather than
// in policy.ts so the object modules don't import each other in a cycle.

export const RISK_LEVELS = ["low", "medium", "high", "blocked"] as const;
export const riskSchema = z.enum(RISK_LEVELS);
export type Risk = z.infer<typeof riskSchema>;

export const IMPACTS = [
  "ui",
  "backend",
  "database",
  "auth",
  "billing",
  "infrastructure",
  "unknown",
] as const;
export const impactSchema = z.enum(IMPACTS);
export type Impact = z.infer<typeof impactSchema>;

export const SCOPES = ["user", "customer", "cohort", "global"] as const;
export const scopeSchema = z.enum(SCOPES);
export type Scope = z.infer<typeof scopeSchema>;

export const DECISIONS = [
  "answer",
  "clarify",
  "decline",
  "escalate",
  "propose_change",
] as const;
export const decisionSchema = z.enum(DECISIONS);
export type Decision = z.infer<typeof decisionSchema>;

export const policyVersionSchema = z.string().min(1).max(100);
export type PolicyVersion = z.infer<typeof policyVersionSchema>;

export const gitShaSchema = z
  .string()
  .regex(/^[0-9a-f]{40}$/, "expected a 40-character lowercase git sha");

/** A path relative to the client repo root: no leading slash, no `..`. */
export const repoPathSchema = z
  .string()
  .min(1)
  .max(500)
  .refine(
    (path) =>
      !path.startsWith("/") &&
      !path.includes("\\") &&
      !path.includes("\0") &&
      !path.split("/").some((segment) => segment === ".."),
    "expected a relative repo path without '..'",
  );

/** A repo-relative glob (`src/**`, `**\/*.test.ts`), same rules as a path. */
export const pathGlobSchema = repoPathSchema;
