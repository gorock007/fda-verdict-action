import {
  HARD_BLOCKS_VERSION,
  repositoryPolicySchema,
  verdictGateProjectionSchema,
  VERDICT_CONFIG_PATH,
  VERDICT_ENVELOPE_PATH,
  type OrgPolicy,
  type PatchManifest,
  type PolicyVerdict,
  type RepositoryPolicy,
  type Task,
  type VerdictGateProjection,
  type VerdictPayload,
} from "@fda/contracts";
import {
  allowedAreasFor,
  evaluatePatch,
  matchesAny,
  specIntegrityIssues,
  type PatchContext,
  type SpecObservation,
} from "@fda/policy";

// Decision 0027: the verdict check runs the build's own gate. This adapter
// only rebuilds `evaluatePatch`'s context from the signed projections and
// adds the two rules a verdict-bearing PR has on top: the shared spec rule,
// and no change to the verifier's own files.

/**
 * The gate semantics a payload was signed under. Bump the `g` number when
 * the verdict gate's own rules change; the hard-block version follows
 * `@fda/contracts`. A verifier accepts only its own revision.
 */
export const VERDICT_GATE_REVISION = `g2+hb-${HARD_BLOCKS_VERSION}`;

/**
 * Paths a verdict-bearing code PR may never change, even when the org allows
 * infrastructure with approval: setup and verifier upgrades are separate
 * administrative PRs, and the carrier belongs to `P..H` only.
 */
export const VERDICT_RESERVED_GLOBS: readonly string[] = [
  ".github/**",
  VERDICT_CONFIG_PATH,
  VERDICT_ENVELOPE_PATH,
];

/**
 * The signed projection of what `evaluatePatch` reads: the task's fields and
 * the build's effective repository policy, never the whole records.
 */
export function gateProjection(
  task: Task,
  repository: RepositoryPolicy,
  orgPolicy: Pick<OrgPolicy, "version" | "sensitive_areas">,
): VerdictGateProjection {
  return verdictGateProjectionSchema.parse({
    task: {
      allowed_paths: task.allowed_paths,
      protected_paths: task.protected_paths,
      target_scope: task.target_scope,
      risk: task.risk,
      policy_version: task.policy_version,
      ...(task.security_test_updates
        ? { security_test_updates: task.security_test_updates }
        : {}),
      ...(task.fda_initiative ? { fda_initiative: task.fda_initiative } : {}),
    },
    repository: {
      allowed_paths: repository.allowed_paths,
      protected_paths: repository.protected_paths,
      max_files: repository.max_files,
      max_changed_lines: repository.max_changed_lines,
      allow_dependency_changes: repository.allow_dependency_changes,
    },
    org_policy_version: orgPolicy.version,
    sensitive_areas: orgPolicy.sensitive_areas,
  });
}

/** `evaluatePatch`'s context, rebuilt from a signed payload. */
export function patchContextFor(
  payload: Pick<VerdictPayload, "gate" | "repository" | "specs">,
): PatchContext {
  const { gate } = payload;
  return {
    repository: repositoryPolicySchema.parse({
      repository_id: payload.repository.fda_id,
      ...gate.repository,
    }),
    task: gate.task,
    policyVersionNumber: gate.org_policy_version,
    allowedAreas: allowedAreasFor(
      { sensitive_areas: gate.sensitive_areas },
      gate.task,
    ),
    specPaths: payload.specs.map((spec) => spec.path),
  };
}

/** Why `B..P` touches a path only an administrative PR may change. */
export function reservedPathIssues(
  manifest: Pick<PatchManifest, "files">,
): string[] {
  const touched = new Set(
    manifest.files.flatMap((file) =>
      file.from === undefined ? [file.path] : [file.path, file.from],
    ),
  );
  return [...touched]
    .filter((path) => matchesAny(path, VERDICT_RESERVED_GLOBS))
    .map(
      (path) =>
        `${path}: a Namlo code change may not change verification setup or the verdict carrier`,
    );
}

export interface VerdictGateResult {
  allowed: boolean;
  /** Reserved-path, spec and patch-gate reasons, in that order. */
  reasons: string[];
  /** `evaluatePatch`'s own verdict, unchanged. */
  verdict: PolicyVerdict;
}

/**
 * Gates the complete `B..P` manifest: `evaluatePatch` under the signed
 * context, the shared spec-integrity rule over what the checker saw at `P`,
 * and the reserved paths. Allowed only when all three pass.
 */
export function gateVerdictPatch(
  manifest: PatchManifest,
  payload: Pick<VerdictPayload, "gate" | "repository" | "specs">,
  observed: ReadonlyMap<string, SpecObservation>,
): VerdictGateResult {
  const verdict = evaluatePatch(manifest, patchContextFor(payload));
  const reserved = reservedPathIssues(manifest);
  const specs = specIntegrityIssues(payload.specs, observed, manifest);
  return {
    allowed: verdict.allowed && reserved.length === 0 && specs.length === 0,
    reasons: [...reserved, ...specs, ...verdict.reasons],
    verdict,
  };
}
