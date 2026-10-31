import {
  HARD_BLOCKS,
  HARD_BLOCK_IMPACTS,
  formatPolicyVersion,
  isAtLeastAsConservative,
  orgPolicySchema,
  policyVerdictSchema,
  type Decision,
  type HardBlock,
  type Impact,
  type OrgPolicy,
  type PolicyVerdict,
  type Risk,
} from "@fda/contracts";

interface VerdictInput {
  policyVersionNumber: number;
  subject: PolicyVerdict["subject"];
  allowed: boolean;
  effectiveDecision: Decision;
  baselineDecision?: Decision;
  reasons?: string[];
  hardBlocks?: HardBlock[];
  requiredApprovals: number;
  riskFloor: Risk;
}

/** Every gate returns through here, so no gate can emit an invalid verdict. */
export function makeVerdict(input: VerdictInput): PolicyVerdict {
  const hardBlocks = [...new Set(input.hardBlocks ?? [])];
  if (hardBlocks.some((block) => !HARD_BLOCKS.includes(block))) {
    throw new Error("policy gate produced an unknown hard block");
  }
  if (
    input.baselineDecision !== undefined &&
    !isAtLeastAsConservative(input.effectiveDecision, input.baselineDecision)
  ) {
    throw new Error("policy gate loosened the model decision");
  }

  return policyVerdictSchema.parse({
    policy_version: formatPolicyVersion(input.policyVersionNumber),
    subject: input.subject,
    allowed: input.allowed,
    effective_decision: input.effectiveDecision,
    reasons: input.reasons ?? [],
    hard_blocks: hardBlocks,
    required_approvals: input.requiredApprovals,
    risk_floor: input.riskFloor,
  });
}

export function parseOrgPolicy(policy: OrgPolicy): OrgPolicy {
  return orgPolicySchema.parse(policy);
}

export function approvalsForRisk(policy: OrgPolicy, risk: Risk): number {
  return policy.required_approvals[risk === "blocked" ? "high" : risk];
}

export function hardBlockForImpact(impact: Impact): HardBlock | undefined {
  if (!(HARD_BLOCK_IMPACTS as readonly Impact[]).includes(impact)) {
    return undefined;
  }
  return `impact_${impact}` as HardBlock;
}

/**
 * Decision 0025: the hard blocks an org still blocks, and those it allows
 * with approval (`allowedSensitiveAreas`). A gate keeps the first as hard
 * blocks and gives each of the second `sensitiveAreaReason` at floor high.
 */
export function splitHardBlocks(
  blocks: Iterable<HardBlock>,
  allowedAreas: ReadonlySet<HardBlock>,
): { blocked: HardBlock[]; allowed: HardBlock[] } {
  const unique = [...new Set(blocks)];
  return {
    blocked: unique.filter((block) => !allowedAreas.has(block)),
    allowed: unique.filter((block) => allowedAreas.has(block)),
  };
}
