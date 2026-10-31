import {
  allowedSensitiveAreas,
  type FdaInitiative,
  type HardBlock,
  type Intent,
  type OrgPolicy,
  type PatchManifest,
} from "@fda/contracts";

import { hardBlockForPath, TEST_FILE_GLOBS } from "./patch.js";
import { matchesAny } from "./paths.js";

// Decision 0026: FDA's own widget install is the one request that may touch
// auth under the default Block, and only in a fixed shape: it adds the
// identity route, edits the root layout, and nothing else. The input is the
// `fda_initiative` field code sets on the intent and copies to the task,
// never a string in request text, so an operator's or a customer's request
// can't claim it.

/** The one hard-block area a widget install opens. */
export const WIDGET_INSTALL_AREA: HardBlock = "impact_auth";

/** The verdict reason that records the exception on an intent or patch. */
export const WIDGET_INSTALL_REASON = "fda_initiative:widget_install";

/**
 * The areas a widget-install request may touch: whatever the org allows
 * with approval (decision 0025) plus `impact_auth`. The gates give the area
 * the same `sensitive_area_allowed:impact_auth` reason, so the floor is
 * high, the high-risk approvals apply, nothing auto-builds and the PR body
 * says so.
 */
export function widgetInstallAllowedAreas(
  policy: Pick<OrgPolicy, "sensitive_areas">,
): ReadonlySet<HardBlock> {
  return new Set([...allowedSensitiveAreas(policy), WIDGET_INSTALL_AREA]);
}

/**
 * The allowed areas for an intent or task: widened only when it carries the
 * initiative, else exactly the org's own setting.
 */
export function allowedAreasFor(
  policy: Pick<OrgPolicy, "sensitive_areas">,
  carrier: { fda_initiative?: FdaInitiative | undefined },
): ReadonlySet<HardBlock> {
  return carrier.fda_initiative
    ? widgetInstallAllowedAreas(policy)
    : allowedSensitiveAreas(policy);
}

/** Whether `path` is one of the two files the initiative names. */
export function isInitiativeFile(
  initiative: FdaInitiative,
  path: string,
): boolean {
  return path === initiative.identity_route || path === initiative.layout_file;
}

/**
 * Why `path` can't be one of a widget install's acceptance specs. The
 * carrier's allowed areas include `impact_auth` and the patch gate lets the
 * spec paths through, so a spec must be a test file by the patch gate's own
 * pattern and sit on no hard-block or auth-named path: otherwise it would
 * land as app code with the auth block lifted.
 */
export function widgetInstallSpecPathIssues(path: string): string[] {
  const issues: string[] = [];
  if (!matchesAny(path, TEST_FILE_GLOBS)) {
    issues.push(
      `${path}: a widget install's acceptance spec must be a test file (decision 0026)`,
    );
  }
  const blocks = hardBlockForPath(path);
  if (blocks.length > 0) {
    issues.push(
      `${path}: a widget install's acceptance spec may not sit on a hard-block or auth-named path (${blocks.join(", ")})`,
    );
  }
  return issues;
}

/** Spec text each install must prove, as a marker the contents must contain. */
const SPEC_MARKERS: ReadonlyArray<{ what: string; pattern: RegExp }> = [
  { what: "signed out → 401", pattern: /\b401\b/ },
  {
    what: "signed in → a token whose cid is the user's customer",
    pattern: /\bcid\b/,
  },
  {
    what: "the widget script on a signed-in page",
    pattern: /data-fda-identity-endpoint|widget\.js/,
  },
];

/**
 * Why a widget-install intent is not in the fixed shape (decision 0026).
 * Judged on the stored intent, so an operator's edit that widens it is
 * refused the same way as a drafter's draft.
 */
export function widgetInstallIntentIssues(
  intent: Pick<
    Intent,
    | "fda_initiative"
    | "affected_files"
    | "scope"
    | "variant"
    | "existing_test_updates"
    | "impact"
    | "acceptance_specs"
  >,
): string[] {
  const initiative = intent.fda_initiative;
  if (!initiative) return [];
  const issues: string[] = [];
  const want = [initiative.identity_route, initiative.layout_file];
  const have = [...new Set(intent.affected_files)];
  if (
    have.length !== want.length ||
    !want.every((path) => have.includes(path))
  ) {
    issues.push(
      `widget install: affected_files must be exactly ${initiative.identity_route} and ${initiative.layout_file} (decision 0026)`,
    );
  }
  if (intent.scope !== "global") {
    issues.push(
      "widget install: the change is for every customer (scope global)",
    );
  }
  if (intent.variant) {
    issues.push("widget install: no variant or flag");
  }
  if ((intent.existing_test_updates ?? []).length > 0) {
    issues.push("widget install: existing security tests are not changed");
  }
  if (!intent.impact.includes("auth")) {
    issues.push(
      "widget install: impact must name auth (the identity route reads the login session)",
    );
  }
  for (const spec of intent.acceptance_specs) {
    if (isInitiativeFile(initiative, spec.path)) {
      issues.push(
        `${spec.path}: an acceptance spec may not be one of the install's two files`,
      );
    }
    issues.push(...widgetInstallSpecPathIssues(spec.path));
  }
  const missing = SPEC_MARKERS.filter(
    ({ pattern }) =>
      !intent.acceptance_specs.some((spec) => pattern.test(spec.contents)),
  );
  if (missing.length > 0) {
    issues.push(
      `widget install: acceptance specs must cover ${missing.map((m) => m.what).join("; ")}`,
    );
  }
  return issues;
}

/**
 * Why a widget-install patch is not in the fixed shape (decision 0026): the
 * identity route added, the layout modified, the acceptance specs added
 * (test files off every hard-block path), and nothing else: no other file,
 * no rename, no dependency change. The
 * build passes the spec paths it wrote; a caller that passes none fails
 * closed on them.
 */
export function widgetInstallPatchIssues(
  manifest: PatchManifest,
  initiative: FdaInitiative,
  specPaths: ReadonlySet<string>,
): string[] {
  const issues: string[] = [];
  const only = `a widget install may only add ${initiative.identity_route}, modify ${initiative.layout_file} and add its acceptance specs (decision 0026)`;
  for (const file of manifest.files) {
    if (file.from !== undefined || file.status === "renamed") {
      issues.push(`${file.path}: renames are not part of a widget install`);
      continue;
    }
    if (file.path === initiative.identity_route) {
      if (file.status !== "added") {
        issues.push(
          `${file.path}: the identity route must be a new file (was ${file.status})`,
        );
      }
    } else if (file.path === initiative.layout_file) {
      if (file.status !== "modified") {
        issues.push(
          `${file.path}: the layout may only be modified (was ${file.status})`,
        );
      }
    } else if (specPaths.has(file.path)) {
      if (file.status !== "added") {
        issues.push(
          `${file.path}: an acceptance spec may only be added (was ${file.status})`,
        );
      }
      issues.push(...widgetInstallSpecPathIssues(file.path));
    } else {
      issues.push(`${file.path}: ${only}`);
    }
  }
  if (manifest.dependency_changes.length > 0) {
    issues.push("a widget install adds no dependencies");
  }
  return issues;
}
