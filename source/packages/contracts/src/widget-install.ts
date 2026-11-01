import { z } from "zod";

import { repoPathSchema } from "./common.js";

// Decision 0026: FDA adds its own widget to the client's app. An admin
// presses one button; FDA opens a request of its own (`requests.source =
// 'system'`, `context.kind = 'widget_install'`), investigates the repository
// read-only, drafts a fixed-template intent, and a human approves it like
// any other. These are the shapes the pipeline, policy and console share.

/** `requests.context.kind` of FDA's own widget-install request. */
export const WIDGET_INSTALL_CONTEXT_KIND = "widget_install";
/** The identity endpoint the widget calls on the client's app. */
export const WIDGET_IDENTITY_PATH = "/api/fda/identity";
/** Environment variable names the client's app reads (never their values). */
export const WIDGET_ENV_KEY_ID = "FDA_ORG_KEY_ID";
export const WIDGET_ENV_SECRET = "FDA_WIDGET_SECRET";

/**
 * What the admin chose, stored on the request's `context`. Written only by
 * the install code path: the widget's intake context is a strict object
 * without `kind`, and operator intake writes `scope_hint` alone, so no text
 * path can produce this marker.
 */
export const widgetInstallContextSchema = z.strictObject({
  kind: z.literal(WIDGET_INSTALL_CONTEXT_KIND),
  repository_id: z.uuid(),
  repository_full_name: z.string().min(1).max(200),
  /** The widget key the app will sign tokens with (`kid` = `iss`). */
  widget_key_kid: z.string().min(1).max(200),
  /** The site origin the key allows, as the admin entered it. */
  site_origin: z.string().min(1).max(2_048),
  /** Where the client's app loads `widget.js` from and sends requests. */
  console_url: z.url().max(2_048),
  /** The operator who pressed the button (also the audit row's actor). */
  started_by: z.uuid(),
});
export type WidgetInstallContext = z.infer<typeof widgetInstallContextSchema>;

export const WIDGET_INSTALL_FRAMEWORKS = ["next-app", "next-pages"] as const;
export const widgetInstallFrameworkSchema = z.enum(WIDGET_INSTALL_FRAMEWORKS);
export type WidgetInstallFramework = z.infer<
  typeof widgetInstallFrameworkSchema
>;

/** How the identity route signs: the app's own `jose`, else Node's crypto. */
export const WIDGET_JWT_LIBRARIES = ["jose", "node:crypto"] as const;

const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * A canonical POSIX repository-relative file path: no leading or trailing
 * slash, no empty, `.` or `..` segment, no segment starting with `-`, no
 * backslash or control character, at most 500 characters. Never normalized:
 * a path that isn't already canonical is refused.
 */
export function isWidgetInstallFilePath(path: string): boolean {
  return (
    path.length > 0 &&
    path.length <= 500 &&
    !CONTROL_CHARS.test(path) &&
    !path.includes("\\") &&
    path
      .split("/")
      .every(
        (segment) =>
          segment !== "" &&
          segment !== "." &&
          segment !== ".." &&
          !segment.startsWith("-"),
      )
  );
}

/** A canonical repository-relative directory; `.` is the repository root. */
export function isWidgetInstallDir(path: string): boolean {
  return path === "." || isWidgetInstallFilePath(path);
}

/** Orders paths by Unicode code point (not UTF-16 unit), as discovery sorts. */
export function compareWidgetInstallPaths(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const x = a.codePointAt(i)!;
    const y = b.codePointAt(j)!;
    if (x !== y) return x < y ? -1 : 1;
    i += x > 0xffff ? 2 : 1;
    j += y > 0xffff ? 2 : 1;
  }
  return a.length - i === b.length - j
    ? 0
    : a.length - i < b.length - j
      ? -1
      : 1;
}

/** A widget-install directory field (`app_root`, `npm_install.root`). */
export const widgetInstallDirSchema = z
  .string()
  .min(1)
  .max(500)
  .refine(isWidgetInstallDir, "expected a canonical repository directory");

/** A package.json script name, as the plan stores it. */
const scriptNameSchema = z
  .string()
  .min(1)
  .max(200)
  .refine((name) => !CONTROL_CHARS.test(name), "expected a script name");

/** Where the app's dependencies install: its own lock, or its npm workspace's. */
export const widgetInstallNpmInstallSchema = z.strictObject({
  root: widgetInstallDirSchema,
  mode: z.enum(["standalone", "workspace"]),
});
export type WidgetInstallNpmInstall = z.infer<
  typeof widgetInstallNpmInstallSchema
>;

const evidenceSchema = z.strictObject({
  path: repoPathSchema,
  line: z.int().min(1),
  /** The line(s) the fact was verified against, cut by code from the file. */
  snippet: z.string().max(2_000),
});

/**
 * What the install needs to know about the app, every item verified by code
 * against the checkout (the file exists, the line exists, the name is on
 * it) before it is accepted. Nothing here is guessed: a missing item stops
 * the install (`WidgetInstallStop`) instead.
 */
export const widgetInstallPlanSchema = z
  .strictObject({
    outcome: z.literal("planned"),
    framework: widgetInstallFrameworkSchema,
    /** The root layout (or `_app`) that wraps every signed-in page. */
    layout_file: repoPathSchema,
    /** The identity route file the build adds; derived from the framework. */
    identity_route: repoPathSchema,
    /** The server-side session helper and the export the route will import. */
    session_helper: evidenceSchema.extend({
      export_name: z.string().min(1).max(200),
      /** How a route reads the signed-in user, in the app's own words. */
      usage: z.string().min(1).max(500),
    }),
    /** The field on the session value that is the customer's external id. */
    customer_field: evidenceSchema.extend({
      expression: z.string().min(1).max(200),
      /**
       * The org's customer external ids the field's literal values matched,
       * when the code lists them; empty when the values aren't literal.
       */
      matched_customer_external_ids: z
        .array(z.string().min(1).max(200))
        .max(50),
    }),
    /**
     * The field on the session value that is the signed-in user's id. When
     * the app's auth library declares it (`library`), the evidence is the
     * repository line that imports that library, not a declaration.
     */
    user_id_field: evidenceSchema.extend({
      expression: z.string().min(1).max(200),
      library: z.string().min(1).max(200).optional(),
    }),
    /** The app's own way to sign in under test; null means a unit test of the token function instead. */
    test_login: evidenceSchema
      .extend({
        export_name: z.string().min(1).max(200),
        usage: z.string().min(1).max(500),
      })
      .nullable(),
    /** Where the e2e tests give the app its environment (so the specs can read the test secret); null means a unit test instead. */
    test_env: evidenceSchema
      .extend({ usage: z.string().min(1).max(500) })
      .nullable(),
    jwt_library: z.enum(WIDGET_JWT_LIBRARIES),
    /** The runner the e2e specs use, from the repository's scripts and config. */
    e2e_runner: z.enum(["playwright"]).nullable(),
    unit_runner: z.enum(["vitest", "jest", "node:test"]).nullable(),
    /**
     * The application directory FDA selected (`.` for the repository root).
     * This and the next two fields come together on every new plan and are
     * all absent on plans stored before them, which run at the root as before.
     */
    app_root: widgetInstallDirSchema.optional(),
    /** Where `npm ci` runs for this app. */
    npm_install: widgetInstallNpmInstallSchema.optional(),
    /** The app's own package.json scripts the specs run with. */
    test_scripts: z
      .strictObject({
        unit: scriptNameSchema.nullable(),
        e2e: scriptNameSchema.nullable(),
      })
      .optional(),
  })
  .refine(
    (plan) => allOrNone([plan.app_root, plan.npm_install, plan.test_scripts]),
    "app_root, npm_install and test_scripts come together or not at all",
  );
export type WidgetInstallPlan = z.infer<typeof widgetInstallPlanSchema>;

export const WIDGET_INSTALL_STOP_REASONS = [
  "no_customers",
  "not_node_typescript",
  "unsupported_framework",
  "no_layout",
  "no_session_helper",
  "no_customer_field",
  "no_user_id_field",
  "already_installed",
  "investigation_failed",
  "incomplete_repo_map",
  "ambiguous_app_root",
  "unsupported_install_layout",
  "unsupported_test_setup",
] as const;
export const widgetInstallStopReasonSchema = z.enum(
  WIDGET_INSTALL_STOP_REASONS,
);
export type WidgetInstallStopReason = z.infer<
  typeof widgetInstallStopReasonSchema
>;

/** Why FDA stopped before drafting, in a form the console can explain. */
export const widgetInstallStopSchema = z.strictObject({
  outcome: z.literal("stopped"),
  reason: widgetInstallStopReasonSchema,
  detail: z.string().min(1).max(2_000),
  /**
   * Every application directory FDA found when it would not choose between
   * them, sorted and unique; absent on other stops and on older rows.
   */
  candidate_roots: z
    .array(widgetInstallDirSchema)
    .max(2_000)
    .refine(
      (roots) =>
        roots.every(
          (root, i) =>
            i === 0 || compareWidgetInstallPaths(roots[i - 1]!, root) < 0,
        ),
      "expected sorted, unique directories",
    )
    .optional(),
});
export type WidgetInstallStop = z.infer<typeof widgetInstallStopSchema>;

/** Stored on the code-built triage decision (`widget_install`). */
export const widgetInstallOutcomeSchema = z.discriminatedUnion("outcome", [
  widgetInstallPlanSchema,
  widgetInstallStopSchema,
]);
export type WidgetInstallOutcome = z.infer<typeof widgetInstallOutcomeSchema>;

/**
 * The policy input a widget-install intent and its task carry (decision
 * 0026): set by code from the request's `source = 'system'` plus its
 * context, never by a model or an operator. It opens `impact_auth` for
 * exactly these two files and narrows the patch to them plus the specs.
 */
export const fdaInitiativeSchema = z
  .strictObject({
    kind: z.literal(WIDGET_INSTALL_CONTEXT_KIND),
    identity_route: repoPathSchema,
    layout_file: repoPathSchema,
    /** Code-owned execution metadata of new plans; absent on older carriers. */
    app_root: widgetInstallDirSchema.optional(),
    npm_install: widgetInstallNpmInstallSchema.optional(),
  })
  .refine(
    (initiative) => allOrNone([initiative.app_root, initiative.npm_install]),
    "app_root and npm_install come together or not at all",
  );
export type FdaInitiative = z.infer<typeof fdaInitiativeSchema>;

/** The plan's two files as the initiative the intent and task carry. */
export function initiativeFromPlan(
  plan: Pick<
    WidgetInstallPlan,
    "identity_route" | "layout_file" | "app_root" | "npm_install"
  >,
): FdaInitiative {
  return {
    kind: WIDGET_INSTALL_CONTEXT_KIND,
    identity_route: plan.identity_route,
    layout_file: plan.layout_file,
    ...(plan.app_root !== undefined &&
      plan.npm_install !== undefined && {
        app_root: plan.app_root,
        npm_install: { ...plan.npm_install },
      }),
  };
}

function allOrNone(fields: readonly unknown[]): boolean {
  const present = fields.filter((field) => field !== undefined).length;
  return present === 0 || present === fields.length;
}

/** The identity route file for a framework, under its app or pages root. */
export function identityRouteFor(
  framework: WidgetInstallFramework,
  layoutFile: string,
): string {
  // `src/app/layout.tsx` → `src/app/api/fda/identity/route.ts`;
  // `pages/_app.tsx` → `pages/api/fda/identity.ts`.
  const dir = layoutFile.includes("/")
    ? layoutFile.slice(0, layoutFile.lastIndexOf("/"))
    : "";
  const under = (file: string) => (dir ? `${dir}/${file}` : file);
  return framework === "next-app"
    ? under("api/fda/identity/route.ts")
    : under("api/fda/identity.ts");
}

/** Plain words for a stop reason, for the request page and the audit row. */
export function widgetInstallStopText(reason: WidgetInstallStopReason): string {
  switch (reason) {
    case "no_customers":
      return "Add at least one customer first: the widget token names the customer, and FDA matches it against your customers' external ids.";
    case "not_node_typescript":
      return "FDA installs the widget in Node/TypeScript apps only.";
    case "unsupported_framework":
      return "FDA installs the widget in Next.js apps (App Router or Pages Router). Other stacks follow the manual guide.";
    case "no_layout":
      return "FDA could not find the root layout that wraps every signed-in page.";
    case "no_session_helper":
      return "FDA could not find, with evidence, how the app reads the signed-in user on the server.";
    case "no_customer_field":
      return "FDA could not find, with evidence, which field of the session is the customer's external id. It never guesses it.";
    case "no_user_id_field":
      return "FDA could not find, with evidence, which field of the session is the signed-in user's id.";
    case "already_installed":
      return "The app already has the FDA identity route or the widget script tag.";
    case "investigation_failed":
      return "The read-only investigation of the repository did not finish.";
    case "incomplete_repo_map":
      return "FDA could not read the whole repository safely (too many files, or a package file it could not read), so it cannot be sure which app to install into.";
    case "ambiguous_app_root":
      return "The repository has more than one Next.js app (or more than one root layout), and FDA does not choose between them. Follow the manual guide for the app you want.";
    case "unsupported_install_layout":
      return "FDA installs dependencies with npm and the app's package-lock.json only. This app's package manager or lock file is not one FDA supports yet.";
    case "unsupported_test_setup":
      return "FDA could not tell which of the app's test scripts to run the widget specs with.";
  }
}
