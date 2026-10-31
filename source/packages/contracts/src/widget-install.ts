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
export const widgetInstallPlanSchema = z.strictObject({
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
    matched_customer_external_ids: z.array(z.string().min(1).max(200)).max(50),
  }),
  /** The field on the session value that is the signed-in user's id. */
  user_id_field: evidenceSchema.extend({
    expression: z.string().min(1).max(200),
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
});
export type WidgetInstallPlan = z.infer<typeof widgetInstallPlanSchema>;

export const WIDGET_INSTALL_STOP_REASONS = [
  "no_customers",
  "not_node_typescript",
  "unsupported_framework",
  "no_layout",
  "no_session_helper",
  "no_customer_field",
  "already_installed",
  "investigation_failed",
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
export const fdaInitiativeSchema = z.strictObject({
  kind: z.literal(WIDGET_INSTALL_CONTEXT_KIND),
  identity_route: repoPathSchema,
  layout_file: repoPathSchema,
});
export type FdaInitiative = z.infer<typeof fdaInitiativeSchema>;

/** The plan's two files as the initiative the intent and task carry. */
export function initiativeFromPlan(
  plan: Pick<WidgetInstallPlan, "identity_route" | "layout_file">,
): FdaInitiative {
  return {
    kind: WIDGET_INSTALL_CONTEXT_KIND,
    identity_route: plan.identity_route,
    layout_file: plan.layout_file,
  };
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
    case "already_installed":
      return "The app already has the FDA identity route or the widget script tag.";
    case "investigation_failed":
      return "The read-only investigation of the repository did not finish.";
  }
}
