import { z } from "zod";

import { repoPathSchema } from "./common.js";

export const PATCH_FILE_STATUSES = [
  "added",
  "modified",
  "deleted",
  "renamed",
] as const;
export const DEPENDENCY_CHANGE_KINDS = ["manifest", "lockfile"] as const;

export const patchFileSchema = z
  .strictObject({
    path: repoPathSchema,
    status: z.enum(PATCH_FILE_STATUSES),
    /** The old path; present exactly when `status` is `renamed`. */
    from: repoPathSchema.optional(),
    additions: z.int().min(0),
    deletions: z.int().min(0),
    /** Git file mode, e.g. `100644`. */
    mode: z.string().regex(/^[0-7]{6}$/, "expected a 6-digit git file mode"),
  })
  .refine((file) => (file.status === "renamed") === (file.from !== undefined), {
    message: "`from` is required for renames and only for renames",
    path: ["from"],
  });

/**
 * A dependency change seen in the diff. `name`/`from`/`to` are set when they
 * could be parsed from a `package.json` diff.
 */
export const dependencyChangeSchema = z.strictObject({
  path: repoPathSchema,
  kind: z.enum(DEPENDENCY_CHANGE_KINDS),
  name: z.string().min(1).max(214).optional(),
  from: z.string().min(1).max(200).optional(),
  to: z.string().min(1).max(200).optional(),
});

export const patchManifestSchema = z
  .strictObject({
    files: z.array(patchFileSchema),
    dependency_changes: z.array(dependencyChangeSchema),
    total_lines: z.int().min(0),
  })
  .superRefine((manifest, ctx) => {
    const paths = manifest.files.map((file) => file.path);
    if (new Set(paths).size !== paths.length) {
      ctx.addIssue({
        code: "custom",
        message: "a path appears more than once",
        path: ["files"],
      });
    }
    const sum = manifest.files.reduce(
      (total, file) => total + file.additions + file.deletions,
      0,
    );
    if (sum !== manifest.total_lines) {
      ctx.addIssue({
        code: "custom",
        message: `total_lines must equal additions + deletions (${sum})`,
        path: ["total_lines"],
      });
    }
  });

export type PatchFile = z.infer<typeof patchFileSchema>;
export type DependencyChange = z.infer<typeof dependencyChangeSchema>;
export type PatchManifest = z.infer<typeof patchManifestSchema>;
