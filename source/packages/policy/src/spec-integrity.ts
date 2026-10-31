import { createHash } from "node:crypto";

import type { PatchManifest } from "@fda/contracts";

// Decision 0027: one spec-integrity rule for the build's gate and for the
// customer's verdict check. The build reads the files it wrote back from the
// workspace; the verifier reads blobs at `P`. Both hand this the digests they
// saw, so neither carries its own comparison.

/** SHA-256 hex of a spec's exact UTF-8 bytes (a string is UTF-8 encoded). */
export function specDigest(contents: string | Uint8Array): string {
  return createHash("sha256").update(contents).digest("hex");
}

/** A spec as approved: its path and the digest of its approved contents. */
export interface ExpectedSpec {
  path: string;
  sha256: string;
}

/** What a checker found at a spec path. */
export type SpecObservation =
  | { kind: "missing" }
  /** A symlink, directory, gitlink, or a path whose parent is not a plain directory. */
  | { kind: "not_regular" }
  | { kind: "file"; sha256: string };

/**
 * Why the specs on disk (or in a tree) are not the approved specs: missing,
 * changed, not a regular file, or renamed away in the patch. An unobserved
 * path counts as missing. Empty means every spec is intact.
 */
export function specIntegrityIssues(
  specs: readonly ExpectedSpec[],
  observed: ReadonlyMap<string, SpecObservation>,
  manifest: Pick<PatchManifest, "files">,
): string[] {
  const reasons: string[] = [];
  for (const spec of specs) {
    const seen = observed.get(spec.path) ?? { kind: "missing" };
    if (seen.kind === "missing") {
      reasons.push(
        `${spec.path}: acceptance spec was removed after FDA wrote it`,
      );
    } else if (seen.kind === "not_regular") {
      reasons.push(`${spec.path}: acceptance spec is not a regular file`);
    } else if (seen.sha256 !== spec.sha256) {
      reasons.push(
        `${spec.path}: acceptance spec was changed after FDA wrote it`,
      );
    }
    if (manifest.files.some((file) => file.from === spec.path)) {
      reasons.push(`${spec.path}: acceptance spec was renamed`);
    }
  }
  return reasons;
}
