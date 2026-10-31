const globCache = new Map<string, RegExp>();

function globToRegExp(glob: string): RegExp {
  const cached = globCache.get(glob);
  if (cached) return cached;

  let source = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*") {
      if (glob[index + 1] === "*") {
        index += 1;
        if (glob[index + 1] === "/") {
          index += 1;
          source += "(?:.*/)?";
        } else {
          source += ".*";
        }
      } else {
        source += "[^/]*";
      }
    } else if (character === "?") {
      source += "[^/]";
    } else {
      source += character?.replace(/[\\^$+?.()|{}[\]]/g, "\\$&") ?? "";
    }
  }
  const expression = new RegExp(`${source}$`);
  globCache.set(glob, expression);
  return expression;
}

/** Minimal minimatch-compatible matching for `**`, `*`, and `?`. */
export function matchesGlob(path: string, glob: string): boolean {
  return globToRegExp(glob).test(path);
}

export function matchesAny(path: string, globs: readonly string[]): boolean {
  return globs.some((glob) => matchesGlob(path, glob));
}

export function isSafeRepoPath(path: string): boolean {
  return (
    path.length > 0 &&
    !path.startsWith("/") &&
    !path.includes("\\") &&
    !path.includes("\0") &&
    !path.split("/").includes("..")
  );
}

export function pathScopeIssues(
  path: string,
  allowedPaths: readonly string[],
  protectedPaths: readonly string[],
): string[] {
  const issues: string[] = [];
  if (!isSafeRepoPath(path)) issues.push(`${path}: path is not repo-relative`);
  if (!matchesAny(path, allowedPaths)) {
    issues.push(`${path}: path is outside allowed paths`);
  }
  if (matchesAny(path, protectedPaths)) {
    issues.push(`${path}: path is protected`);
  }
  return issues;
}
