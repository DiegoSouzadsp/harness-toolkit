import { readFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  flagsDir,
  machineConfigPath,
  projectConfigPath,
  projectStateDir,
  runtimeStateDir,
} from "../../platform/paths.ts";
import { normalizeSeparators } from "../../platform/sanitize.ts";

export function expandHome(text: string, home = homedir()): string {
  if (text === "~") {
    return home;
  }
  return text.startsWith(`~${sep}`) || text.startsWith("~/") ? resolve(home, text.slice(2)) : text;
}

export function resolveTarget(projectDir: string, word: string, home = homedir()): string {
  return resolveFrom(projectDir, word, home);
}

// why: `resolveTarget` names the shape every existing caller already uses — one fixed base. AD-146's `cd`/`-C`
// tracking resolves the same word against several candidate bases in turn (the project root plus every cwd a
// `cd`/`pushd`/`git -C` earlier in the command could have reached), so the base itself has to be a parameter.
export function resolveFrom(base: string, word: string, home = homedir()): string {
  const expanded = expandHome(word, home);
  return isAbsolute(expanded) ? resolve(expanded) : resolve(base, expanded);
}

/**
 * The main checkout of a linked git worktree, or `null` when `dir` is not one.
 *
 * why: a linked worktree's own `.git` is a file naming `gitdir: <path>`, and that directory's `commondir` file
 * names the shared `.git` every worktree of the same repository points at — the same two markers `git` itself
 * reads to answer the question. Nothing here shells out to `git`: the floor decides before any process is worth
 * spawning, and both markers are small, fixed-format files ([/decisions/ad-146.md](/decisions/ad-146.md)).
 * invariant: a missing or malformed marker resolves to "not a linked worktree" rather than guessed — the same
 * prove-safe posture as every other read in this module.
 */
function readWorktreeMarker(dir: string): string | null {
  let marker: string;
  try {
    marker = readFileSync(join(dir, ".git"), "utf8");
  } catch {
    return null;
  }
  const gitdirText = /^gitdir:\s*(.+?)\s*$/m.exec(marker)?.[1];
  if (!gitdirText) {
    return null;
  }
  const gitdir = resolve(dir, gitdirText);
  let commondirText: string;
  try {
    commondirText = readFileSync(join(gitdir, "commondir"), "utf8");
  } catch {
    return null;
  }
  const root = dirname(resolve(gitdir, commondirText.trim()));
  return root === resolve(dir) ? null : root;
}

// why: `checkPolicySurface` calls `mainWorktreeOf` once per candidate root per word it resolves, and a hook
// evaluates a floor decision on every tool call — the two on-disk reads this does are cheap once, not free
// on every call. A directory's worktree relationship does not change mid-process, so a per-process cache is
// exact, not an approximation ([/decisions/ad-146.md](/decisions/ad-146.md)).
const MAIN_WORKTREE_CACHE = new Map<string, string | null>();

export function mainWorktreeOf(dir: string): string | null {
  const key = resolve(dir);
  const cached = MAIN_WORKTREE_CACHE.get(key);
  if (cached !== undefined) {
    return cached;
  }
  const result = readWorktreeMarker(dir);
  MAIN_WORKTREE_CACHE.set(key, result);
  return result;
}

export function isInside(parent: string, child: string): boolean {
  const rel = relative(resolve(parent), resolve(child));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

// why: scratch space is where an agent is supposed to make a mess, so destruction there is not a floor
// concern even though it sits outside the project.
export function isScratch(target: string, tmp = tmpdir()): boolean {
  return isInside(tmp, target);
}

// hazard: the runtime config is merged by `loadPolicy` under the project one, so a field the project does
// not set is decided there — for every repository on the machine. Guarding only the project paths left
// `echo '{}' > ~/.tlc/harness/config.json` allowed, which is the same defect one directory up.
export function isRuntimePolicySurface(filePath: string): boolean {
  const target = resolve(filePath);
  return target === resolve(machineConfigPath()) || isInside(runtimeStateDir(), target);
}

// why: a provider's wiring target (its own editor's user-level hook/settings document) lives outside the
// project and outside the runtime home, so neither existing branch of isPolicySurface would ever match it.
// A protected path is matched by containment, not equality, so a provider that ever declares a directory
// target covers every file written under it.
export function isProtectedWiringTarget(target: string, protectedPaths: readonly string[]): boolean {
  const resolved = resolve(target);
  return protectedPaths.some((path) => isInside(resolve(path), resolved));
}

// invariant: the policy surface is defined here, next to the floor's other path predicates, because the
// floor decides before any policy is read. Defining it inside the policy module would point the dependency
// backwards — against the order the two actually run in.
export function isPolicySurface(
  projectDir: string,
  filePath: string,
  extraSurfacePaths: readonly string[] = [],
): boolean {
  if (isRuntimePolicySurface(filePath)) {
    return true;
  }
  if (isProtectedWiringTarget(filePath, extraSurfacePaths)) {
    return true;
  }
  const target = normalizeSeparators(relative(projectDir, filePath) || filePath);
  const config = normalizeSeparators(relative(projectDir, projectConfigPath(projectDir)));
  const flags = normalizeSeparators(relative(projectDir, flagsDir(projectDir)));
  const state = normalizeSeparators(relative(projectDir, projectStateDir(projectDir)));
  return target === config || target.startsWith(`${flags}/`) || target.startsWith(`${state}/`);
}

const SECRET_HOME_DIRS = [".ssh", ".aws", ".kube", ".gnupg", ".docker", ".config/gh", ".config/gcloud"];
const SECRET_BASENAMES = new Set([
  ".git-credentials",
  ".netrc",
  ".npmrc",
  ".pgpass",
  "credentials",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "id_rsa",
]);
const SECRET_SUFFIXES = [".pem", ".p12", ".pfx"];
// invariant: these are templates checked into repos on purpose — treating them as secrets would
// block ordinary work and teach the operator to distrust the floor.
const ENV_TEMPLATE_SUFFIXES = [".example", ".sample", ".template", ".dist"];

function isEnvFile(name: string): boolean {
  if (name !== ".env" && !name.startsWith(".env.")) {
    return false;
  }
  return !ENV_TEMPLATE_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

export function isSecretPath(target: string, home = homedir()): boolean {
  const name = basename(target);
  if (isEnvFile(name) || SECRET_BASENAMES.has(name)) {
    return true;
  }
  if (SECRET_SUFFIXES.some((suffix) => name.endsWith(suffix))) {
    return true;
  }
  return SECRET_HOME_DIRS.some((dir) => isInside(resolve(home, dir), target));
}
