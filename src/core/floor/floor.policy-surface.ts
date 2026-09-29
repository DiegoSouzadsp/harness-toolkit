import { homedir } from "node:os";
import { basename, dirname, relative, resolve } from "node:path";
import {
  machineConfigPath,
  machineHome,
  projectConfigPath,
  projectStateDir,
  runtimeStateDir,
} from "../../platform/paths.ts";
import { normalizeSeparators } from "../../platform/sanitize.ts";
import { isInside, isProtectedWiringTarget, mainWorktreeOf, resolveFrom } from "./floor.paths.ts";
import {
  type HeredocChunk,
  heredocChunks,
  type ShellSegment,
  type ShellWord,
  tokenizeShell,
} from "./floor.tokenize.ts";
import { firstOperand, type SegmentHead, verbOf, WRAPPERS } from "./floor.verb.ts";

/**
 * `remedy` is the way out for *this* denial.
 *
 * hazard: every policy-surface refusal used to end with the same sentence — set a gate command, make policy changes
 * from your own terminal. That is advice about *writing* policy, handed to an agent that was trying to *read* the
 * handoff the harness had just told it to read. A refusal a model cannot plan around is the opaque-refusal failure
 * the 2026 tool-use literature names, and it is what confused a colleague's agent
 * ([/decisions/ad-047.md](/decisions/ad-047.md)).
 */
export type PolicySurfaceVerdict =
  | { kind: "allow" }
  | { kind: "deny"; detail: string; note: string; remedy?: string };

const ALLOW: PolicySurfaceVerdict = { kind: "allow" };

// invariant: this is an allowlist on purpose. The set of ways a shell can write a file is unbounded —
// `python3 -c`, `perl -pi`, `ex`, any interpreter — so enumerating writers guarantees a hole. Enumerating
// the readers instead means an unknown verb lands on the deny side without anyone having to predict it.
// hazard: `awk` and `sort` look like readers and are not — `awk '{print > f}'` and `sort -o f` both write a
// file the head verb never reveals. They are left out deliberately.
const PROVEN_READERS = new Set([
  "cat",
  "cmp",
  "diff",
  "echo",
  "file",
  "grep",
  "head",
  "jq",
  "less",
  "ls",
  "md5sum",
  "more",
  "od",
  "printf",
  "rg",
  "sha256sum",
  "stat",
  "strings",
  "tail",
  // why: `test` and `[` evaluate a predicate and produce an exit code. They have no way to write a file at all —
  // no output flag, no redirection of their own — so they are strictly safer than `echo`, which is already here.
  // Their absence was an incomplete allowlist rather than a decision: the harness tells an agent to read the
  // handoff, and `test -f handoff.json && head -c 2000 handoff.json` — the obvious way to do it — was denied
  // ([/decisions/ad-047.md](/decisions/ad-047.md)).
  "test",
  "[",
  "wc",
  "xxd",
]);

// hazard: `git checkout -- <path>`, `git restore` and `git apply` overwrite the working tree, so `git` as a
// whole cannot be a reader. Only the subcommands that provably do not write are allowed.
// why: `rev-parse`, `merge-base`, `rev-list`, `for-each-ref`, `ls-tree`, `describe` and `shortlog` joined this
// set for AD-146 — every one of them answers a question about history or refs and has no form that touches the
// working tree or the index. `branch` is not here: most of its forms read, several of them write, and
// `isReadOnlyBranch` is what tells the two apart ([/decisions/ad-146.md](/decisions/ad-146.md)).
// hazard: `grep` is deliberately *not* here even though it only ever prints matches — `git grep
// --open-files-in-pager=<cmd>` (short form `-O<cmd>`) hands `<cmd>` every matched file as an argument and runs
// it, unrelated to the pager. Confirmed against real git: `git grep --open-files-in-pager=tee -e k -- f`
// truncated `f` to empty. An allowlist member that a real, current git build can be made to write through is
// not a reader ([/decisions/ad-146.md](/decisions/ad-146.md)).
const GIT_READERS = new Set([
  "show",
  "diff",
  "log",
  "status",
  "ls-files",
  "cat-file",
  "blame",
  "rev-parse",
  "merge-base",
  "rev-list",
  "for-each-ref",
  "ls-tree",
  "describe",
  "shortlog",
]);

// hazard: `git diff --output=<path>`, and the same flag on `log`, `show` and `format-patch`, write the path it
// names — a reader subcommand with a writer's own flag. `--output-directory` on `format-patch` is the same
// hazard under a different name and is refused the same way it always was: `format-patch` itself is not in
// `GIT_READERS`, only the four names here can carry `--output` at all.
const OUTPUT_CAPABLE_READERS = new Set(["diff", "log", "show", "format-patch"]);

// why: `cd`, `pushd` and `popd` change the shell's own idea of where it is; none of the three can write a byte
// on their own. C1 ([/decisions/ad-146.md](/decisions/ad-146.md)) allows the segment itself outright — a
// redirect riding on one is still caught by `redirectTargets`, checked before this ever runs.
const CD_VERBS = new Set(["cd", "pushd", "popd"]);

// why: the exact list of git's own global options that take a value before the subcommand — `-C <d>`, `-c
// <k=v>`, `--git-dir[=]`, `--work-tree[=]`, `--namespace[=]`, `--config-env[=]`, `--exec-path[=]`. Each can be
// spelled with the value attached (`--git-dir=x`) or as the following word (`--git-dir x`); only the second
// shape needs a word skipped.
const GIT_GLOBAL_OPTIONS_WITH_VALUE = new Set([
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--config-env",
  "--exec-path",
  // why: documented in `git help git` — added so an ordinary invocation carrying one does not turn opaque
  // (item 6, [/decisions/ad-146.md](/decisions/ad-146.md)). `--list-cmds` is only ever spelled attached
  // (`--list-cmds=list1,list2`) in real git, but the attached/separate-word handling below tolerates either.
  "--super-prefix",
  "--list-cmds",
]);

// why: git's own no-value global options — the rest of the C3 list ([/decisions/ad-146.md](/decisions/ad-146.md)),
// plus `--no-advice` and `--no-lazy-fetch` from `git help git` (item 6) so `git -C <dir> --no-advice log`
// reads its subcommand instead of going opaque over an option this gate had never heard of.
const GIT_GLOBAL_FLAGS = new Set([
  "--no-pager",
  "-p",
  "-P",
  "--paginate",
  "--no-replace-objects",
  "--literal-pathspecs",
  "--glob-pathspecs",
  "--noglob-pathspecs",
  "--icase-pathspecs",
  "--bare",
  "--no-optional-locks",
  "--no-advice",
  "--no-lazy-fetch",
]);

// hazard: `-c core.pager=…` and `--exec-path=…` can point a "reading" subcommand at an arbitrary program —
// git's own pager hook, or a whole alternate `git` binary — so a reader allowance earned by the subcommand name
// alone would miss what these three can change about what actually runs (C4, [/decisions/ad-146.md](/decisions/ad-146.md)).
const GIT_OPAQUE_GLOBAL_OPTIONS = new Set(["-c", "--config-env", "--exec-path"]);

// why: `git branch` lists refs with no arguments and with most of its read-only flags; `-d/-D`, `-m/-M`,
// `-c/-C`, `-f`, `-u`/`--set-upstream-to`, `--unset-upstream`, `--edit-description` and the long forms of
// delete/move/copy/force/track/create-reflog all write. C5 ([/decisions/ad-146.md](/decisions/ad-146.md)) is
// this split, kept as two lists rather than one so a flag neither list knows about is refused, not guessed.
const BRANCH_READ_FLAGS = new Set([
  "--show-current",
  "--list",
  "-l",
  "-a",
  "-r",
  "-v",
  "-vv",
  "--contains",
  "--merged",
  "--no-merged",
  "--format",
  "--sort",
  "--color",
  "--no-color",
  "--column",
  "--no-column",
  "--points-at",
]);
const BRANCH_WRITE_FLAGS = new Set([
  "-d",
  "-D",
  "-m",
  "-M",
  "-c",
  "-C",
  "-f",
  "-u",
  "--set-upstream-to",
  "--unset-upstream",
  "--edit-description",
  "--delete",
  "--move",
  "--copy",
  "--force",
  "--track",
  "--create-reflog",
]);
// why: a positional operand on `branch` (a refname pattern) only reads under a flag that scopes it to a query
// — `--contains`/`--merged`/`--no-merged`/`--points-at` take the operand as the value being queried, and
// `--list`/`-l` take it as a glob to filter listed names. `-a`/`-r`/`-v` list without ever consuming an operand
// that way, so a positional word alongside only one of *those* is unproven, not a listing.
const BRANCH_OPERAND_SAFE_FLAGS = new Set([
  "--list",
  "-l",
  "--contains",
  "--merged",
  "--no-merged",
  "--points-at",
]);

// why: `--ff-only` cannot create a merge commit, cannot diverge history and fails closed the moment a real
// merge would be needed — every file it changes already exists, reachable, in the ref being merged. This is
// the same reasoning `history-rewrite` already applies to `--force-with-lease` over `--force`: a flag that
// removes the operation's own ability to invent content is judged differently from the bare verb. `-q`/
// `--quiet` ride along because they change nothing about what gets written. Any other flag — `--no-ff` forces
// a merge commit, `--abort`/`--quit`/`--continue` operate on a merge already in progress, `-m`/`-s`/`-X`/
// `--squash` all shape what the merge produces — ends the safe reading (C3, item 2, [/decisions/ad-146.md](/decisions/ad-146.md)).
const MERGE_ALLOWED_FLAGS = new Set(["--ff-only", "-q", "--quiet"]);

// hazard: a heredoc is only a program when the verb it feeds executes what it reads. `git commit -F -` and
// `cat <<EOF` take a heredoc that *documents* this path — commit messages and docs in this repository name
// it constantly — so judging a body by "not a proven reader" denied writing about the rule at all.
const EXECUTES_STDIN = new Set([
  "ash",
  "awk",
  "bash",
  "bun",
  "dash",
  "deno",
  "ed",
  "ex",
  "fish",
  "gawk",
  "ksh",
  "lua",
  "node",
  "perl",
  "php",
  "python",
  "python2",
  "python3",
  "ruby",
  "sed",
  "sh",
  "tclsh",
  "zsh",
]);

const HARNESS_BINS = new Set(["tlc", "tlc.cmd"]);
// why: `policy` is here for the sharpest reason of any of them — `tlc harness policy accept` exists to clear a
// tampering signal, so an agent that could reach it would make the whole integrity rail decorative. It is refused
// by a floor rule with no config switch, exactly like the rest ([/decisions/ad-030.md](/decisions/ad-030.md)).
const MUTATING_SUBCOMMANDS = new Set(["pause", "resume", "reset", "grind", "mode", "init", "gate", "policy"]);

function deny(detail: string, note: string, remedy?: string): PolicySurfaceVerdict {
  return { kind: "deny", detail, note, ...(remedy ? { remedy } : {}) };
}

/**
 * The route that does work, named in the refusal itself.
 *
 * why: reading harness state is ordinary work the bootstrap asks for by name, so a refusal on that path has to say
 * how to do it rather than what not to do. The command exists so nothing has to reach into the protected path at
 * all — an instruction that points at a path the floor guards is three layers disagreeing.
 */
export const READ_REMEDY =
  // hazard: this said "`tlc harness policy` for the resolved policy". That command reports a policy that changed
  // out of band and prints nothing about the resolved values, so an agent that followed the advice learned nothing
  // and had no other route — measured, it cost a working session. `status` answers posture and gates; the resolved
  // values are read from the file, which the proven readers are allowed to do
  // ([/decisions/ad-100.md](/decisions/ad-100.md)).
  "Reading is allowed: run `tlc harness handoff` for handoff state, `tlc harness status` for posture and gates, `tlc harness doctor` for what the settings amount to, or use a proven reader (cat, head, jq, grep, ls, stat, test) on the path.";

// why: the harness directory prefix is derived from the path module rather than written as a literal, so a
// change to the on-disk layout cannot leave this rule matching a path that no longer exists. The relative
// form is what appears in commands, and an absolute path contains it too.
function harnessPrefix(projectDir: string): string {
  const state = normalizeSeparators(relative(projectDir, projectStateDir(projectDir)));
  return state.slice(0, state.lastIndexOf("/"));
}

// hazard: the incident's command hid the path inside `python3 -c "...open('.tlc/harness/config.json','w')"`,
// which tokenizes as one word that resolves to nothing. Reasoning about the nested quoting is the
// weak-parser trap the floor refuses elsewhere, so the text is only asked whether the surface is named at
// all — and that question is only asked of verbs that were not proven to be readers.
function namesSurface(prefix: string, segment: ShellSegment): boolean {
  const text = normalizeSeparators(segment.words.map((word) => word.text).join(" "));
  return text.includes(prefix);
}

// why: the two paths `overlapsRoot` checks a resolved word against, kept together so they are computed once
// per root instead of once per `overlapsRoot` call — a command with several words and several tracked cwd
// candidates calls it dozens of times over the same handful of roots.
type RootSurface = { root: string; config: string; state: string };

/**
 * The one-time, per-command lookups every rule below shares: the prefix `namesSurface`/unresolved words match
 * literally, the roots (`projectDir`, plus a linked worktree's main checkout) with their config/state paths
 * already joined, and the runtime surface's own resolved paths. Computed once in `checkPolicySurface` and
 * threaded down — `mainWorktreeOf` reads two files from disk, and `resolve`/`relative` are not free at the
 * call count a many-word command with several tracked cwd candidates reaches
 * ([/decisions/ad-146.md](/decisions/ad-146.md); item 4 measured this at ~20ms for a 16-word command before
 * the roots and the runtime surface were hoisted out of the per-root, per-word path).
 */
type SurfaceContext = {
  projectDir: string;
  prefix: string;
  roots: readonly RootSurface[];
  runtimeConfig: string;
  runtimeState: string;
  home: string;
  machineContainer: string;
  extraSurfacePaths: readonly string[];
};

function rootSurface(root: string): RootSurface {
  return { root, config: projectConfigPath(root), state: projectStateDir(root) };
}

// why: a project's own harness dir is named `harness`, one level under a container named `.tlc` — read here
// from `projectStateDir`'s own layout rather than written as a second copy of those two literals, so the
// convention check below can never drift from what the paths module actually produces.
function conventionalNames(projectDir: string): { harness: string; container: string } {
  const harnessDir = dirname(projectStateDir(projectDir));
  return { harness: basename(harnessDir), container: basename(dirname(harnessDir)) };
}

// why: `dirname(machineHome())` is only a meaningful "container" when `machineHome()` itself has the
// conventional shape — `<container>/harness`, e.g. `~/.tlc/harness`. An operator's own `$TLC_HOME`
// (`TLC_HOME_FROM_ENV` unset or `"1"`, meaning it *was* an operator's choice, not `tlc-exec`'s own fallback)
// can be anything — `~/tlc`, `D:/tlc` — and taking its parent as a container swept in the operator's entire
// home directory or entire drive as a no-`cd` zone. When the shape does not match, `machineHome()` itself is
// the narrowest correct container — the exact path the harness reads and writes, not a guess at its parent
// (item 2, [/decisions/ad-146.md](/decisions/ad-146.md)).
function machineContainerOf(projectDir: string): string {
  const home = machineHome();
  const names = conventionalNames(projectDir);
  const isConventional = basename(home) === names.harness && basename(dirname(home)) === names.container;
  return isConventional ? dirname(home) : home;
}

// why: a linked worktree's own surface is not the only one a command run inside it can reach — its main
// checkout's `.tlc/harness` is a policy surface too (C7, [/decisions/ad-146.md](/decisions/ad-146.md)), reached
// by `-C`/`cd`-ing there or simply naming it. `projectDir` is always first, so a plain project loses nothing.
function surfaceContext(projectDir: string, extraSurfacePaths: readonly string[]): SurfaceContext {
  const main = mainWorktreeOf(projectDir);
  const roots = (main === null ? [resolve(projectDir)] : [resolve(projectDir), main]).map(rootSurface);
  return {
    projectDir,
    prefix: harnessPrefix(projectDir),
    roots,
    runtimeConfig: resolve(machineConfigPath()),
    runtimeState: runtimeStateDir(),
    home: resolve(homedir()),
    machineContainer: resolve(machineContainerOf(projectDir)),
    extraSurfacePaths,
  };
}

// why: the surface and the target overlap when either contains the other. Containment in the second
// direction is what catches `rm -rf .tlc/harness/state`, which removes the flags without ever naming one —
// and, deliberately, also what catches a linked worktree's main checkout *containing* the worktree's own
// surface: `git -C <main> clean -fdx` or `checkout -- .` run there can delete or overwrite anything under
// `<main>`, including a nested worktree's checkout, so a resolved path that is merely an ancestor of the
// surface is still treated as reaching it ([/decisions/ad-146.md](/decisions/ad-146.md)). Only `root` itself is
// excluded, so `find .` and `grep -r x .` stay untouched; nothing above `root` is.
function overlapsRoot(surface: RootSurface, resolved: string): boolean {
  if (resolved === surface.root) {
    return false;
  }
  // hazard: this compared `resolved === surface.config` — plain string equality, case-sensitive even on
  // Windows, where the real filesystem is not. `echo x > .TLC/HARNESS/config.json` resolves to a path that
  // differs from `surface.config` only in case and reached a real file all the same, unguarded. `isInside`
  // goes through `relative`/`resolve`, which fold case the way the platform's own filesystem does — restored
  // here even though it costs one path op over the equality check it replaces (item 4, [/decisions/ad-146.md](/decisions/ad-146.md)).
  // why: `config` and `state` are siblings under the same harness directory, so every ancestor that reaches
  // one reaches the other through that shared parent — `isInside(resolved, surface.config)` never catches a
  // case `isInside(resolved, surface.state)` does not, and skipping it halves the ancestor-direction cost.
  return (
    isInside(surface.config, resolved) ||
    isInside(surface.state, resolved) ||
    isInside(resolved, surface.state)
  );
}

// why: the runtime surface and any provider wiring targets are the same regardless of which root is being
// checked, so they are asked once per resolved word, not once per root — the loop below only has to tell
// *this project's* surface apart from *the other project's*.
function overlapsSurface(ctx: SurfaceContext, resolved: string): boolean {
  // why: `resolved` inside the runtime state dir is the direct case — a file the harness itself writes under
  // `~/.tlc/harness/state`.
  if (resolved === ctx.runtimeConfig || isInside(ctx.runtimeState, resolved)) {
    return true;
  }
  // hazard: the ancestor direction (`resolved` an ancestor of the runtime state dir, restored so `cd ~/.tlc`
  // is caught) counted `$HOME` itself, and everything above it, as an ancestor too — `find ~ -name x.log` and
  // `cp notes.txt ~` denied on any machine whose runtime home is conventionally nested under `$HOME`, which
  // is the common case. `$HOME` gets the same exemption `resolved === root` already gives a project's own
  // root: only a path *strictly inside* home, and still an ancestor of (or equal to) the runtime state dir —
  // `~/.tlc`, `~/.tlc/harness` — counts (item 4, [/decisions/ad-146.md](/decisions/ad-146.md)).
  if (resolved !== ctx.home && isInside(ctx.home, resolved) && isInside(resolved, ctx.runtimeState)) {
    return true;
  }
  if (isProtectedWiringTarget(resolved, ctx.extraSurfacePaths)) {
    return true;
  }
  return ctx.roots.some((surface) => overlapsRoot(surface, resolved));
}

// why: C2 ([/decisions/ad-146.md](/decisions/ad-146.md)) resolves a relative word against every cwd a
// `cd`/`pushd` earlier in the command could have reached, not only the project root — `bases` always contains
// at least `projectDir`, so a command with no `cd` in it resolves exactly as before.
function referencesSurface(ctx: SurfaceContext, bases: readonly string[], word: ShellWord): boolean {
  if (word.text === "") {
    return false;
  }
  // hazard: an unresolved word carries a `$var` or `$(...)`, so its value is unknowable here. Matching the
  // literal portion catches `> .tlc/harness/$f`; a fully computed path stays out of reach and is what the
  // per-session integrity baseline exists to catch.
  if (word.unresolved) {
    const normalized = normalizeSeparators(word.text);
    if (normalized.includes(ctx.prefix)) {
      return true;
    }
    return ctx.extraSurfacePaths.some((path) => normalized.includes(normalizeSeparators(path)));
  }
  return bases.some((base) => overlapsSurface(ctx, resolveFrom(base, word.text)));
}

// why: a redirect target is not an argument of the head verb, so argument scanning alone would allow
// `cat x > config.json` — the head verb there is a proven reader. Both the spaced and the attached forms
// have to be read, because `>f`, `>>f` and `x>f` all tokenize as a single word.
const REDIRECT_OPERATOR = />{1,2}\|?/g;

function redirectTargets(words: ShellWord[]): ShellWord[] {
  const targets: ShellWord[] = [];
  for (let index = 0; index < words.length; index += 1) {
    const word = words[index];
    // hazard: a `>` inside a quoted argument is literal text, not a redirect. Scanning quoted words denied
    // commands that merely carry shell-looking data — a JSON hook payload, a fixture, a doc example.
    if (!word || word.quotedStart) {
      continue;
    }
    // hazard (round 7): a word can carry more than one `>`/`>>` once the tokenizer folds a dropped `&` into
    // it — `2>&1>file` tokenizes to the one word `2>1>file`. Reading only the first operator (the old
    // `.exec`) reported `1>file` as a single opaque target and never looked past the first `>`, so the real
    // write target — the text after the SECOND `>`, confirmed against real bash to be the one that actually
    // receives the write — went unread. Every operator in the word is walked in order and every non-empty
    // fragment between one operator and the next (or after the last one) is reported as its own target;
    // naming a fragment that never turns out to be a real filename (`1`) costs nothing, silently dropping one
    // that is does.
    const operators = [...word.text.matchAll(REDIRECT_OPERATOR)];
    for (let opIndex = 0; opIndex < operators.length; opIndex += 1) {
      const operator = operators[opIndex];
      if (!operator) {
        continue;
      }
      const opEnd = (operator.index ?? 0) + operator[0].length;
      const isLastOperator = opIndex === operators.length - 1;
      const nextOperator = operators[opIndex + 1];
      const fragmentEnd = isLastOperator ? word.text.length : (nextOperator?.index ?? word.text.length);
      const fragment = word.text.slice(opEnd, fragmentEnd);
      if (fragment !== "") {
        targets.push({ text: fragment, unresolved: word.unresolved, quotedStart: false });
        continue;
      }
      if (!isLastOperator) {
        continue;
      }
      const next = words[index + 1];
      if (next) {
        targets.push(next);
        index += 1;
      }
    }
  }
  return targets;
}

function harnessSubcommand(args: ShellWord[]): string | null {
  const operands = args.filter((word) => !word.text.startsWith("-") && word.text !== "");
  if (operands[0]?.text.toLowerCase() !== "harness") {
    return null;
  }
  // why: `route()` defaults a missing subcommand to `status`, so bare `tlc harness` reads state and is
  // not a mutation.
  return (operands[1]?.text ?? "status").toLowerCase();
}

// why: split out of `checkSegment` so the mutating-subcommand check is one flat condition there instead of an
// `if` nested inside an `if` — cognitive complexity counts nesting, and this function is called by only one
// caller, unlike every other rule in this file.
function checkHarnessBin(head: SegmentHead | null): PolicySurfaceVerdict | null {
  if (!head || !HARNESS_BINS.has(head.verb)) {
    return null;
  }
  const subcommand = harnessSubcommand(head.args);
  if (subcommand === null || !MUTATING_SUBCOMMANDS.has(subcommand)) {
    return null;
  }
  return deny(
    `\`tlc harness ${subcommand}\` changes harness policy, and policy is the operator's to change.`,
    `tlc harness ${subcommand}`,
  );
}

// why: a bare flag (`-l`) and its `=`-attached form (`--sort=-committerdate`) both name the same option; only
// the part before `=` decides which list it falls in.
function bareFlag(word: ShellWord): string {
  return word.text.split("=")[0] ?? word.text;
}

// hazard: `git branch` with no arguments lists refs, same as `--list` — treating an empty flag set as
// unproven-write would refuse the plainest form there is. Any flag `BRANCH_WRITE_FLAGS` names ends it right
// there; everything else has to be a flag `BRANCH_READ_FLAGS` already knows, or the form is unproven and the
// caller's default (not a reader) applies (C5, [/decisions/ad-146.md](/decisions/ad-146.md)).
// hazard: a *positional* operand (`git branch <pattern-or-path>`) additionally needs one of
// `BRANCH_OPERAND_SAFE_FLAGS` present — `git branch --show-current .tlc/harness/config.json` has a read flag
// and an operand that flag never consults, and the operand is what would matter if `branch` ever grew a form
// that writes to a named path.
function isReadOnlyBranch(args: ShellWord[]): boolean {
  const flags = args.filter((word) => word.text.startsWith("-"));
  const hasOperand = args.some((word) => !word.text.startsWith("-") && word.text !== "");
  if (flags.some((word) => BRANCH_WRITE_FLAGS.has(bareFlag(word)))) {
    return false;
  }
  if (hasOperand && !flags.some((word) => BRANCH_OPERAND_SAFE_FLAGS.has(bareFlag(word)))) {
    return false;
  }
  return flags.every((word) => BRANCH_READ_FLAGS.has(bareFlag(word)));
}

// why: a location that is itself a tracked root, or an ancestor of one (a linked worktree's main checkout is
// both, relative to different roots), is where `git merge x` in *that* checkout would already be allowed by
// this gate on its own — no word in a plain `git merge x` names any surface. A location that is merely
// *inside* a root, at or above its own `.tlc/harness`, is not: running there is not equivalent to an ordinary
// merge anywhere else, it is a merge whose working tree the harness itself owns (item 2, [/decisions/ad-146.md](/decisions/ad-146.md)).
function isRootReachable(ctx: SurfaceContext, resolved: string): boolean {
  return ctx.roots.some((surface) => isInside(resolved, surface.root));
}

// why: `--ff-only` is the one flag that makes `merge` provably unable to write anything beyond what a
// fast-forward moves the branch pointer onto — a ref already reachable, already in the object database — and
// only when nothing else rides along and exactly one ref is named, itself not naming the surface, and the
// merge runs from a root or an ancestor of one rather than from inside the surface itself. This is an
// explicit trade-off, not a general "ff-only is safe" rule: a fast-forward at a root updates the tree with
// content already committed, the same as the plain `git merge x` this gate already allows in a project that
// never cites the surface at all — whether *that* content should have reached this machine is the concern of
// the integrity baseline a commit lands through, not the floor (C3, item 2, [/decisions/ad-146.md](/decisions/ad-146.md)).
function isFastForwardOnlyMerge(
  ctx: SurfaceContext,
  locatedBases: readonly string[],
  args: ShellWord[],
): boolean {
  const flags = args.filter((word) => word.text.startsWith("-"));
  const operands = args.filter((word) => !word.text.startsWith("-") && word.text !== "");
  if (!flags.some((word) => word.text === "--ff-only")) {
    return false;
  }
  if (!flags.every((word) => MERGE_ALLOWED_FLAGS.has(word.text))) {
    return false;
  }
  if (operands.length !== 1) {
    return false;
  }
  const ref = operands[0];
  if (ref === undefined || referencesSurface(ctx, locatedBases, ref)) {
    return false;
  }
  // why: `every`, not `some` — every candidate base the invocation might actually be running from has to be a
  // root or an ancestor of one. `some` let a single root-reachable candidate vouch for the whole set even when
  // another candidate was the surface's own directory, which is exactly the side door item 3 closes: `cd
  // .tlc/harness && git merge --ff-only evil` is already denied by item 1's container check on the `cd`
  // itself, but this gate has to hold on its own terms too, not merely because something upstream happened to
  // catch the same command first ([/decisions/ad-146.md](/decisions/ad-146.md)).
  return locatedBases.every((base) => isRootReachable(ctx, base));
}

type GitInvocation = { subcommand: string; rest: ShellWord[]; opaque: boolean; locations: string[] };

// why: a global option consumes either just itself (`=`-attached, or a value-less flag) or itself plus the
// next word (a separate-word value) — one number the loop in `gitInvocation` can act on without re-deriving it.
type GitGlobalOption = { words: number; opaque: boolean };

// why: split out of `gitInvocation` so classifying one word is one flat set of conditions, not three arms of a
// loop that also has to track an index and an accumulator — cognitive complexity counts both together.
// hazard: a global option this list has never heard of is not skipped as if it were a no-op flag — real git
// options taking a value this parser does not know about (`--attr-source <v>`, confirmed against a real
// build) would otherwise have their value word misread as the subcommand. An option outside every known list
// makes the whole invocation opaque, which only matters once the segment already cites the surface — a plain
// `git --attr-source HEAD status` with no mention of it is unaffected (C3, [/decisions/ad-146.md](/decisions/ad-146.md)).
function gitGlobalOption(word: ShellWord): GitGlobalOption | null {
  const bare = bareFlag(word);
  const attached = word.text.includes("=");
  if (GIT_OPAQUE_GLOBAL_OPTIONS.has(bare)) {
    return { words: attached ? 1 : 2, opaque: true };
  }
  if (GIT_GLOBAL_OPTIONS_WITH_VALUE.has(bare)) {
    return { words: attached ? 1 : 2, opaque: false };
  }
  if (GIT_GLOBAL_FLAGS.has(word.text)) {
    return { words: 1, opaque: false };
  }
  if (word.text.startsWith("-")) {
    return { words: 1, opaque: true };
  }
  return null;
}

// why: `-C`'s value is a location for the rest of the segment, not a target reference — captured here so the
// caller can resolve other words in the same segment against it, alongside every base already tracked. `null`
// means "this word is not -C"; `{ unresolved: true }` means it is, but its value (`$X`, `$(...)`) is not — the
// two are not the same thing, unlike before, when both fell through unnoticed to "no location captured" and
// `-C "$X"` was silently treated as if it named nowhere in particular rather than somewhere unknown (item 2,
// [/decisions/ad-146.md](/decisions/ad-146.md)). Split out of `gitInvocation` for the same reason
// `gitGlobalOption` was: one flat set of conditions per function, not all of them counted against one loop's
// complexity.
type GitDashCLocation = { value: string } | { unresolved: true } | null;

function gitDashCLocation(word: ShellWord, next: ShellWord | undefined): GitDashCLocation {
  if (bareFlag(word) !== "-C") {
    return null;
  }
  const valueWord = word.text.includes("=") ? word : next;
  if (!valueWord || valueWord.text === "") {
    return null;
  }
  if (valueWord.unresolved) {
    return { unresolved: true };
  }
  return { value: word.text.includes("=") ? word.text.slice(word.text.indexOf("=") + 1) : valueWord.text };
}

// why: `firstOperand` treats every word that does not start with `-` as a candidate operand, which is exactly
// right for a plain command but wrong for git — `-C <dir>` and its siblings take a *separate* word as their
// value, and that value does not start with `-` either. Read as "the first operand", it was mistaken for the
// subcommand itself, so `git -C M log` was judged as `git m …` (C3, [/decisions/ad-146.md](/decisions/ad-146.md)).
// hazard: `-C`'s own value being unresolved (`-C "$X"`) makes the invocation's location unknown — folded into
// `opaque` (item 2) rather than a separate flag, because `checkGitSegment` only ever runs once this segment
// already matters (it references or names the surface, or the command already entered it), and "opaque" is
// already exactly "cannot prove this invocation only reads" in that context.
function gitInvocation(args: ShellWord[]): GitInvocation {
  let opaque = false;
  let index = 0;
  const locations: string[] = [];
  while (index < args.length) {
    const word = args[index];
    if (!word) {
      break;
    }
    const location = gitDashCLocation(word, args[index + 1]);
    if (location && "value" in location) {
      locations.push(location.value);
    } else if (location) {
      opaque = true;
    }
    const option = gitGlobalOption(word);
    if (!option) {
      return { subcommand: word.text.toLowerCase(), rest: args.slice(index + 1), opaque, locations };
    }
    opaque = opaque || option.opaque;
    index += option.words;
  }
  return { subcommand: "", rest: [], opaque, locations };
}

// why: `X=y git log` sets `GIT_PAGER`/`GIT_SSH`/anything else for that one invocation only — the same reach as
// `-c`, under different syntax. `verbOf` already skips these words to find `git`; this walks the same words to
// say whether it skipped an assignment on the way there (C4, [/decisions/ad-146.md](/decisions/ad-146.md)).
function envAssignmentPrecedesGit(words: ShellWord[]): boolean {
  let sawAssignment = false;
  for (const word of words) {
    if (WRAPPERS.has(word.text)) {
      continue;
    }
    if (word.text.startsWith("-")) {
      continue;
    }
    if (word.text.includes("=")) {
      sawAssignment = true;
      continue;
    }
    return sawAssignment && (word.text.split("/").pop() ?? word.text) === "git";
  }
  return false;
}

// why: `--output <path>` and `--output=<path>` are the two spellings `diff`/`log`/`show`/`format-patch`
// accept; both are read the same way a shell redirect's target already is (C6, [/decisions/ad-146.md](/decisions/ad-146.md)).
function outputTargets(args: ShellWord[]): ShellWord[] {
  const targets: ShellWord[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const word = args[index];
    if (!word) {
      continue;
    }
    if (word.text.startsWith("--output=")) {
      targets.push({
        text: word.text.slice("--output=".length),
        unresolved: word.unresolved,
        quotedStart: false,
      });
      continue;
    }
    if (word.text === "--output") {
      const next = args[index + 1];
      if (next) {
        targets.push(next);
        index += 1;
      }
    }
  }
  return targets;
}

// why: `-C`'s value is a location for the rest of *this* segment, not a later one — chained onto every base
// already tracked (so `-C ../..` from a nested cwd resolves the same way `cd ../..` would), but never fed back
// into the caller's own `bases`, which only `cd`/`pushd` are allowed to extend (C3, [/decisions/ad-146.md](/decisions/ad-146.md)).
// hazard: this used to keep the pre-`-C` bases *alongside* the resolved ones — a union, not a move. `git -C
// .tlc/harness merge --ff-only evil`'s only base then still included the untouched project root, and the
// project root is always "root-reachable" (it *is* a root), so item 2's location gate passed no matter where
// `-C` actually pointed. Once `-C` is given, it fully determines the segment's own cwd the same way a real
// shell's `-C` does — replacing each base, chaining a second `-C` onto the first's result — not adding a
// second possible location alongside it.
function withGitLocations(bases: readonly string[], locations: readonly string[]): readonly string[] {
  let current = bases;
  for (const location of locations) {
    current = current.map((base) => resolveFrom(base, location));
  }
  return current;
}

function checkGitSegment(
  ctx: SurfaceContext,
  bases: readonly string[],
  head: { args: ShellWord[] },
  segment: ShellSegment,
): PolicySurfaceVerdict {
  const invocation = gitInvocation(head.args);
  if (invocation.opaque || envAssignmentPrecedesGit(segment.words)) {
    return deny(
      "this git invocation carries a global option this gate does not recognize, or an environment assignment ahead of git, either of which can change what a reading subcommand actually does — so it cannot be proven to only read the harness policy surface.",
      "git global option or environment assignment on the policy surface",
      READ_REMEDY,
    );
  }
  const locatedBases = withGitLocations(bases, invocation.locations);
  const reads =
    invocation.subcommand === "branch"
      ? isReadOnlyBranch(invocation.rest)
      : invocation.subcommand === "merge"
        ? isFastForwardOnlyMerge(ctx, locatedBases, invocation.rest)
        : GIT_READERS.has(invocation.subcommand);
  if (!reads) {
    return deny(
      `\`git ${invocation.subcommand}\` can write the working tree, so it cannot be proven to only read the harness policy surface.`,
      `git ${invocation.subcommand} on the policy surface`,
      READ_REMEDY,
    );
  }
  if (OUTPUT_CAPABLE_READERS.has(invocation.subcommand)) {
    for (const target of outputTargets(invocation.rest)) {
      if (referencesSurface(ctx, locatedBases, target)) {
        return deny(
          `\`git ${invocation.subcommand} --output\` writes the path it names, and that path is the harness policy surface.`,
          `git ${invocation.subcommand} --output on the policy surface`,
        );
      }
    }
  }
  return ALLOW;
}

// why: `.tlc` itself, one level above `.tlc/harness`, for every tracked root (a project and, C7, its linked
// worktree's main checkout) — derived by walking up from `surface.state` rather than written as a literal, plus
// `ctx.machineContainer`, precomputed once in `surfaceContext` because whether it is `machineHome()`'s parent
// or `machineHome()` itself depends on that home's own layout (item 2, [/decisions/ad-146.md](/decisions/ad-146.md)).
function containerDirs(ctx: SurfaceContext): readonly string[] {
  return [...ctx.roots.map((surface) => dirname(dirname(surface.state))), ctx.machineContainer];
}

function landsInContainer(ctx: SurfaceContext, resolved: string): boolean {
  return containerDirs(ctx).some((container) => isInside(container, resolved));
}

/**
 * A `cd`/`pushd` destination is a location, not a target reference — neither can write a file on its own. But
 * when that location overlaps a surface (contains it, or is inside it — the same test `overlapsSurface`
 * already applies to any other resolved word), it counts as a reference *for every segment that follows*:
 * `git clean -fdx`, `tar -xf x.tar` and the like name no surface of their own and would otherwise be invisible
 * to this gate once the shell has already been moved there. `-C`'s value gets the equivalent treatment for
 * the rest of *its own* segment already, through the ordinary word scan `entersSurface` does not need to
 * touch (item 1, [/decisions/ad-146.md](/decisions/ad-146.md)).
 */
type CdVerdict = { verdict: PolicySurfaceVerdict; entersSurface: boolean };

const CD_NEUTRAL: CdVerdict = { verdict: ALLOW, entersSurface: false };

// why: `env` can reach this segment's `cd`/`pushd` carrying arguments this gate cannot enumerate — `env -S`,
// `env -f file`, or a plain assignment the scan below already catches — so naming it on its own is what item
// 3 asks for ("ou via env ...") without trying to parse `env`'s own grammar. Any assignment word ahead of the
// resolved head — `CDPATH=`, `HOME=`, `OLDPWD=`, or any other `X=…` — makes the destination unprovable the
// same way: the shell resolves `cd`'s operand using environment state this gate does not read.
function cdHasOpaquePrefix(words: ShellWord[]): boolean {
  for (const word of words) {
    if (word.text === "env") {
      return true;
    }
    if (WRAPPERS.has(word.text) || word.text.startsWith("-")) {
      continue;
    }
    if (word.text.includes("=")) {
      return true;
    }
    return false;
  }
  return false;
}

// why: `cd`/`pushd` cannot write a file on their own, so the segment itself is only ever denied for a prefix
// that hides the destination (item 3) or an unresolved operand whose own text names the surface — never for
// where a resolvable destination lands. What that destination *overlaps* is reported back to the caller
// instead, which is what item 1 turns into a reader-only gate on every later segment.
function checkCdSegment(
  ctx: SurfaceContext,
  bases: readonly string[],
  head: SegmentHead,
  segment: ShellSegment,
): CdVerdict {
  if (cdHasOpaquePrefix(segment.words)) {
    return {
      verdict: deny(
        "an environment assignment ahead of this `cd`/`pushd` (or an `env` wrapper carrying one) can change where it actually lands, so the destination cannot be shown to be safe.",
        "cd/pushd with an environment assignment ahead of it",
      ),
      entersSurface: false,
    };
  }

  // why: upstream parity, restored — a segment whose own *text* names the harness policy surface denies
  // regardless of what path resolution says about it. `resolveFrom` reads standard Windows/POSIX absolute
  // paths; it does not translate an MSYS/Git-Bash path (`/c/Users/…/wt/.tlc/harness`, which `resolve` turns
  // into an unrelated path on the current drive) or a `\\?\`-prefixed one, so a `cd` to either would resolve
  // to a location that overlaps nothing this gate can see — while its own text still spells out the real,
  // relative structure underneath the mangling. Checked once, ahead of every operand-specific branch below,
  // the same way the ordinary (non-`cd`) segment path already checks it before trusting anything about a
  // reader verb (item 1, [/decisions/ad-146.md](/decisions/ad-146.md)).
  if (namesSurface(ctx.prefix, segment)) {
    return {
      verdict: deny(
        "this `cd`/`pushd` names the harness policy surface in its own text, and a path this gate cannot reliably resolve (an MSYS path, a \\\\?\\-prefixed one) could still land there even though the resolved form does not appear to.",
        "cd/pushd naming the policy surface",
      ),
      entersSurface: false,
    };
  }

  const operand = firstOperand(head.args);

  // why: `cd -` goes to $OLDPWD, a value this gate never sees, so nothing about where it actually lands can
  // be shown either way — the segment's own text was already checked above, which is the only thing about
  // this form the gate can read at all.
  if (operand && operand.text === "-") {
    return CD_NEUTRAL;
  }

  // why: an unresolved operand (`$X`, `$(...)`) whose own text names the surface was already caught above,
  // by the same `namesSurface` scan over the whole segment — its value is otherwise unknowable, the same
  // posture every other unresolved word in this file takes.
  if (operand?.unresolved) {
    return CD_NEUTRAL;
  }

  // why: a bare `cd`/`pushd` goes to $HOME (item 3) — resolved through the same `~` expansion every other
  // word already gets, rather than treated as having no destination at all.
  const operandText = operand && operand.text !== "" ? operand.text : "~";
  const resolvedCandidates = bases.map((base) => resolveFrom(base, operandText));

  // hazard: a floor evaluation answers only from the one command string it was handed — it never reads the
  // shell's own persisted cwd, which is what actually carries between two separate Bash tool calls in the
  // same session. `cd .tlc/harness` as one call, then `python3 -c "open('config.json','w')"` as the next,
  // is two commands this gate sees in complete isolation from each other; `entersSurface` only threads state
  // *within* one command string. The one thing this gate can still prove across that gap is that `cd`/`pushd`
  // must not be allowed to land *inside* the surface's own container in the first place — denied here,
  // outright, even as the only segment in the command (item 1, [/decisions/ad-146.md](/decisions/ad-146.md)).
  // An ancestor-only overlap (landing at `M`, or `..`) is not this case: it is far enough from the surface
  // that a second, separate call starting there still has to name something before this gate can act, which
  // is exactly what `entersSurface` continues to cover within a single command.
  if (resolvedCandidates.some((candidate) => landsInContainer(ctx, candidate))) {
    return {
      verdict: deny(
        "this `cd`/`pushd` lands inside the harness policy surface's own container, and a later, separate command could act from there with nothing in its own text to catch — so it is refused outright, not merely tracked.",
        "cd/pushd into the policy surface's own container",
      ),
      entersSurface: false,
    };
  }

  const overlaps = resolvedCandidates.some((candidate) => overlapsSurface(ctx, candidate));
  return overlaps ? { verdict: ALLOW, entersSurface: true } : CD_NEUTRAL;
}

function checkSegment(
  ctx: SurfaceContext,
  segment: ShellSegment,
  bases: readonly string[],
  surfaceEntered: boolean,
): CdVerdict {
  for (const target of redirectTargets(segment.words)) {
    if (referencesSurface(ctx, bases, target)) {
      return {
        verdict: deny(
          "a redirect in this command writes into the harness policy surface.",
          "redirect into the policy surface",
        ),
        entersSurface: false,
      };
    }
  }

  const head = verbOf(segment.words);
  const harnessBinVerdict = checkHarnessBin(head);
  if (harnessBinVerdict) {
    return { verdict: harnessBinVerdict, entersSurface: false };
  }

  // why: `cd`/`pushd`/`popd` are decided directly, never through the "nothing references the surface" shortcut
  // below — `CDPATH=.tlc cd harness` combines an assignment value with the operand in a way neither half alone
  // spells out, so the shortcut would clear it before `checkCdSegment` ever saw it (item 2,
  // [/decisions/ad-146.md](/decisions/ad-146.md)). An opaque split still denies, the same as every other verb.
  if (head && CD_VERBS.has(head.verb)) {
    return segment.opaque
      ? {
          verdict: deny(
            "this command names the harness policy surface inside a segment this gate cannot split, so what it does to it cannot be established.",
            "unprovable policy-surface access",
          ),
          entersSurface: false,
        }
      : checkCdSegment(ctx, bases, head, segment);
  }

  const references = segment.words.filter((word) => referencesSurface(ctx, bases, word));
  // why: item 1 ([/decisions/ad-146.md](/decisions/ad-146.md)) — once an earlier `cd`/`pushd` in this same
  // command landed somewhere that overlaps a surface, every later segment is judged as if it already named
  // the surface, even one like `git clean -fdx` that names nothing of its own. The shortcut below is exactly
  // the gap that let such a segment through unexamined.
  if (!surfaceEntered && references.length === 0 && !namesSurface(ctx.prefix, segment)) {
    return { verdict: ALLOW, entersSurface: false };
  }

  // hazard: an unreliable split means the head verb is not established, so a reader-looking head proves
  // nothing. Unknown resolves to denied, as it does for the destruction rules.
  if (segment.opaque) {
    return {
      verdict: deny(
        "this command names the harness policy surface inside a segment this gate cannot split, so what it does to it cannot be established.",
        "unprovable policy-surface access",
      ),
      entersSurface: false,
    };
  }
  if (!head) {
    return {
      verdict: deny(
        "the harness policy surface is named in a command with no resolvable verb.",
        "policy-surface access with no verb",
      ),
      entersSurface: false,
    };
  }
  // why: a proven reader is cleared before any other question, because reading the policy is ordinary work
  // and the bootstrap asks for it by name. Nothing in this set can write a file on its own.
  if (PROVEN_READERS.has(head.verb)) {
    return { verdict: ALLOW, entersSurface: false };
  }
  if (head.verb === "git") {
    return { verdict: checkGitSegment(ctx, bases, head, segment), entersSurface: false };
  }
  if (references.some((word) => word.unresolved)) {
    return {
      verdict: deny(
        "this command builds a harness policy path at runtime, so the file it would touch cannot be established.",
        "unresolvable policy-surface path",
      ),
      entersSurface: false,
    };
  }
  return {
    verdict: deny(
      `\`${head.verb}\` is not a proven reader, so this command cannot be shown to only read the harness policy surface.`,
      `${head.verb} on the policy surface`,
      READ_REMEDY,
    ),
    entersSurface: false,
  };
}

// why: C2 ([/decisions/ad-146.md](/decisions/ad-146.md)) — a `cd`/`pushd` operand, once resolved, becomes a new
// candidate base for every word after it, alongside every base already seen. Nothing is ever removed (`popd`
// is a no-op here), which is the conservative direction: more candidate bases can only make a later word *more*
// likely to be judged a reference, never less.
function trackCwd(bases: Set<string>, segment: ShellSegment): void {
  const head = verbOf(segment.words);
  if (!head || head.verb === "popd" || (head.verb !== "cd" && head.verb !== "pushd")) {
    return;
  }
  const operand = firstOperand(head.args);
  // why: an unresolved operand (`cd $dir`) contributes no candidate — its value is unknowable here, the same
  // posture `referencesSurface` already takes for any other unresolved word. `cd -` goes to $OLDPWD, which is
  // equally unknowable, so it is left out the same way rather than tracked as a literal "-" path segment.
  if (!operand || operand.unresolved || operand.text === "-") {
    return;
  }
  // why: a bare `cd`/`pushd` goes to $HOME (item 3, [/decisions/ad-146.md](/decisions/ad-146.md)) — tracked as
  // a candidate the same as any other destination, through the same `~` expansion.
  const operandText = operand.text === "" ? "~" : operand.text;
  for (const base of [...bases]) {
    bases.add(resolveFrom(base, operandText));
  }
}

// hazard: `python3 - <<PY` puts the program in the heredoc body, so the path never appears among the words.
// The body only matters when something executes it: `git commit -F -` and `cat <<EOF` receive heredocs that
// merely name this path, which is what writing about the rule looks like. A heredoc that *writes* the
// surface through a redirect or a path argument is caught by the per-segment rules instead.
function checkHeredocs(prefix: string, heredocs: HeredocChunk[]): PolicySurfaceVerdict {
  for (const chunk of heredocs) {
    if (!normalizeSeparators(chunk.body).includes(prefix)) {
      continue;
    }
    // hazard: the body belongs to the verb immediately before its marker, not to the command. Asking
    // whether *any* segment runs an interpreter denied `cat >> f <<EOF ... ; node --test`, where the body
    // goes to cat and node is a separate command.
    const owner = verbOf(tokenizeShell(chunk.prefix).at(-1)?.words ?? []);
    if (owner !== null && EXECUTES_STDIN.has(owner.verb)) {
      return deny(
        `a heredoc fed to \`${owner.verb}\` names the harness policy surface, so the body is a program rather than a document.`,
        "heredoc program naming the policy surface",
      );
    }
  }
  return ALLOW;
}

// invariant: reads no policy. It answers from paths, head verbs and the command's own text, so the file it
// protects can never influence the decision that protects it.
export function checkPolicySurface(
  projectDir: string,
  command: string,
  segments: ShellSegment[],
  extraSurfacePaths: readonly string[] = [],
): PolicySurfaceVerdict {
  // why: the prefix and the surface roots (item 4, [/decisions/ad-146.md](/decisions/ad-146.md)) are computed
  // once here, not per word per candidate base — `mainWorktreeOf` reads disk, and `surfaceContext` is the one
  // place in this file allowed to call it.
  const ctx = surfaceContext(projectDir, extraSurfacePaths);
  // why: seeded with `projectDir` alone, so a command with no `cd`/`pushd` in it resolves exactly as it did
  // before C2 ([/decisions/ad-146.md](/decisions/ad-146.md)) existed.
  const bases = new Set<string>([resolve(projectDir)]);
  // why: item 1 ([/decisions/ad-146.md](/decisions/ad-146.md)) — sticky once true, like `bases`: a `cd`/`pushd`
  // that lands somewhere overlapping a surface gates every segment after it, and nothing in this command can
  // un-gate a later one.
  let surfaceEntered = false;
  for (const segment of segments) {
    const { verdict, entersSurface } = checkSegment(ctx, segment, [...bases], surfaceEntered);
    if (verdict.kind === "deny") {
      return verdict;
    }
    surfaceEntered = surfaceEntered || entersSurface;
    trackCwd(bases, segment);
  }
  return checkHeredocs(ctx.prefix, heredocChunks(command));
}
