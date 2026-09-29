import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { withEnv } from "../../../../tools/test-env.scope.mjs";
import { checkPolicySurface } from "../floor.policy-surface.ts";
import { evaluateFloor } from "../floor.service.ts";
import { tokenizeShell } from "../floor.tokenize.ts";

/**
 * AD-146 — `policy-surface-write` denied legitimate reads from inside a linked git worktree: `overlapsSurface`
 * counted inverse containment in both directions, so the main checkout M "contained" the worktree W's own
 * surface and any command naming M fell under the rule; `cd`/`pushd` were not recognized as harmless; and
 * `git -C <dir> …` had its `-C` *value* read as the subcommand. This file is the fixture the plan and checks
 * (`plan.md`/`checks.md`) describe: a real main checkout M with a real linked worktree W at
 * `M/.worktrees/wt`, `projectDir` always W — built with real `git`, not a hand-written `.git` file, because a
 * git worktree's own marker format is exactly what `mainWorktreeOf` has to parse correctly.
 */

function git(cwd: string, args: string[]): void {
  execFileSync("git", args, { cwd });
}

let main = "";
let worktree = "";
let runtimeHomeRoot = "";
let previousTlcHome: string | undefined;

before(() => {
  main = mkdtempSync(join(tmpdir(), "tlc-ad146-main-"));
  git(main, ["init", "-q"]);
  git(main, ["config", "user.email", "test@example.com"]);
  git(main, ["config", "user.name", "Test"]);
  git(main, ["commit", "-q", "--allow-empty", "-m", "initial"]);
  worktree = join(main, ".worktrees", "wt");
  git(main, ["worktree", "add", "-q", worktree, "-b", "work"]);

  // hazard: `--import ./tools/test-env.mjs` points `TLC_HOME` at a *flat* temp directory with no `.tlc/harness`
  // nesting, so its own parent is bare `tmpdir()` — the same ancestor every `mkdtempSync` fixture in this
  // process shares. Item 2's container check (`runtimeContainerDir` = `dirname(runtimeHome())`) then reads
  // *any* fixture under `tmpdir()` as "inside" it, which a real machine's `~/.tlc` never is. Pinned here to a
  // sibling of `main`, nested the way a real runtime home actually is, so the container check exercises the
  // real shape instead of an artifact of the test harness's own home.
  runtimeHomeRoot = mkdtempSync(join(tmpdir(), "tlc-ad146-runtime-"));
  previousTlcHome = process.env.TLC_HOME;
  process.env.TLC_HOME = join(runtimeHomeRoot, ".tlc", "harness");
});

after(() => {
  try {
    git(main, ["worktree", "remove", "-f", worktree]);
  } catch {
    // why: best effort — a failed cleanup here must not fail the suite over a leaked temp directory.
  }
  rmSync(main, { recursive: true, force: true });
  rmSync(runtimeHomeRoot, { recursive: true, force: true });
  if (previousTlcHome === undefined) {
    delete process.env.TLC_HOME;
  } else {
    process.env.TLC_HOME = previousTlcHome;
  }
});

// why: `projectDir` is always the worktree, matching the fixture every A/D check in checks.md was written
// against — the plan's own bug (M's ancestor position relative to W) only reproduces from inside W.
function verdict(command: string) {
  return checkPolicySurface(worktree, command, tokenizeShell(command));
}

function assertAllowed(command: string): void {
  assert.equal(verdict(command).kind, "allow", `expected allow for: ${command}`);
}

function assertDenied(command: string): void {
  assert.equal(verdict(command).kind, "deny", `expected deny for: ${command}`);
}

// why: a literal, not a real directory — resolveFrom/isInside answer lexically and never touch the
// filesystem, so a home that does not exist is a faithful input (same posture as floor.test.ts's own HOME).
const HOME = "/home/someone";

// why: the suite's own `--import ./tools/test-env.mjs` pins `TLC_HOME` to an unrelated temp directory for
// hermeticity everywhere else. D1/D8 specifically exercise `~/.tlc/harness`, which only lands on the runtime
// policy surface when `TLC_HOME` is unset and the machine falls back to `homedir()` — exactly what an
// operator's own untouched machine does.
function withFakeHome(run: () => void): void {
  withEnv({ HOME, USERPROFILE: HOME, TLC_HOME: undefined, TLC_HOME_FROM_ENV: undefined }, run);
}

// ---- A1-A6: must ALLOW ----

test("A1 cd into the main checkout, then read-only git, is allowed", () => {
  assertAllowed(`cd "${main}" && git branch --show-current && git log --oneline -5 dev`);
});

test("A2 git -C into the main checkout for read-only subcommands is allowed", () => {
  assertAllowed(
    `git -C "${main}" branch --show-current; git -C "${main}" log --oneline -5 dev; git -C "${main}" status --short --untracked-files=no`,
  );
});

test("A3 cd up out of the worktree by relative path, then a git reader, is allowed", () => {
  assertAllowed("cd ../../.. && git log --oneline -3 -- backend/app/x.py");
});

test("A4 git -C into the main checkout for a fast-forward merge is allowed", () => {
  assertAllowed(`git -C "${main}" merge --ff-only fix/x`);
});

test("A5 cd into the main checkout for a fast-forward merge is allowed", () => {
  assertAllowed(`cd "${main}" && git merge --ff-only fix/x`);
});

test("A6 rev-parse and branch --list against the main checkout are allowed", () => {
  assertAllowed(`git -C "${main}" rev-parse HEAD`);
  assertAllowed(`git -C "${main}" branch --list`);
});

// ---- D1-D14: must DENY (or, where nothing denies it today, documented as-is) ----

test("D1 a bare redirect into the runtime policy surface is still denied", () => {
  withFakeHome(() => assertDenied("echo x > ~/.tlc/harness/config.json"));
});

test("D2 git checkout of the worktree's own surface is denied, -C and bare alike", () => {
  assertDenied(`git -C "${worktree}" checkout -- .tlc/`);
  assertDenied("git checkout -- .tlc/");
});

test("D3 git checkout of the main checkout's surface is denied (C7)", () => {
  assertDenied(`git -C "${main}" checkout -- .tlc/`);
});

test("D4 a redirect into the main checkout's surface from the worktree is denied (C7)", () => {
  // hazard: this exact command was allowed before C7 — the main checkout's own policy surface was not
  // guarded at all from a linked worktree, only the worktree's own.
  assertDenied(`echo x > "${main}/.tlc/harness/config.json"`);
});

// why: `core/` and `contracts/` never name a vendor (CONTRIBUTING.md), so the actual reported path — a
// specific editor's home-relative settings file, project-relative here — is stood for by this generic one.
// The finding does not depend on which editor: `wiring-tamper`'s `protectedPaths` names a provider's *global*
// config directory, never a project-relative one, and it is only populated when a caller passes it —
// `evaluateFloor` with none, as here, is exactly what a bare shell command reaches. `policy-surface-write`
// does not reach it either: it is scoped to `.tlc/harness`. Reported rather than fixed here — the plan
// (checks.md D5) says not to expand scope.
test("D5 a project-relative editor settings path — no floor rule guards it today", () => {
  const decision = evaluateFloor({
    projectDir: worktree,
    command: "sed -i s/a/b/ .editor-x/settings.json",
  });
  assert.equal(decision.kind, "allow");
});

test("D6 cd into the worktree's own .tlc/harness, then an editor on a relative path, is denied", () => {
  assertDenied("cd .tlc/harness && sed -i s/a/b/ config.json");
});

test("D7 two chained relative cds into the surface, then rm on a relative path, is denied", () => {
  assertDenied("cd .tlc && cd harness && rm -rf state");
});

test("D8 pushd into the runtime policy surface, then a bare redirect, is denied", () => {
  withFakeHome(() => assertDenied("pushd ~/.tlc/harness; echo x > config.json"));
});

test("D9 git -c core.pager naming the surface is denied even though log is a reader", () => {
  assertDenied(`git -c core.pager="sh -c 'echo > .tlc/harness/config.json'" log`);
});

test("D10 git diff --output into the surface is denied even though diff is a reader", () => {
  assertDenied("git diff --output=.tlc/harness/config.json");
});

test("D11 git -C straight at the surface for a writer subcommand is denied", () => {
  assertDenied("git -C .tlc/harness checkout -- config.json");
});

test("D12 an inline env assignment ahead of git log naming the surface is denied", () => {
  assertDenied(`GIT_PAGER="sh -c 'echo > .tlc/harness/config.json'" git log`);
});

test("D13 git branch -f naming the surface as its target stays denied", () => {
  assertDenied("git branch -f x .tlc/harness/config.json");
});

test("D14 an assignment segment naming the surface is still denied with no verb to clear it", () => {
  assertDenied("H=~/.tlc/harness; cd $H; echo x > config.json");
});

// ---- regression sanity: nothing this fix touches got looser ----

test("removing the worktree's own harness directory is still denied from inside it", () => {
  assertDenied("rm -rf .tlc/harness");
});

test("ordinary work at the worktree root is still untouched", () => {
  assertAllowed("find . -name '*.ts'");
  assertAllowed(`cat ${join(worktree, ".tlc/harness/lessons.md")}`);
});

/**
 * The independent Verifier's own probe (`scratchpad/probe.ts`, `scratchpad/probe-result.md`) found 25
 * deny→allow regressions in the first cut of this fix: bounding `overlapsSurface`'s inverse-containment check
 * to `isInside(root, resolved)` fixed the worktree-ancestor false positive (A1-A6) but also stopped catching a
 * writer aimed *at* the main checkout through an ancestor reference — `git -C <main> clean -fdx`, `mv <main>
 * x`, `chmod -R 000 ..` and the like. Each row below is one line of that table's "REGRESSION?"/"MISMATCH"
 * column, turned into a regression test that must deny.
 */

test("R: destructive or unproven verbs naming the main checkout by an absolute path are denied", () => {
  assertDenied(`mv "${main}" /x/y`);
  assertDenied(`find "${main}" -delete`);
  assertDenied(`chmod -R 000 "${main}"`);
});

test("R: git -C into the main checkout for a non-reader subcommand is denied, pathspec or none", () => {
  assertDenied(`git -C "${main}" clean -fdx`);
  assertDenied(`git -C "${main}" checkout -- .`);
  assertDenied(`git -C "${main}" reset --hard`);
  assertDenied(`git -C "${main}" restore -- ':/.tlc'`);
  assertDenied(`git -C "${main}" apply x.patch`);
  assertDenied(`git -C "${main}" stash -u`);
});

test("R: -C and cd by relative ../.. onto the main checkout, for a non-reader subcommand, are denied", () => {
  assertDenied("git -C ../.. checkout -- .");
  assertDenied("cd ../.. && git checkout -- .");
});

test("R: destructive or unproven verbs naming the worktree's grandparent by ../.. are denied", () => {
  assertDenied("chmod -R 000 ..");
  assertDenied("mv .. /x/y");
  assertDenied("tar -xf /x/evil.tar -C ..");
  assertDenied("cp -r payload/. ..");
});

test("C: CDPATH ahead of cd, resolving into the surface only once combined with the operand, is denied", () => {
  assertDenied("CDPATH=.tlc cd harness && rm config.json");
});

test("C: cd with an unresolved operand naming the surface, and a command-substitution operand, are denied", () => {
  assertDenied("cd .tlc/harness$X && rm config.json");
  assertDenied('cd "$(echo .tlc/harness)" && rm config.json');
});

test("C: cd into the surface, then an interpreter or a glob on a relative path, is denied", () => {
  assertDenied(`cd .tlc/harness && python3 -c "open('config.json','w').write('{}')"`);
  assertDenied(`cd .tlc/harness && node -e "require('fs').writeFileSync('config.json','{}')"`);
  assertDenied("cd .tlc/harness && sh -c ': > config.json'");
  assertDenied("cd .tlc/harness && rm -rf s*");
  assertDenied("cd .tlc/harness && sed -i s/a/b/ *.json");
  assertDenied(`cd .tlc && python3 -c "open('harness/config.json','w')"`);
  assertDenied(`cd .tlc/harness && git -c core.pager='tee config.json' log`);
});

test("G: git grep -O / --open-files-in-pager runs a program and is denied, long and short form", () => {
  assertDenied("git grep --open-files-in-pager=tee -e . -- .tlc/harness/config.json");
  assertDenied("git grep -Otee -e . -- .tlc/harness/config.json");
});

test("G: an unrecognized git global option is opaque, and opaque denies once the surface is cited", () => {
  assertDenied("git --attr-source log checkout -- .tlc/harness/config.json");
});

test("G: -C's own value is not mistaken for the subcommand even when it looks like a reader's name", () => {
  assertDenied("git -C log checkout -- .tlc/harness/config.json");
});

test("M: cd by relative ../../.tlc onto the main checkout's own .tlc, then rm, is denied (C7)", () => {
  assertDenied(`cd ../../.tlc && rm -rf harness`);
});

test("branch --list with a positional operand is still allowed — the operand-safe-flag rule does not overreach", () => {
  assertAllowed("git branch --list .tlc/harness/config.json");
});

test("git rev-parse with a trailing pathspec-shaped argument is still a reader", () => {
  assertAllowed("git rev-parse --show-toplevel -- .tlc/harness");
});

/**
 * Round 2 — the independent Verifier's updated probe (`scratchpad/probe-out-v2.txt`) found 16 more
 * deny→allow regressions once the first correction landed: bounding the ancestor match fixed the reads, but
 * a `cd`/`-C` destination that overlaps a surface only gated *that* segment's own word-by-word scan, not
 * later segments with no surface-naming word of their own (`git clean -fdx`, `tar -xf x.tar`). Each row below
 * is one line of that table's "REGRESSION?"/"MISMATCH" column.
 */

test("I: cd onto the main checkout, then a non-reader git subcommand with no path argument, is denied", () => {
  assertDenied(`cd "${main}" && git clean -fdx`);
  assertDenied(`cd "${main}" && git reset --hard`);
  assertDenied(`cd "${main}" && git stash -u`);
  assertDenied(`cd "${main}" && git clean -ffdx`);
});

test("I: cd by relative .. or ../.. onto an ancestor of the surface, then a non-git writer, is denied", () => {
  assertDenied("cd .. && tar -xf /x/evil.tar");
  assertDenied("cd ../.. && unzip -o /x/e.zip");
});

test("F: git merge --ff-only with any flag beyond --ff-only/-q/--quiet is not a reader", () => {
  assertDenied(`git -C "${main}" merge --ff-only --no-ff -m m evil`);
  assertDenied(`git -C .tlc/harness merge --ff-only --no-ff -m m evil`);
  assertDenied("git -C .tlc/harness merge --ff-only --abort");
  assertDenied(`cd "${main}" && git merge --ff-only --no-ff -m m evil`);
});

test("F: git merge --ff-only with more than one ref operand, or one naming the surface, is not a reader", () => {
  assertDenied("git merge --ff-only .tlc/harness");
});

test("F: git merge --ff-only run from inside the surface itself (not a root or an ancestor of one) is not a reader", () => {
  // hazard: `.tlc/harness` and `.tlc` both overlap the worktree's surface the same way `M` does — through
  // `overlapsSurface`'s ancestor match — but neither is a root or an ancestor of one, which is what item 2's
  // location gate requires. Fast-forwarding a "repo" that is really the harness's own directory is not the
  // same trade-off as fast-forwarding at a root.
  assertDenied("git -C .tlc/harness merge --ff-only evil");
  assertDenied("git -C .tlc merge --ff-only evil");
});

test("K: an env assignment ahead of cd, or cd - naming the surface, is opaque and denied", () => {
  assertDenied("HOME=.tlc/harness cd && rm config.json");
  assertDenied("OLDPWD=.tlc/harness cd - && rm config.json");
});

test("K: a redirect into the surface with different case is still denied on a case-insensitive filesystem", () => {
  // why: the config-equality check was optimized to a plain `===`, which is case-sensitive even on Windows,
  // where the real filesystem is not — `isInside` restores the platform's own comparison (item 4).
  assertDenied("echo x > .TLC/HARNESS/config.json");
});

test("U: a known git global option this gate did not recognize before no longer makes the invocation opaque", () => {
  assertAllowed("git --no-lazy-fetch log -- .tlc/harness/config.json");
  assertAllowed(`git -C "${main}" --no-advice log -1`);
});

/**
 * item 5 — `runtimeContainerDir`'s old derivation followed raw `$TLC_HOME`, which `tlc-exec` sets to the
 * *install* directory with `TLC_HOME_FROM_ENV=0` to say "not an operator's own choice." That is now folded
 * into `overlapsSurface`'s runtime check, which already resolves through `machineConfigPath`/
 * `runtimeStateDir` — both `machineHome`-based, so they already honor `TLC_HOME_FROM_ENV=0` and fall back to
 * the conventional `~/.tlc/harness` regardless of where `$TLC_HOME` itself points.
 */
test("the runtime surface is the machine's own home, not a raw TLC_HOME install path", () => {
  const install = mkdtempSync(join(tmpdir(), "tlc-ad146-install-"));
  const sibling = mkdtempSync(join(tmpdir(), "tlc-ad146-sibling-"));
  try {
    withEnv({ HOME, USERPROFILE: HOME, TLC_HOME: install, TLC_HOME_FROM_ENV: "0" }, () => {
      // why: `~/.tlc` (HOME-based) is an ancestor of the conventional runtime state dir once
      // `TLC_HOME_FROM_ENV=0` forces the fallback — denied even though the raw $TLC_HOME points elsewhere.
      assertDenied(`cd ~/.tlc && python3 -c "open('harness/config.json','w')"`);
      // why: a directory that merely sits next to the *raw* $TLC_HOME install path has nothing to do with
      // the machine's own home and must stay unaffected.
      assertAllowed(`cd ${sibling} && ls`);
    });
  } finally {
    rmSync(install, { recursive: true, force: true });
    rmSync(sibling, { recursive: true, force: true });
  }
});

/**
 * Round 3 — the independent Verifier's updated probe (`scratchpad/probe-out-v3.txt`) found a floor evaluation
 * answers only from the one command string it was handed: it never reads the shell's own persisted cwd, which
 * is what actually carries between two separate Bash tool calls in the same session. `entersSurface` (item 1
 * in round 2) only threads state *within* one command string, so `cd .tlc/harness` as one call, followed by
 * `python3 -c "open('config.json','w')"` as a separate one, escaped entirely. Each item below is one line of
 * that table's "REGRESSION?"/"MISMATCH" column.
 */

test("S: a bare cd/pushd into the surface's own container denies even as the only segment in the command", () => {
  assertDenied("cd .tlc/harness");
  assertDenied("cd .tlc");
  assertDenied("pushd .tlc/harness");
});

test("S: git -C with a second, unresolved location is opaque and denies", () => {
  assertDenied('git -C .tlc -C "$X" log --output=config.json');
});

test("F: git merge --ff-only requires every tracked cwd candidate to be root-reachable, not just one", () => {
  // why: a `cd` to a genuinely unrelated sibling directory is itself neutral (nothing overlaps), but it still
  // joins the tracked cwd candidates — `isRootReachable` has to hold for all of them, not merely for the one
  // a later `cd "${main}"` happens to add, or a merge could run from an ambiguous location set that includes
  // a directory with no tracked root under it at all.
  const unrelated = join(dirname(main), "unrelated-sibling");
  assertDenied(`cd ${unrelated} && cd "${main}" && git merge --ff-only fix/x`);
});

test("S: $HOME itself, and ordinary reads/writes naming it plainly, are not an ancestor-overlap of the runtime surface", () => {
  withFakeHome(() => {
    assertAllowed("find ~ -name x.log");
    assertAllowed("cp notes.txt ~");
    // why: a path *inside* home is still the real surface and still denies — only home itself, and anything
    // above it, is exempt (item 4, [/decisions/ad-146.md](/decisions/ad-146.md)).
    assertDenied("cd ~/.tlc");
  });
});

/**
 * Round 4 — the independent Verifier's probe (`scratchpad/probe-out-v4.txt`, rows X1/X2/X4 and the
 * operator-`$TLC_HOME` container section) found two gaps: `checkCdSegment` had dropped the upstream
 * `namesSurface` text check `resolveFrom` cannot substitute for (an MSYS/Git-Bash path or a `\\?\`-prefixed
 * one resolves to somewhere this gate cannot recognize, even though the segment's own text still names the
 * real, relative surface underneath); and the runtime container took `dirname(machineHome())` unconditionally,
 * which is only meaningful when `machineHome()` itself has the conventional `<container>/harness` shape — an
 * operator's own `$TLC_HOME` (`~/tlc`, `D:/tlc`) does not, and taking its parent swept in the operator's whole
 * home directory or drive.
 */

test("X: a cd whose own text names the surface denies even when resolveFrom cannot make sense of the path", () => {
  // why: an MSYS/Git-Bash-style absolute path — `resolveFrom` treats a leading "/" as absolute on the
  // *current* drive, not as the translated `C:\...` a real MSYS layer would produce, so path-resolution-based
  // checks see an unrelated location. The segment's own text still contains ".tlc/harness" literally, and the
  // drive letter this rewrite uses does not have to be the real one — the point is the text match, not the
  // resolution.
  const harnessDir = join(worktree, ".tlc", "harness");
  const msys = `/c${harnessDir.replace(/^[A-Za-z]:/, "").replaceAll("\\", "/")}`;
  assertDenied(`cd ${msys} && python3 -c "open('config.json','w')"`);
  assertDenied(`cd ${msys}`);
  // why: a `\\?\`-prefixed path is a real Windows extended-length form `resolveFrom` does not special-case
  // either; the literal text still names the surface once backslashes normalize to forward slashes.
  assertDenied(`cd '\\\\?\\${harnessDir}' && rm config.json`);
});

test("X: the runtime container is machineHome() itself when its layout is not the conventional <container>/harness shape", () => {
  const operatorHome = mkdtempSync(join(tmpdir(), "tlc-ad146-operator-"));
  const operatorTlc = join(operatorHome, "tlc");
  const codeProj = join(operatorHome, "code", "proj");
  try {
    withEnv({ TLC_HOME: operatorTlc, TLC_HOME_FROM_ENV: "1" }, () => {
      // why: `~/tlc` (no dot, not `.tlc/harness`) is not the conventional shape, so its *parent* — the
      // operator's entire home — must not become a no-`cd` zone.
      assertAllowed(`cd ${codeProj} && npm test`);
      // why: `machineHome()` itself — the exact path the harness reads and writes — is still the container.
      assertDenied(`cd ${operatorTlc}`);
    });
  } finally {
    rmSync(operatorHome, { recursive: true, force: true });
  }
});

test("X: the runtime container is still machineHome()'s parent under the conventional layout", () => {
  withFakeHome(() => {
    assertDenied("cd ~/.tlc");
    assertDenied("cd ~/.tlc/other");
  });
});

/**
 * Round 6 — a Verifier security pass on `fd47ae0` found the tokenizer's own `&` handling denying an
 * everyday pipeline: `SEPARATORS` treated the `&` in `2>&1` as a background-job separator, splitting
 * `git log … dev 2>&1 | head -20` into a segment ending `2>` and a second, one-word segment `1` — which,
 * under `surfaceEntered` (reached here only because it follows `cd "$main"`), read as a non-reader verb.
 */
test("a redirect-fd pipeline after cd into the main checkout still reads as ordinary git output shaping", () => {
  assertAllowed(`cd "${main}" && git log --oneline -5 dev 2>&1 | head -20`);
  assertAllowed("ls 2>&1");
});

test("&>surface and >&surface are still caught as writes into the policy surface, not a stray & escaping them", () => {
  assertDenied("echo x &>.tlc/harness/config.json");
  assertDenied("echo x >&.tlc/harness/config.json");
});

/**
 * Round 7 — an independent Verifier's probe found the round 6 fix itself regressed: `current.endsWith(">")`
 * cannot tell a genuine bare redirect operator from a `>`/`<` that arrived quoted or escaped, so a `&` right
 * after a *quoted* `>` (`echo "a>"& …`) was wrongly swallowed the same way a real `2>&1` is — folding the
 * command that follows into an argument of `echo` and hiding it from this rule entirely. Confirmed against
 * real bash (`echo "a>"& touch q1; wait` creates `q1`) before fixing. Every spelling the Verifier listed is
 * exercised here against the surface write itself.
 */
test("a quoted or escaped > glued to & no longer hides a write into the surface behind echo", () => {
  assertDenied(`echo "a>"& python3 -c "open('.tlc/harness/config.json','w')"`);
  assertDenied(`echo 'a<'& python3 -c "open('.tlc/harness/config.json','w')"`);
  assertDenied(String.raw`echo a\>& python3 -c "open('.tlc/harness/config.json','w')"`);
  assertDenied(String.raw`echo a\<& rm -f .tlc/harness/config.json`);
  assertDenied(`printf '%s' ">"& sed -i s/a/b/ .tlc/harness/config.json`);
});

/**
 * Round 7 — the same probe found `redirectTargets` reading only the first `>` of a word. Once the tokenizer
 * folds a dropped `&` into the word it touches (`2>&1>surface` becomes the one word `2>1>surface`), the old
 * single `.exec` reported `1>surface` as one opaque target and never read past the first `>` to the real
 * write target after the second one. The same gap pre-dated round 6 for `>/dev/null>surface`, spelled with
 * no `&` at all — both forms need every `>`/`>>` in the word read, not just the first.
 */
test("every > in a word is read as a possible target, not just the first", () => {
  assertDenied("echo x 2>&1>.tlc/harness/config.json");
  assertDenied("echo x >/dev/null>.tlc/harness/config.json");
});
