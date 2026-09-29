export type ShellWord = {
  text: string;
  /** True when the word carries a `$var`, `$(...)` or backtick — its value is not knowable here. */
  unresolved: boolean;
  /**
   * True when the word opened with a quote, so every operator inside it is literal text. A caller looking
   * for redirects must skip these: `'{"cmd":"x > cfg"}'` is one quoted argument, not a redirect.
   * Only the opening matters — `>"$f"` starts unquoted and is a real redirect.
   */
  quotedStart: boolean;
};

export type ShellSegment = {
  words: ShellWord[];
  /**
   * True when the segment could not be split with confidence. Which *verbs* defeat inspection is a
   * policy question and belongs to the caller — this only reports failures of splitting.
   */
  opaque: boolean;
};

const SEPARATORS = new Set([";", "|", "&", "\n"]);
// why: `>`/`<` join the escapable set alongside the redirect-glued-`&` fix below — real bash itself treats
// `\>`/`\<` as literal characters, not redirect operators (`echo a\>b` prints the one argument `a>b`), and
// this tokenizer has to agree, or an escaped `>` would still register as a genuine redirect operator for the
// `&`-drop check that follows.
const ESCAPABLE = new Set([" ", "\t", '"', "'", "$", "`", "\\", ";", "|", "&", "(", ")", ">", "<"]);

function isExpansion(text: string): boolean {
  return text.includes("$") || text.includes("`");
}

// hazard: a heredoc body is data being written, not a command list. Tokenizing it invents segments whose
// head verb never runs, and its quotes make the whole command look unbalanced. It is separated here rather
// than discarded, because `python3 - <<PY` makes that body the program — a caller that never sees it cannot
// tell a document from a script.
/**
 * A heredoc body, paired with the command text that preceded its `<<TAG` marker. The prefix is what
 * identifies the verb the body is fed to — without it, a body can only be attributed to the command as a
 * whole, which mistakes `cat <<EOF ... ; node x` for a program handed to node.
 */
export type HeredocChunk = { body: string; prefix: string };

export function splitHeredocs(command: string): { stripped: string; heredocs: HeredocChunk[] } {
  const heredoc = /<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1/;
  const heredocs: HeredocChunk[] = [];
  let rest = command;
  let stripped = "";
  for (;;) {
    const match = heredoc.exec(rest);
    if (!match) {
      stripped += rest;
      break;
    }
    const bodyStart = rest.indexOf("\n", match.index + match[0].length);
    const prefix = stripped + rest.slice(0, match.index);
    stripped += rest.slice(0, match.index);
    if (bodyStart === -1) {
      break;
    }
    const terminator = new RegExp(`^\\s*${match[2] as string}\\s*$`, "m");
    const body = rest.slice(bodyStart + 1);
    const end = terminator.exec(body);
    if (!end) {
      heredocs.push({ body, prefix });
      break;
    }
    heredocs.push({ body: body.slice(0, end.index), prefix });
    rest = body.slice(end.index + end[0].length);
  }
  return { stripped, heredocs };
}

export function heredocChunks(command: string): HeredocChunk[] {
  return splitHeredocs(command).heredocs;
}

// invariant: this splits words, it does not evaluate them. Anything it cannot split with confidence
// is reported as opaque so callers can refuse rather than guess — a wrong split must never read as
// a safe command.
export function tokenizeShell(command: string): ShellSegment[] {
  const segments: ShellSegment[] = [];
  let words: ShellWord[] = [];
  let current = "";
  let currentHadQuote = false;
  let currentStartedQuoted = false;
  let quote: '"' | "'" | null = null;
  let unbalanced = false;
  let depth = 0;
  // why: `current.endsWith(">")` cannot tell a bare redirect operator from a `>` that arrived quoted
  // (`"a>"`) or escaped (`\>`, now consumed whole by the `ESCAPABLE` branch above) — both leave the same
  // trailing character in `current`. Tracked separately, and only ever set `true` by the one branch below
  // that appends a genuinely bare, unquoted, unescaped `>`/`<`; every other branch that touches `current`
  // clears it.
  let lastCharWasBareRedirect = false;

  function pushWord(): void {
    if (current !== "" || currentHadQuote) {
      words.push({
        text: current,
        unresolved: isExpansion(current),
        quotedStart: currentStartedQuoted,
      });
    }
    current = "";
    currentHadQuote = false;
    currentStartedQuoted = false;
    lastCharWasBareRedirect = false;
  }

  function pushSegment(): void {
    pushWord();
    if (words.length > 0) {
      segments.push({ words, opaque: unbalanced });
    }
    words = [];
  }

  const { stripped } = splitHeredocs(command);

  for (let index = 0; index < stripped.length; index += 1) {
    const char = stripped[index] as string;

    if (quote !== null) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
        lastCharWasBareRedirect = false;
      }
      continue;
    }

    // hazard: treating every backslash as an escape turned `C:\Users\me\.ssh\id_rsa` into
    // `C:Usersme.sshid_rsa`, so no Windows path resolved and the secret rule silently passed it.
    // A backslash only escapes what actually needs escaping; anything else is part of the path.
    if (char === "\\") {
      const next = stripped[index + 1];
      if (next !== undefined && ESCAPABLE.has(next)) {
        current += next;
        index += 1;
      } else {
        current += char;
      }
      lastCharWasBareRedirect = false;
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      if (current === "" && !currentHadQuote) {
        currentStartedQuoted = true;
      }
      currentHadQuote = true;
      lastCharWasBareRedirect = false;
      continue;
    }

    // hazard: a separator inside $( ) or ${ } belongs to the substitution, not to the command list.
    // Splitting there would hand a fragment to the rules and lose the real verb.
    if (char === "$" && (stripped[index + 1] === "(" || stripped[index + 1] === "{")) {
      depth += 1;
      current += char;
      lastCharWasBareRedirect = false;
      continue;
    }
    if (depth > 0 && (char === ")" || char === "}")) {
      depth -= 1;
      current += char;
      lastCharWasBareRedirect = false;
      continue;
    }

    // hazard: `&` is a separator (background) on its own, but `N>&M`, `>&M`, `N<&M` (fd duplication) and
    // `&>file`/`&>>file` (bash's combined stdout+stderr redirect) all carry one glued to a `>` or `<` — the
    // separator check below used to fire on it regardless, splitting `git log … dev 2>&1 | head` into a
    // segment ending in `2>` and a second, one-word segment `1`, which then got judged as a non-reader verb.
    // Dropped rather than kept: keeping it would leave `>&.tlc/harness/config.json` tokenized with the `&`
    // still glued to the front of the extracted target text (`&.tlc/harness/config.json`, a name that does
    // not match the real surface path), silently defeating the redirect check it must still reach. Dropping
    // it uniformly collapses every one of these forms to a plain `>`/`<` operator `redirectTargets` (and every
    // other rule reading a word) already parses correctly — `2>&1` becomes `2>1`, a harmless fake filename
    // no rule will ever match, and `>&file`/`&>file` both become `>file`, the real target intact.
    // hazard (round 7): `current.endsWith(">")` cannot tell a genuine bare operator from a `>` that arrived
    // quoted (`"a>"`) or escaped (`\>`) — both leave the same trailing character in `current`. That let
    // `echo "a>"& python3 -c "…"` swallow the `&` as if it were glued to a real redirect, folding the
    // `python3` command into `echo`'s argument list and hiding it from every floor rule (confirmed against
    // real bash: the `&` there is a genuine background separator and the second command really runs).
    // `lastCharWasBareRedirect` is only ever set `true` by the bare-character fallthrough below, and is
    // cleared by every branch that appends quoted or escaped content, so it tracks exactly that distinction.
    if (depth === 0 && char === "&" && (lastCharWasBareRedirect || stripped[index + 1] === ">")) {
      continue;
    }

    if (depth === 0 && SEPARATORS.has(char)) {
      pushSegment();
      continue;
    }

    if (depth === 0 && (char === " " || char === "\t")) {
      pushWord();
      continue;
    }

    current += char;
    lastCharWasBareRedirect = char === ">" || char === "<";
  }

  if (quote !== null || depth > 0) {
    unbalanced = true;
  }
  pushSegment();

  // why: an unbalanced quote is only detectable at the end, so segments split before it were judged
  // under the wrong assumption. Re-mark the whole list rather than trust those splits.
  return unbalanced ? segments.map((segment) => ({ ...segment, opaque: true })) : segments;
}
