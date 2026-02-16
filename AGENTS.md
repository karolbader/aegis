# AEGIS — AGENTS.md (Codex execution rules)

You are working in this repository as an engineering agent. Follow these rules strictly.

## North Star
Ship an audit/readiness agent pipeline that is:
- Evidence-first (no invented evidence)
- Deterministic (replayable outputs)
- Local-first (no network dependency for analysis)
- Reviewer-ready (sealed artifacts + replay instructions)

## Non-Negotiables
1) **Diff-only changes**
   - Make the smallest possible patch that satisfies the task.
   - Do not rewrite files wholesale.
   - Prefer additive edits and small refactors.

2) **No hallucinated evidence**
   - Never fabricate paths, hashes, excerpts, or citations.
   - Only reference evidence produced by Cupola search hits and manifests.

3) **Determinism**
   - Use versioned JSON schemas.
   - Timestamps must be RFC3339 UTC.
   - Outputs must be reproducible from the same inputs.

4) **No network calls**
   - Do not add HTTP requests, web scraping, or external API calls.
   - The quote engine must be pure computation from intake JSON.

5) **Local execution**
   - All commands must run locally on Windows.
   - Prefer robust error messages.

## Quality Gates (must run before you claim “done”)
- `cargo fmt`
- `cargo clippy -- -D warnings`
- `cargo test`

## Output Artifacts (canonical)
When producing a Decision Pack, write to the chosen output folder:
- `DecisionPack.html`
- `DecisionPack.manifest.json` (versioned schema)
- `DecisionPack.seal.json` (sha256 envelope)
- `REPLAY.md`
- `cupola.manifest.json` (when Cupola freeze is executed)

When producing a quote, write:
- `Quote.json` (versioned schema)
- `Quote.md`
- `DataShareChecklist.md` (when applicable)

## Repo Hygiene
- Do not commit `target/`, transient `out/`, large media files, or other local artifacts unless explicitly requested.
- Keep `data/packs/**` tracked (these are part of the product).

## Communication Style
When finished, print:
1) A short bullet list of changes
2) The exact verification commands you ran
3) Where output files are written
