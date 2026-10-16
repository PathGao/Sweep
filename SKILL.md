---
name: sweep
description: Exhaustive bug / duplication / dead-code scan of a codebase as a table that must be filled cell by cell, instead of free-roaming agent reviews that each follow one thread and miss the rest. Use when the user asks to scan a project for bugs, duplicated logic, inconsistent behaviour across entry points, or dead code "completely", to resume or extend such a scan, to rescan only what changed, or to measure how much a scan missed.
---

# Sweep

A free agent review walks one thread from wherever it starts and stops when its context fills. Nothing records what it did not look at, so every rerun finds "new" problems and no run is complete. Sweep fixes the denominator first:

```
rows    = units:  fn     every function (graphify + tree-sitter)
                  lit    every key or sentence written in 2+ files        (one fact copied, or answered twice)
                  clone  every block of code copied into 2+ functions     (one fact copied)
                  same   every function name defined in 2+ files           (copied helpers)
                  sib    function pairs in different files sharing callees,
                         API calls and literals: two entry points, one job   (two places answer one question)
                  text   every user-visible string, in chunks, judged against
                         .sweep/text-catalog.md (all of them)              (same situation, same words)
                  hard   every number, key, prefix or sentence that equals a named constant
                         or table entry elsewhere, or is written inline 2+ times     (one fact, one source)
                  mech   every mechanism an agent registers                (a member that did not join)
columns = lenses: logic, guard, async, errors, state, dup, dead, security, wording,
                  lit-one, clone-one, same-one, sib-alike, text-same, hard-one, mech-members  (lenses.json)
cell    = (unit, lens), only where the lens applies (regex on the unit's source)
```

The cross-file kinds exist because per-function review cannot see the other copy: in the MoonDigest pilot most misses were "the same thing done differently in another entry point". `hard` overlaps with what a lint can enforce. A lint is better when the project has one (it runs on every change for free); `hard` covers projects without it, and its findings are the input for writing that lint. A packet carries one lens only; one checklist at a time goes deeper than nine.

Agents fill cells. A cell is `clean` only with evidence naming the lines read; `record` rejects the whole packet otherwise, and rejects a packet with any cell missing. Coverage is `filled / applicable cells` and is printed, not claimed.

Each cell stores the unit's hash. `scan` after a code change reopens exactly the cells whose unit changed. Rescans cost what changed, not the whole repo.

## Commands

`S=<this skill's directory>/sweep.py` (absolute path; workers get it spelled out), always with `--root <project>`. Needs `graphify` on PATH (`uv tool install graphifyy`).

| Command | What |
|---|---|
| `$S --root R init --include 'src/*' --exclude '*.test.*'` | First run. Builds graphify graph if missing, inventory, cells. Adds `.sweep/` and `graphify-out/` to `.git/info/exclude`. |
| `$S --root R scan` | After code changes. Reopens changed cells, adds new units, retires deleted ones. |
| `$S --root R status [--path x.js]` | Coverage per lens. |
| `$S --root R next [--path x.js] [--pass 2]` | Leases one single-lens packet (~600 lines of code, or a few cross-file units) and prints its path. `NONE` when nothing is open. |
| `$S --root R record <packet> <answers.json>` | Validates and stores answers. All-or-nothing. |
| `$S --root R release [packet]` | Returns leased cells to open (after workers stopped, or for one abandoned packet). |
| `$S --root R mech "<name>" "<rule every member must follow>" <file:line>` | Registers a mechanism; creates its `mech-members` cell. |
| `$S --root R dedupe` / `report` | Merges same place + same pattern; prints the findings table and patterns seen in 2+ units (lint candidates). |
| `$S --root R judge F12 confirmed\|rejected\|fixed "note"` | Verifier verdict. |
| `$S --root R sample --pct 10` then `next --pass 2` ... then `estimate` | Independent second pass on a random sample; estimates how many defects pass 1 missed (capture-recapture). |

## Procedure

1. Read the project's rules (README, CONTRIBUTING, `AGENTS.md` / `CLAUDE.md`, design docs). Choose include/exclude: production code only; tests, mocks and generated files out. `init`. Show the user the `status` table and the cell count before spending agents. A full sweep is roughly one worker per 5 packets; scope with `--path` when the user wants a pilot or one area.
2. Launch workers in parallel (Agent tool, one message, `run_in_background: true`), each with the worker prompt below and the same `--path` filter. Workers lease packets themselves, so they never overlap. Relaunch until `next` prints `NONE` and `status` shows no open or leased cells. Workers may register mechanisms; that adds cells, so check `status` again after they finish.
3. `dedupe`, then one verifier per ~15 findings: re-read the code, argue for and against, `judge`. Do not show the user unverified findings as confirmed.
4. `report`. For more than ~10 findings, write it as a review file the user can annotate: numbered items, location, symptom, suggestion, a decision column. Patterns seen in 2+ units go to the user as lint candidates: a class found twice is cheaper as a check that runs on every change than as another scan.
5. When the user wants a completeness number: `sample --pct 10`, run workers with `--pass 2` (fresh agents, they must not see pass-1 results), `estimate`. If a known-defect list exists (fixes merged later, an earlier audit), also report how many of those pass 1 found.

Never fix code during a sweep. Fixing changes hashes and reopens cells; fix after the report, then `scan`.

## Worker prompt

```
You fill cells of a sweep table for the project at <ROOT>. Loop up to 5 times (never call next after recording your 5th packet; a leased packet you do not answer stays blocked):
1. Run: <S> --root <ROOT> next --path <PATH> [--pass N]. If it prints NONE, stop.
2. Read the packet file it prints, completely. Each packet has one lens; apply it thoroughly. Read the project's rules once (README, AGENTS.md / CLAUDE.md, design docs: the sections that matter for the lens in the packet).
3. For every cell, apply that lens's checklist to that unit. Open callers, sibling files and docs as needed; grep the repo when a lens asks about other places. Do not edit project files.
4. Write the answers as a JSON array (the skeleton at the end of the packet) to <ROOT>/.sweep/packets/<id>.answers.json and run the record command printed in the packet. If it says REJECTED, fix what it lists and record again.
Rules: "clean" needs evidence naming the lines you read and why they are fine. Any helper file you write goes under <ROOT>/.sweep/packets/ and starts with your packet id; other workers run in parallel. A finding needs a concrete scenario (input/state -> wrong result), not a style opinion. Report what is wrong now, including things that are consistent but wrong. When a lens makes you check other places that must behave alike and you could not check them all, register the mechanism with the mech command. Reply at the end with one line: packets recorded, findings count.
```

## Cost

Measured on MoonDigest (2026-10-16): about 20 packets and 0.8M tokens per 1000 production lines; a worker does 5–6 packets for about 200–300k tokens. The whole extension (19k lines, 7050 cells, 511 packets) took about 85 workers, 20M tokens and 2.5 hours, then 6 verifiers for 81 medium findings. Rescans after a change cost only the reopened cells. Show the user the packet count (simulate `next` on a copy of `.sweep/`) and this estimate before launching.

## What it does not cover

Cells cover what the lenses ask. A defect class no lens asks about will be missed every time; when a verified miss shows up (from users, later fixes, or pass 2), add or sharpen a lens in `lenses.json`, then `scan` adds the new column. Runtime-only behaviour (real browser, real network) still needs the project's smoke tests.
