# Eipex Phase 7 — Documentation, EDS & v0.1.0 Release Prep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `eipex` a publishable v0.1.0 hex package: complete packaging metadata + LICENSE + ex_doc so `mix docs` and `mix hex.build` are clean; an accuracy pass over every moduledoc/@doc; resolve the one deferred code item (BOOL-in-UDT bit source); a sample adapter EDS; a finalized README and CHANGELOG; and a release dry-run producing a RELEASE checklist. **The actual `mix hex.publish` is NOT performed by this plan** — it is an external, irreversible action requiring the maintainer's hex.pm credentials and is left as a documented manual step.

**Architecture:** No protocol behavior changes except Task 3 (the BOOL-in-UDT bit-source fix, if verification shows the current source is wrong). Everything else is packaging, documentation, and verification.

**Decisions:**
- Package: `name: :eipex`, license `Apache-2.0` (needs a LICENSE file), `source_url: "https://github.com/valiot/eipex"`, maintainer "Valiot" (matches the org's `modbux`/`abex`/`opex62541` convention). If the maintainer wants a different org/URL they change one string later — not a blocker.
- Docs generated with `ex_doc` (dev-only dep), grouped by role (Codecs / Scanner / Adapter), README as the extras overview page.
- v0.1.0 ships the deferred protocol scope (multicast, heartbeat connection types, structure writes, deep UDT nesting, tag-path polish) as documented **Known Limitations**, not as blockers.

## Global Constraints

- All committed content (code, comments, docs, commit messages, CHANGELOG) in English.
- Zero runtime dependencies. `ex_doc` is dev-only (`only: :dev, runtime: false`); `stream_data` stays test-only.
- `mix format` before every commit. CHANGELOG entries stay one line, `[Type] What changed`, ≤100 chars (until Task 5 cuts the release header).
- No `mix hex.publish`. No pushing to a git remote. No network calls except the BOOL-source research in Task 3 (WebFetch of public pycomm3/Rockwell docs) and `mix deps.get` for ex_doc.
- TDD for the Task 3 code change; docs tasks verify with `mix docs`/`mix hex.build`/`mix compile --warnings-as-errors`.
- Phases 1-6 suites (291 tests + 3 properties, 7 interop excluded) stay green throughout.

## File Structure

```
eipex/
├── LICENSE                          # Task 1: Apache-2.0 full text
├── mix.exs                          # Task 1: full package + docs metadata, ex_doc dep
├── lib/eipex.ex                     # Task 2: root moduledoc (library overview)
├── lib/eipex/**                     # Task 2: moduledoc/@doc accuracy pass; Task 3: bool fix
├── priv/eds/eipex_adapter.eds       # Task 4: sample EDS
├── README.md                        # Task 4: install, feature matrix, known limitations, roadmap
├── CHANGELOG.md                     # Task 5: v0.1.0 release header
└── RELEASE.md                       # Task 5: maintainer publish checklist
```

---

### Task 1: Packaging metadata + LICENSE + ex_doc

**Files:**
- Create: `LICENSE`
- Modify: `mix.exs`
- Test: none (verified by `mix docs` + `mix hex.build`)

**Interfaces:**
- Produces a `mix.exs` where `mix hex.build` succeeds with no warnings about missing metadata, and `mix docs` generates HTML.

- [ ] **Step 1: Write the LICENSE**

Create `LICENSE` with the full, verbatim Apache License 2.0 text (the standard ~11KB document). Copyright line at the end's appendix boilerplate: `Copyright 2026 Valiot`. Use the canonical text from https://www.apache.org/licenses/LICENSE-2.0.txt (WebFetch it to get the exact wording, or reproduce the standard text — it must be the complete license, not a summary).

- [ ] **Step 2: Rewrite `mix.exs` with full metadata**

```elixir
defmodule Eipex.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/valiot/eipex"

  def project do
    [
      app: :eipex,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      name: "Eipex",
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp description do
    "A pure-Elixir EtherNet/IP (CIP) protocol stack: scanner (originator) and " <>
      "adapter (target) roles, explicit and implicit (class 1 I/O) messaging, " <>
      "and Rockwell Logix tag services."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      maintainers: ["Valiot"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      },
      files: ~w(lib priv .formatter.exs mix.exs README.md CHANGELOG.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      groups_for_modules: [
        Codecs: [
          Eipex.Encap,
          Eipex.CPF,
          Eipex.Identity,
          Eipex.IO,
          Eipex.CIP.Path,
          Eipex.CIP.MessageRouter,
          Eipex.CIP.Types,
          Eipex.CIP.ConnectionManager,
          Eipex.CIP.Logix
        ],
        Scanner: [
          Eipex.Scanner,
          Eipex.Scanner.Discovery,
          Eipex.Scanner.IOConnection,
          Eipex.Scanner.Logix,
          Eipex.Scanner.Logix.Value,
          Eipex.Tag
        ],
        Adapter: [
          Eipex.Adapter,
          Eipex.Adapter.Config,
          Eipex.Adapter.Handler,
          Eipex.Adapter.Object,
          Eipex.Adapter.AssemblyStore,
          Eipex.Adapter.ConnectionTable
        ]
      ]
    ]
  end

  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
```

Note: verify each module name in `groups_for_modules` actually exists (run
`find lib -name '*.ex' | xargs grep -l defmodule` and cross-check). If the
`Eipex.Adapter.Object.*` / `Eipex.Adapter.Session*` / `Listener` / `UDP` /
`IoConnection` modules should be grouped too, add them under Adapter — but any
module NOT listed still appears in docs ungrouped, so a missing entry is
cosmetic, not a build failure. Include the ones that exist; don't invent names.

- [ ] **Step 3: Fetch deps and verify docs + package build**

```bash
mix deps.get
mix docs
mix hex.build
```

Expected: `mix docs` writes `doc/index.html` with no errors; `mix hex.build`
prints the package contents and reports no missing-metadata warnings (it will
note it won't publish — that's fine). `mix test` still green (ex_doc is dev-only,
no test impact). If `mix hex.build` warns about anything (missing files, bad
license id), fix it.

- [ ] **Step 4: Ignore generated docs; format; commit**

Add `/doc/` to `.gitignore` (ex_doc output — not committed). Then:

Append to `CHANGELOG.md`: `- [Added] Package metadata, Apache-2.0 LICENSE and ex_doc documentation generation`

```bash
mix format && git add -A && git commit -m "chore: package metadata, license and ex_doc"
```

---

### Task 2: Moduledoc & @doc accuracy pass

**Files:**
- Modify: `lib/eipex.ex` (root overview moduledoc), and any module whose moduledoc/@doc is stale or thin.
- Test: none (verified by `mix docs` + reading).

**Interfaces:** documentation only — no code/behavior changes.

- [ ] **Step 1: Write the root `Eipex` moduledoc**

`lib/eipex.ex`'s `Eipex` module gets a library-overview `@moduledoc`: what the
library is (EtherNet/IP + CIP, both roles, pure Elixir, zero deps), the three
capability layers (codecs / scanner / adapter), a 4-line "getting started"
pointer to `Eipex.Scanner` and `Eipex.Adapter`, and a one-line note on the
interop-verified peers (cpppo, pycomm3, OpENer). Keep it a real overview, not a
stub.

- [ ] **Step 2: Accuracy pass over every public module**

For each module under `lib/eipex/` (34 modules), read its `@moduledoc` and public
`@doc`s against the current code and fix anything stale or wrong. Known targets
(from the deferred-findings docs):
- `Eipex.Scanner`: confirm the moduledoc mentions `route_path`, the no-reconnect
  `{:shutdown, :connection_lost}` link contract (supervise or trap exits), and
  the time-on-wire timeout semantics for queued requests (deferred from Phase 2).
- `Eipex.Adapter.Object.ConnectionManager`: the moduledoc must not claim
  "Forward Open/Close arrive in Phase 4" or "class 3 only" — class 1 I/O is
  implemented; state the class-3-and-class-1 reality and the no-per-connection-
  watchdog deviation (dies with the session / by Forward Close / by watchdog).
- `Eipex.Adapter.SessionHandler`: no stale "send_unit_data (phase 4)" comments.
- `Eipex.Scanner.Logix`: the moduledoc's element/member addressing note is now
  accurate (Task 6 fix wave added the parser) — verify it says `Tag[i]` and
  `A.B` ARE supported and states what is NOT (bit access, multi-dim beyond
  simple, structure writes).
- `test/interop/cpppo_logix_test.exs`: the "stale interop doc" flagged in the
  Phase 7 deferred doc — update its moduledoc note that element addressing now
  works via the parser (docs-only; do NOT re-run docker here).

Grep for stale phase references: `grep -rn "Phase [0-9]\|phase [0-9]\|arrive in\|until Phase\|not yet" lib` and fix any that are now false.

- [ ] **Step 3: Verify**

```bash
mix docs
mix compile --force --warnings-as-errors
mix test
```

Expected: docs build; no warnings; suite green. Skim `doc/index.html`'s module
grouping and the `Eipex` overview page render (open the file / check it exists
with the overview content).

- [ ] **Step 4: Format and commit**

Append to `CHANGELOG.md`: `- [Added] Library overview moduledoc and documentation accuracy pass`

```bash
mix format && git add -A && git commit -m "docs: moduledoc accuracy pass and library overview"
```

---

### Task 3: Resolve the deferred BOOL-in-UDT bit-source question

**Files:**
- Modify (only if verification shows the current source is wrong): `lib/eipex/scanner/logix/value.ex`, `lib/eipex/cip/logix.ex` and/or `lib/eipex/cip/types.ex`; `test/support/logix_responder.ex` (model a real member layout); the deferred-findings docs.
- Test: `test/eipex/scanner/logix/value_test.exs` (append).

**Background:** Phase 6 left a `# TODO(phase-7)` at the BOOL member decode in
`value.ex`: a UDT's BOOL member bit index is currently taken from
`symbol_type.bool_position` (bits 8-10 of the member **type** word). The Phase 6
review suspected the real source is the member **info** word (per pycomm3 and
1756-PM020). Loopback can't settle this because `LogixResponder.udt/1` mirrors
eipex's own assumption. This task resolves it definitively.

- [ ] **Step 1: Research the authoritative bit source**

Determine, from primary sources, where a Template Object member's BOOL bit
number actually lives. Use WebFetch on:
- pycomm3's template/tag-type parsing: `https://raw.githubusercontent.com/ottowayi/pycomm3/master/pycomm3/cip/data_types.py` and its tag/struct decoding (look for how a BOOL member's bit offset is derived — the member `info`/`offset` field vs the type code's bits).
- The Rockwell 1756-PM020 "Logix 5000 Data Access" template member layout (already summarized in `docs/research/protocol-byte-layouts.md` §7 — re-read it: the member metadata is `INFO (UINT) + Data Type (UINT) + Offset (UDINT)`, and it states the INFO field = "0 if atomic | size if array | **position of bit if BOOL**").

`docs/research/protocol-byte-layouts.md` §7 almost certainly already answers it:
the member **INFO** field holds the BOOL bit position, NOT the type word. Confirm
this against pycomm3, then decide.

- [ ] **Step 2: Write the failing test (RED) reflecting the correct source**

If the research confirms INFO is the bit source, write a value_test that builds
a template whose BOOL member has its bit position in `info` (e.g. a BOOL at bit 5
of the host byte → `info: 5`, `symbol_type.bool_position: 0`) and a body byte
with only bit 5 set, asserting the member decodes to `true`. With the current
code (reading `bool_position` = 0) this returns `false` → RED.

```elixir
  test "UDT BOOL member bit index comes from the member info field" do
    template = %{
      name: "Bits",
      structure_size: 4,
      members: [
        # BOOL at bit 5 of the SINT host byte at offset 0; info carries the bit
        %{name: "alarm", raw_type: 0x00C1,
          symbol_type: %{atomic_type: :bool, bool_position: 0, structure?: false},
          offset: 0, info: 5}
      ]
    }

    body = <<0x20, 0, 0, 0>>   # 0x20 = bit 5 set
    templates = %{0x4444 => template}

    assert {:ok, %{"alarm" => true}} =
             Eipex.Scanner.Logix.Value.decode_reply(<<0xA0, 0x02, 0x44, 0x44, body::binary>>, templates)
  end
```

(If the research instead confirms the CURRENT source is right, do NOT change
code: replace the TODO with a comment citing the primary source that settles it,
add a test pinning the current behavior against a responder modelling the real
layout, and record the resolution in the deferred docs. Report which way it went.)

- [ ] **Step 3: Run to verify it fails (if a change is warranted)**

Run: `mix test test/eipex/scanner/logix/value_test.exs`
Expected: FAIL — decodes `false` (reads bit 0 via `bool_position`, ignoring `info`).

- [ ] **Step 4: Fix the bit source**

In `value.ex`'s BOOL `decode_member` clause, take the bit index from the member's
`info` field (falling back to `bool_position` only if that's the confirmed
secondary source). Remove the `# TODO(phase-7)` comment; replace it with a
one-line citation (e.g. `# 1756-PM020 §template: member INFO = BOOL bit position`).
Keep array-member `info` handling correct: a member is a BOOL-bit member when its
`atomic_type == :bool`; an array member has `atomic_type` non-bool with `info` =
count — the two uses of `info` don't collide because they're guarded by type.
Verify the existing array-member test (info ≥ 2 → list) still passes.

- [ ] **Step 5: Run to verify it passes; commit**

Run: `mix test` — all green (the new bool test + the existing struct/array/string
tests). Append to `CHANGELOG.md`: `- [Fixed] UDT BOOL member bit index read from the member info field` (or
`- [Added] Verified UDT BOOL bit source against Rockwell 1756-PM020` if no code change).

```bash
mix format && git add -A && git commit -m "fix: udt bool member bit source"
```

Also: move the BOOL-in-UDT item in `docs/superpowers/plans/2026-07-06-phase-7-deferred-findings.md` from "deferred" to "resolved" with the outcome.

---

### Task 4: Sample adapter EDS + README polish

**Files:**
- Create: `priv/eds/eipex_adapter.eds`
- Modify: `README.md`
- Test: none.

**Interfaces:** an EDS a scanner-config tool (RSNetWorx/Studio 5000) can import
to know the adapter's identity and I/O connections, matching the adapter's
default sample config; a README that reads as a hex package landing page.

- [ ] **Step 1: Write the sample EDS**

`priv/eds/eipex_adapter.eds` — a minimal, well-commented Electronic Data Sheet
for an `Eipex.Adapter` started with a representative config (vendor id, device
type 0x0C communications adapter, product code, revision, one exclusive-owner
class 1 connection: config 151 / output 150 / input 100, 32-byte assemblies,
RPI range). Standard EDS sections: `[File]`, `[Device]` (VendMajRev, VendMinRev,
VendCode, ProdType, ProdCode, MajRev, MinRev, ProdName), `[Device Classification]`
(Class1 = EtherNetIP), `[Params]`, `[Assembly]` (Assem1..3 for O→T/T→O/config with
sizes), `[Connection Manager]` (Connection1: exclusive-owner, trigger cyclic,
transport class 1, the O→T/T→O sizes and RPI limits, the connection path). Add a
top comment block explaining it's a SAMPLE matching the README's adapter example
and that vendor/product codes are placeholders the user replaces with their
ODVA-assigned values. Keep the connection parameters consistent with what
`Eipex.Adapter.Object.ConnectionManager` actually validates (point-to-point,
exclusive owner, class 1). Reference the ODVA EDS format; a correct, importable
skeleton is the goal — not every optional field.

- [ ] **Step 2: Reference it and polish the README**

Rework `README.md` into a hex landing page:
- Title + one-paragraph description matching `mix.exs`.
- **Installation**: the `{:eipex, "~> 0.1.0"}` deps snippet.
- **Feature matrix**: a table of what's supported per role (discovery, explicit
  UCMM, connected class 3, class 1 I/O, Logix tags) with ✓/deferred.
- Keep the existing Usage sections (Class 1 I/O, Logix tags) — verify the code
  snippets still match the current API (option names, message shapes).
- Add a short **Adapter** usage snippet (start_link with identity/assemblies/
  handler) — the README currently only shows the scanner side.
- **Known limitations**: consolidate the deferred protocol scope (multicast;
  input-only/listen-only heartbeat; structure writes; UDT nesting > 2 levels;
  bit/multi-dim tag addressing) into a clear list — honest scoping, not buried.
- **Interoperability**: the cpppo / pycomm3 / OpENer verification (one line each).
- **EDS**: a line pointing to `priv/eds/eipex_adapter.eds`.
- Trim the design-doc path reference (internal); point instead to the generated
  HexDocs once published.

- [ ] **Step 3: Verify + commit**

`mix docs` (README renders as the docs home), `mix compile --warnings-as-errors`,
`mix test` green. Append to `CHANGELOG.md`:
`- [Added] Sample adapter EDS and hex-ready README (install, feature matrix, limitations)`

```bash
mix format && git add -A && git commit -m "docs: sample EDS and release README"
```

---

### Task 5: CHANGELOG v0.1.0 finalization + release dry-run + RELEASE checklist

**Files:**
- Modify: `CHANGELOG.md`
- Create: `RELEASE.md`
- Test: none (this task is verification + the maintainer handoff).

**Interfaces:** a CHANGELOG with a proper `## v0.1.0` release section; a
RELEASE.md the maintainer follows to publish; a verified dry-run. **This task
does NOT publish** — `mix hex.publish` is explicitly the maintainer's manual step.

- [ ] **Step 1: Cut the v0.1.0 CHANGELOG release header**

Consolidate the running `v0.1.0-dev` entries under a dated release header,
grouped by Keep-a-Changelog categories (`### Added`, `### Fixed`), and keep the
one-line-per-entry style. Structure:

```markdown
# Changelog

## v0.1.0 — 2026-07-06

First public release: a pure-Elixir EtherNet/IP (CIP) stack with scanner and
adapter roles, explicit + class 1 implicit messaging, and Logix tag services.

### Added
- <the [Added] lines, de-duplicated and ordered by layer: codecs, scanner, adapter, logix, docs>

### Fixed
- <the [Fixed] lines that represent behavior shipped in 0.1.0>
```

De-duplicate and merge the incremental dev lines into readable release notes
(e.g. many small codec `[Added]` lines → grouped). Do NOT lose information —
every capability and every user-visible fix should be represented. Keep the
existing detailed history below the release section is unnecessary; the release
section IS the history for 0.1.0.

- [ ] **Step 2: Write RELEASE.md (maintainer handoff — publish is manual)**

`RELEASE.md` — a checklist the maintainer runs to publish. It MUST state up top
that publishing is a manual maintainer action (needs a hex.pm account and
`mix hex.user auth`), and that this repo's automation never runs `mix hex.publish`.
Contents:
1. Preconditions: hex.pm account, `mix hex.user auth`; decide the final
   `source_url`/org in `mix.exs` (default `valiot/eipex`); create + push the
   GitHub repo if desired (the package works without it — links are metadata).
2. Verify: `mix format --check-formatted`, `mix test` (291+ green),
   `mix test --include interop` (requires docker: cpppo + pycomm3 + OpENer —
   the reference-peer validation), `mix docs`, `mix hex.build`.
3. Tag: `git tag v0.1.0` (matches `source_ref` in docs).
4. Publish (MAINTAINER RUNS THIS, not automation): `mix hex.publish` — review
   the file list it prints, confirm, and it uploads the package + docs to
   HexDocs. Note it's irreversible (a version can be retired but not re-uploaded).
5. Post: push the tag; announce.

- [ ] **Step 3: Release dry-run (everything except publish)**

Run and capture the output of each — this is the proof the package is
publishable without actually publishing:

```bash
mix format --check-formatted
mix test
mix docs
mix hex.build
```

Expected: all clean; `mix hex.build` produces `eipex-0.1.0.tar` and lists the
packaged files (lib, priv, README, CHANGELOG, LICENSE, mix.exs, .formatter.exs)
with no metadata warnings. Do NOT run `mix hex.publish`. (Interop tests are
docker-gated and excluded by default; note in the report that the maintainer
runs `--include interop` per RELEASE.md — do not run docker in this task.)

- [ ] **Step 4: Commit**

Append to `CHANGELOG.md` is not needed (Step 1 already finalized it). Commit the
release header + RELEASE.md:

```bash
mix format && git add -A && git commit -m "docs: v0.1.0 changelog and release checklist"
```

---

## Completion criteria for Phase 7

- `mix docs` generates grouped HTML with the README overview; `mix hex.build`
  produces the 0.1.0 tarball with no metadata warnings.
- LICENSE present; `mix.exs` has full package metadata; ex_doc dev-only; zero
  runtime deps.
- Every moduledoc accurate against the shipped code; no stale phase references.
- BOOL-in-UDT bit source resolved (fixed or verified-and-documented).
- Sample EDS present; README is a hex landing page with known limitations.
- CHANGELOG has a dated `## v0.1.0` section; RELEASE.md documents the manual
  publish; the dry-run is clean.
- `mix format --check-formatted` and full `mix test` (291+ tests) green.
- **`mix hex.publish` NOT run** — left to the maintainer per RELEASE.md.

## After this plan

v0.1.0 is publishable. The maintainer publishes per RELEASE.md when ready.
Post-release backlog lives in `docs/superpowers/plans/2026-07-06-phase-7-deferred-findings.md`
(multicast, heartbeat connection types, structure writes, deep UDT nesting,
tag-path polish, perf niggles) — candidates for a v0.2. `abex`/libplctag (the C
NIF) can be retired in favor of this pure-Elixir stack.

