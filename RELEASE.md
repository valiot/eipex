# Releasing eipex

> **Publishing is a manual maintainer action.** Nothing in this repo's
> automation (CI, agents, scripts) ever runs `mix hex.publish`. That command
> uploads a package to hex.pm and HexDocs — it requires the maintainer's own
> hex.pm account and credentials, and it is effectively irreversible (a
> published version can be **retired**, never re-uploaded or deleted). Only a
> human, running the command locally with their own `mix hex.user auth`
> session, publishes a release.

This checklist walks the maintainer through releasing `v0.1.0` (and, with the
version bumped, any subsequent release).

## 1. Preconditions

- [ ] You have a [hex.pm](https://hex.pm) account.
- [ ] You are authenticated locally: `mix hex.user auth` (or `mix hex.user
      whoami` to check an existing session).
- [ ] `mix.exs`'s `@source_url` reflects where the code will actually live.
      It currently defaults to `https://github.com/valiot/eipex` — change it
      first if the org/repo name differs, then re-run the verification steps
      below (`source_url` feeds both `mix.exs` package `links` and the
      `docs/source_ref` used for HexDocs "View Source" links).
- [ ] If you want GitHub links (README badges, the `links["GitHub"]` package
      metadata, HexDocs "View Source") to resolve, create and push the GitHub
      repository now. This is optional — the package builds and publishes
      fine without a live repo; the links are just metadata that would 404.

## 2. Verify

Run every command below and confirm clean output before tagging. All of
these are safe to re-run and touch nothing outside the local `_build`/`doc`
directories.

```bash
mix format --check-formatted
mix test
mix test --include interop   # requires docker: cpppo + pycomm3 + OpENer
mix docs
mix hex.build
```

- `mix test` should show the full hermetic suite green (291+ tests, 3
  properties, interop excluded by default).
- `mix test --include interop` starts the reference-peer interop suites
  (cpppo, pycomm3, OpENer via `docker compose -f interop/docker-compose.yml
  up -d`, per the README's Interoperability section) — bring the containers
  down afterward (`docker compose -f interop/docker-compose.yml down`).
- `mix docs` should generate `doc/index.html` with no errors.
- `mix hex.build` should print the package contents (lib, priv, README,
  CHANGELOG, LICENSE, mix.exs, .formatter.exs) and produce
  `eipex-<version>.tar` locally, with **no** metadata warnings (missing
  license, missing description, etc.). This step never uploads anything.

If any command fails or warns, fix it and re-run the full list before
proceeding — don't tag against a red or warning build.

## 3. Tag

```bash
git tag v0.1.0
```

The tag name must match the version being published (`mix.exs`'s `@version`)
and the `source_ref` used by `mix docs` (`"v#{@version}"`), so HexDocs' "View
Source" links resolve to the right commit.

## 4. Publish — MAINTAINER RUNS THIS

```bash
mix hex.publish
```

- Review the file list it prints (it should match what `mix hex.build`
  showed in step 2) before confirming the prompt.
- On confirmation, it uploads the package to hex.pm **and** the generated
  docs to HexDocs in one step.
- This is irreversible: a published version can be retired
  (`mix hex.retire`) to mark it unsuitable for use, but it can never be
  deleted or re-uploaded under the same version number. If something is
  wrong, fix it and publish a new patch version instead.

No script or CI job in this repository runs this command. It is listed here
purely as the maintainer's manual step.

## 5. Post-publish

- [ ] Push the tag: `git push origin v0.1.0`.
- [ ] Push `main` if the release commit(s) haven't been pushed yet.
- [ ] Announce the release (team channel, README badge check, etc.).
- [ ] Confirm the package page (`https://hex.pm/packages/eipex`) and docs
      (`https://hexdocs.pm/eipex`) render as expected.
