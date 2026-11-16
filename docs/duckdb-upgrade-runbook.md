# Runbook: moving the DuckDB extension to a new DuckDB release

The extension uses DuckDB's C API v2, in which every function is still
unstable. A build is stamped `C_STRUCT_UNSTABLE` and loads in exactly one
DuckDB release, so every DuckDB release, patch releases included, needs a new
build, and until one is published the users of that DuckDB release have no
pcapsql. This is the procedure for producing it. It implements section 9 of
[`duckdb-v2-extension-roadmap.md`](duckdb-v2-extension-roadmap.md).

Commands are run in `pcapsql-duckdb/` unless a path says otherwise.

## When to run it

| Trigger | What it means |
|---|---|
| DuckDB publishes a release (`vX.Y.Z` on github.com/duckdb/duckdb) | Run the whole runbook once `duckdb-neo` for it is on crates.io |
| `duckdb-neo` publishes a new version for the DuckDB release already targeted (`0.20000.2` to `0.20000.3`) | Steps 2b, 4 and 6 only: nothing else names the binding's own version |
| The canary workflow (`duckdb-canary.yml`) goes red | Nothing to release yet. Read the failure, and note in the roadmap what the next upgrade will have to change |

The canary is the early warning. `make canary` builds against the newest
`duckdb-neo` on crates.io and `make canary CANARY=main` against the main
branch of `duckdb-rs`; `CANARY_KEEP=1` leaves the moved pin in the working
tree, which is a way to start step 2b.

## What names the DuckDB release

`make check_pins` (`scripts/check-pins.sh`) fails while these disagree. It
is the checklist for step 2.

| # | Place | Holds |
|---|---|---|
| a | `pcapsql-duckdb/Makefile`: `TARGET_DUCKDB_VERSION` | `vX.Y.Z`. Stamped into the artifact; also the DuckDB the Python test runner installs |
| b | `duckdb-neo` in `pcapsql-duckdb/Cargo.toml`, `ext/Cargo.toml`, `itest/Cargo.toml`; `Cargo.lock` and `itest/Cargo.lock` | `=0.XYYZZ.n`: the middle number is the DuckDB release (`20000` is 2.0.0, `20103` would be 2.1.3), `n` counts the binding's own releases for it |
| c | `api_version` in `ext/src/lib.rs` and `itest/src/lib.rs` | `"vX.Y.Z"` |
| d | `scripts/fetch-duckdb.sh` (default version) and `scripts/duckdb-release.sha256` | The release whose shell and library the tests download, and their checksums |
| e | The `extension-ci-tools` submodule, and its commit in `.github/workflows/duckdb-dist.yml` (after `@`, and `ci_tools_version`) | The branch of extension-ci-tools for the DuckDB release line (`v2.0-cyanoptera` for 2.0), at one commit |
| f | `.github/workflows/duckdb-dist.yml`: `duckdb_version`, and the artifact name in the `verify` job | `vX.Y.Z` |
| g | `pcapsql-duckdb/community/description.yml`: `extension.version` | The pcapsql version that will be released with the upgrade |

Not checked by the script, because they are prose: the DuckDB version in
`pcapsql-duckdb/README.md`, the top-level `README.md`,
`docs/duckdb-extension-reference.md` and the roadmap. `git grep -n -F 'X.Y.Z'`
with the old version finds them.

## Steps

### 1. Find out what exists

- The DuckDB release tag: `git ls-remote --tags https://github.com/duckdb/duckdb 'v*'`.
- The matching `duckdb-neo`: `make canary` prints the newest published
  version and the DuckDB release it is for. If there is none yet, stop: the
  binding is the dependency that cannot be worked around.
- The extension-ci-tools branch for the release line:
  `git ls-remote --heads https://github.com/duckdb/extension-ci-tools`. For a
  patch release of the same line the branch is the same, at a newer commit.
- What community-extensions builds with: `DUCKDB_LATEST_STABLE` and the
  `uses:` line of the `build` job in `.github/workflows/build.yml` of
  duckdb/community-extensions. The extension-ci-tools branch named there is
  the one to follow in (e).
- The release notes of `duckdb-rs` for changes to `duckdb-neo`.

### 2. Move the pins, on a branch

```sh
git switch -c duckdb-vX.Y.Z
```

a. `TARGET_DUCKDB_VERSION=vX.Y.Z` in the `Makefile`.

b. The `duckdb-neo` version in the three manifests, then let cargo resolve
both lock files:

```sh
cargo check -p pcapsql-duckdb-ext              # rewrites ../Cargo.lock; compile errors are step 3
cargo metadata --manifest-path itest/Cargo.toml --format-version 1 > /dev/null   # rewrites itest/Cargo.lock
```

`git diff --stat -- '*.lock'` should show `duckdb-neo`, `libduckdb-sys` and
`duckdb-loadable-macros` moving and little else.

c. `api_version` in `ext/src/lib.rs` and `itest/src/lib.rs`.

d. The default in `scripts/fetch-duckdb.sh`, and the checksums:

```sh
scripts/duckdb-release-checksums.sh vX.Y.Z > scripts/duckdb-release.sha256
```

The file then holds the new release only, which is what `fetch-duckdb.sh`
will be asked for. If DuckDB renamed its release archives the script fails
with a 404; the names are in `fetch-duckdb.sh` and in the checksum script.

e. The submodule and the workflow:

```sh
git submodule set-branch --branch <branch> pcapsql-duckdb/extension-ci-tools   # only for a new release line
git submodule update --remote pcapsql-duckdb/extension-ci-tools
git add pcapsql-duckdb/extension-ci-tools ../.gitmodules
git ls-files --stage pcapsql-duckdb/extension-ci-tools                         # the commit to copy
```

Put that commit in `.github/workflows/duckdb-dist.yml` in both places. Then
read what changed in the submodule's
`makefiles/c_api_extensions/{base,rust}.Makefile` (the `Makefile` here
includes them and overrides `TARGET_INFO`, `TARGET_PATH` and
`EXTENSION_VERSION`) and in the inputs of
`.github/workflows/_extension_distribution.yml` (`duckdb-dist.yml` passes
`build_directory`, `extra_toolchains`, `exclude_archs`, `reduced_ci_mode`).
If `config/distribution_matrix.json` gained a platform that is built by
default, decide whether to build it or to add it to `exclude_archs` and to
`excluded_platforms` of the community descriptor.

f. `duckdb_version` and the artifact name in `duckdb-dist.yml`.

g. The prose places, and the Python environment, which still has the old
DuckDB:

```sh
make clean_configure configure
make check_pins
```

### 3. Make it compile

```sh
cargo check -p pcapsql-duckdb-ext
make check_containment
```

`duckdb_neo` is used only under `src/engine/` (and in the two entrypoints),
so that is where the changes are. Expect them, by how exposed each file is:

| File | Depends on |
|---|---|
| `engine/pushdown.rs` | The filter-pushdown and expression API, the part most likely to be redesigned |
| `engine/table/` | Table function callbacks (`mod.rs`), bind arguments and the file system's glob (`args.rs`), batch indices |
| `engine/writer.rs` | Vector layout: data pointers, validity, string and list storage, chunk capacity |
| `engine/fs.rs` | The file API |
| `engine/scalar/`, `macros.rs`, `settings.rs`, `replacement.rs`, `listing.rs` | Registration builders |

Nothing outside `pcapsql-duckdb/` should change. If the shared scan layer
(`pcapsql_core::scan`) has to change to fit a new DuckDB API, that is a
design change with its own review, not part of an upgrade.

### 4. Test

```sh
make release test_release load_test_release check_reference_release
make itest
make check
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings      # at the repository root
```

- `itest/tests/spike_*.rs` are the assumptions the design makes about the
  engine (file handles across callbacks, batch indices and row order, vector
  pointers, what the multi-file wrapper forwards). A spike test that fails
  after an upgrade names the assumption that no longer holds; fix the design,
  not the test.
- `make load_test_release` is the check that the artifact loads in the
  release's own shell. A failure of `LOAD` itself, with everything else
  green, means a pin of the table above was missed.
- `check_reference_release` fails if the upgrade added or removed a
  registered function without the reference following.

### 5. Revisit what was built around the old release

Each of these is a limit of DuckDB 2.0.0 that the extension works around. On
every upgrade, check whether the new release lifts it; if so, record it in
the roadmap (section 8, P9) rather than changing behaviour inside the
upgrade.

| Limit in 2.0.0 | Where | What lifting it allows |
|---|---|---|
| The multi-file wrapper forwards neither named parameters nor filter pushdown (D9, U6) | `engine/table/` does its own multi-file handling | `hive_partitioning`, `union_by_name` through DuckDB's wrapper |
| A `BETWEEN` node does not say whether its bounds are inclusive | `engine/pushdown.rs` uses a range without accepting it | Accepting ranges, so `EXPLAIN` shows no filter for a time window |
| The file API has no modification time | The index cache is in memory only and tells a changed file by its size and some of its bytes (`engine/table/index_cache.rs`); `pcapsql_index_cache_dir` is not implemented | Keeping the boundary index on disk, a surer check of a kept one; partitioning remote captures |
| No statistics callback, no `file_row_number` virtual column | Roadmap P9 | Min/max of `timestamp` and `frame_number` from the index |
| Table functions and the file system are unstable API | The `C_STRUCT_UNSTABLE` stamp; this runbook | Roadmap P9: one build for many DuckDB releases |

### 6. Release

1. `CHANGELOG.md`: the DuckDB release the extension now targets, under
   `[Unreleased]`. Update the prose places of the table above.
2. Merge. `duckdb.yml` runs on the pull request; `duckdb-dist.yml` runs on
   `main` and must be green for every platform before tagging.
3. Tag a pcapsql release as usual. A DuckDB upgrade alone is a patch release
   of pcapsql. `release.yml` attaches one archive of the extension per
   platform to the GitHub release.
4. Open a pull request to duckdb/community-extensions that sets `repo.ref`
   (and `extension.version`) in `extensions/pcapsql/description.yml`
   ([`pcapsql-duckdb/community/README.md`](../pcapsql-duckdb/community/README.md)).

### Supporting two DuckDB releases at once

One commit of this repository targets one DuckDB release. To keep serving the
previous release line after an upgrade, branch before the upgrade
(`duckdb-v2.0`), release fixes from that branch, and give community-extensions
that branch's commit in the field of `repo` it reads for the older line.
Nothing in this repository builds for two releases from one commit.

## Dry run, 2026-11-15

The runbook was walked once on the day it was written. There was nothing to
upgrade to, so the steps were run against the release already targeted, where
each must be a no-op that passes.

What exists (step 1):

- DuckDB: the only 2.x tag is `v2.0.0`.
- `duckdb-neo` on crates.io: `0.20000.0`, `0.20000.1`, `0.20000.2`; the pin
  is the newest. The main branch of `duckdb-rs` is at `0.20000.2` too.
- extension-ci-tools: `v2.0-cyanoptera` is the branch community-extensions
  builds DuckDB 2.0.0 with.

What was run, and what it showed:

| Step | Command | Result |
|---|---|---|
| 1 | `make canary` | "the pin is the newest published duckdb-neo: nothing newer to build against" |
| 1 | `CANARY_COMPILE_ONLY=1 make canary CANARY=main` | The extension compiles unchanged against `duckdb-rs` main (commit `b8447b55`), 1 min 47 s |
| 2b | The two cargo commands, with the pin unchanged | Both lock files unchanged |
| 2d | `scripts/duckdb-release-checksums.sh v2.0.0` | Output identical to the committed `duckdb-release.sha256` |
| 2e | `git submodule set-branch`, `git submodule update --remote` | This step did change something. The submodule was at a commit of extension-ci-tools `main` (`2e5d22f`), not of the branch community-extensions uses. It is now at `c286b12` of `v2.0-cyanoptera`. The makefiles the build includes are identical in the two; the reusable workflow differs, and only the branch has the `build_directory` input that `duckdb-dist.yml` and the community descriptor need |
| 2g | `make check_pins` | Failed while the submodule move was not staged (the workflow named `c286b12`, the index `2e5d22f`), passed after `git add`. So it catches a half-done step 2e |
| 3 | `cargo check -p pcapsql-duckdb-ext`, `make check_containment` | Pass |
| 4 | `CANARY_FORCE=1 make canary`: `configure`, `release`, `test_release`, `load_test_release`, `itest`; then `check_reference_release`, `check`, `cargo fmt --all --check` | Pass |

Not exercised, because no newer release exists: an actual version change in
steps 2a to 2d and 2f, compile errors in step 3, and step 6. The first real
upgrade should correct this runbook where it turns out to be wrong.
