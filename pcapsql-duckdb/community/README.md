# Community-extensions descriptor

`description.yml` is what DuckDB's
[community-extensions](https://github.com/duckdb/community-extensions)
repository needs to build, sign and serve the extension, so that

```sql
INSTALL pcapsql FROM community;
LOAD pcapsql;
```

works. It is kept here so that it changes with the code it describes. Nothing
has been submitted yet.

## What the fields say

Checked against `scripts/build.py` and `.github/workflows/build.yml` of
community-extensions on 2026-11-15.

| Field | Value | Why |
|---|---|---|
| `extension.language`, `build` | `Rust`, `cargo` | As for DuckDB's Rust template (`rusty_quack`) |
| `extension.requires_toolchains` | `rust;python3` | Rust for the build; Python for the metadata footer and the SQL test runner |
| `extension.version` | the workspace version | `scripts/check-pins.sh` fails if it differs from `Cargo.toml` |
| `extension.excluded_platforms` | Windows and WebAssembly | `pcapsql-core` does not compile for Windows; WebAssembly is not shown to build (roadmap section 10, U10 and U13). The same list as `exclude_archs` of `.github/workflows/duckdb-dist.yml` |
| `extension.maintainers` | `mtottenh` | GitHub account names. This is the owner of the repository; confirm before submitting |
| `repo.github` | `mtottenh/pcapsql` | |
| `repo.ref` | a placeholder | The commit community-extensions builds. Set at submission |
| `repo.build_directory` | `pcapsql-duckdb` | The Makefile is not at the root of the repository. community-extensions runs `make configure_ci`, `make release` and `make test_release` in this directory |

community-extensions builds with the `v2.0-cyanoptera` branch of
`extension-ci-tools`, the branch the submodule here follows, by calling the
same reusable workflow as `.github/workflows/duckdb-dist.yml`. A green run of
that workflow on the release commit is the evidence that the community build
will pass.

## Submitting

1. Release pcapsql as usual (tag `vX.Y.Z`). `duckdb-dist.yml` runs for the
   tag; check that it is green for `linux_amd64`, `linux_arm64` and
   `osx_arm64`.
2. Copy `description.yml` to `extensions/pcapsql/description.yml` in a fork
   of `duckdb/community-extensions`. Replace `repo.ref` with the full SHA of
   the tagged commit (`git rev-parse vX.Y.Z^{commit}`), and check that
   `extension.version` is `X.Y.Z`.
3. Open a pull request there. Its CI builds the extension for every platform
   that is not excluded; after the merge the extension is signed and served.

## Updating

A new pcapsql release, or a rebuild for a new DuckDB release
([`docs/duckdb-upgrade-runbook.md`](../../docs/duckdb-upgrade-runbook.md)), is
a pull request to community-extensions that changes `repo.ref` (and
`extension.version`). community-extensions rebuilds an extension only when its
`repo.ref` changes.

While the C API v2 is unstable, a build loads in one DuckDB release only. If
community-extensions keeps serving an older DuckDB release line alongside the
newest, the descriptor names the commit for it in a second field of `repo`
(as `andium` and `variegata` do for 1.4 and 1.5 at the time of writing); the
field names are in `scripts/build.py` there.
