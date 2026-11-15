# Builds and tests the pcapsql DuckDB extension.
#
#   make configure          one-time: Python venv with DuckDB and its SQL test runner
#   make release            build/release/pcapsql.duckdb_extension
#   make test_release       run test/sql against it (DuckDB's Python package)
#   make load_test_release  LOAD it in the stock DuckDB command-line shell
#   make itest              in-process tests (itest/) against a linked libduckdb
#   make check              duckdb_neo containment, no std::fs in the extension, and fmt and
#                           clippy for itest/
#
# `debug`, `test_debug` and `load_test_debug` do the same for an unoptimised build.

.PHONY: all configure debug release test test_debug test_release load_test load_test_debug load_test_release
.PHONY: itest lint_itest check_containment check_no_std_fs check clean clean_all

PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

EXTENSION_NAME=pcapsql

# Every function of the DuckDB C API v2 is unstable, so the binary is stamped C_STRUCT_UNSTABLE
# and loads only in exactly TARGET_DUCKDB_VERSION. This version, the `duckdb-neo` pin in the
# Cargo.toml files and scripts/duckdb-release.sha256 change together.
USE_UNSTABLE_C_API=1
CAPI_VERSION=2
TARGET_DUCKDB_VERSION=v2.0.0

# The extension version is the workspace version.
EXTENSION_VERSION ?= v$(shell sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' $(PROJ_DIR)../Cargo.toml)

all: configure debug

include extension-ci-tools/makefiles/c_api_extensions/base.Makefile
include extension-ci-tools/makefiles/c_api_extensions/rust.Makefile

# The cdylib is one package of the repository's cargo workspace, and cargo puts its artifacts in
# the workspace's target directory, one level up, where the included makefile expects ./target.
TARGET_INFO += --package pcapsql-duckdb-ext
CARGO_TARGET_DIR ?= $(abspath $(PROJ_DIR)../target)
TARGET_PATH := $(patsubst ./target%,$(CARGO_TARGET_DIR)%,$(TARGET_PATH))

configure: venv platform extension_version

debug: build_extension_library_debug build_extension_with_metadata_debug
release: build_extension_library_release build_extension_with_metadata_release

test: test_debug
test_debug: test_extension_debug
test_release: test_extension_release

load_test: load_test_debug
load_test_debug:
	scripts/load-test.sh build/debug/$(EXTENSION_FILENAME) $(TARGET_DUCKDB_VERSION) $(EXTENSION_VERSION)
load_test_release:
	scripts/load-test.sh build/release/$(EXTENSION_FILENAME) $(TARGET_DUCKDB_VERSION) $(EXTENSION_VERSION)

# itest/ is its own cargo workspace (see its Cargo.toml) and links the libduckdb of the release.
ITEST_CARGO = lib=$$(DUCKDB_VERSION=$(TARGET_DUCKDB_VERSION) scripts/fetch-duckdb.sh lib) && \
	DUCKDB_LIB_DIR="$$lib" DUCKDB_DOWNLOAD_LIB=0 cargo
itest:
	$(ITEST_CARGO) test --manifest-path itest/Cargo.toml $(ITEST_ARGS)

# The workspace-wide `cargo fmt` and `cargo clippy` runs do not reach itest/.
lint_itest:
	cargo fmt --manifest-path itest/Cargo.toml -- --check
	$(ITEST_CARGO) clippy --manifest-path itest/Cargo.toml --all-targets -- -D warnings

check_containment:
	scripts/check-neo-containment.sh

check_no_std_fs:
	scripts/check-no-std-fs.sh

check: check_containment check_no_std_fs lint_itest

clean: clean_build
	cargo clean --package pcapsql-duckdb-ext --package pcapsql-duckdb
	cargo clean --manifest-path itest/Cargo.toml
clean_all: clean_configure clean
