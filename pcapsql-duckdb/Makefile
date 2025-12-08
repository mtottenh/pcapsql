.PHONY: all debug release test clean info extension

EXTENSION_NAME = pcapsql
LIB_NAME = pcapsql_duckdb
DUCKDB = /home/mtottenh/.duckdb/cli/latest/duckdb
DUCKDB_VERSION = v1.4.2
PLATFORM = linux_amd64
EXT_VERSION = 0.1.0

# Workspace target directory (relative to workspace root)
TARGET_DIR = ../target

all: extension

# Build debug version
debug:
	cargo build -p pcapsql-duckdb

# Build release version
release:
	cargo build -p pcapsql-duckdb --release

# Build extension with metadata (release)
extension: release
	python3 scripts/append_metadata.py \
		$(TARGET_DIR)/release/lib$(LIB_NAME).so \
		$(TARGET_DIR)/release/$(EXTENSION_NAME).duckdb_extension \
		--name $(EXTENSION_NAME) \
		--duckdb-version $(DUCKDB_VERSION) \
		--ext-version $(EXT_VERSION) \
		--platform $(PLATFORM) \
		--abi-type C_STRUCT_UNSTABLE

# Run tests
test: debug
	cargo test -p pcapsql-duckdb

# Test loading in DuckDB
test_load: extension
	$(DUCKDB) -unsigned -c "LOAD '$(TARGET_DIR)/release/$(EXTENSION_NAME).duckdb_extension'; SELECT 'Extension loaded successfully!' AS status;"

# Clean build artifacts
clean:
	cargo clean -p pcapsql-duckdb
	rm -f $(TARGET_DIR)/release/$(EXTENSION_NAME).duckdb_extension
	rm -f $(TARGET_DIR)/debug/$(EXTENSION_NAME).duckdb_extension

# Show extension info
info:
	@echo "Extension: $(EXTENSION_NAME)"
	@echo "Library: $(TARGET_DIR)/release/lib$(LIB_NAME).so"
	@echo "Extension file: $(TARGET_DIR)/release/$(EXTENSION_NAME).duckdb_extension"
	@echo "DuckDB version: $(DUCKDB_VERSION)"
	@echo "Platform: $(PLATFORM)"

# Check exported symbols
symbols: release
	nm -D $(TARGET_DIR)/release/lib$(LIB_NAME).so | grep -i init
