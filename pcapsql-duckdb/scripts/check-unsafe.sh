#!/usr/bin/env bash
# Fail if `unsafe` code is allowed anywhere in the extension crate but its two audited places.
#
# src/lib.rs denies `unsafe_code` for the crate, so the compiler rejects an `unsafe` block that
# no `allow` covers. This pins where the allows are:
#
#   src/engine/writer.rs  `#![allow(unsafe_code)]` for the module: the chunk writer stores values
#                         through the raw pointers of DuckDB's vectors; its header states the
#                         invariants.
#   src/engine/scalar.rs  one `#[allow(unsafe_code)]`, on the one statement of
#                         `values_without_nulls` that borrows the values of a flat vector
#                         without NULLs as a slice; its comment states what that requires.
#
# A third place is a decision for a maintainer, not for a patch: it changes this list.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
    echo "check-unsafe: $1" >&2
    exit 1
}

grep -q '^#!\[deny(unsafe_code)\]$' src/lib.rs ||
    fail "src/lib.rs must have #![deny(unsafe_code)]"

# Every attribute that lets `unsafe` through, as file:text. Comment lines are ignored.
found=$(grep -r -n -E '(allow|expect|warn)\([^)]*unsafe_code' --include='*.rs' src |
    grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//' |
    sed -E 's/^([^:]+):[0-9]+:[[:space:]]*/\1:/' | sort)
expected='src/engine/scalar.rs:#[allow(unsafe_code)]
src/engine/writer.rs:#![allow(unsafe_code)]'
if [[ "$found" != "$expected" ]]; then
    echo "$found" >&2
    fail "unsafe code is allowed somewhere other than engine::writer and the one statement of engine::scalar"
fi

# The allow in scalar.rs covers one statement, and no other line of the file may say `unsafe`.
count=$(grep -v -E '^[[:space:]]*//' src/engine/scalar.rs | grep -c -w 'unsafe' || true)
[[ "$count" == 1 ]] ||
    fail "src/engine/scalar.rs must have exactly one \`unsafe\` block (found $count)"
grep -A1 -F '#[allow(unsafe_code)]' src/engine/scalar.rs | grep -q -F 'unsafe { reader.as_slice() }' ||
    fail "the allow in src/engine/scalar.rs must be on the \`as_slice\` call of values_without_nulls"
echo "check-unsafe: ok"
