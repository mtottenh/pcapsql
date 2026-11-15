#!/usr/bin/env bash
# Fail if `unsafe` code is allowed anywhere in the extension crate but its two audited places.
#
# src/lib.rs denies `unsafe_code` for the crate, so the compiler rejects an `unsafe` block that
# no `allow` covers. This pins where the allows are:
#
#   src/engine/writer.rs  `#![allow(unsafe_code)]` for the module: the chunk writer stores values
#                         through the raw pointers of DuckDB's vectors; its header states the
#                         invariants.
#   src/engine/scalar.rs  one `#[allow(unsafe_code)]`, on its private module `valid`, which lends
#                         the values of rows of a flat vector as a slice when none of those
#                         rows is NULL. Outside its tests the module has three `unsafe`s: the
#                         function `slots`, which forms the slice from a pointer and a validity
#                         mask; the `slice::from_raw_parts` in it; and the one call of it, in
#                         `values`, with the pointer and the mask of a vector reader. Their
#                         comments state what each requires and how it is met. The module's
#                         tests call `slots` with buffers of their own.
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
    fail "unsafe code is allowed somewhere other than engine::writer and the module \`valid\` of engine::scalar"
fi

# The allow in scalar.rs is on the module `valid`, which ends at the first `}` in column one.
allowed=$(grep -A1 -x -F '#[allow(unsafe_code)]' src/engine/scalar.rs || true)
grep -q -x -F 'mod valid {' <<<"$allowed" ||
    fail "the allow in src/engine/scalar.rs must be on \`mod valid\`"

# The lines of scalar.rs that are not comments, in three parts: `outside` the module, the module
# up to its tests (`audited`), and its `tests`. Each is read whole before it is searched: a
# `grep -q` on the pipe stops at its first match, which `pipefail` reports as a failure.
part() {
    awk -v want="$1" '
        /^mod valid \{$/ { part = "audited" }
        part != "" && /^    #\[cfg\(test\)\]$/ { part = "tests" }
        !/^[[:space:]]*\/\// && (part == "" ? "outside" : part) == want
        /^\}$/ { part = "" }
    ' src/engine/scalar.rs
}
outside=$(part outside)
audited=$(part audited)
[[ -n "$(part tests)" ]] ||
    fail "the module \`valid\` of src/engine/scalar.rs must have its tests"
if grep -q -w 'unsafe' <<<"$outside"; then
    fail "src/engine/scalar.rs must have no \`unsafe\` outside its module \`valid\`"
fi

# Each `unsafe` of the module outside its tests, without its indentation.
found=$(grep -w 'unsafe' <<<"$audited" | sed -E 's/^[[:space:]]+//' || true)
expected="unsafe { slots(reader.as_ptr(), reader.len(), reader.validity(), rows) }
unsafe fn slots<'a, T>(
Some(unsafe { slice::from_raw_parts(data.add(rows.start), rows.end - rows.start) })"
if [[ "$found" != "$expected" ]]; then
    echo "$found" >&2
    fail "the module \`valid\` of src/engine/scalar.rs must have exactly its three audited \`unsafe\`s"
fi

# What `slots` is given is the reader's pointer and mask: the module borrows nothing that
# exposes every slot of a vector, and writes nothing.
if grep -q -E 'as_slice|as_mut_ptr|validity_mut|\*mut' <<<"$audited"; then
    fail "the module \`valid\` of src/engine/scalar.rs must not borrow the slots of a vector another way"
fi
echo "check-unsafe: ok"
