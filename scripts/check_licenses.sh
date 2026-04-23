#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

errors=0

require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "ERROR: required file missing: $path"
        errors=1
    fi
}

require_notice_or_spdx() {
    local path="$1"
    if rg -q '^[[:space:]#/*-]*Modified by .*[0-9]{4}-[0-9]{2}-[0-9]{2}\.?$' "$path"; then
        return 0
    fi
    if rg -q '^[[:space:]#/*-]*SPDX-License-Identifier:' "$path"; then
        return 0
    fi
    echo "ERROR: missing notice in: $path (expected Modified-by line or SPDX-License-Identifier)"
    errors=1
}

echo "[license-check] checking required top-level files"
require_file "LICENSE"
require_file "NOTICE"
require_file "THIRD_PARTY_LICENSES.md"

echo "[license-check] checking vendored license references"
while IFS= read -r vendored_license; do
    [[ -z "$vendored_license" ]] && continue
    if ! rg -Fq "$vendored_license" "THIRD_PARTY_LICENSES.md"; then
        echo "ERROR: THIRD_PARTY_LICENSES.md does not reference $vendored_license"
        errors=1
    fi
done < <(find fss-core/libOTe -type f -name 'LICENSE' | sort)

echo "[license-check] checking modified notices for changed first-party source files"
while IFS= read -r changed_file; do
    [[ -z "$changed_file" ]] && continue

    case "$changed_file" in
        client/*|server/*|network/*|utils/*|scripts/*) ;;
        *) continue ;;
    esac

    case "$changed_file" in
        fss-core/*|*/CMakeFiles/*|*CMakeCache.txt|*cmake_install.cmake|*Makefile|*.a|*.o|*.d|*.yaml) continue ;;
    esac

    case "$changed_file" in
        *query.pb.cc|*query.pb.h|*query.grpc.pb.cc|*query.grpc.pb.h) continue ;;
    esac

    case "$changed_file" in
        *.c|*.cc|*.cpp|*.h|*.hpp|*.py|*.sh|*.proto)
            if [[ -f "$changed_file" ]]; then
                require_notice_or_spdx "$changed_file"
            fi
            ;;
    esac
done < <(git diff --name-only --diff-filter=ACMRTUXB HEAD)

if [[ "$errors" -ne 0 ]]; then
    echo "[license-check] FAILED"
    exit 1
fi

echo "[license-check] PASSED"
