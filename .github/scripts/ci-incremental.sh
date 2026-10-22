#!/usr/bin/env bash
# Validate source invariants and the packages affected by the current change.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

base="${1:-HEAD~1}"
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  base=HEAD
fi
changed="$(git diff --name-only "$base...HEAD"; git diff --name-only; git diff --cached --name-only; git ls-files --others --exclude-standard)"
if [ "$base" = "$(git rev-parse HEAD)" ] || [ "$base" = HEAD ]; then
  changed="$(git ls-files --cached --others --exclude-standard)"
fi

python3 - <<'PY'
from pathlib import Path
import subprocess
import sys
import tomllib

paths = subprocess.check_output(
    ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard']
).decode().split('\0')
errors = []
source_suffixes = {'.rs', '.c', '.h', '.cpp', '.hpp'}
text_suffixes = source_suffixes | {'.sh', '.toml', '.yml', '.yaml'}
for name in sorted(set(paths) - {''}):
    path = Path(name)
    if not path.is_file() or '.scratch' in path.parts:
        continue
    if path.suffix not in text_suffixes:
        continue
    content = path.read_text()
    if path.suffix in source_suffixes and len(content.splitlines()) > 800:
        errors.append(f'{name}: exceeds 800 lines')
    if ''.join(map(chr, (104, 102, 116))) in content.lower():
        errors.append(f'{name}: forbidden vocabulary')
    if any(0x2E80 <= ord(c) <= 0xA4CF or 0xAC00 <= ord(c) <= 0xD7AF
           or 0xF900 <= ord(c) <= 0xFAFF or 0xFF65 <= ord(c) <= 0xFFDC
           or 0x20000 <= ord(c) <= 0x323AF for c in content):
        errors.append(f'{name}: source text must use English')
    if path.name != 'Cargo.toml':
        continue
    document = tomllib.loads(content)

    def visit(table):
        for key, value in table.items():
            if key.endswith('dependencies') and isinstance(value, dict):
                for alias, spec in value.items():
                    package = spec.get('package', alias) if isinstance(spec, dict) else alias
                    prefixes = ('tokio', 'futures', 'async', 'smol')
                    if (alias.startswith(prefixes) or package.startswith(prefixes)
                            or package in {'mio', 'polling', 'pkg-config'}):
                        errors.append(f'{name}: forbidden dependency {package}')
                    if not isinstance(spec, dict):
                        errors.append(f'{name}: dependency {alias} must use an inline table')
            elif isinstance(value, dict):
                visit(value)
    visit(document)
if errors:
    sys.exit('\n'.join(errors))
print('Source and manifest invariants passed')
PY

run_all=0
case "${GITHUB_EVENT_NAME:-}" in schedule|workflow_dispatch) run_all=1 ;; esac
declare -A affected=()
while IFS= read -r file; do
  case "$file" in
    '') ;;
    Cargo.toml|Cargo.lock|rust-toolchain.toml|rustfmt.toml|deny.toml|.github/*) run_all=1 ;;
    crates/liburing-sys/*) affected[liburing-sys]=1; affected[liburing]=1 ;;
    crates/liburing-macros/*) affected[liburing-macros]=1; affected[liburing]=1 ;;
    crates/liburing/*) affected[liburing]=1 ;;
    *.md|*.png|.scratch/*|.gitignore|LICENSE) ;;
    *) run_all=1 ;;
  esac
done <<< "$changed"

metadata="$(cargo metadata --no-deps --format-version 1)"
mapfile -t packages < <(python3 -c '
import json, sys
metadata = json.load(sys.stdin)
members = set(metadata["workspace_members"])
for package in metadata["packages"]:
    if package["id"] in members:
        print(package["name"])
' <<< "$metadata")
selected=()
for package in "${packages[@]}"; do
  if [ "$run_all" -eq 1 ] || [ -n "${affected[$package]:-}" ]; then
    selected+=("$package")
  fi
done
if [ "${#selected[@]}" -eq 0 ]; then
  echo 'No Cargo packages affected'
  exit 0
fi
cargo fmt --all -- --check
for package in "${selected[@]}"; do
  cargo clippy -p "$package" --all-targets -- -D warnings
  cargo test -p "$package"
  case "$package" in
    liburing-sys|liburing)
      cargo clippy -p "$package" --all-targets --no-default-features --features stable -- -D warnings
      cargo test -p "$package" --no-default-features --features stable
      ;;
  esac
done

if [ "$run_all" -eq 1 ] || [ -n "${affected[liburing-sys]:-}" ] || [ -n "${affected[liburing]:-}" ]; then
  for mode in pre-release stable; do
    artifacts="$(mktemp)"
    cargo test -p liburing-sys --no-default-features --features "$mode" --no-run --message-format=json > "$artifacts"
    python3 - "$artifacts" <<'PY'
import json
import subprocess
import sys

executables = set()
with open(sys.argv[1]) as stream:
    for line in stream:
        event = json.loads(line)
        if event.get('executable'):
            executables.add(event['executable'])
if not executables:
    sys.exit('No test executables found for static-linkage validation')
for executable in executables:
    dynamic = subprocess.check_output(['readelf', '-d', executable], text=True)
    if any('NEEDED' in line and 'liburing.so' in line for line in dynamic.splitlines()):
        sys.exit(f'{executable}: unexpected shared liburing dependency')
print(f'Static linkage passed for {len(executables)} test executables')
PY
    rm "$artifacts"
  done
fi
echo "Incremental CI passed: ${selected[*]}"
