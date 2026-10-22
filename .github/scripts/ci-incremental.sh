#!/usr/bin/env bash
# Validate source invariants and the packages affected by the current change.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

base="${1:-HEAD~1}"
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  base=HEAD
fi
committed_changes="$(git diff --name-only "$base...HEAD")"
working_changes="$(git diff --name-only)"
staged_changes="$(git diff --cached --name-only)"
untracked_changes="$(git ls-files --others --exclude-standard)"
changed="$(printf '%s\n' "$committed_changes" "$working_changes" "$staged_changes" "$untracked_changes")"
if [ "$base" = "$(git rev-parse HEAD)" ] || [ "$base" = HEAD ]; then
  changed="$(git ls-files --cached --others --exclude-standard)"
fi

python3 - <<'PY'
from pathlib import Path
import re
import subprocess
import sys
import tomllib

paths = subprocess.check_output(
    ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard']
).decode().split('\0')
errors = []
source_suffixes = {'.rs', '.c', '.h', '.cpp', '.hpp'}
text_suffixes = source_suffixes | {'.sh', '.toml', '.yml', '.yaml', '.md', '.txt'}
for name in sorted(set(paths) - {''}):
    path = Path(name)
    if '.scratch' in path.parts:
        errors.append(f'{name}: scratch artifacts must remain untracked')
        continue
    if not path.is_file():
        continue
    try:
        content = path.read_text()
    except UnicodeDecodeError:
        if path.suffix in text_suffixes or path.name in {'Cargo.lock', 'LICENSE', '.gitignore'}:
            errors.append(f'{name}: text must use UTF-8')
        continue
    if path.suffix in source_suffixes and len(content.splitlines()) > 800:
        errors.append(f'{name}: exceeds 800 lines')
    if ''.join(map(chr, (104, 102, 116))) in content.lower():
        errors.append(f'{name}: forbidden vocabulary')
    ranges = ((0x1100, 0x11FF), (0x2E80, 0xA4CF), (0xA960, 0xA97F),
              (0xAC00, 0xD7FF), (0xF900, 0xFAFF), (0xFE30, 0xFE4F),
              (0xFF65, 0xFFDC), (0x16FE0, 0x18DFF), (0x1AFF0, 0x1AFFF),
              (0x1B000, 0x1B16F), (0x20000, 0x323AF))
    if any(low <= ord(c) <= high for c in content for low, high in ranges):
        errors.append(f'{name}: source text must use English')
    if path.name != 'Cargo.toml':
        continue
    document = tomllib.loads(content)
    in_dependencies = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('['):
            header = stripped
            section = tomllib.loads(header + '\n__ci_section = true')
            keys = []
            while '__ci_section' not in section:
                key, section = next(iter(section.items()))
                keys.append(key)
                if isinstance(section, list):
                    section = section[0]
            dependency_sections = [index for index, key in enumerate(keys)
                                   if key in {'dependencies', 'dev-dependencies', 'build-dependencies'}]
            if dependency_sections and dependency_sections[-1] != len(keys) - 1:
                errors.append(f'{name}: dependency subtable must use an inline table')
            in_dependencies = bool(dependency_sections) and dependency_sections[-1] == len(keys) - 1
        elif in_dependencies:
            assignment = r"^\s*(?:[A-Za-z0-9_-]+|\"(?:[^\"\\]|\\.)*\"|'[^']*')\s*=\s*\{"
            if not re.match(assignment, line):
                errors.append(f'{name}: dependency must use an inline table')

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

# Examples exercise the real kernel even when no package was selected by the diff.
run_examples() {
  cargo build -p liburing --examples
  for example in proactor_subsystems_and_waker fixed_files_and_pbuf_tcp_echo socket_bridge_readiness; do
    echo "Running example: $example"
    timeout 30s cargo run -p liburing --example "$example"
  done
}

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
package_names="$(python3 -c '
import json, sys
metadata = json.load(sys.stdin)
members = set(metadata["workspace_members"])
for package in metadata["packages"]:
    if package["id"] in members:
        print(package["name"])
' <<< "$metadata")"
mapfile -t packages <<< "$package_names"
selected=()
for package in "${packages[@]}"; do
  if [ "$run_all" -eq 1 ] || [ -n "${affected[$package]:-}" ]; then
    selected+=("$package")
  fi
done
cargo fmt --all -- --check
if [ "${#selected[@]}" -eq 0 ]; then
  echo 'No Cargo packages affected; validating all examples'
  run_examples
  exit 0
fi
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
run_examples
echo "Incremental CI passed: ${selected[*]}"
