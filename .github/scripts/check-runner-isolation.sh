#!/usr/bin/env bash
# Keep build and temporary state inside the runner's own checkout.
set -euo pipefail

workspace="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
workspace="$(cd "$workspace" && pwd -P)"
if [ -n "${RUNNER_WORKSPACE:-}" ]; then
  runner_workspace="$(cd "$RUNNER_WORKSPACE" && pwd -P)"
  case "$workspace/" in
    "$runner_workspace/"*) ;;
    *) echo "::error::workspace is outside RUNNER_WORKSPACE"; exit 1 ;;
  esac
fi

target="${CARGO_TARGET_DIR:-$workspace/target}"
case "$target" in /*) ;; *) target="$workspace/$target" ;; esac
target="$(realpath -m "$target")"
case "$target/" in
  "$workspace/"*) ;;
  *) echo "::error::CARGO_TARGET_DIR must remain inside the workspace"; exit 1 ;;
esac

origin="$(git -C "$workspace" remote get-url origin)"
case "$origin" in
  https://github.com/trunkszi/liburing-rs|https://github.com/trunkszi/liburing-rs.git|git@github.com:trunkszi/liburing-rs.git) ;;
  *) echo "::error::checkout origin must identify trunkszi/liburing-rs"; exit 1 ;;
esac

if [ -n "${GITHUB_ENV:-}" ]; then
  tmp="$(mktemp -d "$workspace/.liburing-ci-tmp.XXXXXXXX")"
  echo "TMPDIR=$tmp" >> "$GITHUB_ENV"
  echo "Runner temporary state: $tmp"
fi
