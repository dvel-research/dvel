#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bench_build_dir="$ROOT/benchmarks/build"
sim_build_dir="$ROOT/cpp-sim/build"

log() { printf '[smoke] %s\n' "$*"; }

run_rust_tests() {
  log "Running cargo test --release (rust-core)"
  (cd "$ROOT/rust-core" && cargo test --release)
}

ensure_bench_build() {
  if [[ ! -x "$bench_build_dir/benchmark" ]]; then
    log "Configuring benchmark"
    cmake -S "$ROOT/benchmarks" -B "$bench_build_dir"
  fi
  log "Building benchmark"
  cmake --build "$bench_build_dir"
}

ensure_sim_build() {
  if [[ ! -x "$sim_build_dir/sim_baseline" ]]; then
    log "Configuring simulator"
    cmake -S "$ROOT/cpp-sim" -B "$sim_build_dir"
  fi
  log "Building simulator"
  cmake --build "$sim_build_dir"
}

run_and_check() {
  local cmd="$1"
  local label="$2"
  local workdir="$3"
  shift 3 || true
  log "Running $label"

  local out
  if [[ -n "$workdir" ]]; then
    out="$(cd "$workdir" && eval "$cmd")"
  else
    out="$(eval "$cmd")"
  fi
  printf '%s\n' "$out"
  while [[ $
    local needle="$1"
    if ! grep -Fq "$needle" <<<"$out"; then
      log "FAILED: did not find \"$needle\" in $label output"
      exit 1
    fi
    shift
  done
}

run_rust_tests
ensure_bench_build
ensure_sim_build

run_and_check "$bench_build_dir/benchmark" "benchmark" "" "Throughput:"
run_and_check "./sim_baseline" "sim_baseline" "$sim_build_dir" "done"
run_and_check "./sim_scenario" "sim_scenario" "$sim_build_dir" "done"
run_and_check "./sim_scheduler" "sim_scheduler" "$sim_build_dir" "SUMMARY"
run_and_check "./sim_metrics" "sim_metrics" "$sim_build_dir" "[inv] basic: OK"
run_and_check "./sim_sybil" "sim_sybil" "$sim_build_dir" "SUMMARY"

log "All smoke checks passed"
