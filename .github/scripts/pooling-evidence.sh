#!/usr/bin/env bash
# Portable CI harness: source is read-only; every executable/cache lives in tmpfs.
set -euo pipefail
record_resources() {
  cat /sys/fs/cgroup/memory.peak > /evidence/cgroup-memory-peak.txt
  cat /sys/fs/cgroup/memory.events /sys/fs/cgroup/pids.events > /evidence/cgroup-events.txt
}
trap record_resources EXIT
mkdir -p "$GOTMPDIR"
cp -a /src/. /work/source
cd /work/source
go version | tee /evidence/go-version.txt
go build ./...
go vet ./...
go test -race -count=1 -parallel=1 -timeout=120s ./... > /evidence/unit-race.log
go test -race -tags=integration -count=1 -parallel=1 -timeout=120s ./... > /evidence/integration-race.log
tags=integration,mixed,wan,pooling
go test -c -tags="$tags" -o /work/traffic.test ./pkg/wireguard
go test -c -race -tags="$tags" -o /work/traffic-race.test ./pkg/wireguard
go test -c -tags=pooling -o /work/packets.test ./pkg/socket
go test -c -race -tags=pooling -o /work/packets-race.test ./pkg/socket
go vet -tags="$tags" ./pkg/wireguard
printf '%s\n' "$STUDY_PROFILE" > /evidence/study-profile.txt
case "$STUDY_PROFILE" in
  basic) repetitions='1 2 3'; workloads='mixed wan' ;;
  sustained|selective)
    repetitions='1 2 3 4 5 6'; workloads='sustained-mixed'
    for binary in traffic traffic-race; do
      /work/$binary.test -test.v -test.run='^TestMixedStreamingVerifier$' -test.timeout=30s > "/evidence/verifier-$binary.log" 2>&1
      for pooling in false true; do
        POOLING="$pooling" POOLING_WORKLOAD=mixed /work/$binary.test \
          -test.v -test.run='^TestPoolingEvidence$' -test.timeout=120s -test.parallel=1 \
          > "/evidence/legacy-$binary-$pooling.log" 2>&1
        grep -q POOLING_ACCEPTED "/evidence/legacy-$binary-$pooling.log"
      done
    done
    ;;
  *) echo 'Unknown pooling study profile' >&2; exit 1 ;;
esac
if [ "$STUDY_PROFILE" = selective ]; then
  # Keep the current fixture/toolchain, restoring only the two production policy
  # files from the known full-pooling revision in a disposable source copy.
  baseline=90e4df7d42fca7973f027e4024b56cfb4f90c4a2
  printf '%s\n' "$baseline" > /evidence/full-pooling-baseline.txt
  cp -a /work/source /work/full-pooling-source
  for file in poolutil.go packet_storage.go; do
    git show "$baseline:pkg/socket/$file" > "/work/full-pooling-source/pkg/socket/$file"
    sha256sum "/work/full-pooling-source/pkg/socket/$file" >> /evidence/full-pooling-files.sha256
  done
  (cd /work/full-pooling-source
    go test -c -tags="$tags" -o /work/fullpool.test ./pkg/wireguard
    go test -c -race -tags="$tags" -o /work/fullpool-race.test ./pkg/wireguard
    go test -c -tags=pooling -o /work/fullpool-packets.test ./pkg/socket)
  for binary in fullpool fullpool-race; do
    POOLING=true POOLING_WORKLOAD=mixed /work/$binary.test \
      -test.v -test.run='^TestPoolingEvidence$' -test.timeout=120s -test.parallel=1 \
      > "/evidence/legacy-$binary.log" 2>&1
    grep -q POOLING_ACCEPTED "/evidence/legacy-$binary.log"
  done
fi
# Counterbalance order; never mix policies within a process. Race is a correctness
# control only, and is excluded from performance comparisons.
for repetition in $repetitions; do
  order='false true'
  if (( repetition % 2 == 0 )); then order='true false'; fi
  if [ "$STUDY_PROFILE" = selective ]; then
    case "$repetition" in
      1) order='off full selective' ;; 2) order='selective full off' ;;
      3) order='full selective off' ;; 4) order='off selective full' ;;
      5) order='full off selective' ;; 6) order='selective off full' ;;
    esac
  fi
  for policy in $order; do
    pooling="$policy"; binary=traffic; packets_binary=packets
    case "$policy" in
      off) pooling=false ;; selective) pooling=true ;;
      full) pooling=true; binary=fullpool; packets_binary=fullpool-packets ;;
    esac
    export POOLING="$pooling"
    for workload in $workloads; do
      export POOLING_WORKLOAD="$workload"
      log="/evidence/ordinary-$repetition-$policy-$workload.log"
      profile_flags=()
      if [ "$STUDY_PROFILE" != basic ]; then profile_flags=("-test.cpuprofile=/evidence/cpu-$repetition-$policy.pprof"); fi
      /work/$binary.test -test.v -test.run='^TestPoolingEvidence$' -test.timeout=120s -test.count=1 -test.parallel=1 "${profile_flags[@]}" > "$log" 2>&1
      grep -q POOLING_ACCEPTED "$log"
      grep -E 'POOLING_RESULT|MIXED_RESULTS|MIXED_BULK|WAN_PROFILE|ADMISSION|SUSTAINED_POOLING_RESULTS' "$log"
      if [ "$STUDY_PROFILE" != basic ]; then
        grep -q SUSTAINED_POOLING_ACCEPTED "$log"
        go tool pprof -top /work/$binary.test "/evidence/cpu-$repetition-$policy.pprof" > "/evidence/cpu-$repetition-$policy.txt"
      fi
    done
    if [ "$STUDY_PROFILE" = basic ] || [ "$STUDY_PROFILE" = selective ]; then
      test_name='^TestPoolingQueueCapacityEvidence$'
      if [ "$policy" = full ]; then test_name='^$'; fi # Candidate capacity assertions do not describe the baseline.
      bench_time=500ms
      if [ "$STUDY_PROFILE" = selective ]; then bench_time=200ms; fi
      /work/$packets_binary.test -test.v -test.run="$test_name" \
        -test.bench='^BenchmarkPoolingPackets$' -test.benchmem -test.benchtime="$bench_time" \
        -test.timeout=60s -test.parallel=1 > "/evidence/packets-$repetition-$policy.log" 2>&1
    fi
  done
done
race_order='false true'
if [ "$STUDY_PROFILE" = selective ]; then race_order='off full selective'; fi
for policy in $race_order; do
  pooling="$policy"; binary=traffic-race
  case "$policy" in off) pooling=false ;; selective) pooling=true ;; full) pooling=true; binary=fullpool-race ;; esac
  export POOLING="$pooling"
  for workload in $workloads; do
    export POOLING_WORKLOAD="$workload"
    log="/evidence/race-$policy-$workload.log"
    POOLING_EVIDENCE_RACE=true /work/$binary.test -test.v -test.run='^TestPoolingEvidence$' -test.timeout=120s -test.parallel=1 > "$log" 2>&1
    grep -q POOLING_ACCEPTED "$log"
    if [ "$STUDY_PROFILE" != basic ]; then grep -q SUSTAINED_POOLING_ACCEPTED "$log"; fi
  done
  if [ "$policy" != full ]; then
    /work/packets-race.test -test.v -test.run='^TestPoolingQueueCapacityEvidence$' \
      -test.timeout=60s > "/evidence/capacity-race-$policy.log" 2>&1
  fi
done
record_resources
if grep -Eq '^(max|oom|oom_kill|oom_group_kill) [1-9]' /evidence/cgroup-events.txt; then exit 1; fi
echo POOLING_STUDY_ACCEPTED
