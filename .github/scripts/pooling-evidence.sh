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
# Counterbalance order; never mix policies within a process. Race is a correctness
# control only, and is excluded from performance comparisons.
for repetition in 1 2 3; do
  order='false true'
  if [ "$repetition" = 2 ]; then order='true false'; fi
  for pooling in $order; do
    export POOLING="$pooling"
    for workload in mixed wan; do
      export POOLING_WORKLOAD="$workload"
      log="/evidence/ordinary-$repetition-$pooling-$workload.log"
      /work/traffic.test -test.v -test.run='^TestPoolingEvidence$' -test.timeout=120s -test.count=1 -test.parallel=1 > "$log" 2>&1
      grep -q POOLING_ACCEPTED "$log"
      grep -E 'POOLING_RESULT|MIXED_RESULTS|MIXED_BULK|WAN_PROFILE|ADMISSION' "$log"
    done
    /work/packets.test -test.v -test.run='^TestPoolingQueueCapacityEvidence$' \
      -test.bench='^BenchmarkPoolingPackets$' -test.benchmem -test.benchtime=500ms \
      -test.timeout=60s -test.parallel=1 > "/evidence/packets-$repetition-$pooling.log" 2>&1
  done
done
for pooling in false true; do
  export POOLING="$pooling"
  for workload in mixed wan; do
    export POOLING_WORKLOAD="$workload"
    log="/evidence/race-$pooling-$workload.log"
    /work/traffic-race.test -test.v -test.run='^TestPoolingEvidence$' -test.timeout=120s -test.parallel=1 > "$log" 2>&1
    grep -q POOLING_ACCEPTED "$log"
  done
  /work/packets-race.test -test.v -test.run='^TestPoolingQueueCapacityEvidence$' \
    -test.timeout=60s > "/evidence/capacity-race-$pooling.log" 2>&1
done
record_resources
if grep -Eq '^(max|oom|oom_kill|oom_group_kill) [1-9]' /evidence/cgroup-events.txt; then exit 1; fi
echo POOLING_STUDY_ACCEPTED
