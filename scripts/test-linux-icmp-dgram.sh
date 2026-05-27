#!/bin/sh
set -eu

image="${WGSLIRP_LINUX_TEST_IMAGE:-wgslirp-test-linux}"

docker build -t "$image" -f Dockerfile.test-linux .
docker run --rm \
	--cap-drop NET_RAW \
	--sysctl "net.ipv4.ping_group_range=10001 10001" \
	"$image" \
	-tags=integration \
	./pkg/socket \
	-run='^TestICMPDatagramIntegration_EchoLoopback$' \
	-v
