package main

import (
	"bytes"
	"encoding/json"
	"github.com/irctrakz/wgslirp/pkg/logging"
	"github.com/irctrakz/wgslirp/pkg/socket"
	wg "github.com/irctrakz/wgslirp/pkg/wireguard"
	"github.com/sirupsen/logrus"
	"strings"
	"testing"
)

func TestAdmissionMetricsReachBothReportFormats(t *testing.T) {
	logger := logging.WithFields(nil).Logger
	output, level, formatter := logger.Out, logger.Level, logger.Formatter
	defer func() { logger.SetOutput(output); logger.SetLevel(level); logger.SetFormatter(formatter) }()
	var buffer bytes.Buffer
	logger.SetOutput(&buffer)
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})
	s := socket.NewSocketInterface(socket.DefaultConfig())
	tun, err := wg.NewWGTunWithConfig("metrics", 1380, s, wg.DefaultTunConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	hold, err := s.ReservePacketBuffer(socket.DefaultSocketBufferCap - 128)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	if _, err := s.ReservePacketBuffer(1); err == nil {
		t.Fatal("expected refusal")
	}
	dumpMetrics(s, tun, nil, "json")
	var line struct {
		Message string `json:"msg"`
	}
	if err := json.Unmarshal(buffer.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	var snapshot metricsSnapshot
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line.Message, "metrics: ")), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.WGAvailable {
		t.Fatal("invalid schema/availability", snapshot)
	}
	if len(snapshot.Admission) != 9 || snapshot.Admission["aggregate_buffer_limit"] != 1 {
		t.Fatalf("JSON admission: %v", snapshot.Admission)
	}
	buffer.Reset()
	dumpMetrics(s, tun, nil, "text")
	if !strings.Contains(buffer.String(), "aggregate_buffer_limit=1") || !strings.Contains(buffer.String(), "tcp_pending_limit=0") {
		t.Fatal("text admission missing")
	}
}
