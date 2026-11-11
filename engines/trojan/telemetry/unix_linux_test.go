//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
package telemetry

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixExporterPermissionsReadOnlyAndStaleRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry.sock")
	if err := os.WriteFile(path, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if listener, err := ListenUnix(path); err == nil {
		listener.Close()
		t.Fatal("statistics exporter replaced ordinary file")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "sentinel" {
		t.Fatal("protected file changed", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0660 {
		t.Fatal("statistics socket permissions incorrect", err)
	}
	if second, err := ListenUnix(path); err == nil {
		second.Close()
		t.Fatal("live statistics socket was replaced")
	}
	sampler, err := NewSampler(256, 60)
	if err != nil {
		t.Fatal(err)
	}
	sampler.Flush()
	exporter, err := Serve(listener, sampler)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}, DisableKeepAlives: true}}
	response, err := client.Get("http://localhost/snapshot?after=0&instance=")
	if err != nil {
		t.Fatal(err)
	}
	var window Window
	err = json.NewDecoder(response.Body).Decode(&window)
	response.Body.Close()
	if err != nil || len(window.Batches) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("read-only statistics snapshot failed", err)
	}
	response, err = client.Post("http://localhost/apply", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("statistics exporter exposes a control path", response.StatusCode)
	}
	if err = exporter.Close(); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	recovered, err := ListenUnix(path)
	if err != nil {
		t.Fatal("owned stale statistics socket was not recovered", err)
	}
	recovered.Close()
}
