package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestStandardManagementImportsDefaultsAndKeepsSSHOnBadSettings(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "corrupt"}[bad], func(t *testing.T) {
			ctx := context.Background()
			c := config.Config{Version: 1, AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, DataDir: t.TempDir(), StandardIngress: true}
			initial := control.Revision{Number: 1}
			if bad {
				initial.Settings = "corrupt"
			}
			db, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), initial)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			m, err := newManagement(c, db, make([]byte, 32), nil)
			if err != nil {
				t.Fatal(err)
			}
			if m.API.Settings == nil || m.API.Certificates == nil || m.API.VPN == nil {
				t.Fatal("standard management not connected")
			}
			origins := func() map[string]bool {
				result := map[string]bool{}
				for _, endpoint := range m.API.EndpointsProvider() {
					result[endpoint.Origin] = true
				}
				return result
			}
			if !origins()["http://127.0.0.1:18090"] {
				t.Fatal("SSH login origin unavailable before migration")
			}
			err = m.Prepare(ctx)
			if bad {
				if err == nil {
					t.Fatal("corrupt settings silently replaced")
				}
				if !origins()["http://127.0.0.1:18090"] || len(origins()) != 2 {
					t.Fatal("bad settings removed SSH access or widened origins")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				state, err := m.Settings.Status(ctx)
				if err != nil || state.Site.Domain != "" || state.Site.VPNResolver != "9.9.9.9:53" {
					t.Fatal("fresh defaults unavailable", state, err)
				}
			}
		})
	}
}
