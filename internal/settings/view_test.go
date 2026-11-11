package settings

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/files"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestViewProjectsCommittedSettingsAndBoundedOrigins(t *testing.T) {
	ctx := context.Background()
	legacy := deployment()
	d := FromLegacy(legacy)
	d.Site.AdminPort = 8006
	candidate := d.Site
	candidate.Domain = "next.example"
	now := time.Unix(1800000000, 0)
	d.Pending = &Transition{Candidate: candidate, Deadline: now.Add(time.Minute).Unix()}
	body, err := d.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), control.Revision{Number: 1, Settings: body})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v := &View{Store: db, Deployment: legacy, Now: func() time.Time { return now }}
	settings, frozen, err := v.Gateway(ctx, control.Revision{Settings: body})
	if err != nil || !frozen || settings.AdminPort != 8006 || settings.ControlPort != legacy.ControlPort {
		t.Fatal("view ignored persisted settings", settings, frozen, err)
	}
	origins, err := v.Origins(ctx)
	if err != nil || !origins["https://example.com:8006"] || !origins["https://next.example:8006"] || !origins["http://127.0.0.1:18090"] || origins["https://example.com:8007"] {
		t.Fatal("view generated incorrect origins", origins, err)
	}
	now = time.Unix(d.Pending.Deadline, 0)
	origins, err = v.Origins(ctx)
	if err != nil || origins["https://next.example:8006"] || !origins["https://example.com:8006"] {
		t.Fatal("expired candidate origin remained trusted", origins, err)
	}
	v.Standard = true
	if _, err = v.ForSite(ctx, d.Site); err == nil {
		t.Fatal("standard ingress silently fell back to staging mode")
	}
	v.Ingress = func(context.Context, Site) (*gateway.Ingress, error) { return &gateway.Ingress{Mode: "automatic"}, nil }
	if s, err := v.ForSite(ctx, d.Site); err != nil || s.Ingress == nil || !s.Policy.AllowStandardPorts {
		t.Fatal("standard ingress was not explicit", s, err)
	}
	if _, _, err = v.Gateway(ctx, control.Revision{}); err == nil {
		t.Fatal("missing settings fell back to legacy file")
	}
}

func TestViewDirectoryUsesCommittedBindingAndSubroot(t *testing.T) {
	ctx := context.Background()
	legacy := deployment()
	rootPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootPath, "public"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "public", "file.txt"), []byte("published"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := files.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	d := FromLegacy(legacy)
	d.Site.Directories = []Directory{{ID: "visible", Root: "downloads", Relative: "public"}}
	candidate := d.Site
	candidate.Directories = []Directory{{ID: "candidate-only", Root: "downloads", Relative: "."}}
	d.Pending = &Transition{Candidate: candidate, Deadline: time.Now().Add(time.Minute).Unix()}
	body, err := d.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), control.Revision{Number: 1, Settings: body})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v := &View{Store: db, Deployment: legacy, Roots: map[string]*files.Root{"downloads": root}}
	if err := v.CheckDirectories(d.Site); err != nil {
		t.Fatal(err)
	}
	child, err := v.Directory(ctx, "visible")
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	f, err := child.Open("file.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "published" {
		t.Fatal("committed subdirectory unavailable", string(b), err)
	}
	if child, err := v.Directory(ctx, "candidate-only"); err == nil {
		child.Close()
		t.Fatal("candidate directory published before confirmation")
	}
	bad := d.Site
	bad.Directories = []Directory{{ID: "bad", Root: "downloads", Relative: "absent"}}
	if err := v.CheckDirectories(bad); err == nil {
		t.Fatal("missing candidate directory accepted")
	}
}
