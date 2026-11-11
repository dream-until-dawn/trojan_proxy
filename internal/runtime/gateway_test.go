package runtime

import (
	"context"
	"testing"
)

type blockedGateway struct {
	entered chan struct{}
	release chan struct{}
	values  []string
}

func (g *blockedGateway) Check(context.Context, string) error { return nil }
func (g *blockedGateway) Apply(_ context.Context, value string) error {
	if value == "new-g" && len(g.values) == 0 {
		close(g.entered)
		<-g.release
	}
	g.values = append(g.values, value)
	return nil
}

func TestGatewayReconcileSerializesWithEntryCommit(t *testing.T) {
	ctx := context.Background()
	s := &memoryStore{j: Journal{Applied: Revision{Number: 1, Gateway: "old-g", VPN: "old-v"}}}
	g := &blockedGateway{entered: make(chan struct{}), release: make(chan struct{})}
	c := NewCoordinator(s, g, &component{})
	commitDone := make(chan error, 1)
	go func() { commitDone <- c.Apply(ctx, 1, next()) }()
	<-g.entered
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- c.ReconcileGateway(ctx) }()
	close(g.release)
	if err := <-commitDone; err != nil {
		t.Fatal(err)
	}
	if err := <-reconcileDone; err != nil {
		t.Fatal(err)
	}
	if len(g.values) != 2 || g.values[0] != "new-g" || g.values[1] != "new-g" {
		t.Fatal("reconcile replayed obsolete gateway during entry commit", g.values)
	}
	// 遗留pending不能绕过补偿事务直接恢复任何组件。
	pending := Revision{Number: 3, Gateway: "third-g"}
	s.j.Pending = &pending
	if err := c.ReconcileGateway(ctx); err == nil || len(g.values) != 2 {
		t.Fatal("reconcile bypassed pending transaction")
	}
}
