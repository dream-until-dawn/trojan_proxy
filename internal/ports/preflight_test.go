package ports

import (
	"net"
	"strconv"
	"testing"
)

func TestConflictPreservesOwner(t *testing.T) {
	owner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	port := owner.Addr().(*net.TCPAddr).Port
	if err = Check([]int{port}); err == nil {
		t.Fatal("未拒绝已占端口")
	}
	conn, err := net.Dial("tcp4", owner.Addr().String())
	if err != nil {
		t.Fatal("预检干扰原监听", err)
	}
	conn.Close()
}
func TestAvailableAndReleased(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if err = Check([]int{port}); err != nil {
		t.Fatal(err)
	}
	l, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal("预检遗留句柄", err)
	}
	l.Close()
}
