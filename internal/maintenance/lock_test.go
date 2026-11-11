package maintenance

import "testing"

func TestSharedControlAndExclusiveRecoveryCannotOverlap(t *testing.T) {
	directory := t.TempDir()
	control, err := Acquire(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(directory, true); err == nil {
		lock.Close()
		t.Fatal("recovery overlapped running control")
	}
	control.Close()
	second.Close()
	recovery, err := Acquire(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(directory, false); err == nil {
		lock.Close()
		t.Fatal("control started during exclusive recovery")
	}
	recovery.Close()
	control, err = Acquire(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	control.Close()
}
