package maintenance

import (
	"golang.org/x/sys/windows"
	"os"
)

func openLock(path string) (*os.File, error) { return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600) }
func lockFile(file *os.File, exclusive bool) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	return windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &windows.Overlapped{})
}
