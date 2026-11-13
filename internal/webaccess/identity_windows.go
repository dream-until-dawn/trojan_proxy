//go:build windows

package webaccess

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func fileIdentity(f *os.File) (string, error) {
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info)
	return fmt.Sprintf("%d:%d:%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), err
}
