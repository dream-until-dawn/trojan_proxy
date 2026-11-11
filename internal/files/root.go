// Package files 提供限制在发布目录内的只读文件访问。
package files

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
)

// Root 持有操作系统目录句柄，避免校验路径后再打开产生换链竞争。
type Root struct{ root *os.Root }

// OpenRoot 打开显式授权的发布目录；调用者负责关闭。
func OpenRoot(path string) (*Root, error) {
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &Root{root: r}, nil
}

// Close 释放目录句柄。
func (r *Root) Close() error { return r.root.Close() }

// Open 只打开根目录内普通文件；name 必须是 HTTP 层解码后的相对路径。
// os.Root 在实际打开时约束路径解析，符号链接不得逃出发布根目录。
func (r *Root) Open(name string) (*os.File, error) {
	if !validName(name, false) {
		return nil, fs.ErrPermission
	}
	// Linux 使用非阻塞打开，避免攻击者把文件换成 FIFO 后阻塞下载工作线程。
	f, err := r.root.OpenFile(name, os.O_RDONLY|nonblockFlag, 0)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("仅允许访问普通文件")
	}
	return f, nil
}

func validName(name string, allowRoot bool) bool {
	if name == "." {
		return allowRoot
	}
	if !fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00%") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// Entry 仅包含公开目录项名称和类型，不回显宿主机路径或权限。
type Entry struct {
	Name      string
	Directory bool
}

// List 在根目录约束下读取有界目录项；不读取条目内容，不跟随条目符号链接。
func (r *Root) List(name string) ([]Entry, error) {
	if !validName(name, true) {
		return nil, fs.ErrPermission
	}
	f, err := r.root.OpenFile(name, os.O_RDONLY|nonblockFlag, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, fs.ErrInvalid
	}
	entries, err := f.ReadDir(1001)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 1000 {
		return nil, errors.New("目录超过1000项，请使用更细的发布目录")
	}
	result := []Entry{}
	for _, entry := range entries {
		if !validName(entry.Name(), false) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			continue
		}
		result = append(result, Entry{Name: entry.Name(), Directory: entry.IsDir()})
	}
	return result, nil
}
