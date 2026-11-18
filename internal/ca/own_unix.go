//go:build unix

package ca

import (
	"os"
	"syscall"
)

// tightenOwn sets dir to 0700 when uid owns it and group or others can access it. A container volume starts with the
// image directory's mode (0755 after a COPY), and ghgate created none of what is in it yet; a directory someone else
// owns is left for requirePrivate to refuse.
func tightenOwn(dir string, uid int) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid || fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return os.Chmod(dir, 0o700)
}
