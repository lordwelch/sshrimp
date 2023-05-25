package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func logRotate(path string, count int) {
	if _, err := os.Stat(path); err == nil {
		ext := filepath.Ext(path)
		base := strings.TrimSuffix(path, ext)
		for i := count - 1; i >= 1; i-- {
			source := fmt.Sprintf("%s.%d%s", base, i, ext)
			dest := fmt.Sprintf("%s.%d%s", base, i+1, ext)
			_ = os.Remove(dest)
			_ = os.Rename(source, dest)
		}
		dest := fmt.Sprintf("%s.%d%s", base, 1, ext)
		_ = os.Remove(dest)
		_ = os.Rename(path, dest)
	}

}
