package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func SaveSpool(dir string, payload []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("%d.json", time.Now().UnixNano())
	tmp := filepath.Join(dir, name+".tmp")
	final := filepath.Join(dir, name)
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func DrainSpool(dir string, send func([]byte) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(files)
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := send(data); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}
