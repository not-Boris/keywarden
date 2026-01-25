package logs

import (
	"os"
	"strings"
)

func ReadCursor(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func WriteCursor(path string, cursor string) error {
	if cursor == "" {
		return nil
	}
	return os.WriteFile(path, []byte(cursor+"\n"), 0o600)
}
