package logs

import (
	"encoding/json"
	"os"
)

func ReadOffsets(path string) (map[string]int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]int64{}, nil
		}
		return nil, err
	}
	out := map[string]int64{}
	if len(data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func WriteOffsets(path string, offsets map[string]int64) error {
	if offsets == nil {
		offsets = map[string]int64{}
	}
	data, err := json.Marshal(offsets)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
