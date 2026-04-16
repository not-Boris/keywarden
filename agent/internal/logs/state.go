package logs

import (
	"encoding/json"
	"os"
)

func ReadState(path string) (map[string]SourceState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]SourceState{}, nil
		}
		return nil, err
	}
	out := map[string]SourceState{}
	if len(data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func WriteState(path string, state map[string]SourceState) error {
	if state == nil {
		state = map[string]SourceState{}
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
