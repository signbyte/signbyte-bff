package session

import "encoding/json"

func encode(v any) ([]byte, error) { return json.Marshal(v) }

func decode(b []byte, v any) error { return json.Unmarshal(b, v) }
