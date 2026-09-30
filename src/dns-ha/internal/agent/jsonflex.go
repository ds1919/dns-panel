package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Perl encodes JSON loosely: booleans arrive as numbers (`"ok":1`) and numbers sometimes as strings
// (`"new_epoch":"8"`), depending on how the scalar was last used. Strict Go types fail on that, so agent
// replies are read through tolerant wrappers. Tolerance covers only the value's form: garbage is still an error.

// FlexBool accepts true/false, 1/0 (any non-zero number), "1"/"0"/"true"/"false"/"yes"/"no".
type FlexBool bool

func (b *FlexBool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case bool:
		*b = FlexBool(t)
	case float64:
		*b = FlexBool(t != 0)
	case string:
		switch t {
		case "1", "true", "yes", "on":
			*b = true
		case "0", "false", "no", "off", "":
			*b = false
		default:
			return fmt.Errorf("not a boolean: %q", t)
		}
	case nil:
		*b = false
	default:
		return fmt.Errorf("not a boolean: %v", v)
	}
	return nil
}

// Bool returns the value; a nil receiver (field absent) yields false rather than a panic. Where absence
// matters, the owner checks nil itself (see rawStatus.OK).
func (b *FlexBool) Bool() bool { return b != nil && bool(*b) }

// FlexInt accepts a number or a numeric string; JSON null means "not observed" (nil pointer in the owner).
type FlexInt int64

func (n *FlexInt) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case float64:
		*n = FlexInt(int64(t))
	case string:
		i, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return fmt.Errorf("not an integer: %q", t)
		}
		*n = FlexInt(i)
	case bool:
		if t {
			*n = 1
		} else {
			*n = 0
		}
	default:
		return fmt.Errorf("not an integer: %v", v)
	}
	return nil
}

// Int64 returns the value as *int64 (nil = not observed).
func (n *FlexInt) Int64() *int64 {
	if n == nil {
		return nil
	}
	v := int64(*n)
	return &v
}

// Int returns the value as *int for the health model (nil = not observed).
func (n *FlexInt) Int() *int {
	if n == nil {
		return nil
	}
	v := int(*n)
	return &v
}
