package server

import "github.com/BurntSushi/toml"

// validTOML reports whether text parses as TOML. The grants document is
// validated before writing: a malformed grants file fails closed at the share
// gateway, which would lock the owner out.
func validTOML(text string) bool {
	var into map[string]any
	_, err := toml.Decode(text, &into)
	return err == nil
}
