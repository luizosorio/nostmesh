package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// maxConfigSize bounds how much is read from a configuration file. Validation
// order is cheapest-first: refuse an implausibly large file before parsing it.
const maxConfigSize = 1 << 20 // 1 MiB

// Load reads, decodes and validates a configuration file.
//
// Defaults are applied before decoding, so a file may omit any field that has a
// safe default. The returned configuration is always valid; on any problem the
// error explains what to fix and the configuration must not be used.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return Config{}, fmt.Errorf("configuration file not found: %s", path)
		case errors.Is(err, fs.ErrPermission):
			return Config{}, fmt.Errorf("configuration file not readable: %s", path)
		default:
			return Config{}, fmt.Errorf("opening configuration: %w", err)
		}
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("inspecting configuration: %w", err)
	}
	if info.IsDir() {
		return Config{}, fmt.Errorf("configuration path is a directory: %s", path)
	}
	if info.Size() > maxConfigSize {
		return Config{}, fmt.Errorf("configuration file exceeds %d bytes: %s", maxConfigSize, path)
	}

	return decode(io.LimitReader(file, maxConfigSize), path)
}

func decode(r io.Reader, source string) (Config, error) {
	cfg := Default()

	decoder := json.NewDecoder(r)
	// Unknown fields are rejected. A typo in a security-relevant key must fail
	// loudly rather than leave the intended setting at its default.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", source, decodeHint(err))
	}

	// Trailing content indicates a malformed file, such as two concatenated
	// documents, where the second would be silently ignored.
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parsing %s: unexpected content after the configuration object", source)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// decodeHint rewrites decoder errors that are unhelpful on their own.
func decodeHint(err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			field = "(root)"
		}
		return fmt.Errorf("field %q expects %s, got %s", field, typeErr.Type, typeErr.Value)
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Errorf("malformed JSON at byte %d: %w", syntaxErr.Offset, err)
	}

	if strings.Contains(err.Error(), "unknown field") {
		return fmt.Errorf("%w; remove it or check for a typo", err)
	}

	return err
}
