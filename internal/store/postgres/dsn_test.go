package postgres

import "testing"

func TestWithBinaryParameters(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://u:p@h:5432/db?sslmode=disable": "postgres://u:p@h:5432/db?binary_parameters=yes&sslmode=disable",
		"postgresql://u@h/db":                      "postgresql://u@h/db?binary_parameters=yes",
		"host=h user=u dbname=db":                  "host=h user=u dbname=db binary_parameters=yes",
		"postgres://h/db?binary_parameters=no":     "postgres://h/db?binary_parameters=no", // explicit choice kept
	} {
		if got := withBinaryParameters(in); got != want {
			t.Errorf("withBinaryParameters(%q) = %q, want %q", in, got, want)
		}
	}
}
