package service

import (
	"reflect"
	"testing"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name     string
		cfg      string
		expected map[string]string
	}{
		{name: "SinglePair", cfg: "k1=v1", expected: map[string]string{"k1": "v1"}},
		{name: "SinglePairTrimSpaces", cfg: " k1 = v1 ", expected: map[string]string{"k1": "v1"}},
		{name: "SinglePairEscapedSpaces", cfg: "\\ k1\\ =\\ v1\\ ", expected: map[string]string{" k1 ": " v1 "}},
		{name: "SinglePairTrailingSeparator", cfg: "k1=v1;", expected: map[string]string{"k1": "v1"}},
		{name: "SinglePairEscapedSemicolon", cfg: "k1=v\\;1", expected: map[string]string{"k1": "v;1"}},
		{name: "SinglePairEscapedEquals", cfg: "k\\=1=v1", expected: map[string]string{"k=1": "v1"}},
		{name: "MultiplePair", cfg: "k1=v1;k2=v2", expected: map[string]string{"k1": "v1", "k2": "v2"}},
		{name: "MultiplePairDoubleSemicolon", cfg: "k1=v1;;k2=v2", expected: map[string]string{"k1": "v1", ";k2": "v2"}},
		{name: "MultiplePairDoubleEquals", cfg: "k1==v1;k2=v2", expected: map[string]string{"k1": "=v1", "k2": "v2"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := parseConfig(test.cfg)
			if !reflect.DeepEqual(res, test.expected) {
				t.Fatalf("expected %+v, got %+v", test.expected, res)
			}
		})
	}
}
