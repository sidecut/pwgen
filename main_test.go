package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestParseOptions(t *testing.T) {
	opts, err := parseOptions([]string{"--no-numerals", "-c", "--num-passwords=3", "10"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if opts.length != 10 || opts.count != 3 || opts.flags&flagDigits != 0 || opts.flags&flagUppers == 0 {
		t.Fatalf("unexpected parsed options: %+v", opts)
	}
}

func TestGeneratedPasswordsHaveRequestedLength(t *testing.T) {
	for _, test := range []struct {
		name   string
		secure bool
		flags  int
	}{
		{name: "phoneme", flags: flagDigits | flagUppers},
		{name: "random", secure: true, flags: flagDigits | flagUppers | flagSymbols | flagAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			var password string
			var err error
			if test.secure {
				password, err = generateRandomPassword(12, test.flags, "", false, randomNumber)
			} else {
				password, err = generatePhonemePassword(12, test.flags, randomNumber)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(password) != 12 {
				t.Fatalf("got %q with length %d", password, len(password))
			}
			if test.flags&flagAmbiguous != 0 && strings.ContainsAny(password, ambiguous) {
				t.Fatalf("password contains ambiguous character: %q", password)
			}
		})
	}
}

func TestSHA1GenerationIsRepeatable(t *testing.T) {
	path := t.TempDir() + "/input"
	if err := os.WriteFile(path, []byte("stable input"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := sha1NumberSource(path, "seed")
	if err != nil {
		t.Fatal(err)
	}
	second, err := sha1NumberSource(path, "seed")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		a, err := first(97)
		if err != nil {
			t.Fatal(err)
		}
		b, err := second(97)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Fatalf("sequence differs at %d: %d != %d", i, a, b)
		}
	}
}

func TestRunWritesRequestedCount(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-s", "-0", "-A", "8", "2"}, &stdout, &stderr, false); code != 0 {
		t.Fatalf("run returned %d: %s", code, stderr.String())
	}
	if lines := strings.Split(strings.TrimSpace(stdout.String()), "\n"); len(lines) != 2 {
		t.Fatalf("expected two output lines, got %q", stdout.String())
	}
}
