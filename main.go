package main

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
)

const (
	flagDigits = 1 << iota
	flagUppers
	flagSymbols
	flagAmbiguous
	flagNoVowels
)

const (
	consonant = 1 << iota
	vowel
	diphthong
	notFirst
)

const (
	digits    = "0123456789"
	uppers    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowers    = "abcdefghijklmnopqrstuvwxyz"
	symbols   = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	ambiguous = "B8G6I1l0OQDS5Z2"
	vowels    = "01aeiouyAEIOUY"
)

type phoneme struct {
	text  string
	flags int
}

var phonemes = []phoneme{
	{"a", vowel}, {"ae", vowel | diphthong}, {"ah", vowel | diphthong},
	{"ai", vowel | diphthong}, {"b", consonant}, {"c", consonant},
	{"ch", consonant | diphthong}, {"d", consonant}, {"e", vowel},
	{"ee", vowel | diphthong}, {"ei", vowel | diphthong}, {"f", consonant},
	{"g", consonant}, {"gh", consonant | diphthong | notFirst},
	{"h", consonant}, {"i", vowel}, {"ie", vowel | diphthong},
	{"j", consonant}, {"k", consonant}, {"l", consonant}, {"m", consonant},
	{"n", consonant}, {"ng", consonant | diphthong | notFirst}, {"o", vowel},
	{"oh", vowel | diphthong}, {"oo", vowel | diphthong}, {"p", consonant},
	{"ph", consonant | diphthong}, {"qu", consonant | diphthong},
	{"r", consonant}, {"s", consonant}, {"sh", consonant | diphthong},
	{"t", consonant}, {"th", consonant | diphthong}, {"u", vowel},
	{"v", consonant}, {"w", consonant}, {"x", consonant},
	{"y", consonant}, {"z", consonant},
}

type options struct {
	length    int
	count     int
	flags     int
	columns   bool
	secure    bool
	remove    string
	removeSet bool
	sha1File  string
	sha1Seed  string
	sha1Mode  bool
}

type numberSource func(int) (int, error)

func randomNumber(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("random range must be positive")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func parseOptions(args []string, isTerminal bool) (options, error) {
	opts := options{length: 12, count: -1, columns: isTerminal, flags: flagDigits | flagUppers}
	var positional []string
	var err error

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			switch name {
			case "alt-phonics":
			case "capitalize":
				opts.flags |= flagUppers
			case "numerals":
				opts.flags |= flagDigits
			case "symbols":
				opts.flags |= flagSymbols
			case "num-passwords":
				value, i, err = optionValue(args, i, value, hasValue)
				if err != nil {
					return opts, err
				}
				opts.count, err = parseNumber(value)
				if err != nil {
					return opts, fmt.Errorf("Invalid number of passwords: %s", value)
				}
			case "remove-chars":
				value, i, err = optionValue(args, i, value, hasValue)
				if err != nil {
					return opts, err
				}
				opts.remove, opts.removeSet = value, true
			case "secure":
				opts.secure = true
			case "help":
				return opts, errHelp
			case "no-numerals":
				opts.flags &^= flagDigits
			case "no-capitalize":
				opts.flags &^= flagUppers
			case "sha1":
				value, i, err = optionValue(args, i, value, hasValue)
				if err != nil {
					return opts, err
				}
				opts.sha1File, opts.sha1Seed, opts.sha1Mode = splitSHA1Arg(value)
			case "ambiguous":
				opts.flags |= flagAmbiguous
			case "no-vowels":
				opts.secure = true
				opts.flags |= flagNoVowels
			default:
				return opts, fmt.Errorf("unknown option: --%s", name)
			}
			continue
		}

		for j := 1; j < len(arg); j++ {
			option := arg[j]
			var value string
			requiresValue := option == 'N' || option == 'H' || option == 'r'
			if requiresValue {
				if j+1 < len(arg) {
					value = arg[j+1:]
				} else if i+1 < len(args) {
					i++
					value = args[i]
				} else {
					return opts, fmt.Errorf("option requires an argument: -%c", option)
				}
			}
			switch option {
			case '0':
				opts.flags &^= flagDigits
			case '1':
				opts.columns = false
			case 'A':
				opts.flags &^= flagUppers
			case 'a':
			case 'B':
				opts.flags |= flagAmbiguous
			case 'c':
				opts.flags |= flagUppers
			case 'C':
				opts.columns = true
			case 'n':
				opts.flags |= flagDigits
			case 'N':
				var err error
				opts.count, err = parseNumber(value)
				if err != nil {
					return opts, fmt.Errorf("Invalid number of passwords: %s", value)
				}
			case 's':
				opts.secure = true
			case 'r':
				opts.remove, opts.removeSet, opts.secure = value, true, true
			case 'H':
				opts.sha1File, opts.sha1Seed, opts.sha1Mode = splitSHA1Arg(value)
			case 'v':
				opts.secure = true
				opts.flags |= flagNoVowels
			case 'y':
				opts.flags |= flagSymbols
			case 'h':
				return opts, errHelp
			default:
				return opts, fmt.Errorf("unknown option: -%c", option)
			}
			if requiresValue {
				break
			}
		}
	}

	if len(positional) > 0 {
		length, err := parseNumber(positional[0])
		if err != nil {
			return opts, fmt.Errorf("Invalid password length: %s", positional[0])
		}
		opts.length = length
		if length < 5 {
			opts.secure = true
		}
		if !opts.secure {
			if length <= 2 {
				opts.flags &^= flagUppers
			}
			if length <= 1 {
				opts.flags &^= flagDigits
			}
		}
	}
	if len(positional) > 1 {
		count, err := parseNumber(positional[1])
		if err != nil {
			return opts, fmt.Errorf("Invalid number of passwords: %s", positional[1])
		}
		opts.count = count
	}
	if len(positional) > 2 {
		return opts, errors.New("too many arguments")
	}
	return opts, nil
}

var errHelp = errors.New("help requested")

func optionValue(args []string, index int, value string, hasValue bool) (string, int, error) {
	if hasValue {
		return value, index, nil
	}
	if index+1 >= len(args) {
		return "", index, errors.New("option requires an argument")
	}
	return args[index+1], index + 1, nil
}

func parseNumber(value string) (int, error) {
	n, err := strconv.ParseInt(value, 0, strconv.IntSize)
	return int(n), err
}

func splitSHA1Arg(value string) (string, string, bool) {
	file, seed, found := strings.Cut(value, "#")
	if !found {
		seed = "pwgen"
	}
	return file, seed, true
}

func generateRandomPassword(length, flags int, remove string, removeSet bool, number numberSource) (string, error) {
	charset := ""
	if flags&flagDigits != 0 {
		charset += digits
	}
	if flags&flagUppers != 0 {
		charset += uppers
	}
	charset += lowers
	if flags&flagSymbols != 0 {
		charset += symbols
	}
	if removeSet {
		filter := func(chars string) string {
			var kept strings.Builder
			for _, char := range chars {
				if !strings.ContainsRune(ambiguous, char) || flags&flagAmbiguous == 0 {
					if !strings.ContainsRune(vowels, char) || flags&flagNoVowels == 0 {
						if !strings.ContainsRune(remove, char) {
							kept.WriteRune(char)
						}
					}
				}
			}
			return kept.String()
		}
		charset = filter(charset)
		if flags&flagDigits != 0 && !containsAny(charset, digits) {
			return "", errors.New("Error: No digits left in the valid set")
		}
		if flags&flagUppers != 0 && !containsAny(charset, uppers) {
			return "", errors.New("Error: No upper case letters left in the valid set")
		}
		if flags&flagSymbols != 0 && !containsAny(charset, symbols) {
			return "", errors.New("Error: No symbols left in the valid set")
		}
	}
	if charset == "" {
		return "", errors.New("Error: No characters left in the valid set")
	}
	for {
		password := make([]byte, length)
		remaining := flags
		if length <= 2 {
			remaining = 0
		}
		for i := 0; i < length; {
			index, err := number(len(charset))
			if err != nil {
				return "", err
			}
			char := charset[index]
			if flags&flagAmbiguous != 0 && strings.ContainsRune(ambiguous, rune(char)) {
				continue
			}
			if flags&flagNoVowels != 0 && strings.ContainsRune(vowels, rune(char)) {
				continue
			}
			password[i] = char
			i++
			if strings.ContainsRune(digits, rune(char)) {
				remaining &^= flagDigits
			}
			if strings.ContainsRune(uppers, rune(char)) {
				remaining &^= flagUppers
			}
			if strings.ContainsRune(symbols, rune(char)) {
				remaining &^= flagSymbols
			}
		}
		if remaining&(flagDigits|flagUppers|flagSymbols) == 0 {
			return string(password), nil
		}
	}
}

func containsAny(text, set string) bool {
	for i := range set {
		if strings.ContainsRune(text, rune(set[i])) {
			return true
		}
	}
	return false
}

func generatePhonemePassword(length, flags int, number numberSource) (string, error) {
	for {
		var result strings.Builder
		featureFlags, previous, first := flags, 0, true
		shouldBe, err := number(2)
		if err != nil {
			return "", err
		}
		if shouldBe == 1 {
			shouldBe = vowel
		} else {
			shouldBe = consonant
		}
		for result.Len() < length {
			index, err := number(len(phonemes))
			if err != nil {
				return "", err
			}
			item := phonemes[index]
			text, itemFlags := item.text, item.flags
			if itemFlags&shouldBe == 0 || first && itemFlags&notFirst != 0 {
				continue
			}
			if previous&vowel != 0 && itemFlags&vowel != 0 && itemFlags&diphthong != 0 {
				continue
			}
			if len(text) > length-result.Len() {
				continue
			}
			if flags&flagUppers != 0 && (first || itemFlags&consonant != 0) {
				upper, err := number(10)
				if err != nil {
					return "", err
				}
				if upper < 2 {
					text = strings.ToUpper(text[:1]) + text[1:]
					featureFlags &^= flagUppers
				}
			}
			result.WriteString(text)
			if flags&flagAmbiguous != 0 && strings.ContainsAny(result.String(), ambiguous) {
				break
			}
			if result.Len() >= length {
				break
			}
			if result.Len() >= length {
				break
			}
			if flags&flagDigits != 0 && !first {
				add, err := number(10)
				if err != nil {
					return "", err
				}
				if add < 3 {
					for {
						digit, err := number(10)
						if err != nil {
							return "", err
						}
						char := byte('0' + digit)
						if flags&flagAmbiguous == 0 || !strings.ContainsRune(ambiguous, rune(char)) {
							result.WriteByte(char)
							break
						}
					}
					featureFlags &^= flagDigits
					first, previous = true, 0
					next, err := number(2)
					if err != nil {
						return "", err
					}
					if next == 1 {
						shouldBe = vowel
					} else {
						shouldBe = consonant
					}
					if result.Len() >= length {
						break
					}
					continue
				}
			}
			if flags&flagSymbols != 0 && !first {
				add, err := number(10)
				if err != nil {
					return "", err
				}
				if add < 2 {
					for {
						symbolIndex, err := number(len(symbols))
						if err != nil {
							return "", err
						}
						char := symbols[symbolIndex]
						if flags&flagAmbiguous == 0 || !strings.ContainsRune(ambiguous, rune(char)) {
							result.WriteByte(char)
							break
						}
					}
					featureFlags &^= flagSymbols
				}
			}
			if result.Len() >= length {
				break
			}
			if shouldBe == consonant {
				shouldBe = vowel
			} else if previous&vowel != 0 || itemFlags&diphthong != 0 {
				shouldBe = consonant
			} else {
				next, err := number(10)
				if err != nil {
					return "", err
				}
				if next > 3 {
					shouldBe = consonant
				} else {
					shouldBe = vowel
				}
			}
			previous, first = itemFlags, false
		}
		password := result.String()
		if len(password) != length || featureFlags&(flagUppers|flagDigits|flagSymbols) != 0 || flags&flagAmbiguous != 0 && strings.ContainsAny(password, ambiguous) {
			continue
		}
		return password, nil
	}
}

func sha1NumberSource(file, seed string) (numberSource, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Couldn't open file: %s.", file)
	}
	payload := append([]byte(nil), content...)
	digestIndex := 20
	var digest [sha1.Size]byte
	return func(max int) (int, error) {
		if digestIndex > 19 {
			payload = append(payload, seed...)
			digest = sha1.Sum(payload)
			digestIndex = 0
		}
		value := int(float64(digest[digestIndex]) / 256 * float64(max))
		digestIndex++
		return value, nil
	}, nil
}

func run(args []string, stdout, stderr io.Writer, isTerminal bool) int {
	opts, err := parseOptions(args, isTerminal)
	if err != nil {
		if errors.Is(err, errHelp) {
			printUsage(stderr)
			return 1
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	if opts.length < 1 {
		fmt.Fprintln(stderr, "Invalid password length: must be positive")
		return 1
	}
	if opts.length > 1<<20 {
		fmt.Fprintln(stderr, "Invalid password length: too large")
		return 1
	}
	number := numberSource(randomNumber)
	if opts.sha1Mode {
		number, err = sha1NumberSource(opts.sha1File, opts.sha1Seed)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if opts.count < 0 {
		if opts.columns {
			columns := 80 / (opts.length + 1)
			if columns == 0 {
				columns = 1
			}
			opts.count = columns * 20
		} else {
			opts.count = 1
		}
	}
	columns := 0
	if opts.columns {
		columns = 80 / (opts.length + 1)
		if columns == 0 {
			columns = 1
		}
	}
	for i := 0; i < opts.count; i++ {
		var password string
		if opts.secure {
			password, err = generateRandomPassword(opts.length, opts.flags, opts.remove, opts.removeSet, number)
		} else {
			password, err = generatePhonemePassword(opts.length, opts.flags, number)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		separator := "\n"
		if columns > 0 && (i%columns != columns-1) && i != opts.count-1 {
			separator = " "
		}
		fmt.Fprint(stdout, password, separator)
	}
	return 0
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Usage: pwgen [ OPTIONS ] [ pw_length ] [ num_pw ]")
	fmt.Fprintln(writer, "\nOptions supported by pwgen:")
	fmt.Fprintln(writer, "  -c or --capitalize\n\tInclude at least one capital letter in the password")
	fmt.Fprintln(writer, "  -A or --no-capitalize\n\tDon't include capital letters in the password")
	fmt.Fprintln(writer, "  -n or --numerals\n\tInclude at least one number in the password")
	fmt.Fprintln(writer, "  -0 or --no-numerals\n\tDon't include numbers in the password")
	fmt.Fprintln(writer, "  -y or --symbols\n\tInclude at least one special symbol in the password")
	fmt.Fprintln(writer, "  -r <chars> or --remove-chars=<chars>\n\tRemove characters from the set of characters to generate passwords")
	fmt.Fprintln(writer, "  -s or --secure\n\tGenerate completely random passwords")
	fmt.Fprintln(writer, "  -B or --ambiguous\n\tDon't include ambiguous characters in the password")
	fmt.Fprintln(writer, "  -h or --help\n\tPrint a help message")
	fmt.Fprintln(writer, "  -H or --sha1=path/to/file[#seed]\n\tUse sha1 hash of given file as a (not so) random generator")
	fmt.Fprintln(writer, "  -C\n\tPrint the generated passwords in columns")
	fmt.Fprintln(writer, "  -1\n\tDon't print the generated passwords in columns")
	fmt.Fprintln(writer, "  -v or --no-vowels\n\tDo not use any vowels so as to avoid accidental nasty words")
}

func main() {
	info, err := os.Stdout.Stat()
	isTerminal := err == nil && info.Mode()&os.ModeCharDevice != 0
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, isTerminal))
}
