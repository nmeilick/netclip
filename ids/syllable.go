package ids

import (
	"math"
	"math/rand"
	"strings"
	"time"
)

var rnd = rand.New(rand.NewSource(time.Now().UnixNano()))

// Common syllables in English that can be combined to create pronounceable words
var defaultSyllables = []string{
	// Consonant-Vowel
	"ba", "be", "bi", "bo", "bu", "ca", "ce", "ci", "co", "cu",
	"da", "de", "di", "do", "du", "fa", "fe", "fi", "fo", "fu",
	"ga", "ge", "gi", "go", "gu", "ha", "he", "hi", "ho", "hu",
	"ja", "je", "ji", "jo", "ju", "ka", "ke", "ki", "ko", "ku",
	"la", "le", "li", "lo", "lu", "ma", "me", "mi", "mo", "mu",
	"na", "ne", "ni", "no", "nu", "pa", "pe", "pi", "po", "pu",
	"ra", "re", "ri", "ro", "ru", "sa", "se", "si", "so", "su",
	"ta", "te", "ti", "to", "tu", "va", "ve", "vi", "vo", "vu",
	"wa", "we", "wi", "wo", "wu", "za", "ze", "zi", "zo", "zu",

	/*
		// Vowel-Consonant
		"ab", "ac", "ad", "af", "ag", "ah", "aj", "ak", "al", "am",
		"an", "ap", "ar", "as", "at", "av", "aw", "ax", "ay", "az",
		"eb", "ec", "ed", "ef", "eg", "eh", "ej", "ek", "el", "em",
		"en", "ep", "er", "es", "et", "ev", "ew", "ex", "ey", "ez",
		"ib", "ic", "id", "if", "ig", "ih", "ij", "ik", "il", "im",
		"in", "ip", "ir", "is", "it", "iv", "iw", "ix", "iy", "iz",
	*/
}

// SyllableOptions provides configuration for syllable ID generation
type SyllableOptions struct {
	// Syllables is the list of syllables to use for ID generation. If empty, defaults will be used.
	Syllables []string
	// Digits is the number of random digits to append to each syllable group
	Digits int
	// DigitsAfter determines after how many syllables the digits will be appended (default: 2)
	DigitsAfter int
	// Separator is the string used to join syllables (default: empty string)
	Separator string
	// SeparatorAfter determines after how many syllables a separator is placed (default: 2)
	SeparatorAfter int
	// Random is the random number generator to use
	Random *rand.Rand
}

// DefaultSyllableOptions returns the default options for syllable ID generation
func DefaultSyllableOptions() *SyllableOptions {
	return &SyllableOptions{
		Syllables:      defaultSyllables,
		Digits:         1,
		DigitsAfter:    2,
		Separator:      "-",
		SeparatorAfter: 2,
		Random:         rnd,
	}
}

// SyllableID generates a pronounceable ID by concatenating random syllables
// to reach approximately the requested length
func SyllableID(length int) string {
	return SyllableIDWithOptions(length, DefaultSyllableOptions())
}

// SyllableIDWithOptions generates a pronounceable ID with custom options
func SyllableIDWithOptions(length int, options *SyllableOptions) string {
	if options == nil {
		options = DefaultSyllableOptions()
	}

	if len(options.Syllables) == 0 {
		options.Syllables = defaultSyllables
	}

	if options.Random == nil {
		options.Random = rnd
	}

	if length == 0 {
		return ""
	}

	var result strings.Builder

	n := 0
	for result.Len() < length {
		if n > 0 && options.Separator != "" && options.SeparatorAfter > 0 && n%options.SeparatorAfter == 0 {
			result.WriteString(options.Separator)
		}

		syllable := options.Syllables[options.Random.Intn(len(options.Syllables))]
		result.WriteString(syllable)
		n += 1
		if options.Digits > 0 && options.DigitsAfter > 0 && n%options.DigitsAfter == 0 {
			for i := 0; i < options.Digits; i++ {
				result.WriteByte('0' + byte(options.Random.Intn(10)))
			}
		}
	}
	return result.String()
}

// MinLengthForEntropy calculates the minimum length of a syllable ID needed
// to provide the requested entropy in bits
func MinLengthForEntropy(entropyBits float64, options *SyllableOptions) int {
	if options == nil {
		options = DefaultSyllableOptions()
	}

	if len(options.Syllables) == 0 {
		options.Syllables = defaultSyllables
	}

	// Calculate entropy per syllable
	// Entropy = log2(possible combinations)
	syllableCount := float64(len(options.Syllables))
	entropyPerSyllable := math.Log2(syllableCount)

	// Calculate entropy from digits (if any)
	digitEntropy := 0.0
	if options.Digits > 0 && options.DigitsAfter > 0 {
		digitEntropy = math.Log2(math.Pow10(options.Digits))
	}

	// Calculate entropy per syllable group
	// A syllable group consists of options.DigitsAfter syllables plus optional digits
	groupEntropy := entropyPerSyllable * float64(options.DigitsAfter)
	if options.Digits > 0 {
		groupEntropy += digitEntropy
	}

	// Calculate how many complete groups we need
	groupsNeeded := math.Ceil(entropyBits / groupEntropy)

	// Calculate total syllables needed
	syllablesNeeded := int(groupsNeeded * float64(options.DigitsAfter))

	// Calculate the resulting string length
	// Each syllable is typically 2 characters
	length := syllablesNeeded * 2

	// Add length for digits
	if options.Digits > 0 {
		length += int(groupsNeeded) * options.Digits
	}

	// Add length for separators
	if options.Separator != "" && options.SeparatorAfter > 0 {
		// Number of separators = (syllablesNeeded / SeparatorAfter) - 1
		// But we need to round up the division and ensure we don't go negative
		separatorCount := int(math.Max(0, math.Ceil(float64(syllablesNeeded)/float64(options.SeparatorAfter))-1))
		length += separatorCount * len(options.Separator)
	}

	return length
}
