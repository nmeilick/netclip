package main

import (
	"flag"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/nmeilick/netclip/ids"
)

func main() {
	// Define command-line flags
	length := flag.Int("length", 8, "Length of the generated ID")
	count := flag.Int("count", 5, "Number of IDs to generate")
	separator := flag.String("separator", "", "Separator between syllables")
	separatorAfter := flag.Int("separator-after", 2, "Insert separator after every N syllables")
	seed := flag.Int64("seed", time.Now().UnixNano(), "Random seed (for reproducible results)")
	customSyllables := flag.String("syllables", "", "Custom syllables (comma-separated)")
	entropy := flag.Float64("entropy", 0, "Show minimum length needed for given entropy in bits")
	digits := flag.Int("digits", 0, "Number of random digits to append after syllables")
	digitsAfter := flag.Int("digits-after", 2, "Append digits after every N syllables")

	// Parse flags
	flag.Parse()

	// Print help if requested
	if flag.NArg() > 0 && flag.Arg(0) == "help" {
		printUsage()
		return
	}

	// Check if entropy calculation is requested
	if *entropy > 0 {
		displayEntropyInfo(*entropy, *separator, *separatorAfter, *customSyllables, *digits, *digitsAfter)
		return
	}

	// Generate and display IDs
	generateAndDisplayIDs(*length, *count, *separator, *separatorAfter, *seed, *customSyllables, *digits, *digitsAfter)
}

func printUsage() {
	fmt.Println("IDs Package Demo")
	fmt.Println("================")
	fmt.Println("This demo showcases the syllable ID generation functionality.")
	fmt.Println("\nUsage: go run demo.go [flags]")
	fmt.Println("\nFlags:")
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Println("  go run demo.go")
	fmt.Println("  go run demo.go -length 12 -count 10")
	fmt.Println("  go run demo.go -separator \"-\" -capitalize")
	fmt.Println("  go run demo.go -seed 12345")
	fmt.Println("  go run demo.go -syllables \"foo,bar,baz\"")
	fmt.Println("  go run demo.go -entropy 128")
}

func displayEntropyInfo(entropyBits float64, separator string, separatorAfter int, customSyllables string, digits int, digitsAfter int) {
	// Create options for syllable ID generation
	options := ids.DefaultSyllableOptions()
	options.Separator = separator
	options.SeparatorAfter = separatorAfter
	options.Digits = digits
	options.DigitsAfter = digitsAfter

	// Use custom syllables if provided
	if customSyllables != "" {
		options.Syllables = strings.Split(customSyllables, ",")
	}

	// Calculate minimum length needed
	minLength := ids.MinLengthForEntropy(entropyBits, options)

	// Print entropy information
	fmt.Println("Entropy Calculation")
	fmt.Println("==================")
	fmt.Printf("For %.1f bits of entropy:\n", entropyBits)
	fmt.Printf("  - Minimum ID length needed: %d characters\n", minLength)
	fmt.Printf("  - Using %d syllables\n", len(options.Syllables))
	fmt.Printf("  - Separator: %q (after every %d syllables)\n", separator, separatorAfter)
	fmt.Printf("  - Digits: %d (after every %d syllables)\n", digits, digitsAfter)

	// Generate an example ID of the calculated length
	exampleID := ids.SyllableIDWithOptions(minLength, options)
	fmt.Printf("\nExample ID with sufficient entropy: %s\n", exampleID)

	// Calculate actual entropy of the generated ID
	syllableCount := len(options.Syllables)

	// Estimate number of syllables in the ID
	avgSyllableLength := 0.0
	for _, s := range options.Syllables {
		avgSyllableLength += float64(len(s))
	}
	avgSyllableLength /= float64(len(options.Syllables))

	// Account for separators and digits in the length
	effectiveLength := float64(minLength)
	if len(separator) > 0 && separatorAfter > 0 {
		// Estimate number of separators
		numSeparators := math.Floor(float64(minLength) / float64(separatorAfter*2+len(separator)))
		effectiveLength -= numSeparators * float64(len(separator))
	}

	if digits > 0 && digitsAfter > 0 {
		// Estimate number of digit groups
		numDigitGroups := math.Floor(float64(minLength) / float64(digitsAfter*2+digits))
		effectiveLength -= numDigitGroups * float64(digits)
	}

	// Estimate number of syllables
	estimatedSyllables := effectiveLength / avgSyllableLength

	// Calculate entropy
	syllableEntropy := math.Log2(float64(syllableCount)) * estimatedSyllables
	digitEntropy := 0.0
	if digits > 0 && digitsAfter > 0 {
		numDigitGroups := math.Floor(estimatedSyllables / float64(digitsAfter))
		digitEntropy = math.Log2(math.Pow10(digits)) * numDigitGroups
	}

	actualEntropy := syllableEntropy + digitEntropy
	fmt.Printf("Actual entropy: approximately %.1f bits\n", actualEntropy)
}

func generateAndDisplayIDs(length, count int, separator string, separatorAfter int, seed int64, customSyllables string, digits int, digitsAfter int) {
	// Create options for syllable ID generation
	options := ids.DefaultSyllableOptions()
	options.Separator = separator
	options.SeparatorAfter = separatorAfter
	options.Random = rand.New(rand.NewSource(seed))
	options.Digits = digits
	options.DigitsAfter = digitsAfter

	// Use custom syllables if provided
	if customSyllables != "" {
		options.Syllables = strings.Split(customSyllables, ",")
	}

	// Print configuration
	fmt.Println("IDs Package Demo")
	fmt.Println("================")
	fmt.Printf("Generating %d syllable IDs of length %d\n", count, length)
	fmt.Printf("Configuration:\n")
	fmt.Printf("  - Separator: %q (after every %d syllables)\n", separator, separatorAfter)
	fmt.Printf("  - Random seed: %d\n", seed)
	fmt.Printf("  - Digits: %d (after every %d syllables)\n", digits, digitsAfter)

	if customSyllables != "" {
		fmt.Printf("  - Using %d custom syllables\n", len(options.Syllables))
	} else {
		fmt.Printf("  - Using %d default syllables\n", len(options.Syllables))
	}

	fmt.Println("\nGenerated IDs:")
	fmt.Println("==============")

	// Generate and display IDs
	for i := 0; i < count; i++ {
		id := ids.SyllableIDWithOptions(length, options)
		fmt.Printf("%2d: %s\n", i+1, id)
	}

	// Show examples of different configurations
	if !strings.Contains(customSyllables, ",") && separator == "" && digits == 0 {
		fmt.Println("\nMore Examples:")
		fmt.Println("=============")

		// Example with separator
		sepOptions := *options
		sepOptions.Separator = "-"
		fmt.Printf("With separator \"-\": %s\n",
			ids.SyllableIDWithOptions(length, &sepOptions))

		// Example with different separator frequency
		sepFreqOptions := *options
		sepFreqOptions.Separator = "-"
		sepFreqOptions.SeparatorAfter = 1
		fmt.Printf("With separator after each syllable: %s\n",
			ids.SyllableIDWithOptions(length, &sepFreqOptions))

		// Example with digits
		digitOptions := *options
		digitOptions.Separator = "-"
		digitOptions.Digits = 2
		digitOptions.DigitsAfter = 1
		fmt.Printf("With 2 digits after each syllable: %s\n",
			ids.SyllableIDWithOptions(length, &digitOptions))

		// Example with both
		bothOptions := *options
		bothOptions.Separator = "-"
		bothOptions.SeparatorAfter = 2
		bothOptions.Digits = 1
		bothOptions.DigitsAfter = 2
		fmt.Printf("With separator and digits: %s\n",
			ids.SyllableIDWithOptions(length, &bothOptions))
	}
}
