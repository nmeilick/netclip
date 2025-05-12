package paste

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/nmeilick/netclip/streampack"
	"golang.org/x/term"
)

// promptOverwrite asks the user if they want to overwrite a file
func promptOverwrite(u *streampack.Unpacker, path string, destTime, srcTime time.Time, destSize int64) (bool, error) {
	age := ""
	if destTime.Before(srcTime) {
		age = "older, "
	} else if destTime.After(srcTime) {
		age = "newer, "
	}
	// Format the prompt with file information
	fmt.Printf("Overwrite %s (%s%s) (y=yes, n=no, a=all, N=none, q=quit)? ", path, age, humanize.Bytes(uint64(destSize)))

	for {
		choice, err := promptForChoice()
		if err != nil {
			return false, fmt.Errorf("prompt error: %w", err)
		}

		switch choice {
		case "y", "Y":
			fmt.Println("Yes")
			return true, nil
		case "n":
			fmt.Println("No")
			return false, nil
		case "a", "A":
			fmt.Println("All")
			u.SetUpdatePolicy(streampack.UpdateAll)
			return true, nil
		case "N":
			fmt.Println("None")
			u.SetUpdatePolicy(streampack.UpdateNone)
			return false, nil
		case "q", "Q", "\x1b", "\x03":
			fmt.Println("Quit")
			os.Exit(1)
		default:
			fmt.Printf("%q\n", choice)
		}
	}
}

// promptForChoice presents a choice to the user and returns the result based on their selection
func promptForChoice() (string, error) {
	// Use platform-specific implementation
	if runtime.GOOS == "windows" {
		return promptForChoiceWindows()
	}
	return promptForChoiceUnix()
}

// promptForChoiceUnix handles interactive prompts on Unix systems
func promptForChoiceUnix() (string, error) {
	// Try to use term.ReadPassword for single character input without echo
	if term.IsTerminal(int(os.Stdin.Fd())) {
		// First attempt: Use term package to read a single key
		fd := int(os.Stdin.Fd())
		oldState, err := term.GetState(fd)
		if err == nil {
			// Put terminal in raw mode to read a single character
			_, err := term.MakeRaw(fd)
			if err == nil {
				// Read a single character
				var b [1]byte
				_, err = os.Stdin.Read(b[:])
				term.Restore(fd, oldState)
				if err == nil {
					return string(b[:]), nil
				}
			}
			term.Restore(fd, oldState)
		}
	}

	// Fallback to line-based input
	return promptFallback()
}

// promptForChoiceWindows handles interactive prompts on Windows systems
func promptForChoiceWindows() (string, error) {
	// On Windows, we'll use a simpler approach that works reliably
	// Try to use term.ReadPassword which works well on Windows
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fd := int(os.Stdin.Fd())

		// Read a single character without echoing
		passwordBytes, err := term.ReadPassword(fd)
		if err == nil && len(passwordBytes) > 0 {
			char := string(passwordBytes[0])
			return string(char), nil
		}
	}

	// Fallback to line-based input
	return promptFallback()
}

// promptFallback is a fallback method that reads a full line of input
func promptFallback() (string, error) {
	var input string
	fmt.Scanln(&input)

	// Normalize input
	input = strings.TrimSpace(input)
	return input, nil
}
