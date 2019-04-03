package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	encrypt := readBool("Encrypt?")
	compress := readBool("Compress?")
	_ = encrypt
	_ = compress
}

func readBool(msg string) bool {
	s := strings.ToLower(readString(msg + " [y/n]"))
	if s == "y" {
		return true
	} else if s == "n" {
		return false
	} else {
		fmt.Println("Invalid!")
		return readBool(msg)
	}
}

func readString(msg string) string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(msg + " ")
	input, _ := reader.ReadString('\n')
	return strings.ReplaceAll(input, "\n", "")
}
