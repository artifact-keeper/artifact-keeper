// Package main provides a test package for E2E native client testing.
package main

import "fmt"

// Version of the package
const Version = "VERSION_PLACEHOLDER"

// Hello returns a greeting message.
func Hello() string {
	return "Hello from test-package!"
}

func main() {
	fmt.Println(Hello())
}
