package main

import "fmt"

// Version is set during build time using -ldflags
var Version = "unknown"

// printVersion prints the application version
func printVersion() {
	fmt.Printf("Version: %s\n", Version)
}
