package main

import "path/filepath"

func getFilePath(input string) (string, error) {
	return filepath.Abs(input)
}
