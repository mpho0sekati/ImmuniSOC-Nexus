package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// Define the path to the old backup directory
	backupDir := filepath.Join(".", "old_backup")

	// Check if the backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		fmt.Println("Backup directory does not exist, nothing to clean up.")
		return
	}

	fmt.Printf("Removing old backup directory: %s\n", backupDir)
	
	// Remove the entire backup directory and its contents
	err := os.RemoveAll(backupDir)
	if err != nil {
		fmt.Printf("Error removing backup directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully cleaned up unused backup files.")
}