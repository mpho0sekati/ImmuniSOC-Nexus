package monocyte

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewMonocyteLogger(t *testing.T) {
	tempFile := "test_log_new.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	
	if logger == nil {
		t.Fatal("Expected logger to be created, got nil")
	}
	
	// Clean up
	os.Remove(tempFile)
}

func TestAppendAndRetrieve(t *testing.T) {
	tempFile := "test_log_append_retrieve.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	defer os.Remove(tempFile)
	
	data := "Test log entry"
	err := logger.Append(data)
	if err != nil {
		t.Fatalf("Unexpected error appending entry: %v", err)
	}
	
	entries := logger.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}
	
	entry := entries[0]
	if entry.Data != data {
		t.Errorf("Expected data '%s', got '%s'", data, entry.Data)
	}
	
	if entry.Index != 0 {
		t.Errorf("Expected index 0, got %d", entry.Index)
	}
}

func TestMultipleEntries(t *testing.T) {
	tempFile := "test_log_multiple_entries.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	defer os.Remove(tempFile)
	
	entries := []string{"Entry 1", "Entry 2", "Entry 3"}
	
	for i, data := range entries {
		err := logger.Append(data)
		if err != nil {
			t.Fatalf("Unexpected error appending entry %d: %v", i, err)
		}
	}
	
	logEntries := logger.GetEntries()
	if len(logEntries) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(logEntries))
	}
	
	for i, entry := range logEntries {
		expectedData := entries[i]
		if entry.Data != expectedData {
			t.Errorf("Entry %d: Expected data '%s', got '%s'", i, expectedData, entry.Data)
		}
		
		if entry.Index != int64(i) {
			t.Errorf("Entry %d: Expected index %d, got %d", i, i, entry.Index)
		}
	}
}

func TestGetEntry(t *testing.T) {
	tempFile := "test_log_get_entry_func.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	defer os.Remove(tempFile)
	
	entries := []string{"First", "Second", "Third"}
	
	for _, data := range entries {
		err := logger.Append(data)
		if err != nil {
			t.Fatalf("Unexpected error appending entry: %v", err)
		}
	}
	
	// Test valid indices
	for i := 0; i < len(entries); i++ {
		entry, err := logger.GetEntry(int64(i))
		if err != nil {
			t.Errorf("Unexpected error getting entry %d: %v", i, err)
			continue
		}
		
		if entry.Data != entries[i] {
			t.Errorf("Entry %d: Expected data '%s', got '%s'", i, entries[i], entry.Data)
		}
	}
	
	// Test invalid index
	_, err := logger.GetEntry(10)
	if err == nil {
		t.Error("Expected error for invalid index, got nil")
	}
}

func TestCryptographicChainIntegrity(t *testing.T) {
	tempFile := "test_log_chain_integrity.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	defer os.Remove(tempFile)
	
	entries := []string{"First entry", "Second entry", "Third entry"}
	
	for _, data := range entries {
		err := logger.Append(data)
		if err != nil {
			t.Fatalf("Unexpected error appending entry: %v", err)
		}
	}
	
	// Verify the chain integrity
	isValid, corrupted := logger.VerifyChain()
	if !isValid {
		t.Errorf("Expected chain to be valid, corrupted at indices: %v", corrupted)
	}
	
	allEntries := logger.GetEntries()
	
	// Check that hashes connect properly
	for i := 1; i < len(allEntries); i++ {
		if allEntries[i].PrevHash != allEntries[i-1].Hash {
			t.Errorf("Entry %d: PrevHash doesn't match previous entry's Hash", i)
		}
	}
}

func TestPOPIABreachReportGeneration(t *testing.T) {
	tempFile := "test_log_popia_report.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	defer os.Remove(tempFile)
	
	// Add some entries including ones that might be relevant to POPIA
	entries := []string{
		"Normal operation",
		"Unauthorized access attempt detected",
		"Data breach incident occurred",
		"PII exposure identified",
		"Regular system check",
	}
	
	for _, data := range entries {
		err := logger.Append(data)
		if err != nil {
			t.Fatalf("Unexpected error appending entry: %v", err)
		}
	}
	
	// Generate POPIA report
	report, err := logger.GeneratePOPIABreachReport()
	if err != nil {
		t.Fatalf("Unexpected error generating POPIA report: %v", err)
	}
	
	// Check that the report contains expected elements
	if len(report) == 0 {
		t.Error("Expected non-empty POPIA report")
	}
	
	// The report should contain information about the breach-related entries
	if !strings.Contains(strings.ToLower(report), "breach events:") {
		t.Error("Expected report to contain 'Breach Events:' section")
	}
	
	// It should identify the POPIA-relevant entries
	if !strings.Contains(strings.ToLower(report), "breach") && !strings.Contains(strings.ToLower(report), "pii") {
		t.Error("Expected report to identify POPIA-relevant entries")
	}
}

func TestGetLogSize(t *testing.T) {
	tempFile := "test_log_size_func.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	defer os.Remove(tempFile)
	
	initialSize := logger.GetLogSize()
	if initialSize != 0 {
		t.Errorf("Expected initial size 0, got %d", initialSize)
	}
	
	entries := []string{"First", "Second", "Third"}
	
	for i, data := range entries {
		err := logger.Append(data)
		if err != nil {
			t.Fatalf("Unexpected error appending entry %d: %v", i, err)
		}
		
		currentSize := logger.GetLogSize()
		expectedSize := i + 1
		if currentSize != expectedSize {
			t.Errorf("After adding entry %d: Expected size %d, got %d", i, expectedSize, currentSize)
		}
	}
}

func TestPersistence(t *testing.T) {
	tempFile := "test_log_persistence_func.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	// Create logger and add entries
	logger1 := NewMonocyteLogger(tempFile, secret)
	
	entries := []string{"Persistent", "Entry", "Test"}
	
	for _, data := range entries {
		err := logger1.Append(data)
		if err != nil {
			t.Fatalf("Unexpected error appending entry: %v", err)
		}
	}
	
	logger1Size := logger1.GetLogSize()
	
	// Close the first logger to ensure all writes are flushed
	logger1.Close()
	
	// Wait briefly to ensure file writes are completed
	time.Sleep(200 * time.Millisecond)
	
	// Create a new logger instance with the same file
	logger2 := NewMonocyteLogger(tempFile, secret)
	defer logger2.Close()
	logger2Size := logger2.GetLogSize()
	
	if logger1Size != logger2Size {
		t.Errorf("Expected same size after persistence: %d vs %d", logger1Size, logger2Size)
	}
	
	// Get entries from the second logger to check persistence
	entries2 := logger2.GetEntries()
	
	// Also create a temporary logger to get the original entries for comparison
	loggerCheck := NewMonocyteLogger(tempFile, secret)
	entries1 := loggerCheck.GetEntries()
	loggerCheck.Close()
	
	if len(entries1) != len(entries2) {
		t.Fatalf("Expected same number of entries after persistence: %d vs %d", len(entries1), len(entries2))
	}
	
	// Entries should match
	for i := 0; i < len(entries1); i++ {
		if entries1[i].Data != entries2[i].Data {
			t.Errorf("Entry %d doesn't match after persistence: '%s' vs '%s'", 
				i, entries1[i].Data, entries2[i].Data)
		}
	}
	
	// Clean up
	os.Remove(tempFile)
}

func TestConcurrentAccess(t *testing.T) {
	tempFile := "test_log_concurrent_access.json"
	secret := "test_secret_12345"
	// Ensure file doesn't exist before test
	os.Remove(tempFile)
	
	logger := NewMonocyteLogger(tempFile, secret)
	defer logger.Close()
	defer os.Remove(tempFile)
	
	done := make(chan bool)
	
	// Run multiple goroutines appending entries
	for i := 0; i < 10; i++ {
		go func(id int) {
			data := fmt.Sprintf("Concurrent entry %d", id)
			err := logger.Append(data)
			if err != nil {
				t.Errorf("Unexpected error in goroutine %d: %v", id, err)
			}
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Wait for background writes to complete
	time.Sleep(100 * time.Millisecond)
	
	// Verify the log integrity
	isValid, corrupted := logger.VerifyChain()
	if !isValid {
		t.Errorf("Expected chain to be valid after concurrent access, corrupted at: %v", corrupted)
	}
	
	finalSize := logger.GetLogSize()
	if finalSize != 10 {
		t.Errorf("Expected 10 entries after concurrent appends, got %d", finalSize)
	}
}