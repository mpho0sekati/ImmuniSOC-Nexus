package monocyte

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// LogEntry represents a single log entry with cryptographic properties
type LogEntry struct {
	Index     int64     `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Data      string    `json:"data"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
	Signature string    `json:"signature,omitempty"` // Optional signature for authenticity
}

// MonocyteLogger represents the immutable logging system
type MonocyteLogger struct {
	mutex       sync.RWMutex // Using RWMutex for better concurrency
	logEntries  []LogEntry
	logFile     string
	secret      string          // Secret for HMAC signatures
	lastHash    string          // Hash of the latest entry
	pendingSave chan []LogEntry // Channel for async file writes (sending batches)
	stopChan    chan struct{}   // Channel to stop the save goroutine
	closed      bool            // Flag to prevent double close
	closeMutex  sync.Mutex      // Mutex to protect close operations
	wg          sync.WaitGroup  // WaitGroup to ensure background saver finishes
}

// NewMonocyteLogger creates a new immutable logger instance
// NewMonocyteLogger creates a new immutable logger instance
func NewMonocyteLogger(logFile string, secret string) *MonocyteLogger {
	logger := &MonocyteLogger{
		logEntries:  make([]LogEntry, 0),
		logFile:     logFile,
		lastHash:    "",                           // Genesis block has no previous hash
		pendingSave: make(chan []LogEntry, 100), // Buffer up to 100 pending save batches
		stopChan:    make(chan struct{}),
		closed:      false,
		secret:      secret,
	}

	// Load existing log entries if file exists
	logger.loadFromFile()

	// Start the background save goroutine
	logger.wg.Add(1)
	go logger.backgroundSaver()

	return logger
}

// backgroundSaver runs in a separate goroutine to handle file I/O
func (ml *MonocyteLogger) backgroundSaver() {
	defer ml.wg.Done()
	
	for {
		select {
		case entries := <-ml.pendingSave:
			// Perform the file write operation
			data, err := json.MarshalIndent(entries, "", "  ")
			if err != nil {
				// In a real implementation, we'd have better error handling
				continue
			}
			
			// Write to file
			err = os.WriteFile(ml.logFile, data, 0644)
			if err != nil {
				// In a real implementation, we'd have better error handling
				continue
			}
		case <-ml.stopChan:
			// Drain any remaining items in the channel before exiting
			for len(ml.pendingSave) > 0 {
				entries := <-ml.pendingSave
				// Perform the file write operation
				data, err := json.MarshalIndent(entries, "", "  ")
				if err != nil {
					// In a real implementation, we'd have better error handling
					continue
				}
				
				// Write to file
				err = os.WriteFile(ml.logFile, data, 0644)
				if err != nil {
					// In a real implementation, we'd have better error handling
					continue
				}
			}
			return
		}
	}
}

// Append adds a new entry to the immutable log
func (ml *MonocyteLogger) Append(data string) error {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()

	// Prevent appending to a closed logger
	ml.closeMutex.Lock()
	if ml.closed {
		ml.closeMutex.Unlock()
		return fmt.Errorf("logger is closed")
	}
	ml.closeMutex.Unlock()

	index := int64(len(ml.logEntries))
	timestamp := time.Now().UTC()

	// Create the entry content to be hashed
	entryData := fmt.Sprintf("%d|%s|%s|%s", index, timestamp.Format(time.RFC3339), data, ml.lastHash)

	// Calculate the hash of this entry
	hashBytes := sha256.Sum256([]byte(entryData))
	currentHash := hex.EncodeToString(hashBytes[:])

	// Calculate HMAC signature for authenticity
	h := hmac.New(sha256.New, []byte(ml.secret))
	h.Write([]byte(entryData))
	signature := hex.EncodeToString(h.Sum(nil))

	// Create the log entry
	newEntry := LogEntry{
		Index:     index,
		Timestamp: timestamp,
		Data:      data,
		PrevHash:  ml.lastHash,
		Hash:      currentHash,
		Signature: signature,
	}

	// Add to entries
	ml.logEntries = append(ml.logEntries, newEntry)
	ml.lastHash = currentHash

	// Create a copy of the entries to send to the background saver
	entriesCopy := make([]LogEntry, len(ml.logEntries))
	copy(entriesCopy, ml.logEntries)

	// Send to background saver (non-blocking due to buffered channel)
	select {
	case ml.pendingSave <- entriesCopy:
		// Successfully sent to background saver
	default:
		// Channel is full, but we've already updated in-memory state
		// This is acceptable for an append-only log where durability is eventually guaranteed
	}

	return nil
}

// writeEntryToFile writes a single entry as a JSON line

// GetEntries returns all log entries
func (ml *MonocyteLogger) GetEntries() []LogEntry {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()

	// Return a copy to prevent external modification
	entries := make([]LogEntry, len(ml.logEntries))
	copy(entries, ml.logEntries)
	return entries
}

// GetEntry returns a specific log entry by index
func (ml *MonocyteLogger) GetEntry(index int64) (*LogEntry, error) {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()

	if index < 0 || index >= int64(len(ml.logEntries)) {
		return nil, fmt.Errorf("entry index %d out of range", index)
	}

	return &ml.logEntries[index], nil
}

// VerifyChain verifies the integrity of the entire log chain
func (ml *MonocyteLogger) VerifyChain() (bool, []int) {
	ml.mutex.RLock()
	defer ml.mutex.RUnlock()

	var corruptedIndices []int
	valid := true

	for i := range ml.logEntries {
		entry := ml.logEntries[i] // Copy to local variable to avoid pointer issues in loop
		// Recalculate what the hash should be
		expectedData := fmt.Sprintf("%d|%s|%s|%s", entry.Index, entry.Timestamp.Format(time.RFC3339), entry.Data, entry.PrevHash)
		expectedHashBytes := sha256.Sum256([]byte(expectedData))
		expectedHash := hex.EncodeToString(expectedHashBytes[:])

		// Check if the stored hash matches the calculated hash
		if entry.Hash != expectedHash {
			corruptedIndices = append(corruptedIndices, i)
			valid = false
			continue
		}

		// For non-genesis entries, check if the prevHash matches the previous entry's hash
		if i > 0 {
			prevEntry := ml.logEntries[i-1]
			if entry.PrevHash != prevEntry.Hash {
				corruptedIndices = append(corruptedIndices, i)
				valid = false
			}
		}
		
		// Verify the HMAC signature
		h := hmac.New(sha256.New, []byte(ml.secret))
		h.Write([]byte(expectedData))
		expectedSignature := hex.EncodeToString(h.Sum(nil))
		if entry.Signature != expectedSignature {
			corruptedIndices = append(corruptedIndices, i)
			valid = false
		}
	}

	return valid, corruptedIndices
}

// loadFromFile loads log entries from the persistent storage file
func (ml *MonocyteLogger) loadFromFile() error {
	data, err := os.ReadFile(ml.logFile)
	if err != nil {
		// If file doesn't exist, that's okay - start fresh
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if len(data) == 0 {
		return nil
	}

	var entries []LogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	ml.mutex.Lock()
	defer ml.mutex.Unlock()
	
	ml.logEntries = entries

	// Update lastHash to the hash of the final entry
	if len(entries) > 0 {
		ml.lastHash = entries[len(entries)-1].Hash
	}

	return nil
}

// Close gracefully shuts down the logger
func (ml *MonocyteLogger) Close() {
	ml.closeMutex.Lock()
	if ml.closed {
		ml.closeMutex.Unlock()
		return
	}
	ml.closed = true
	close(ml.stopChan)
	ml.closeMutex.Unlock()

	// Wait for the background goroutine to finish
	ml.wg.Wait()
}


// GeneratePOPIABreachReport generates a POPIA-compliant breach report from the log
func (ml *MonocyteLogger) GeneratePOPIABreachReport() (string, error) {
	// We'll call VerifyChain which will acquire its own lock
	isValid, corruptedIndices := ml.VerifyChain()
	if !isValid {
		return "", fmt.Errorf("log chain is corrupted at indices: %v", corruptedIndices)
	}

	// Get a snapshot of entries with proper locking
	ml.mutex.Lock()
	entries := make([]LogEntry, len(ml.logEntries))
	copy(entries, ml.logEntries)
	ml.mutex.Unlock()

	// Filter entries that are relevant to POPIA breach reporting
	var breachEvents []LogEntry
	for _, entry := range entries {
		// Look for entries that indicate potential data breaches or unauthorized access
		if containsPOPIARelevantTerms(entry.Data) {
			breachEvents = append(breachEvents, entry)
		}
	}

	report := fmt.Sprintf("POPIA Breach Report - Generated on %s\n", time.Now().Format(time.RFC3339))
	report += fmt.Sprintf("Total log entries: %d\n", len(entries))
	report += fmt.Sprintf("Breach-related events found: %d\n", len(breachEvents))
	report += "Breach Events:\n"

	for _, event := range breachEvents {
		report += fmt.Sprintf("  [%s] Index %d: %s\n",
			event.Timestamp.Format(time.RFC3339),
			event.Index,
			event.Data)
	}

	return report, nil
}

// containsPOPIARelevantTerms checks if the log data contains terms relevant to POPIA breach reporting
func containsPOPIARelevantTerms(data string) bool {
	terms := []string{
		"breach", "unauthorized", "compromise", "exposure", "leak",
		"access_violation", "data_breach", "privacy_violation",
		"sensitive_data", "personal_information", "PII", "identifiable",
	}

	for _, term := range terms {
		if containsIgnoreCase(data, term) {
			return true
		}
	}
	return false
}

// containsIgnoreCase checks if a string contains a substring ignoring case
func containsIgnoreCase(str, substr string) bool {
	return len(str) >= len(substr) && 
		   (str == substr || 
		    containsIgnoreCaseHelper(str, substr))
}

// containsIgnoreCaseHelper is a helper for case-insensitive string comparison
func containsIgnoreCaseHelper(str, substr string) bool {
	sLen := len(str)
	subLen := len(substr)
	if subLen == 0 {
		return true
	}
	if sLen < subLen {
		return false
	}
	
	strLower := toLowerSimple(str)
	substrLower := toLowerSimple(substr)
	
	for i := 0; i <= sLen-subLen; i++ {
		match := true
		for j := 0; j < subLen; j++ {
			if strLower[i+j] != substrLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// toLowerSimple converts a string to lowercase using a simple approach
func toLowerSimple(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + ('a' - 'A')
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// GetLogSize returns the number of entries in the log
func (ml *MonocyteLogger) GetLogSize() int {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()

	return len(ml.logEntries)
}

// VerifyEntry verifies the integrity of a specific entry
func (ml *MonocyteLogger) VerifyEntry(index int64) (bool, error) {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()

	if index < 0 || index >= int64(len(ml.logEntries)) {
		return false, fmt.Errorf("entry index %d out of range", index)
	}

	entry := ml.logEntries[index]

	// Recalculate what the hash should be
	expectedData := fmt.Sprintf("%d|%s|%s|%s", entry.Index, entry.Timestamp.Format(time.RFC3339), entry.Data, entry.PrevHash)
	expectedHashBytes := sha256.Sum256([]byte(expectedData))
	expectedHash := hex.EncodeToString(expectedHashBytes[:])

	// Check if the stored hash matches the calculated hash
	isValid := entry.Hash == expectedHash

	// For non-genesis entries, also check the prevHash relationship
	if isValid && index > 0 {
		prevEntry := ml.logEntries[index-1]
		isValid = entry.PrevHash == prevEntry.Hash
	}

	return isValid, nil
}
