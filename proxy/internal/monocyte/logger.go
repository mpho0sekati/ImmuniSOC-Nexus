package monocyte

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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
	secret      string         // Secret for HMAC signatures
	lastHash    string         // Hash of the latest entry
	pendingSave chan LogEntry  // Channel for async file writes (sending single entries)
	stopChan    chan struct{}  // Channel to stop the save goroutine
	closed      bool           // Flag to prevent double close
	closeMutex  sync.Mutex     // Mutex to protect close operations
	wg          sync.WaitGroup // WaitGroup to ensure background saver finishes
}

// NewMonocyteLogger creates a new immutable logger instance
func NewMonocyteLogger(logFile string, secret string) *MonocyteLogger {
	if dir := filepath.Dir(logFile); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[MONOCYTE ERROR] Failed to create log directory %s: %v", dir, err)
		}
	}

	logger := &MonocyteLogger{
		logEntries:  make([]LogEntry, 0),
		logFile:     logFile,
		lastHash:    "",                        // Genesis block has no previous hash
		pendingSave: make(chan LogEntry, 1000), // Buffer up to 1000 pending entries
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

	// Open the file once in append mode for the lifetime of the saver
	f, err := os.OpenFile(ml.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[MONOCYTE ERROR] Failed to open log file for background saving: %v", err)
		return
	}
	defer f.Close()

	for {
		select {
		case entry := <-ml.pendingSave:
			if err := ml.writeEntry(f, entry); err != nil {
				log.Printf("[MONOCYTE ERROR] Failed to persist log entry %d: %v", entry.Index, err)
			}
		case <-ml.stopChan:
			// Drain any remaining items in the channel before exiting
			for len(ml.pendingSave) > 0 {
				entry := <-ml.pendingSave
				if err := ml.writeEntry(f, entry); err != nil {
					log.Printf("[MONOCYTE ERROR] Failed to persist log entry %d during shutdown: %v", entry.Index, err)
				}
			}
			if err := f.Sync(); err != nil {
				log.Printf("[MONOCYTE ERROR] Failed to sync log file during shutdown: %v", err)
			}
			return
		}
	}
}

func (ml *MonocyteLogger) writeEntry(f *os.File, entry LogEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		return err
	}

	return nil
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

	// Block instead of dropping when the buffer is full. Forensic logs should
	// prefer backpressure over silent persistence loss.
	ml.pendingSave <- newEntry

	return nil
}

// GetEntries returns all log entries
func (ml *MonocyteLogger) GetEntries() []LogEntry {
	ml.mutex.RLock()
	defer ml.mutex.RUnlock()

	// Return a copy to prevent external modification
	entries := make([]LogEntry, len(ml.logEntries))
	copy(entries, ml.logEntries)
	return entries
}

// GetEntry returns a specific log entry by index
func (ml *MonocyteLogger) GetEntry(index int64) (*LogEntry, error) {
	ml.mutex.RLock()
	defer ml.mutex.RUnlock()

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
	file, err := os.Open(ml.logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
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

	// Get a snapshot of entries with proper read locking
	ml.mutex.RLock()
	entries := make([]LogEntry, len(ml.logEntries))
	copy(entries, ml.logEntries)
	ml.mutex.RUnlock()

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

	lowerData := strings.ToLower(data)
	for _, term := range terms {
		if strings.Contains(lowerData, strings.ToLower(term)) {
			return true
		}
	}
	return false
}

// GetLogSize returns the number of entries in the log
func (ml *MonocyteLogger) GetLogSize() int {
	ml.mutex.RLock()
	defer ml.mutex.RUnlock()

	return len(ml.logEntries)
}

// VerifyEntry verifies the integrity of a specific entry
func (ml *MonocyteLogger) VerifyEntry(index int64) (bool, error) {
	ml.mutex.RLock()
	defer ml.mutex.RUnlock()

	if index < 0 || index >= int64(len(ml.logEntries)) {
		return false, fmt.Errorf("entry index %d out of range", index)
	}

	entry := ml.logEntries[index]

	// Recalculate what the hash should be
	expectedData := fmt.Sprintf("%d|%s|%s|%s", entry.Index, entry.Timestamp.Format(time.RFC3339), entry.Data, entry.PrevHash)
	expectedHashBytes := sha256.Sum256([]byte(expectedData))
	expectedHash := hex.EncodeToString(expectedHashBytes[:])

	// Verify Hash and Signature
	h := hmac.New(sha256.New, []byte(ml.secret))
	h.Write([]byte(expectedData))
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	isValid := entry.Hash == expectedHash && entry.Signature == expectedSignature

	// For non-genesis entries, also check the prevHash relationship
	if isValid && index > 0 {
		prevEntry := ml.logEntries[index-1]
		isValid = entry.PrevHash == prevEntry.Hash
	}

	return isValid, nil
}
