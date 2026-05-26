package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

type QuarantineRecord struct {
	SessionID string    `json:"session_id"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

var quarantinesStore = struct {
	mu    sync.RWMutex
	items []QuarantineRecord
}{}

func startTCellService() {
	http.HandleFunc("/quarantine", quarantinePostHandler)
	http.HandleFunc("/quarantines", quarantinesGetHandler)

	go func() {
		log.Println("T-Cell service listening on :8090")
		if err := http.ListenAndServe(":8090", nil); err != nil {
			log.Printf("T-Cell server error: %v", err)
		}
	}()
}

func quarantinePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var rec QuarantineRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	rec.Timestamp = time.Now()

	quarantinesStore.mu.Lock()
	quarantinesStore.items = append(quarantinesStore.items, rec)
	quarantinesStore.mu.Unlock()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusAccepted)
}

func quarantinesGetHandler(w http.ResponseWriter, r *http.Request) {
	quarantinesStore.mu.RLock()
	items := make([]QuarantineRecord, len(quarantinesStore.items))
	copy(items, quarantinesStore.items)
	quarantinesStore.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(items)
}
