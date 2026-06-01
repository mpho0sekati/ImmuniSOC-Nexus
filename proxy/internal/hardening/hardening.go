package hardening

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"immunisoc-nexus/proxy/internal/classification"
	"immunisoc-nexus/proxy/internal/microseg"
	"immunisoc-nexus/proxy/internal/netutil"
)

// ServiceInfo represents information about a service
type ServiceInfo struct {
	Name      string
	Address   string
	Port      int
	Status    ServiceStatus
	Tier      ServiceTier
	LastCheck time.Time
	Used      bool
}

// ServiceStatus represents the status of a service
type ServiceStatus int

const (
	Active ServiceStatus = iota
	Inactive
	Disabled
	Removed
)

// ServiceTier represents the security tier of a service
type ServiceTier int

const (
	Public ServiceTier = iota
	Standard
	Critical
)

// HardeningManager manages system hardening and service lifecycle
type HardeningManager struct {
	services        map[string]*ServiceInfo
	classifier      *classification.Classifier
	microSegManager *microseg.MicrosegmentationManager
	mutex           sync.RWMutex
}

// NewHardeningManager creates a new hardening manager
func NewHardeningManager(classifier *classification.Classifier, microSegManager *microseg.MicrosegmentationManager) *HardeningManager {
	manager := &HardeningManager{
		services:        make(map[string]*ServiceInfo),
		classifier:      classifier,
		microSegManager: microSegManager,
	}

	// Start background service monitoring
	go manager.startServiceMonitoring()

	return manager
}

// RegisterService registers a service for monitoring
func (hm *HardeningManager) RegisterService(name, address string, port int, tier ServiceTier) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	serviceKey := fmt.Sprintf("%s:%d", address, port)
	hm.services[serviceKey] = &ServiceInfo{
		Name:      name,
		Address:   address,
		Port:      port,
		Status:    Active,
		Tier:      tier,
		LastCheck: time.Now(),
		Used:      true,
	}
}

// MarkServiceUsed marks a service as having been used recently
func (hm *HardeningManager) MarkServiceUsed(address string, port int) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	serviceKey := fmt.Sprintf("%s:%d", address, port)
	if service, exists := hm.services[serviceKey]; exists {
		service.Used = true
		service.LastCheck = time.Now()
	}
}

// DisableUnusedServices disables services that haven't been used recently
func (hm *HardeningManager) DisableUnusedServices(unusedThreshold time.Duration) {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	now := time.Now()
	for key, service := range hm.services {
		if now.Sub(service.LastCheck) > unusedThreshold && !service.Used {
			if service.Tier == Critical {
				// For critical tier, we log and alert but don't immediately remove
				log.Printf("WARNING: Unused critical service detected: %s (%s). Consider investigating.", service.Name, key)
			} else {
				// For non-critical services, disable them
				service.Status = Disabled
				log.Printf("Service disabled due to inactivity: %s (%s)", service.Name, key)

				// Remove from microsegmentation if present
				hm.removeServiceFromMicrosegmentation(service.Address, service.Port)
			}
		} else {
			// Reset the used flag for the next monitoring cycle
			service.Used = false
		}
	}
}

// removeServiceFromMicrosegmentation removes a service from microsegmentation rules
func (hm *HardeningManager) removeServiceFromMicrosegmentation(address string, port int) {
	// In a real implementation, this would remove the service from microsegmentation policies
	// For now, we'll just log the action
	log.Printf("Removing service from microsegmentation: %s:%d", address, port)
}

// HardenCriticalTier enforces strict boundaries for critical tier services
func (hm *HardeningManager) HardenCriticalTier() {
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	for key, service := range hm.services {
		if service.Tier == Critical && service.Status == Active {
			// Apply stricter microsegmentation rules for critical tier
			hm.enforceCriticalTierPolicy(service.Address, service.Port)

			// Log critical tier access
			log.Printf("Critical tier service secured: %s (%s)", service.Name, key)
		}
	}
}

// enforceCriticalTierPolicy enforces strict policies for critical tier services
func (hm *HardeningManager) enforceCriticalTierPolicy(address string, port int) {
	// Define stricter policies for critical tier services
	sourceSubnets := []string{"192.168.1.0/24"} // Only allow from trusted subnets

	// Create a policy that only allows access from specific sources
	policy := microseg.Policy{
		Name:        fmt.Sprintf("critical-service-policy-%s-%d", address, port),
		Action:      "allow",
		Source:      sourceSubnets,
		Destination: []string{address},
		Protocol:    []string{"tcp"},
		Port:        []int{port},
		Priority:    5, // High priority
		Enabled:     true,
	}

	// Add the policy to microsegmentation manager
	// Create a new segment for each critical service
	segmentName := fmt.Sprintf("critical-service-%s-%d", address, port)
	segment, err := hm.microSegManager.CreateSegment(segmentName, fmt.Sprintf("Critical service for %s:%d", address, port), nil)
	if err != nil {
		// If we can't create a segment, log and try a different approach
		log.Printf("Could not create segment for critical service %s:%d", address, port)
		// Try to use service address directly as segment ID
		segment = &microseg.Segment{
			ID:   address,
			Name: segmentName,
		}
	}

	if segment != nil {
		// Add the critical service IP to the segment
		hm.microSegManager.AddMember(segment.ID, address)

		// Add the strict policy
		err = hm.microSegManager.AddPolicy(segment.ID, policy)
		if err != nil {
			log.Printf("Warning: Could not add critical tier policy for %s:%d: %v", address, port, err)
		}
	}
}

// startServiceMonitoring starts the background service monitoring routine
func (hm *HardeningManager) startServiceMonitoring() {
	ticker := time.NewTicker(15 * time.Minute) // Check every 15 minutes
	defer ticker.Stop()

	for range ticker.C {
		// Disable services that haven't been used in the last 30 minutes
		hm.DisableUnusedServices(30 * time.Minute)

		// Re-harden critical tier services
		hm.HardenCriticalTier()

		// Perform classification-based hardening
		hm.performClassificationBasedHardening()
	}
}

// performClassificationBasedHardening adjusts hardening based on classification results
func (hm *HardeningManager) performClassificationBasedHardening() {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	// Get current classification results (in a real system, this would come from the classifier)
	// For now, we'll simulate some classification results
	classificationResults := hm.simulateClassificationResults()

	for serviceKey, classification := range classificationResults {
		service, exists := hm.services[serviceKey]
		if !exists {
			continue
		}

		// Adjust hardening based on classification
		switch classification {
		case "high-risk":
			service.Tier = Critical
			hm.enforceCriticalTierPolicy(service.Address, service.Port)
		case "medium-risk":
			service.Tier = Standard
		case "low-risk":
			service.Tier = Standard // Still Standard but with relaxed rules
		}
	}
}

// simulateClassificationResults simulates getting classification results
func (hm *HardeningManager) simulateClassificationResults() map[string]string {
	// In a real implementation, this would get actual classification results
	// For now, we'll return some simulated results
	results := make(map[string]string)

	for key, service := range hm.services {
		if strings.Contains(service.Name, "critical") || service.Tier == Critical {
			results[key] = "high-risk"
		} else if strings.Contains(service.Name, "admin") {
			results[key] = "medium-risk"
		} else {
			results[key] = "low-risk"
		}
	}

	return results
}

// ApplyHardeningMiddleware applies hardening checks to incoming requests
func (hm *HardeningManager) ApplyHardeningMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mark the destination backend service as used based on request Host
		hostIP := r.Host
		port := getPortFromRequest(r)

		hm.MarkServiceUsed(hostIP, port)
		clientIP := getClientIP(r)

		// Check if access should be restricted based on hardening policies
		if !hm.isAccessPermitted(clientIP, r.URL.Path) {
			log.Printf("Access denied by hardening policy: %s -> %s", clientIP, r.URL.Path)
			http.Error(w, "Access denied by security policy", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isAccessPermitted checks if access should be permitted based on hardening policies
func (hm *HardeningManager) isAccessPermitted(clientIP, path string) bool {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	// System Hardening: Enforce that the destination service is Active
	// We scan our registered services to see if the requested path maps to a disabled service
	for _, service := range hm.services {
		// Check if the path belongs to this service (simplified prefix match)
		if strings.HasPrefix(path, "/api/"+strings.ToLower(service.Name)) ||
			strings.HasPrefix(path, "/"+strings.ToLower(service.Name)) {

			if service.Status != Active {
				log.Printf("Blocking access to hardened/disabled service: %s", service.Name)
				return false
			}
		}
	}

	return true
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	return netutil.ClientIP(r)
}

// getPortFromRequest extracts the port from the request
func getPortFromRequest(r *http.Request) int {
	host := r.Host
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		portStr := host[colonIndex+1:]
		if p, err := strconv.Atoi(portStr); err == nil {
			return p
		}
	}

	if r.TLS != nil {
		return 443
	}
	return 80
}

// GetCriticalServicesCount returns the count of critical services
func (hm *HardeningManager) GetCriticalServicesCount() int {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	count := 0
	for _, service := range hm.services {
		if service.Tier == Critical && service.Status == Active {
			count++
		}
	}
	return count
}

// GetDisabledServicesCount returns the count of disabled services
func (hm *HardeningManager) GetDisabledServicesCount() int {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	count := 0
	for _, service := range hm.services {
		if service.Status == Disabled {
			count++
		}
	}
	return count
}

// GetActiveServicesCount returns the count of active services
func (hm *HardeningManager) GetActiveServicesCount() int {
	hm.mutex.RLock()
	defer hm.mutex.RUnlock()

	count := 0
	for _, service := range hm.services {
		if service.Status == Active {
			count++
		}
	}
	return count
}
