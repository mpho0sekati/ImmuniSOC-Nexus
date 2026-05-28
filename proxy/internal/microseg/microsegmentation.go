package microseg

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Segment represents a network segment with its own security policies
type Segment struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Policies    []Policy          `json:"policies"`
	Members     map[string]bool   `json:"members"` // IP addresses or service IDs
	CreatedAt   time.Time         `json:"created_at"`
	Tags        map[string]string `json:"tags"`
}

// Policy defines access control rules within a segment
type Policy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Action      string   `json:"action"`      // "allow", "deny", "redirect"
	Source      []string `json:"source"`      // Source IP ranges or service IDs
	Destination []string `json:"destination"` // Destination IP ranges or service IDs
	Protocol    []string `json:"protocol"`    // "tcp", "udp", "icmp", etc.
	Port        []int    `json:"port"`        // Port numbers
	Priority    int      `json:"priority"`    // Lower number means higher priority
	Enabled     bool     `json:"enabled"`
}

// MicrosegmentationManager manages network segments and their policies
type MicrosegmentationManager struct {
	segments map[string]*Segment
	mutex    sync.RWMutex
	logger   func(string)
}

// NewMicrosegmentationManager creates a new microsegmentation manager
func NewMicrosegmentationManager(logger func(string)) *MicrosegmentationManager {
	return &MicrosegmentationManager{
		segments: make(map[string]*Segment),
		logger:   logger,
	}
}

// CreateSegment creates a new network segment
func (m *MicrosegmentationManager) CreateSegment(name, description string, tags map[string]string) (*Segment, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if name == "" {
		return nil, fmt.Errorf("segment name cannot be empty")
	}

	// Check if segment with this name already exists
	for _, seg := range m.segments {
		if seg.Name == name {
			return nil, fmt.Errorf("segment with name '%s' already exists", name)
		}
	}

	id := uuid.New().String()
	segment := &Segment{
		ID:          id,
		Name:        name,
		Description: description,
		Policies:    []Policy{},
		Members:     make(map[string]bool),
		CreatedAt:   time.Now(),
		Tags:        tags,
	}

	m.segments[id] = segment

	if m.logger != nil {
		m.logger(fmt.Sprintf("Created microsegment: %s (%s)", name, id))
	}

	return segment, nil
}

// DeleteSegment removes a network segment
func (m *MicrosegmentationManager) DeleteSegment(id string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.segments[id]; !exists {
		return fmt.Errorf("segment with ID '%s' does not exist", id)
	}

	delete(m.segments, id)

	if m.logger != nil {
		m.logger(fmt.Sprintf("Deleted microsegment: %s", id))
	}

	return nil
}

// AddMember adds a member (IP/service) to a segment
func (m *MicrosegmentationManager) AddMember(segmentID, member string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	segment, exists := m.segments[segmentID]
	if !exists {
		return fmt.Errorf("segment with ID '%s' does not exist", segmentID)
	}

	if segment.Members == nil {
		segment.Members = make(map[string]bool)
	}

	segment.Members[member] = true

	if m.logger != nil {
		m.logger(fmt.Sprintf("Added member '%s' to segment '%s'", member, segment.Name))
	}

	return nil
}

// RemoveMember removes a member (IP/service) from a segment
func (m *MicrosegmentationManager) RemoveMember(segmentID, member string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	segment, exists := m.segments[segmentID]
	if !exists {
		return fmt.Errorf("segment with ID '%s' does not exist", segmentID)
	}

	delete(segment.Members, member)

	if m.logger != nil {
		m.logger(fmt.Sprintf("Removed member '%s' from segment '%s'", member, segment.Name))
	}

	return nil
}

// AddPolicy adds a policy to a segment
func (m *MicrosegmentationManager) AddPolicy(segmentID string, policy Policy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	segment, exists := m.segments[segmentID]
	if !exists {
		return fmt.Errorf("segment with ID '%s' does not exist", segmentID)
	}

	policy.ID = uuid.New().String()
	segment.Policies = append(segment.Policies, policy)

	// Sort policies by priority (lower number = higher priority)
	m.sortPolicies(segment)

	if m.logger != nil {
		m.logger(fmt.Sprintf("Added policy '%s' to segment '%s'", policy.Name, segment.Name))
	}

	return nil
}

// sortPolicies sorts policies by priority (lower number = higher priority)
func (m *MicrosegmentationManager) sortPolicies(segment *Segment) {
	for i := 0; i < len(segment.Policies)-1; i++ {
		for j := i + 1; j < len(segment.Policies); j++ {
			if segment.Policies[i].Priority > segment.Policies[j].Priority {
				segment.Policies[i], segment.Policies[j] = segment.Policies[j], segment.Policies[i]
			}
		}
	}
}

// IsAccessAllowed determines if access is allowed based on microsegmentation rules
func (m *MicrosegmentationManager) IsAccessAllowed(srcIP, dstIP, protocol string, port int) (bool, string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	srcSegment := m.getSegmentByIP(srcIP)
	dstSegment := m.getSegmentByIP(dstIP)

	// First, check if there are any global policies that apply
	globalPolicies := m.getAllPolicies()
	for _, policy := range globalPolicies {
		if !policy.Enabled {
			continue
		}

		if m.matchesPolicy(policy, srcIP, dstIP, protocol, port) {
			return policy.Action == "allow", fmt.Sprintf("global policy '%s': %s", policy.Name, policy.Action), nil
		}
	}

	// If both IPs are in segments, enforce segmentation rules
	if srcSegment != nil && dstSegment != nil {
		// Check cross-segment policies first
		for _, policy := range srcSegment.Policies {
			if !policy.Enabled {
				continue
			}

			if m.matchesPolicy(policy, srcIP, dstIP, protocol, port) {
				return policy.Action == "allow", fmt.Sprintf("source segment policy '%s': %s", policy.Name, policy.Action), nil
			}
		}

		// Check destination segment policies
		for _, policy := range dstSegment.Policies {
			if !policy.Enabled {
				continue
			}

			if m.matchesPolicy(policy, srcIP, dstIP, protocol, port) {
				return policy.Action == "allow", fmt.Sprintf("destination segment policy '%s': %s", policy.Name, policy.Action), nil
			}
		}

		// Default deny behavior within segments
		return false, "default deny - no matching policy within segments", nil
	}

	// If only source IP is in a segment, apply source segment policies
	if srcSegment != nil && dstSegment == nil {
		for _, policy := range srcSegment.Policies {
			if !policy.Enabled {
				continue
			}

			if m.matchesPolicy(policy, srcIP, dstIP, protocol, port) {
				return policy.Action == "allow", fmt.Sprintf("source segment policy '%s': %s", policy.Name, policy.Action), nil
			}
		}

		// Default deny for segmented sources accessing non-segmented destinations
		return false, "default deny - segmented source accessing non-segmented destination", nil
	}

	// If only destination IP is in a segment, apply destination segment policies
	if srcSegment == nil && dstSegment != nil {
		for _, policy := range dstSegment.Policies {
			if !policy.Enabled {
				continue
			}

			if m.matchesPolicy(policy, srcIP, dstIP, protocol, port) {
				return policy.Action == "allow", fmt.Sprintf("destination segment policy '%s': %s", policy.Name, policy.Action), nil
			}
		}

		// Default deny for non-segmented sources accessing segmented destinations
		return false, "default deny - non-segmented source accessing segmented destination", nil
	}

	// Both IPs are not in segments - apply default policy
	// For security, we implement default deny for unsegmented traffic
	// unless explicitly allowed by a global policy (checked above)
	return false, "default deny - both IPs not in segments", nil
}

// getAllPolicies gets all policies from all segments
func (m *MicrosegmentationManager) getAllPolicies() []Policy {
	var allPolicies []Policy

	for _, segment := range m.segments {
		allPolicies = append(allPolicies, segment.Policies...)
	}

	// Sort by priority
	for i := 0; i < len(allPolicies)-1; i++ {
		for j := i + 1; j < len(allPolicies); j++ {
			if allPolicies[i].Priority > allPolicies[j].Priority {
				allPolicies[i], allPolicies[j] = allPolicies[j], allPolicies[i]
			}
		}
	}

	return allPolicies
}

// matchesPolicy checks if a request matches a policy
func (m *MicrosegmentationManager) matchesPolicy(policy Policy, srcIP, dstIP, protocol string, port int) bool {
	// Check source match
	sourceMatch := false
	for _, src := range policy.Source {
		if src == "*" || src == srcIP || m.ipInCIDR(srcIP, src) {
			sourceMatch = true
			break
		}
	}

	if !sourceMatch {
		return false
	}

	// Check destination match
	destMatch := false
	for _, dest := range policy.Destination {
		if dest == "*" || dest == dstIP || m.ipInCIDR(dstIP, dest) {
			destMatch = true
			break
		}
	}

	if !destMatch {
		return false
	}

	// Check protocol match
	protocolMatch := false
	for _, prot := range policy.Protocol {
		if prot == "*" || strings.EqualFold(prot, protocol) {
			protocolMatch = true
			break
		}
	}

	if !protocolMatch {
		return false
	}

	// Check port match
	portMatch := false
	for _, p := range policy.Port {
		if p == 0 || p == port { // 0 means all ports
			portMatch = true
			break
		}
	}

	return portMatch
}

// ipInCIDR checks if an IP is within a CIDR range
func (m *MicrosegmentationManager) ipInCIDR(ip, cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// If it's not a CIDR, maybe it's a single IP
		return ip == cidr
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return ipNet.Contains(parsedIP)
}

// getSegmentByIP finds the segment that contains a given IP
func (m *MicrosegmentationManager) getSegmentByIP(ip string) *Segment {
	for _, segment := range m.segments {
		if segment.Members[ip] {
			return segment
		}
	}
	return nil
}

// GetSegment retrieves a segment by ID
func (m *MicrosegmentationManager) GetSegment(id string) (*Segment, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	segment, exists := m.segments[id]
	return segment, exists
}

// GetAllSegments returns all segments managed by the microsegmentation manager
func (m *MicrosegmentationManager) GetAllSegments() []*Segment {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	segments := make([]*Segment, 0, len(m.segments))
	for _, segment := range m.segments {
		segments = append(segments, segment)
	}
	return segments
}

// GetTotalPolicies returns the total number of policies across all segments
func (m *MicrosegmentationManager) GetTotalPolicies() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	total := 0
	for _, segment := range m.segments {
		total += len(segment.Policies)
	}
	return total
}

// ListSegments returns all segments
func (m *MicrosegmentationManager) ListSegments() []*Segment {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	segments := make([]*Segment, 0, len(m.segments))
	for _, segment := range m.segments {
		segments = append(segments, segment)
	}
	return segments
}

// MicrosegmentationMiddleware provides HTTP middleware for microsegmentation
func (m *MicrosegmentationManager) MicrosegmentationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		hostIP := r.Host

		// For simplicity, extract port from host if present
		hostParts := strings.Split(hostIP, ":")
		hostWithoutPort := hostParts[0]
		port := 80 // Default HTTP port
		if len(hostParts) > 1 {
			if p, err := strconv.Atoi(hostParts[1]); err == nil {
				port = p
			}
		}

		// Determine if access is allowed based on microsegmentation
		allowed, reason, err := m.IsAccessAllowed(clientIP, hostWithoutPort, "tcp", port)
		if err != nil {
			// Log the error but don't necessarily block the request
			if m.logger != nil {
				m.logger(fmt.Sprintf("Microsegmentation error: %v", err))
			}
		}

		if !allowed {
			if m.logger != nil {
				m.logger(fmt.Sprintf("Access denied by microsegmentation: %s -> %s (%s)", clientIP, hostWithoutPort, reason))
			}
			http.Error(w, "Access denied by microsegmentation policy", http.StatusForbidden)
			return
		}

		// Add segment information to request context
		ctx := context.WithValue(r.Context(), "segment", reason)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ip := strings.Split(forwarded, ",")[0]
		return strings.TrimSpace(ip)
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Use RemoteAddr as fallback
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
