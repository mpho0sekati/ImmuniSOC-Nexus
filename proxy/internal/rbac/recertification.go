package rbac

import (
	"fmt"
	"sync"
	"time"
)

// AccessCertification represents a certification cycle for a user's access
type AccessCertification struct {
	ID          string
	UserID      string
	Role        UserRole
	RequestedBy string
	ManagerID   string
	CreatedAt   time.Time
	DueDate     time.Time
	Status      CertificationStatus
	Notes       string
}

// CertificationStatus represents the status of an access certification
type CertificationStatus int

const (
	Pending CertificationStatus = iota
	Approved
	Rejected
	Expired
)

// RecertificationManager manages the periodic access recertification process
type RecertificationManager struct {
	certifications map[string]*AccessCertification
	sync.RWMutex
}

// NewRecertificationManager creates a new recertification manager
func NewRecertificationManager() *RecertificationManager {
	return &RecertificationManager{
		certifications: make(map[string]*AccessCertification),
	}
}

// ScheduleCertification schedules a new access certification for a user
func (rc *RecertificationManager) ScheduleCertification(userID string, role UserRole, managerID string, cycleDays int) (string, error) {
	rc.Lock()
	defer rc.Unlock()

	certID := generateCertificationID()
	
	certification := &AccessCertification{
		ID:          certID,
		UserID:      userID,
		Role:        role,
		RequestedBy: userID,
		ManagerID:   managerID,
		CreatedAt:   time.Now(),
		DueDate:     time.Now().AddDate(0, 0, cycleDays),
		Status:      Pending,
	}

	rc.certifications[certID] = certification

	return certID, nil
}

// ApproveCertification approves an access certification
func (rc *RecertificationManager) ApproveCertification(certID, approverID string, notes string) error {
	rc.Lock()
	defer rc.Unlock()

	cert, exists := rc.certifications[certID]
	if !exists {
		return fmt.Errorf("certification not found: %s", certID)
	}

	if cert.Status != Pending {
		return fmt.Errorf("certification is not in pending state: %v", cert.Status)
	}

	cert.Status = Approved
	cert.Notes = notes

	return nil
}

// RejectCertification rejects an access certification
func (rc *RecertificationManager) RejectCertification(certID, approverID string, notes string) error {
	rc.Lock()
	defer rc.Unlock()

	cert, exists := rc.certifications[certID]
	if !exists {
		return fmt.Errorf("certification not found: %s", certID)
	}

	if cert.Status != Pending {
		return fmt.Errorf("certification is not in pending state: %v", cert.Status)
	}

	cert.Status = Rejected
	cert.Notes = notes

	return nil
}

// GetPendingCertifications returns all pending certifications for a manager
func (rc *RecertificationManager) GetPendingCertifications(managerID string) []*AccessCertification {
	rc.RLock()
	defer rc.RUnlock()

	var pending []*AccessCertification
	for _, cert := range rc.certifications {
		if cert.ManagerID == managerID && cert.Status == Pending && time.Now().Before(cert.DueDate) {
			pending = append(pending, cert)
		}
	}

	return pending
}

// GetOverdueCertifications returns all overdue certifications that need attention
func (rc *RecertificationManager) GetOverdueCertifications() []*AccessCertification {
	rc.RLock()
	defer rc.RUnlock()

	var overdue []*AccessCertification
	now := time.Now()
	for _, cert := range rc.certifications {
		if cert.Status == Pending && now.After(cert.DueDate) {
			overdue = append(overdue, cert)
			cert.Status = Expired
		}
	}

	return overdue
}

// CleanupExpiredCertifications removes expired certifications
func (rc *RecertificationManager) CleanupExpiredCertifications() {
	rc.Lock()
	defer rc.Unlock()

	now := time.Now()
	for id, cert := range rc.certifications {
		if now.After(cert.DueDate) && cert.Status == Pending {
			rc.certifications[id].Status = Expired
		}
	}
}

// StartCertificationReminders starts a background routine to remind managers about upcoming certifications
func (rc *RecertificationManager) StartCertificationReminders() {
	ticker := time.NewTicker(24 * time.Hour) // Daily check
	go func() {
		for range ticker.C {
			rc.processCertificationReminders()
		}
	}()
}

// processCertificationReminders sends reminders for upcoming certifications
func (rc *RecertificationManager) processCertificationReminders() {
	rc.RLock()
	defer rc.RUnlock()

	now := time.Now()
	reminderThreshold := now.AddDate(0, 0, 7) // 7 days ahead

	for _, cert := range rc.certifications {
		if cert.Status == Pending && 
		   now.Before(cert.DueDate) && 
		   cert.DueDate.Before(reminderThreshold) {
			// In a real system, this would send a notification to the manager
			// For now, we'll just log it
			fmt.Printf("REMINDER: Access certification for user %s due on %s. Manager: %s\n", 
				cert.UserID, cert.DueDate.Format("2006-01-02"), cert.ManagerID)
		}
	}
}

// Helper function to generate certification IDs
func generateCertificationID() string {
	return fmt.Sprintf("cert_%d", time.Now().UnixNano())
}