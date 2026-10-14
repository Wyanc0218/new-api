package model

import (
	"errors"
	"slices"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// A receipt proves a scoped relay completed. The desktop must independently
// attest the observed child process; a receipt alone never proves tool identity.
type LinkToolVerification struct {
	ID                 string `json:"id" gorm:"type:varchar(36);primaryKey"`
	UserID             int    `json:"-" gorm:"not null;index"`
	DeviceID           string `json:"-" gorm:"type:varchar(36);not null"`
	SessionID          string `json:"-" gorm:"type:varchar(36);not null"`
	ConnectionID       string `json:"connection_id" gorm:"type:varchar(36);not null;index"`
	ConnectionRevision int64  `json:"connection_revision"`
	TokenID            int    `json:"token_id"`
	Target             string `json:"target" gorm:"type:varchar(32);not null"`
	Model              string `json:"model" gorm:"column:model_name;type:varchar(255);not null"`
	Protocol           string `json:"protocol" gorm:"type:varchar(32);not null"`
	ChallengeHash      string `json:"-" gorm:"type:char(64);not null;uniqueIndex"`
	Status             string `json:"status" gorm:"type:varchar(16);not null"`
	RequestID          string `json:"request_id,omitempty" gorm:"type:varchar(64)"`
	CreatedAt          int64  `json:"created_at"`
	ExpiresAt          int64  `json:"expires_at" gorm:"index"`
	ObservedAt         int64  `json:"observed_at,omitempty"`
}

type LinkToolVerificationRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Target           string `json:"target"`
	Model            string `json:"model"`
	Protocol         string `json:"protocol"`
}

type LinkToolChallenge struct {
	*LinkToolVerification
	Challenge string `json:"challenge"`
}

var ErrLinkVerification = LinkFailure(409, "LINK_VERIFICATION_REJECTED", "Tool verification is expired, already used or does not match the active connection")

func CreateLinkToolVerification(session *LinkSession, connectionID string, r LinkToolVerificationRequest) (*LinkToolChallenge, error) {
	family := ""
	switch {
	case r.Target == "codex-cli" && r.Protocol == "openai_responses":
		family = "codex"
	case r.Target == "claude-code" && r.Protocol == "anthropic_messages":
		family = "claude_code"
	case r.Target == "hermes" && r.Protocol == "openai_chat_completions":
		family = "hermes"
	default:
		return nil, LinkFailure(400, "LINK_INVALID_REQUEST", "Unsupported verification target or protocol")
	}
	if session == nil || len(r.Model) == 0 || len(r.Model) > 255 || r.ExpectedRevision < 1 {
		return nil, LinkFailure(400, "LINK_INVALID_REQUEST", "Invalid verification request")
	}
	secret, err := LinkRandomSecret("link_v_")
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	verification := LinkToolVerification{ID: uuid.NewString(), UserID: session.UserID, DeviceID: session.DeviceID, SessionID: session.ID, ConnectionID: connectionID, ConnectionRevision: r.ExpectedRevision, Target: r.Target, Model: r.Model, Protocol: r.Protocol, ChallengeHash: linkHash("verification", secret), Status: "pending", CreatedAt: now, ExpiresAt: now + 180}
	err = DB.Transaction(func(tx *gorm.DB) error {
		claim := tx.Model(&User{}).Where("id = ? AND auth_version = ? AND status = ?", session.UserID, session.AuthVersion, common.UserStatusEnabled).UpdateColumn("auth_version", gorm.Expr("auth_version"))
		if claim.Error != nil {
			return claim.Error
		}
		var live LinkSession
		if err := tx.Where("id = ? AND access_hash = ? AND revoked_at = 0 AND expires_at > ? AND access_expires_at > ?", session.ID, session.AccessHash, now, now).First(&live).Error; err != nil {
			return ErrLinkUnauthorized
		}
		var user User
		if err := tx.Where("id = ? AND auth_version = ? AND status = ?", session.UserID, session.AuthVersion, common.UserStatusEnabled).First(&user).Error; err != nil {
			return ErrLinkUnauthorized
		}
		var connection LinkConnection
		if err := lockForUpdate(tx).Where("id = ? AND user_id = ? AND device_id = ?", connectionID, session.UserID, session.DeviceID).First(&connection).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrLinkNotFound
			}
			return err
		}
		if connection.Revision != r.ExpectedRevision || connection.ToolFamily != family || connection.Status != "active" || connection.CandidateTokenID != 0 {
			return ErrLinkState
		}
		_, key, err := validateLinkKey(tx, &connection, connection.ActiveTokenID, true, true)
		if err != nil {
			return err
		}
		var selected []string
		if err := common.UnmarshalJsonStr(key.Models, &selected); err != nil {
			return err
		}
		if !slices.Contains(selected, r.Model) {
			return ErrLinkVerification
		}
		// One live attempt per connection. Starting another invalidates an abandoned one.
		if err := tx.Model(&LinkToolVerification{}).Where("connection_id = ? AND status = ?", connectionID, "pending").Update("status", "failed").Error; err != nil {
			return err
		}
		verification.TokenID = connection.ActiveTokenID
		return tx.Create(&verification).Error
	})
	if err != nil {
		return nil, err
	}
	return &LinkToolChallenge{&verification, secret}, nil
}

// Claim is atomic and happens before inference, including retries inside that
// same gateway request. Replaying a header in a second request is rejected.
func ClaimLinkToolVerification(challenge string, userID, tokenID int, modelID, protocol, requestID string) (string, error) {
	if len(challenge) != 50 || len(requestID) == 0 || len(requestID) > 64 {
		return "", ErrLinkVerification
	}
	var verification LinkToolVerification
	err := DB.Transaction(func(tx *gorm.DB) error {
		// Follow the same account -> connection lock order as connection mutations.
		claim := tx.Model(&User{}).Where("id = ? AND status = ?", userID, common.UserStatusEnabled).UpdateColumn("auth_version", gorm.Expr("auth_version"))
		if claim.Error != nil {
			return claim.Error
		}
		if err := tx.Where("challenge_hash = ? AND user_id = ? AND token_id = ? AND model_name = ? AND protocol = ? AND status = ? AND request_id = ? AND expires_at > ?", linkHash("verification", challenge), userID, tokenID, modelID, protocol, "pending", "", time.Now().Unix()).First(&verification).Error; err != nil {
			return ErrLinkVerification
		}
		var session LinkSession
		if err := tx.Where("id = ? AND revoked_at = 0 AND expires_at > ?", verification.SessionID, time.Now().Unix()).First(&session).Error; err != nil {
			return ErrLinkVerification
		}
		var user User
		if err := tx.Where("id = ? AND auth_version = ? AND status = ?", userID, session.AuthVersion, common.UserStatusEnabled).First(&user).Error; err != nil {
			return ErrLinkVerification
		}
		var connection LinkConnection
		if err := lockForUpdate(tx).Where("id = ? AND user_id = ? AND device_id = ? AND revision = ? AND active_token_id = ? AND status = ? AND candidate_token_id = 0", verification.ConnectionID, userID, verification.DeviceID, verification.ConnectionRevision, tokenID, "active").First(&connection).Error; err != nil {
			return ErrLinkVerification
		}
		if _, _, err := validateLinkKey(tx, &connection, tokenID, true, true); err != nil {
			return ErrLinkVerification
		}
		result := tx.Model(&LinkToolVerification{}).Where("id = ? AND status = ? AND request_id = ? AND expires_at > ?", verification.ID, "pending", "", time.Now().Unix()).Update("request_id", requestID)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrLinkVerification
		}
		return nil
	})
	return verification.ID, err
}

func FinishLinkToolVerification(id, requestID string, success bool) error {
	status := "failed"
	if success {
		status = "succeeded"
	}
	return DB.Model(&LinkToolVerification{}).Where("id = ? AND request_id = ? AND status = ? AND expires_at > ?", id, requestID, "pending", time.Now().Unix()).Updates(map[string]any{"status": status, "observed_at": time.Now().Unix()}).Error
}

func GetLinkToolVerification(session *LinkSession, id string) (*LinkToolVerification, error) {
	var verification LinkToolVerification
	if err := DB.Where("id = ? AND user_id = ? AND device_id = ?", id, session.UserID, session.DeviceID).First(&verification).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLinkNotFound
		}
		return nil, err
	}
	var connection LinkConnection
	if err := DB.Where("id = ? AND revision = ? AND active_token_id = ? AND status = ? AND candidate_token_id = 0", verification.ConnectionID, verification.ConnectionRevision, verification.TokenID, "active").First(&connection).Error; err != nil {
		verification.Status = "failed"
	}
	if verification.ExpiresAt <= time.Now().Unix() && verification.Status == "pending" {
		verification.Status = "expired"
	}
	return &verification, nil
}

func DeleteExpiredLinkToolVerifications(now int64) error {
	return DB.Where("expires_at < ?", now-86400).Delete(&LinkToolVerification{}).Error
}
