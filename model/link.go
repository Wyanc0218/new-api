package model

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Link sessions are deliberately separate from dashboard sessions and relay tokens.
type LinkSession struct {
	ID                  string `json:"session_id" gorm:"type:varchar(36);primaryKey"`
	UserID              int    `json:"-" gorm:"not null;index"`
	DeviceID            string `json:"device_id" gorm:"type:varchar(36);not null;index"`
	AuthVersion         int64  `json:"-" gorm:"not null"`
	AccessHash          string `json:"-" gorm:"type:char(64);not null;uniqueIndex"`
	RefreshHash         string `json:"-" gorm:"type:char(64);not null;uniqueIndex"`
	PreviousRefreshHash string `json:"-" gorm:"type:char(64)"`
	AccessExpiresAt     int64  `json:"access_expires_at"`
	ExpiresAt           int64  `json:"expires_at"`
	RevokedAt           int64  `json:"-"`
	CreatedAt           int64  `json:"-"`
}

// Retain only one-way hashes of spent refresh credentials for the family lifetime.
// Reuse after several rotations must revoke the family, not just the latest predecessor.
type LinkRefreshUse struct {
	Hash      string `gorm:"type:char(64);primaryKey"`
	SessionID string `gorm:"type:varchar(36);not null;index"`
	UserID    int    `gorm:"not null;index"`
	ExpiresAt int64  `gorm:"not null;index"`
}

type LinkConnection struct {
	ID               string `json:"id" gorm:"type:varchar(36);primaryKey"`
	ScopeHash        string `json:"-" gorm:"type:char(64);not null;uniqueIndex"`
	UserID           int    `json:"-" gorm:"not null;index"`
	DeviceID         string `json:"-" gorm:"type:varchar(36);not null;index"`
	ToolFamily       string `json:"tool_family" gorm:"type:varchar(32);not null"`
	ConfigScope      string `json:"config_scope" gorm:"type:varchar(128);not null"`
	Status           string `json:"status" gorm:"type:varchar(20);not null"`
	Revision         int64  `json:"revision" gorm:"not null"`
	ActiveTokenID    int    `json:"-"`
	CandidateTokenID int    `json:"-"`
	CreatedAt        int64  `json:"-"`
	UpdatedAt        int64  `json:"-"`
}

type LinkKey struct {
	TokenID      int    `json:"token_id" gorm:"primaryKey;autoIncrement:false"`
	ConnectionID string `json:"-" gorm:"type:varchar(36);not null;index"`
	UserID       int    `json:"-" gorm:"not null;index"`
	Group        string `json:"group" gorm:"column:price_group;type:varchar(64);not null"`
	Models       string `json:"-" gorm:"type:text;not null"`
	DefaultModel string `json:"default_model" gorm:"type:varchar(255);not null"`
	Status       string `json:"-" gorm:"type:varchar(20);not null"`
}

type LinkOperation struct {
	ID           string `json:"-" gorm:"type:char(64);primaryKey"`
	OperationID  string `json:"operation_id" gorm:"type:varchar(36);not null"`
	UserID       int    `json:"-" gorm:"not null;index"`
	DeviceID     string `json:"-" gorm:"type:varchar(36);not null;index"`
	RequestHash  string `json:"-" gorm:"type:char(64);not null"`
	ConnectionID string `json:"connection_id" gorm:"type:varchar(36);not null"`
	Action       string `json:"action" gorm:"type:varchar(32);not null"`
	TokenID      int    `json:"token_id,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

type LinkError struct {
	Code    string
	Status  int
	Message string
}

func (e *LinkError) Error() string { return e.Message }
func LinkFailure(status int, code, message string) error {
	return &LinkError{Code: code, Status: status, Message: message}
}

var (
	ErrLinkUnauthorized = LinkFailure(http.StatusUnauthorized, "LINK_UNAUTHORIZED", "Client session is invalid or expired")
	ErrLinkNotFound     = LinkFailure(http.StatusNotFound, "LINK_NOT_FOUND", "Client record not found")
	ErrLinkState        = LinkFailure(http.StatusConflict, "LINK_STATE_CONFLICT", "Connection state does not permit this action")
	ErrLinkToken        = LinkFailure(http.StatusConflict, "LINK_TOKEN_UNAVAILABLE", "The platform key is deleted, restricted, expired or unavailable")
)

func linkHash(purpose, raw string) string {
	mac := hmac.New(sha256.New, []byte(common.SessionSecret))
	_, _ = mac.Write([]byte("link/v1/" + purpose + ":" + raw))
	return hex.EncodeToString(mac.Sum(nil))
}
func linkStableHash(purpose, raw string) string {
	sum := sha256.Sum256([]byte("link/v1/" + purpose + ":" + raw))
	return hex.EncodeToString(sum[:])
}
func IsLinkCredential(raw string) bool {
	return strings.HasPrefix(raw, "link_a_") || strings.HasPrefix(raw, "link_r_")
}
func LinkRandomSecret(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func linkCredentials(session *LinkSession) (string, string, error) {
	access, err := LinkRandomSecret("link_a_")
	if err != nil {
		return "", "", err
	}
	refresh, err := LinkRandomSecret("link_r_")
	if err != nil {
		return "", "", err
	}
	session.AccessHash = linkHash("access", access)
	session.RefreshHash = linkHash("refresh", refresh)
	session.AccessExpiresAt = time.Now().Add(15 * time.Minute).Unix()
	return access, refresh, nil
}

type LinkAuthPayload struct {
	DeviceID       string `json:"device_id"`
	CodeChallenge  string `json:"code_challenge"`
	RedirectURI    string `json:"redirect_uri"`
	State          string `json:"state"`
	AuthVersion    int64  `json:"auth_version,omitempty"`
	SessionVersion int64  `json:"session_version,omitempty"`
}

type LinkAuthBundle struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	AccessExpiresAt int64  `json:"access_expires_at"`
	ExpiresAt       int64  `json:"expires_at"`
	SessionID       string `json:"session_id"`
	DeviceID        string `json:"device_id"`
}

func linkBundle(s *LinkSession, a, r string) *LinkAuthBundle {
	return &LinkAuthBundle{a, r, s.AccessExpiresAt, s.ExpiresAt, s.ID, s.DeviceID}
}

func CompleteLinkAuthorization(flowToken string, identity AuthSessionIdentity) (string, *LinkAuthPayload, error) {
	// Native step-up identities now include scoped PATs; desktop approval stays browser-only.
	if _, pat := ParseAccessTokenSessionID(identity.SessionID); pat {
		return "", nil, ErrLinkUnauthorized
	}
	var code string
	var payload LinkAuthPayload
	_, err := ConsumeAuthFlowWithAction(flowToken, AuthFlowMatch{Purpose: "link_start"}, func(tx *gorm.DB, flow *AuthFlow) error {
		if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
			return ErrLinkUnauthorized
		}
		if err := common.UnmarshalJsonStr(flow.Payload, &payload); err != nil {
			return err
		}
		payload.AuthVersion = identity.UserAuthVersion
		payload.SessionVersion = identity.SessionVersion
		data, err := common.Marshal(payload)
		if err != nil {
			return err
		}
		code, _, err = createAuthFlowWithTx(tx, AuthFlowCreate{Purpose: "link_code", UserId: identity.UserID, SessionId: identity.SessionID, Payload: string(data), ExpiresAt: time.Now().Add(time.Minute)})
		return err
	})
	return code, &payload, err
}

func ExchangeLinkAuthorization(code, verifier, redirectURI, deviceID string) (*LinkAuthBundle, int, error) {
	var bundle *LinkAuthBundle
	var userID int
	_, err := ConsumeAuthFlowWithAction(code, AuthFlowMatch{Purpose: "link_code"}, func(tx *gorm.DB, flow *AuthFlow) error {
		var payload LinkAuthPayload
		if err := common.UnmarshalJsonStr(flow.Payload, &payload); err != nil {
			return err
		}
		challenge := sha256.Sum256([]byte(verifier))
		got := base64.RawURLEncoding.EncodeToString(challenge[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(payload.CodeChallenge)) != 1 || payload.RedirectURI != redirectURI || payload.DeviceID != deviceID {
			return ErrLinkUnauthorized
		}
		var browser UserSession
		if err := tx.Where("sid = ? AND user_id = ?", flow.SessionId, flow.UserId).First(&browser).Error; err != nil {
			return ErrLinkUnauthorized
		}
		identity := AuthSessionIdentity{UserID: flow.UserId, SessionID: flow.SessionId, UserAuthVersion: payload.AuthVersion, SessionVersion: payload.SessionVersion}
		if err := ValidateAuthSessionWithTx(tx, identity); err != nil {
			return ErrLinkUnauthorized
		}
		now := time.Now().Unix()
		var count int64
		if err := tx.Model(&LinkSession{}).Where("user_id = ? AND revoked_at = 0 AND expires_at > ?", flow.UserId, now).Count(&count).Error; err != nil {
			return err
		}
		if count >= 20 {
			return LinkFailure(409, "LINK_SESSION_LIMIT", "Too many active client sessions")
		}
		session := LinkSession{ID: uuid.NewString(), UserID: flow.UserId, DeviceID: deviceID, AuthVersion: payload.AuthVersion, ExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(), CreatedAt: now}
		a, r, err := linkCredentials(&session)
		if err != nil {
			return err
		}
		if err = tx.Create(&session).Error; err != nil {
			return err
		}
		userID = flow.UserId
		bundle = linkBundle(&session, a, r)
		return nil
	})
	return bundle, userID, err
}

func ValidateLinkSession(raw string) (*LinkSession, error) {
	if !strings.HasPrefix(raw, "link_a_") || len(raw) > 128 {
		return nil, ErrLinkUnauthorized
	}
	var session LinkSession
	if err := DB.Where("access_hash = ?", linkHash("access", raw)).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLinkUnauthorized
		}
		return nil, err
	}
	if session.RevokedAt != 0 || session.ExpiresAt <= time.Now().Unix() || session.AccessExpiresAt <= time.Now().Unix() {
		return nil, ErrLinkUnauthorized
	}
	var user User
	if err := DB.Select("id", "status", "auth_version").First(&user, session.UserID).Error; err != nil {
		return nil, ErrLinkUnauthorized
	}
	if user.Status != common.UserStatusEnabled || user.AuthVersion != session.AuthVersion {
		return nil, ErrLinkUnauthorized
	}
	return &session, nil
}

func RefreshLinkSession(raw string) (*LinkAuthBundle, int, error) {
	if !strings.HasPrefix(raw, "link_r_") || len(raw) > 128 {
		return nil, 0, ErrLinkUnauthorized
	}
	hash := linkHash("refresh", raw)
	var bundle *LinkAuthBundle
	var uid int
	err := DB.Transaction(func(tx *gorm.DB) error {
		// First claim is a write, including on SQLite. A used refresh secret cannot win twice.
		now := time.Now().Unix()
		res := tx.Model(&LinkSession{}).Where("refresh_hash = ? AND revoked_at = 0 AND expires_at > ?", hash, now).UpdateColumn("access_expires_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrLinkUnauthorized
		}
		var s LinkSession
		if err := tx.Where("refresh_hash = ?", hash).First(&s).Error; err != nil {
			return err
		}
		var user User
		if err := tx.Select("id", "status", "auth_version").First(&user, s.UserID).Error; err != nil {
			return ErrLinkUnauthorized
		}
		if user.Status != common.UserStatusEnabled || user.AuthVersion != s.AuthVersion {
			return ErrLinkUnauthorized
		}
		s.PreviousRefreshHash = hash
		if err := tx.Create(&LinkRefreshUse{Hash: hash, SessionID: s.ID, UserID: s.UserID, ExpiresAt: s.ExpiresAt}).Error; err != nil {
			return err
		}
		a, r, err := linkCredentials(&s)
		if err != nil {
			return err
		}
		if err = tx.Save(&s).Error; err != nil {
			return err
		}
		bundle = linkBundle(&s, a, r)
		uid = s.UserID
		return nil
	})
	if errors.Is(err, ErrLinkUnauthorized) {
		var used LinkRefreshUse
		lookup := DB.Where("hash = ? AND expires_at > ?", hash, time.Now().Unix()).First(&used).Error
		if lookup == nil {
			if revokeErr := DB.Model(&LinkSession{}).Where("id = ? AND revoked_at = 0", used.SessionID).Update("revoked_at", time.Now().Unix()).Error; revokeErr != nil {
				return nil, 0, revokeErr
			}
		} else if !errors.Is(lookup, gorm.ErrRecordNotFound) {
			return nil, 0, lookup
		}
	}
	return bundle, uid, err
}
func LogoutLinkSession(session *LinkSession) error {
	return DB.Model(&LinkSession{}).Where("id = ? AND user_id = ?", session.ID, session.UserID).Update("revoked_at", time.Now().Unix()).Error
}

func DeleteExpiredLinkSessions(now int64) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("expires_at <= ?", now).Delete(&LinkRefreshUse{}).Error; err != nil {
			return err
		}
		return tx.Where("expires_at <= ?", now).Delete(&LinkSession{}).Error
	})
}

// LinkActionRequest is also the canonical idempotency input. Callers may not overwrite quota/group fields on existing keys.
type LinkActionRequest struct {
	OperationID      string   `json:"operation_id"`
	Action           string   `json:"action,omitempty"`
	ExpectedRevision int64    `json:"expected_revision,omitempty"`
	ToolFamily       string   `json:"tool_family,omitempty"`
	ConfigScope      string   `json:"config_scope,omitempty"`
	Group            string   `json:"group,omitempty"`
	Models           []string `json:"models,omitempty"`
	DefaultModel     string   `json:"default_model,omitempty"`
	CatalogRevision  string   `json:"catalog_revision,omitempty"`
}

type LinkKeyView struct {
	TokenID            int      `json:"token_id"`
	Group              string   `json:"group"`
	Models             []string `json:"models"`
	DefaultModel       string   `json:"default_model"`
	TokenStatus        int      `json:"token_status"`
	ExpiredTime        int64    `json:"expired_time"`
	UnlimitedQuota     bool     `json:"unlimited_quota"`
	RemainQuota        int      `json:"remain_quota"`
	ModelLimitsEnabled bool     `json:"model_limits_enabled"`
	ModelLimits        string   `json:"model_limits"`
	Missing            bool     `json:"missing"`
}
type LinkConnectionView struct {
	LinkConnection
	Active    *LinkKeyView `json:"active"`
	Candidate *LinkKeyView `json:"candidate"`
}
type LinkOperationResult struct {
	OperationID string              `json:"operation_id"`
	Connection  *LinkConnectionView `json:"connection"`
	TokenID     int                 `json:"token_id,omitempty"`
	APIKey      string              `json:"api_key,omitempty"`
}

func linkKeyView(tx *gorm.DB, conn *LinkConnection, id int) (*LinkKeyView, error) {
	if id == 0 {
		return nil, nil
	}
	var key LinkKey
	if err := tx.Where("token_id = ? AND connection_id = ? AND user_id = ?", id, conn.ID, conn.UserID).First(&key).Error; err != nil {
		return nil, err
	}
	v := &LinkKeyView{TokenID: id, Group: key.Group, DefaultModel: key.DefaultModel, Models: []string{}}
	if err := common.UnmarshalJsonStr(key.Models, &v.Models); err != nil {
		return nil, err
	}
	var token Token
	err := tx.Where("id = ? AND user_id = ?", id, conn.UserID).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		v.Missing = true
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	v.TokenStatus = token.Status
	v.ExpiredTime = token.ExpiredTime
	v.UnlimitedQuota = token.UnlimitedQuota
	v.RemainQuota = token.RemainQuota
	v.ModelLimitsEnabled = token.ModelLimitsEnabled
	v.ModelLimits = token.ModelLimits
	return v, nil
}
func linkConnectionView(tx *gorm.DB, conn *LinkConnection) (*LinkConnectionView, error) {
	active, err := linkKeyView(tx, conn, conn.ActiveTokenID)
	if err != nil {
		return nil, err
	}
	candidate, err := linkKeyView(tx, conn, conn.CandidateTokenID)
	if err != nil {
		return nil, err
	}
	return &LinkConnectionView{*conn, active, candidate}, nil
}
func GetLinkConnection(session *LinkSession, id string) (*LinkConnectionView, error) {
	var conn LinkConnection
	if err := DB.Where("id = ? AND user_id = ? AND device_id = ?", id, session.UserID, session.DeviceID).First(&conn).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLinkNotFound
		}
		return nil, err
	}
	return linkConnectionView(DB, &conn)
}
func ListLinkConnections(session *LinkSession) ([]*LinkConnectionView, error) {
	var rows []LinkConnection
	if err := DB.Where("user_id = ? AND device_id = ?", session.UserID, session.DeviceID).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]*LinkConnectionView, 0, len(rows))
	for i := range rows {
		view, err := linkConnectionView(DB, &rows[i])
		if err != nil {
			return nil, err
		}
		result = append(result, view)
	}
	return result, nil
}
func linkOperationID(session *LinkSession, operationID string) string {
	return linkStableHash("operation", fmt.Sprintf("%d:%s:%s", session.UserID, session.DeviceID, operationID))
}
func linkRequestHash(id string, request LinkActionRequest) (string, error) {
	raw, err := common.Marshal(struct {
		ConnectionID string            `json:"connection_id"`
		Request      LinkActionRequest `json:"request"`
	}{id, request})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func findLinkOperation(session *LinkSession, operationID string) (*LinkOperation, error) {
	var op LinkOperation
	err := DB.Where("id = ? AND user_id = ? AND device_id = ?", linkOperationID(session, operationID), session.UserID, session.DeviceID).First(&op).Error
	return &op, err
}
func linkOperationResult(session *LinkSession, op *LinkOperation, reveal bool) (*LinkOperationResult, error) {
	conn, err := GetLinkConnection(session, op.ConnectionID)
	if err != nil {
		return nil, err
	}
	out := &LinkOperationResult{OperationID: op.OperationID, Connection: conn, TokenID: op.TokenID}
	if reveal && op.TokenID > 0 && (conn.ActiveTokenID == op.TokenID || conn.CandidateTokenID == op.TokenID) {
		var token Token
		if err := DB.Where("id = ? AND user_id = ? AND status = ?", op.TokenID, session.UserID, common.TokenStatusEnabled).First(&token).Error; err == nil && (token.ExpiredTime == -1 || token.ExpiredTime > time.Now().Unix()) && (token.UnlimitedQuota || token.RemainQuota > 0) {
			out.APIKey = "sk-" + token.Key
		}
	}
	return out, nil
}
func GetLinkOperation(session *LinkSession, operationID string) (*LinkOperationResult, error) {
	op, err := findLinkOperation(session, operationID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrLinkNotFound
	}
	if err != nil {
		return nil, err
	}
	return linkOperationResult(session, op, false)
}

// Retry recognition precedes catalog validation: a completed operation never creates a replacement key.
func RetryLinkOperation(session *LinkSession, id string, request LinkActionRequest) (*LinkOperationResult, error) {
	op, err := findLinkOperation(session, request.OperationID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	hash, err := linkRequestHash(id, request)
	if err != nil {
		return nil, err
	}
	if op.RequestHash != hash {
		return nil, LinkFailure(409, "LINK_OPERATION_CONFLICT", "Operation ID was already used with different parameters")
	}
	return linkOperationResult(session, op, true)
}

func getOwnedLinkKey(tx *gorm.DB, conn *LinkConnection, id int) (*Token, *LinkKey, error) {
	if id == 0 {
		return nil, nil, ErrLinkState
	}
	var key LinkKey
	var token Token
	if err := tx.Where("token_id = ? AND connection_id = ? AND user_id = ?", id, conn.ID, conn.UserID).First(&key).Error; err != nil {
		return nil, nil, ErrLinkToken
	}
	if err := lockForUpdate(tx).Where("id = ? AND user_id = ?", id, conn.UserID).First(&token).Error; err != nil {
		return nil, nil, ErrLinkToken
	}
	if token.Group != key.Group {
		return nil, nil, ErrLinkToken
	}
	return &token, &key, nil
}
func validateLinkKey(tx *gorm.DB, conn *LinkConnection, id int, enabled, validateModels bool) (*Token, *LinkKey, error) {
	token, key, err := getOwnedLinkKey(tx, conn, id)
	if err != nil {
		return nil, nil, err
	}
	if (token.ExpiredTime != -1 && token.ExpiredTime <= time.Now().Unix()) || (!token.UnlimitedQuota && token.RemainQuota <= 0) {
		return nil, nil, ErrLinkToken
	}
	if enabled && token.Status != common.TokenStatusEnabled {
		return nil, nil, ErrLinkToken
	}
	if !enabled && token.Status != common.TokenStatusEnabled && token.Status != common.TokenStatusDisabled {
		return nil, nil, ErrLinkToken
	}
	if validateModels && token.ModelLimitsEnabled {
		allowed := token.GetModelLimitsMap()
		var models []string
		_ = common.UnmarshalJsonStr(key.Models, &models)
		for _, m := range models {
			if !allowed[m] {
				return nil, nil, ErrLinkToken
			}
		}
	}
	return token, key, nil
}
func setLinkTokenStatus(tx *gorm.DB, conn *LinkConnection, id, status int) error {
	if id == 0 {
		return nil
	}
	var token Token
	err := tx.Where("id = ? AND user_id = ?", id, conn.UserID).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) && status == common.TokenStatusDisabled {
		return nil
	}
	if err != nil {
		return err
	}
	// Fail closed if a distributed cache fence cannot be installed.
	if err := invalidateTokenCacheForMutation(token.Key); err != nil {
		return err
	}
	return tx.Model(&Token{}).Where("id = ? AND user_id = ?", id, conn.UserID).Update("status", status).Error
}
func createLinkCandidate(tx *gorm.DB, conn *LinkConnection, r LinkActionRequest) (int, error) {
	var count int64
	if err := tx.Model(&Token{}).Where("user_id = ?", conn.UserID).Count(&count).Error; err != nil {
		return 0, err
	}
	if count >= int64(operation_setting.GetMaxUserTokens()) {
		return 0, LinkFailure(409, "LINK_TOKEN_LIMIT", "Platform key limit reached")
	}
	secret, err := common.GenerateKey()
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	token := Token{UserId: conn.UserID, Key: secret, Status: common.TokenStatusEnabled, Name: "Link " + conn.ToolFamily + " " + uuid.NewString()[:8], CreatedTime: now, AccessedTime: now, ExpiredTime: -1, UnlimitedQuota: true, Group: r.Group}
	if err := tx.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Create(&token).Error; err != nil {
		return 0, err
	}
	models, err := common.Marshal(r.Models)
	if err != nil {
		return 0, err
	}
	key := LinkKey{TokenID: token.Id, ConnectionID: conn.ID, UserID: conn.UserID, Group: r.Group, Models: string(models), DefaultModel: r.DefaultModel, Status: "candidate"}
	if err := tx.Create(&key).Error; err != nil {
		return 0, err
	}
	conn.CandidateTokenID = token.Id
	return token.Id, nil
}

func ApplyLinkAction(session *LinkSession, id string, r LinkActionRequest, validate func(*gorm.DB, *User, *LinkConnection) error) (*LinkOperationResult, error) {
	hash, err := linkRequestHash(id, r)
	if err != nil {
		return nil, err
	}
	op := LinkOperation{ID: linkOperationID(session, r.OperationID), OperationID: r.OperationID, UserID: session.UserID, DeviceID: session.DeviceID, RequestHash: hash, Action: r.Action, CreatedAt: time.Now().Unix()}
	err = DB.Transaction(func(tx *gorm.DB) error {
		// A first write serializes mutations per account on all supported databases.
		claim := tx.Model(&User{}).Where("id = ? AND auth_version = ? AND status = ?", session.UserID, session.AuthVersion, common.UserStatusEnabled).UpdateColumn("auth_version", gorm.Expr("auth_version"))
		if claim.Error != nil {
			return claim.Error
		}
		var currentUser User
		if err := tx.Where("id = ? AND auth_version = ? AND status = ?", session.UserID, session.AuthVersion, common.UserStatusEnabled).First(&currentUser).Error; err != nil {
			return ErrLinkUnauthorized
		}
		var live LinkSession
		if err := tx.Where("id = ? AND access_hash = ? AND revoked_at = 0 AND expires_at > ? AND access_expires_at > ?", session.ID, session.AccessHash, time.Now().Unix(), time.Now().Unix()).First(&live).Error; err != nil {
			return ErrLinkUnauthorized
		}
		var previous LinkOperation
		err := tx.Where("id = ?", op.ID).First(&previous).Error
		if err == nil {
			if previous.RequestHash != hash {
				return LinkFailure(409, "LINK_OPERATION_CONFLICT", "Operation ID was already used with different parameters")
			}
			op = previous
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var conn LinkConnection
		if r.Action == "create" {
			scope := linkStableHash("scope", fmt.Sprintf("%d:%s:%s:%s", session.UserID, session.DeviceID, r.ToolFamily, r.ConfigScope))
			err = tx.Where("scope_hash = ?", scope).First(&conn).Error
			if err == nil && conn.Status != "disconnected" {
				return ErrLinkState
			}
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if conn.ID == "" {
				conn = LinkConnection{ID: uuid.NewString(), ScopeHash: scope, UserID: session.UserID, DeviceID: session.DeviceID, ToolFamily: r.ToolFamily, ConfigScope: r.ConfigScope, CreatedAt: time.Now().Unix()}
			}
			if validate != nil {
				if err := validate(tx, &currentUser, &conn); err != nil {
					return err
				}
			}
			conn.Status = "pending"
			conn.ActiveTokenID = 0
			op.TokenID, err = createLinkCandidate(tx, &conn, r)
			if err != nil {
				return err
			}
		} else {
			if err := lockForUpdate(tx).Where("id = ? AND user_id = ? AND device_id = ?", id, session.UserID, session.DeviceID).First(&conn).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrLinkNotFound
				}
				return err
			}
			if conn.Revision != r.ExpectedRevision {
				return LinkFailure(409, "LINK_REVISION_CONFLICT", "Connection changed; reload before retrying")
			}
			if validate != nil {
				if err := validate(tx, &currentUser, &conn); err != nil {
					return err
				}
			}
			switch r.Action {
			case "prepare_switch":
				if conn.CandidateTokenID != 0 || (conn.Status != "active" && conn.Status != "paused") {
					return ErrLinkState
				}
				// The source must still belong to this connection. Its independent
				// quota, expiry and model restrictions do not govern the new group key.
				_, key, err := getOwnedLinkKey(tx, &conn, conn.ActiveTokenID)
				if err != nil {
					return err
				}
				if key.Group == r.Group {
					return ErrLinkState
				}
				op.TokenID, err = createLinkCandidate(tx, &conn, r)
				if err != nil {
					return err
				}
			case "commit":
				if _, _, err := validateLinkKey(tx, &conn, conn.CandidateTokenID, true, true); err != nil {
					return err
				}
				if err := setLinkTokenStatus(tx, &conn, conn.ActiveTokenID, common.TokenStatusDisabled); err != nil {
					return err
				}
				if conn.ActiveTokenID != 0 {
					if err := tx.Model(&LinkKey{}).Where("token_id = ?", conn.ActiveTokenID).Update("status", "retired").Error; err != nil {
						return err
					}
				}
				if err := tx.Model(&LinkKey{}).Where("token_id = ?", conn.CandidateTokenID).Update("status", "active").Error; err != nil {
					return err
				}
				conn.ActiveTokenID = conn.CandidateTokenID
				conn.CandidateTokenID = 0
				conn.Status = "active"
			case "abort":
				if conn.CandidateTokenID == 0 {
					return ErrLinkState
				}
				if err := setLinkTokenStatus(tx, &conn, conn.CandidateTokenID, common.TokenStatusDisabled); err != nil {
					return err
				}
				if err := tx.Model(&LinkKey{}).Where("token_id = ?", conn.CandidateTokenID).Update("status", "aborted").Error; err != nil {
					return err
				}
				conn.CandidateTokenID = 0
				if conn.ActiveTokenID == 0 {
					conn.Status = "disconnected"
				}
			case "disconnect":
				for _, tokenID := range []int{conn.ActiveTokenID, conn.CandidateTokenID} {
					if err := setLinkTokenStatus(tx, &conn, tokenID, common.TokenStatusDisabled); err != nil {
						return err
					}
				}
				if err := tx.Model(&LinkKey{}).Where("connection_id = ? AND status IN ?", conn.ID, []string{"active", "candidate"}).Update("status", "disconnected").Error; err != nil {
					return err
				}
				conn.CandidateTokenID = 0
				conn.Status = "disconnected"
			case "pause", "resume":
				if conn.CandidateTokenID != 0 || (conn.Status != "active" && conn.Status != "paused") {
					return ErrLinkState
				}
				status := common.TokenStatusDisabled
				if r.Action == "resume" {
					if _, _, err := validateLinkKey(tx, &conn, conn.ActiveTokenID, false, true); err != nil {
						return err
					}
					status = common.TokenStatusEnabled
					conn.Status = "active"
				} else {
					conn.Status = "paused"
				}
				if err := setLinkTokenStatus(tx, &conn, conn.ActiveTokenID, status); err != nil {
					return err
				}
			case "update_models":
				if conn.CandidateTokenID != 0 || (conn.Status != "active" && conn.Status != "paused") {
					return ErrLinkState
				}
				token, key, err := validateLinkKey(tx, &conn, conn.ActiveTokenID, false, false)
				if err != nil {
					return err
				}
				if token.ModelLimitsEnabled {
					allowed := token.GetModelLimitsMap()
					for _, m := range r.Models {
						if !allowed[m] {
							return ErrLinkToken
						}
					}
				}
				models, err := common.Marshal(r.Models)
				if err != nil {
					return err
				}
				key.Models = string(models)
				key.DefaultModel = r.DefaultModel
				if err := tx.Save(key).Error; err != nil {
					return err
				}
			default:
				return LinkFailure(400, "LINK_INVALID_REQUEST", "Unknown connection action")
			}
		}
		conn.Revision++
		conn.UpdatedAt = time.Now().Unix()
		if err := tx.Save(&conn).Error; err != nil {
			return err
		}
		op.ConnectionID = conn.ID
		return tx.Create(&op).Error
	})
	if err != nil {
		return nil, err
	}
	return linkOperationResult(session, &op, true)
}
