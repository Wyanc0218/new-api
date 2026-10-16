package controller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// Runs inside the existing real SQLite/MySQL/PostgreSQL workflow fixture.
func testLinkToolVerification(t *testing.T, db *gorm.DB, client, otherDevice, otherUser *linkTestClient, connection map[string]any, userID, tokenID int, target, protocol, path string) {
	t.Helper()
	endpoint := "/connections/" + connection["id"].(string) + "/tool-verifications"
	body := gin.H{"expected_revision": connection["revision"], "target": target, "model": "verified-model", "protocol": protocol}
	create := func() map[string]any { return client.request("POST", endpoint, body, 200).Data }
	get := func(id any) map[string]any {
		return client.request("GET", "/tool-verifications/"+id.(string), nil, 200).Data
	}
	for _, mutation := range []gin.H{{"target": "codex-desktop"}, {"protocol": "anthropic_messages"}, {"model": ""}} {
		invalid := gin.H{}
		for k, v := range body {
			invalid[k] = v
		}
		for k, v := range mutation {
			invalid[k] = v
		}
		client.request("POST", endpoint, invalid, 400)
	}
	for _, mutation := range []gin.H{{"expected_revision": 999}, {"model": "not-selected"}} {
		invalid := gin.H{}
		for k, v := range body {
			invalid[k] = v
		}
		for k, v := range mutation {
			invalid[k] = v
		}
		client.request("POST", endpoint, invalid, 409)
	}
	first := create()
	assert.Equal(t, "pending", first["status"])
	assert.Equal(t, float64(tokenID), first["token_id"])
	assert.NotContains(t, get(first["id"]), "challenge")
	assert.NotContains(t, get(first["id"]), "ChallengeHash")
	otherDevice.request("GET", "/tool-verifications/"+first["id"].(string), nil, 404)
	otherUser.request("GET", "/tool-verifications/"+first["id"].(string), nil, 404)
	otherDevice.request("POST", endpoint, body, 404)
	second := create()
	_, err := model.ClaimLinkToolVerification(first["challenge"].(string), userID, tokenID, "verified-model", protocol, "abandoned")
	require.Error(t, err)
	assert.Equal(t, "failed", get(first["id"])["status"])
	challenge := second["challenge"].(string)
	for _, wrong := range []struct {
		user, token     int
		model, protocol string
	}{{userID + 1, tokenID, "verified-model", protocol}, {userID, tokenID + 1, "verified-model", protocol}, {userID, tokenID, "wrong", protocol}, {userID, tokenID, "verified-model", "anthropic_messages"}} {
		_, err = model.ClaimLinkToolVerification(challenge, wrong.user, wrong.token, wrong.model, wrong.protocol, "wrong-request")
		require.Error(t, err)
	}
	// A concurrent replay cannot observe two successful claims.
	var workers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		workers.Go(func() {
			_, err := model.ClaimLinkToolVerification(challenge, userID, tokenID, "verified-model", protocol, "same-request")
			results <- err
		})
	}
	workers.Wait()
	close(results)
	succeeded := 0
	for result := range results {
		if result == nil {
			succeeded++
		}
	}
	assert.Equal(t, 1, succeeded)
	require.NoError(t, model.FinishLinkToolVerification(second["id"].(string), "wrong-request", true))
	assert.Equal(t, "pending", get(second["id"])["status"])
	require.NoError(t, model.FinishLinkToolVerification(second["id"].(string), "same-request", true))
	receipt := get(second["id"])
	assert.Equal(t, "succeeded", receipt["status"])
	assert.Equal(t, "same-request", receipt["request_id"])
	assert.GreaterOrEqual(t, receipt["observed_at"].(float64), second["created_at"].(float64))
	require.NoError(t, model.FinishLinkToolVerification(second["id"].(string), "same-request", false))
	assert.Equal(t, "succeeded", get(second["id"])["status"])
	for range 2 {
		require.NoError(t, db.AutoMigrate(&model.LinkToolVerification{}))
	}
	assert.Equal(t, "succeeded", get(second["id"])["status"], "repeated migration preserves receipts")
	var duplicate model.LinkToolVerification
	require.NoError(t, db.First(&duplicate, "id = ?", second["id"]).Error)
	duplicate.ID = uuid.NewString()
	assert.Error(t, db.Create(&duplicate).Error, "challenge hashes must remain unique after migration")

	for _, tc := range []struct {
		name                          string
		stream, ok, completed, failed bool
		end                           relaycommon.StreamEndReason
		want                          string
	}{
		{"complete", true, true, true, false, relaycommon.StreamEndReasonDone, "succeeded"},
		{"missing terminal", true, true, false, false, relaycommon.StreamEndReasonEOF, "failed"},
		{"incomplete", true, true, false, true, relaycommon.StreamEndReasonDone, "failed"},
		{"error after completion", true, true, true, true, relaycommon.StreamEndReasonDone, "failed"},
		{"broken stream", true, true, true, false, relaycommon.StreamEndReasonScannerErr, "failed"},
		{"client closed after terminal", true, true, true, false, relaycommon.StreamEndReasonClientGone, "succeeded"},
		{"client closed before terminal", true, true, false, false, relaycommon.StreamEndReasonClientGone, "failed"},
		{"handler failure", true, false, true, false, relaycommon.StreamEndReasonDone, "failed"},
		{"non-stream", false, true, true, false, relaycommon.StreamEndReasonDone, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt := create()
			id := attempt["id"].(string)
			requestID := uuid.NewString()
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest("POST", "http://127.0.0.1"+path, nil)
			c.Set(common.RequestIdKey, requestID)
			claimed, err := service.ClaimLinkRelayVerification(c, &relaycommon.RelayInfo{IsStream: true, UserId: userID, TokenId: tokenID, OriginModelName: "verified-model"}, attempt["challenge"].(string))
			require.NoError(t, err)
			assert.Equal(t, id, claimed)
			stream := relaycommon.NewStreamStatus()
			stream.RequireTerminal()
			stream.SetEndReason(tc.end, nil)
			if tc.completed {
				stream.MarkCompleted()
			}
			if tc.failed {
				stream.MarkFailed("synthetic_error", "synthetic", 502)
			}
			service.FinishLinkRelayVerification(c, &relaycommon.RelayInfo{IsStream: tc.stream, StreamStatus: stream}, id, tc.ok)
			assert.Equal(t, tc.want, get(id)["status"])
		})
	}
	// Non-stream probes cannot acquire a challenge, even on a known response path.
	nonstream := create()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "http://127.0.0.1"+path, nil)
	c.Set(common.RequestIdKey, "nonstream")
	_, err = service.ClaimLinkRelayVerification(c, &relaycommon.RelayInfo{IsStream: false, UserId: userID, TokenId: tokenID, OriginModelName: "verified-model"}, nonstream["challenge"].(string))
	require.Error(t, err)
	assert.NotContains(t, get(nonstream["id"]), "request_id")
	c.Request = httptest.NewRequest("POST", "http://127.0.0.1/v1/messages", nil)
	_, err = service.ClaimLinkRelayVerification(c, &relaycommon.RelayInfo{IsStream: true, UserId: userID, TokenId: tokenID, OriginModelName: "verified-model"}, nonstream["challenge"].(string))
	require.Error(t, err, "a challenge cannot cross its protocol boundary")

	expired := create()
	require.NoError(t, db.Model(&model.LinkToolVerification{}).Where("id = ?", expired["id"]).Update("expires_at", time.Now().Unix()-1).Error)
	_, err = model.ClaimLinkToolVerification(expired["challenge"].(string), userID, tokenID, "verified-model", protocol, "expired")
	require.Error(t, err)
	assert.Equal(t, "expired", get(expired["id"])["status"])
	stale := create()
	require.NoError(t, db.Model(&model.LinkConnection{}).Where("id = ?", connection["id"]).Update("revision", gorm.Expr("revision + 1")).Error)
	_, err = model.ClaimLinkToolVerification(stale["challenge"].(string), userID, tokenID, "verified-model", protocol, "stale")
	require.Error(t, err)
	assert.Equal(t, "failed", get(stale["id"])["status"])
	require.NoError(t, db.Model(&model.LinkConnection{}).Where("id = ?", connection["id"]).Update("revision", connection["revision"]).Error)
	logout := create()
	require.NoError(t, db.Model(&model.LinkSession{}).Where("id = ?", client.sessionID).Update("revoked_at", time.Now().Unix()).Error)
	_, err = model.ClaimLinkToolVerification(logout["challenge"].(string), userID, tokenID, "verified-model", protocol, "logout")
	require.Error(t, err)
	require.NoError(t, db.Model(&model.LinkSession{}).Where("id = ?", client.sessionID).Update("revoked_at", 0).Error)
	require.NoError(t, db.Model(&model.LinkToolVerification{}).Where("id = ?", logout["id"]).Update("expires_at", time.Now().Unix()-86401).Error)
	require.NoError(t, model.DeleteExpiredLinkToolVerifications(time.Now().Unix()))
	client.request("GET", "/tool-verifications/"+logout["id"].(string), nil, 404)
}

func testLinkHermesWorkflow(t *testing.T, db *gorm.DB, client, otherDevice, otherUser *linkTestClient, userID int) {
	t.Helper()
	catalogPath := filepath.Join(t.TempDir(), "hermes-catalog.json")
	entries := []gin.H{
		{"id": "verified-second", "protocol": "openai_chat_completions", "tool_families": []string{"hermes"}, "groups": []string{"default", "vip"}},
		{"id": "verified-model", "protocol": "openai_chat_completions", "tool_families": []string{"hermes"}, "groups": []string{"default", "vip"}},
		{"id": "not-on-channel", "protocol": "openai_chat_completions", "tool_families": []string{"hermes"}, "groups": []string{"default", "vip"}},
		{"id": "verified-model", "protocol": "openai_responses", "tool_families": []string{"codex"}, "groups": []string{"default", "vip"}},
	}
	raw, err := common.Marshal(gin.H{"models": entries})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(catalogPath, raw, 0600))
	t.Setenv("LINK_MODEL_CATALOG_FILE", catalogPath)
	catalog := client.request("GET", "/catalog?tool_family=hermes&group=default", nil, 200)
	assert.Equal(t, "verified-model", catalog.Data["default_model"], "live model order determines the initial model")
	models := catalog.Data["models"].([]any)
	require.Len(t, models, 2)
	for _, item := range models {
		assert.Equal(t, "openai_chat_completions", item.(map[string]any)["protocol"])
	}
	// Invalid optional metadata must not hide a live, protocol-compatible route.
	entries[0]["protocol"] = "openai_responses"
	invalid, err := common.Marshal(gin.H{"models": entries})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(catalogPath, invalid, 0600))
	assert.Equal(t, catalog.Data["revision"], client.request("GET", "/catalog?tool_family=hermes&group=default", nil, 200).Data["revision"])
	require.NoError(t, os.WriteFile(catalogPath, raw, 0600))
	create := gin.H{"operation_id": uuid.NewString(), "tool_family": "hermes", "config_scope": "default", "group": "default", "models": []string{"verified-model", "verified-second"}, "default_model": "verified-model", "catalog_revision": catalog.Data["revision"]}
	created := client.request("POST", "/connections", create, 200)
	retried := client.request("POST", "/connections", create, 200)
	assert.Equal(t, created.Data["token_id"], retried.Data["token_id"])
	assert.Equal(t, created.Data["api_key"], retried.Data["api_key"])
	conn := linkConnectionFrom(t, created)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "commit", nil))
	assert.Equal(t, "hermes", conn["tool_family"])
	tokenID := int(created.Data["token_id"].(float64))
	testLinkToolVerification(t, db, client, otherDevice, otherUser, conn, userID, tokenID, "hermes", "openai_chat_completions", "/v1/chat/completions")
	client.request("POST", "/connections/"+conn["id"].(string)+"/tool-verifications", gin.H{"expected_revision": conn["revision"], "target": "codex-cli", "model": "verified-model", "protocol": "openai_responses"}, 409)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "pause", nil))
	assert.Equal(t, "paused", conn["status"])
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "resume", nil))
	assert.Equal(t, "active", conn["status"])
	vip := client.request("GET", "/catalog?tool_family=hermes&group=vip", nil, 200)
	prepared := linkAction(t, client, conn, "prepare_switch", gin.H{"group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": vip.Data["revision"]})
	conn = linkConnectionFrom(t, prepared)
	candidateID := int(prepared.Data["token_id"].(float64))
	assert.NotEqual(t, tokenID, candidateID)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "commit", nil))
	var original, candidate model.Token
	require.NoError(t, db.First(&original, tokenID).Error)
	require.NoError(t, db.First(&candidate, candidateID).Error)
	assert.Equal(t, "default", original.Group)
	assert.Equal(t, common.TokenStatusDisabled, original.Status)
	assert.Equal(t, "vip", candidate.Group)
	assert.Equal(t, common.TokenStatusEnabled, candidate.Status)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "disconnect", nil))
	assert.Equal(t, "disconnected", conn["status"])
	assert.NoError(t, db.First(&candidate, candidateID).Error)
	assert.Equal(t, common.TokenStatusDisabled, candidate.Status)
	t.Run("configurable_tool_verification", func(t *testing.T) {
		testLinkConfigurableToolVerification(t, db, client, userID)
	})
}

func writeLinkVerificationRegistry(t *testing.T, path string, tools []gin.H) {
	t.Helper()
	raw, err := common.Marshal(gin.H{"version": 1, "tools": tools})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))
}

func testLinkConfigurableToolVerification(t *testing.T, db *gorm.DB, parent *linkTestClient, userID int) {
	t.Helper()
	// Initialize the native token lookup's dialect columns against the fixture's
	// existing database, without creating another database or running migrations.
	t.Setenv("LOG_SQL_DSN", "")
	master := common.IsMasterNode
	common.IsMasterNode = false
	err := model.InitLogDB()
	common.IsMasterNode = master
	require.NoError(t, err)
	registryPath := filepath.Join(t.TempDir(), "tools.json")
	t.Setenv("LINK_TOOL_REGISTRY_FILE", registryPath)
	for _, tc := range []struct{ name, protocol, path string }{
		{"chat", "openai_chat_completions", "/v1/chat/completions"},
		{"messages", "anthropic_messages", "/v1/messages"},
		{"responses", "openai_responses", "/v1/responses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := *parent
			client.t = t
			family, target := "registered_"+tc.name, "registered-"+tc.name
			definition := gin.H{"id": family, "protocol": tc.protocol, "verification_targets": []string{target}}
			writeLinkVerificationRegistry(t, registryPath, []gin.H{definition})
			catalog := client.request("GET", "/catalog?tool_family="+family+"&group=default", nil, 200)
			created := client.request("POST", "/connections", gin.H{
				"operation_id": uuid.NewString(), "tool_family": family, "config_scope": "verification-registry", "group": "default",
				"models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": catalog.Data["revision"],
			}, 200)
			connection := linkConnectionFrom(t, created)
			connection = linkConnectionFrom(t, linkAction(t, &client, connection, "commit", nil))
			tokenID := int(created.Data["token_id"].(float64))
			var persisted model.LinkConnection
			require.NoError(t, db.First(&persisted, "id = ?", connection["id"]).Error)
			assert.Equal(t, tc.protocol, persisted.ToolProtocol, "connections preserve their original configured protocol")
			endpoint := "/connections/" + connection["id"].(string) + "/tool-verifications"
			body := gin.H{"expected_revision": connection["revision"], "target": target, "model": "verified-model", "protocol": tc.protocol}
			attempt := client.request("POST", endpoint, body, 200).Data
			requestID := uuid.NewString()
			context, _ := gin.CreateTestContext(httptest.NewRecorder())
			context.Request = httptest.NewRequest("POST", "http://127.0.0.1"+tc.path, nil)
			context.Set(common.RequestIdKey, requestID)
			claimed, err := service.ClaimLinkRelayVerification(context, &relaycommon.RelayInfo{IsStream: true, UserId: userID, TokenId: tokenID, OriginModelName: "verified-model"}, attempt["challenge"].(string))
			require.NoError(t, err)
			assert.Equal(t, attempt["id"], claimed)
			require.NoError(t, model.FinishLinkToolVerification(claimed, requestID, true))
			assert.Equal(t, "succeeded", client.request("GET", "/tool-verifications/"+claimed, nil, 200).Data["status"])

			if tc.name == "chat" {
				// Registration controls desktop management and verification. Existing
				// inference keys must remain usable until explicitly paused or disconnected.
				inference := gin.New()
				inference.POST(tc.path, middleware.TokenAuth(), func(c *gin.Context) {
					assert.Equal(t, tokenID, c.GetInt("token_id"))
					c.Status(http.StatusNoContent)
				})
				for _, change := range []struct {
					name         string
					tools        []gin.H
					invalid      bool
					createStatus int
				}{
					{name: "disabled", tools: []gin.H{{"id": family, "enabled": false, "protocol": tc.protocol, "verification_targets": []string{target}}}, createStatus: 400},
					{name: "removed", tools: []gin.H{}, createStatus: 400},
					{name: "target reassigned", tools: []gin.H{{"id": family, "protocol": tc.protocol}, {"id": "other_registered", "protocol": tc.protocol, "verification_targets": []string{target}}}, createStatus: 409},
					{name: "protocol changed", tools: []gin.H{{"id": family, "protocol": "anthropic_messages", "verification_targets": []string{target}}}, createStatus: 400},
					{name: "invalid configuration", invalid: true, createStatus: 503},
				} {
					t.Run(change.name, func(t *testing.T) {
						changedClient := client
						changedClient.t = t
						writeLinkVerificationRegistry(t, registryPath, []gin.H{definition})
						pending := changedClient.request("POST", endpoint, body, 200).Data
						if change.invalid {
							require.NoError(t, os.WriteFile(registryPath, []byte(`{"version":1,"tools":`), 0600))
						} else {
							writeLinkVerificationRegistry(t, registryPath, change.tools)
						}
						changedClient.request("POST", endpoint, body, change.createStatus)
						_, err := model.ClaimLinkToolVerification(pending["challenge"].(string), userID, tokenID, "verified-model", tc.protocol, uuid.NewString())
						require.Error(t, err)
						if change.invalid {
							changedClient.request("GET", "/tool-verifications/"+pending["id"].(string), nil, 503)
						} else {
							assert.Equal(t, "failed", changedClient.request("GET", "/tool-verifications/"+pending["id"].(string), nil, 200).Data["status"])
							assert.Equal(t, "failed", changedClient.request("GET", "/tool-verifications/"+claimed, nil, 200).Data["status"], "a prior receipt cannot attest a different current tool definition")
						}
						if change.name == "protocol changed" {
							changedClient.request("POST", endpoint, gin.H{"expected_revision": connection["revision"], "target": target, "model": "verified-model", "protocol": "anthropic_messages"}, 409)
						}
						request := httptest.NewRequest("POST", "http://127.0.0.1"+tc.path, nil)
						request.Header.Set("Authorization", "Bearer "+created.Data["api_key"].(string))
						response := httptest.NewRecorder()
						inference.ServeHTTP(response, request)
						assert.Equal(t, http.StatusNoContent, response.Code, "tool registration must not revoke ordinary inference authorization")
						var stored model.LinkToolVerification
						require.NoError(t, db.First(&stored, "id = ?", claimed).Error)
						assert.Equal(t, "succeeded", stored.Status, "definition changes must not rewrite historical completion records")
					})
				}
			}
			writeLinkVerificationRegistry(t, registryPath, []gin.H{definition})
			connection = linkConnectionFrom(t, linkAction(t, &client, connection, "disconnect", nil))
			assert.Equal(t, "disconnected", connection["status"])
		})
	}
}
