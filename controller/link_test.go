package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type linkTestEnvelope struct {
	Success bool           `json:"success"`
	Code    string         `json:"code"`
	Data    map[string]any `json:"data"`
}
type linkTestClient struct {
	t         *testing.T
	router    *gin.Engine
	access    string
	refresh   string
	sessionID string
	origin    string
}

func (client *linkTestClient) request(method, path string, body any, status int) linkTestEnvelope {
	client.t.Helper()
	raw, err := common.Marshal(body)
	require.NoError(client.t, err)
	r := httptest.NewRequest(method, "http://127.0.0.1:3000/api/link/v1"+path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	if client.origin != "" {
		r.Header.Set("Origin", client.origin)
	}
	if client.access != "" {
		r.Header.Set("Authorization", "Bearer "+client.access)
	}
	w := httptest.NewRecorder()
	client.router.ServeHTTP(w, r)
	require.Equal(client.t, status, w.Code, w.Body.String())
	var result linkTestEnvelope
	require.NoError(client.t, common.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(client.t, "no-store", w.Header().Get("Cache-Control"))
	return result
}
func linkTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/link/v1", middleware.LinkTransport())
	g.POST("/auth/start", LinkAuthStart)
	g.POST("/auth/complete", middleware.UserAuth(), LinkAuthComplete)
	g.POST("/auth/exchange", LinkAuthExchange)
	g.POST("/auth/refresh", LinkAuthRefresh)
	a := g.Group("", middleware.LinkAuth())
	a.POST("/auth/logout", LinkAuthLogout)
	a.GET("/bootstrap", LinkBootstrap)
	a.GET("/catalog", LinkCatalog)
	a.POST("/connections", LinkConnectionCreate)
	a.GET("/connections/:id", LinkConnectionGet)
	a.POST("/connections/:id/actions", LinkConnectionAction)
	a.GET("/operations/:id", LinkOperationGet)
	a.POST("/connections/:id/tool-verifications", LinkToolVerificationCreate)
	a.GET("/tool-verifications/:id", LinkToolVerificationGet)
	return r
}
func linkTestLogin(t *testing.T, router *gin.Engine, user *model.User, deviceID string) *linkTestClient {
	t.Helper()
	browser, err := service.CreateLoginSession(user.Id, "password", "127.0.0.1", "link-test")
	require.NoError(t, err)
	verifier := strings.Repeat("v", 43)
	challenge := sha256.Sum256([]byte(verifier))
	client := &linkTestClient{t: t, router: router}
	start := client.request("POST", "/auth/start", gin.H{"device_id": deviceID, "code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256", "redirect_uri": "http://127.0.0.1:12345/callback", "state": strings.Repeat("s", 43)}, 200)
	client.access = browser.AccessToken
	client.origin = "https://untrusted.example"
	client.request("POST", "/auth/complete", gin.H{"flow_token": start.Data["flow_token"]}, 403)
	client.origin = ""
	complete := client.request("POST", "/auth/complete", gin.H{"flow_token": start.Data["flow_token"]}, 200)
	callback, err := url.Parse(complete.Data["callback_url"].(string))
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("s", 43), callback.Query().Get("state"))
	exchange := gin.H{"code": callback.Query().Get("code"), "code_verifier": verifier, "redirect_uri": "http://127.0.0.1:12345/callback", "device_id": deviceID}
	client.access = ""
	wrong := gin.H{}
	for k, v := range exchange {
		wrong[k] = v
	}
	wrong["code_verifier"] = strings.Repeat("x", 43)
	assert.Equal(t, "LINK_UNAUTHORIZED", client.request("POST", "/auth/exchange", wrong, 401).Code)
	result := client.request("POST", "/auth/exchange", exchange, 200)
	client.access = result.Data["access_token"].(string)
	client.refresh = result.Data["refresh_token"].(string)
	client.sessionID = result.Data["session_id"].(string)
	assert.Equal(t, "LINK_UNAUTHORIZED", client.request("POST", "/auth/exchange", exchange, 401).Code)
	require.NotEqual(t, browser.AccessToken, client.access)
	return client
}
func linkConnectionFrom(t *testing.T, result linkTestEnvelope) map[string]any {
	t.Helper()
	conn, ok := result.Data["connection"].(map[string]any)
	require.True(t, ok)
	return conn
}
func linkAction(t *testing.T, client *linkTestClient, conn map[string]any, action string, extra gin.H) linkTestEnvelope {
	t.Helper()
	r := gin.H{"operation_id": uuid.NewString(), "action": action, "expected_revision": conn["revision"]}
	for k, v := range extra {
		r[k] = v
	}
	return client.request("POST", "/connections/"+conn["id"].(string)+"/actions", r, 200)
}

func testLinkLivePrices(t *testing.T, db *gorm.DB, user *model.User, client *linkTestClient, catalogPath string, channelID int) {
	t.Helper()
	priorCatalog, err := os.ReadFile(catalogPath)
	require.NoError(t, err)
	priorUnit, priorSelfUse := common.QuotaPerUnit, operation_setting.SelfUseModeEnabled
	billing := config.GlobalConfig.Get("billing_setting")
	priorBilling, err := config.ConfigToMap(billing)
	require.NoError(t, err)
	settings := []struct {
		value   string
		restore func(string) error
	}{
		{ratio_setting.ModelRatio2JSONString(), ratio_setting.UpdateModelRatioByJSONString},
		{ratio_setting.ModelPrice2JSONString(), ratio_setting.UpdateModelPriceByJSONString},
		{ratio_setting.CompletionRatio2JSONString(), ratio_setting.UpdateCompletionRatioByJSONString},
		{ratio_setting.CacheRatio2JSONString(), ratio_setting.UpdateCacheRatioByJSONString},
		{ratio_setting.CreateCacheRatio2JSONString(), ratio_setting.UpdateCreateCacheRatioByJSONString},
		{ratio_setting.GroupRatio2JSONString(), ratio_setting.UpdateGroupRatioByJSONString},
		{ratio_setting.GroupGroupRatio2JSONString(), ratio_setting.UpdateGroupGroupRatioByJSONString},
	}
	t.Cleanup(func() {
		common.QuotaPerUnit, operation_setting.SelfUseModeEnabled = priorUnit, priorSelfUse
		for _, setting := range settings {
			require.NoError(t, setting.restore(setting.value))
		}
		require.NoError(t, config.UpdateConfigFromMap(billing, priorBilling))
		require.NoError(t, os.WriteFile(catalogPath, priorCatalog, 0600))
		require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.Id).Update("group", user.Group).Error)
	})
	modelNames := []string{"link-price-model", "claude-link-price-model"}
	t.Cleanup(func() {
		require.NoError(t, db.Where("channel_id = ? AND model IN ?", channelID, modelNames).Delete(&model.Ability{}).Error)
	})
	for _, id := range modelNames {
		require.NoError(t, db.Create(&model.Ability{Group: "vip", Model: id, ChannelId: channelID, Enabled: true}).Error)
	}
	const suffix = "；已含当前账号及所选组倍率，工具等附加费用另计，以请求时平台结算为准"
	const normal = "文本基础价（美元/百万令牌）：输入 6，输出 18，缓存读取 0.6，缓存写入 7.5" + suffix
	tests := []struct {
		name, model, userGroup, ratios, prices, cache, creation, groups, special, mode string
		unit                                                                           float64
		selfUse                                                                        bool
		want                                                                           string
		status                                                                         int
	}{
		{name: "ordinary group multiplier", want: normal},
		{name: "account-specific group replaces ordinary multiplier", special: `{"default":{"vip":0.25}}`, want: "文本基础价（美元/百万令牌）：输入 0.5，输出 1.5，缓存读取 0.05，缓存写入 0.625" + suffix},
		{name: "another account group does not inherit discount", userGroup: "vip", special: `{"default":{"vip":0.25}}`, want: normal},
		{name: "explicit zero special multiplier", special: `{"default":{"vip":0}}`, want: "文本基础价（美元/百万令牌）：输入 0，输出 0，缓存读取 0，缓存写入 0" + suffix},
		{name: "configured quota unit", unit: 500000, want: "文本基础价（美元/百万令牌）：输入 12，输出 36，缓存读取 1.2，缓存写入 15" + suffix},
		{name: "fixed price takes precedence", prices: `{"link-price-model":0.02}`, want: "基础价 0.06 美元/次" + suffix},
		{name: "Claude native dual cache lifetime", model: "claude-link-price-model", want: "文本基础价（美元/百万令牌）：输入 6，输出 18，缓存读取 0.6，缓存写入（5 分钟） 7.5，缓存写入（1 小时） 12" + suffix},
		{name: "unconfigured cache uses native read rate without invented write lane", cache: `{}`, creation: `{}`, want: "文本基础价（美元/百万令牌）：输入 6，输出 18，缓存读取 6" + suffix},
		{name: "missing input data", ratios: `{}`, want: "价格资料不完整；以平台计费说明为准"},
		{name: "self-use fallback is not a quote", ratios: `{}`, selfUse: true, want: "价格资料不完整；以平台计费说明为准"},
		{name: "removed group is not selectable", groups: `{}`, status: 403},
		{name: "invalid group price", groups: `{"vip":-1}`, want: "价格资料不完整；以平台计费说明为准"},
		{name: "conditional expression overrides fixed price", prices: `{"link-price-model":0.02}`, mode: `{"link-price-model":"tiered_expr"}`, want: "条件计费，价格取决于实际请求；以平台计费说明为准"},
		{name: "small nonzero price never appears free", ratios: `{"link-price-model":0.000000001}`, want: "文本基础价（美元/百万令牌）：输入 <0.00000001，输出 0.00000001，缓存读取 <0.00000001，缓存写入 <0.00000001" + suffix},
	}
	var regularRevision string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.model
			if id == "" {
				id = modelNames[0]
			}
			userGroup := tc.userGroup
			if userGroup == "" {
				userGroup = "default"
			}
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.Id).Update("group", userGroup).Error)
			common.QuotaPerUnit = tc.unit
			if common.QuotaPerUnit == 0 {
				common.QuotaPerUnit = 1000000
			}
			operation_setting.SelfUseModeEnabled = tc.selfUse
			changes := []struct {
				value, fallback string
				apply           func(string) error
			}{
				{tc.ratios, `{"link-price-model":2,"claude-link-price-model":2}`, ratio_setting.UpdateModelRatioByJSONString},
				{tc.prices, `{}`, ratio_setting.UpdateModelPriceByJSONString},
				{"", `{"link-price-model":3,"claude-link-price-model":3}`, ratio_setting.UpdateCompletionRatioByJSONString},
				{tc.cache, `{"link-price-model":0.1,"claude-link-price-model":0.1}`, ratio_setting.UpdateCacheRatioByJSONString},
				{tc.creation, `{"link-price-model":1.25,"claude-link-price-model":1.25}`, ratio_setting.UpdateCreateCacheRatioByJSONString},
				{tc.groups, `{"default":1,"vip":3}`, ratio_setting.UpdateGroupRatioByJSONString},
				{tc.special, `{}`, ratio_setting.UpdateGroupGroupRatioByJSONString},
			}
			for _, change := range changes {
				value := change.value
				if value == "" {
					value = change.fallback
				}
				require.NoError(t, change.apply(value))
			}
			mode := tc.mode
			if mode == "" {
				mode = `{}`
			}
			require.NoError(t, config.UpdateConfigFromMap(billing, map[string]string{"billing_mode": mode, "billing_expr": `{"link-price-model":"p*2+c*3"}`}))
			raw, err := common.Marshal(gin.H{"models": []gin.H{{"id": id, "protocol": "openai_responses", "tool_families": []string{"codex"}, "groups": []string{"vip"}, "price_text": "do not trust static quote"}}})
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(catalogPath, raw, 0600))
			current := *client
			current.t = t
			status := tc.status
			if status == 0 {
				status = 200
			}
			result := current.request("GET", "/catalog?tool_family=codex&group=vip", nil, status)
			if status != 200 {
				return
			}
			entries := result.Data["models"].([]any)
			require.Len(t, entries, 1)
			assert.Equal(t, tc.want, entries[0].(map[string]any)["price_text"])
			if tc.name == "ordinary group multiplier" {
				regularRevision = result.Data["revision"].(string)
			}
			if tc.name == "account-specific group replaces ordinary multiplier" {
				assert.NotEqual(t, regularRevision, result.Data["revision"], "a price change invalidates a prior confirmation")
				current.request("POST", "/connections", gin.H{"operation_id": uuid.NewString(), "tool_family": "codex", "group": "vip", "models": []string{id}, "default_model": id, "catalog_revision": regularRevision}, 409)
			}
		})
	}
}

func testLinkAuthorizationGuards(t *testing.T, db *gorm.DB, router *gin.Engine, user *model.User) {
	t.Helper()
	for _, scenario := range []string{"expired start", "single-use browser approval", "expired code", "revoked browser", "redirect and device binding", "canonical public origin"} {
		t.Run(scenario, func(t *testing.T) {
			browser, err := service.CreateLoginSession(user.Id, "password", "127.0.0.1", "link-guard-test")
			require.NoError(t, err)
			identity, err := service.ParseAccessToken(browser.AccessToken)
			require.NoError(t, err)
			device, verifier := uuid.NewString(), strings.Repeat("g", 43)
			challenge := sha256.Sum256([]byte(verifier))
			client := &linkTestClient{t: t, router: router, access: browser.AccessToken}
			if scenario == "canonical public origin" {
				t.Setenv("LINK_PUBLIC_URL", "https://PLATFORM.example:443/")
				client.origin = "https://platform.example"
			}
			start := client.request("POST", "/auth/start", gin.H{"device_id": device, "code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256", "redirect_uri": "http://127.0.0.1:12345/callback", "state": strings.Repeat("s", 43)}, 200)
			flow := start.Data["flow_token"].(string)
			if scenario == "canonical public origin" {
				assert.True(t, strings.HasPrefix(start.Data["authorize_url"].(string), "https://platform.example/link/authorize?"))
			}
			if scenario == "expired start" {
				saved, err := model.GetAuthFlow(flow, model.AuthFlowMatch{Purpose: "link_start"})
				require.NoError(t, err)
				require.NoError(t, db.Model(saved).Update("expires_at", time.Now().Add(-time.Second)).Error)
				client.request("POST", "/auth/complete", gin.H{"flow_token": flow}, 401)
				return
			}
			complete := client.request("POST", "/auth/complete", gin.H{"flow_token": flow}, 200)
			if scenario == "canonical public origin" {
				return
			}
			if scenario == "single-use browser approval" {
				client.request("POST", "/auth/complete", gin.H{"flow_token": flow}, 401)
				return
			}
			callback, err := url.Parse(complete.Data["callback_url"].(string))
			require.NoError(t, err)
			request := gin.H{"code": callback.Query().Get("code"), "code_verifier": verifier, "redirect_uri": "http://127.0.0.1:12345/callback", "device_id": device}
			client.access = ""
			switch scenario {
			case "expired code":
				saved, err := model.GetAuthFlow(request["code"].(string), model.AuthFlowMatch{Purpose: "link_code"})
				require.NoError(t, err)
				require.NoError(t, db.Model(saved).Update("expires_at", time.Now().Add(-time.Second)).Error)
				client.request("POST", "/auth/exchange", request, 401)
			case "revoked browser":
				_, err := model.RevokeUserSession(user.Id, identity.SessionID, "test")
				require.NoError(t, err)
				client.request("POST", "/auth/exchange", request, 401)
			case "redirect and device binding":
				request["redirect_uri"] = "http://127.0.0.1:23456/callback"
				client.request("POST", "/auth/exchange", request, 401)
				request["redirect_uri"], request["device_id"] = "http://127.0.0.1:12345/callback", uuid.NewString()
				client.request("POST", "/auth/exchange", request, 401)
				request["device_id"] = device
				client.request("POST", "/auth/exchange", request, 200)
			}
		})
	}
}

func testLinkWorkBuddyLiveCatalog(t *testing.T, db *gorm.DB, client *linkTestClient) {
	t.Helper()
	t.Setenv("LINK_MODEL_CATALOG_FILE", "")
	baseline := client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200)
	require.Len(t, baseline.Data["models"], 2)
	assert.Empty(t, baseline.Data["models"].([]any)[0].(map[string]any)["metadata"])
	client.request("GET", "/catalog?tool_family=workbuddy&group=not-authorized", nil, 403)

	customSettings := `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/chat/completions","upstream_path":"/chat","models":["custom-chat"]},{"incoming_path":"/v1/responses","upstream_path":"/responses","models":["custom-response"]}]}}`
	cases := []struct {
		name, group, settings string
		channelType, status   int
		enabled               bool
	}{
		{"glm-5.2", "default", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true},
		{"opaque-alias", "default", "", constant.ChannelTypeAnthropic, common.ChannelStatusEnabled, true},
		{"dall-e-3", "default", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true},
		{"text-embedding-3-large", "default", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true},
		{"rerank-v3.5", "default", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true},
		{"group-isolated", "default", "", constant.ChannelTypeCodex, common.ChannelStatusEnabled, true},
		{"group-isolated", "vip", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true},
		{"disabled-channel", "default", "", constant.ChannelTypeOpenAI, common.ChannelStatusManuallyDisabled, true},
		{"disabled-ability", "default", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, false},
		{"custom-chat", "default", customSettings, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, true},
		{"chat-about-embeddings", "default", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/chat/completions","upstream_path":"/chat","models":["chat-about-embeddings"]}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, true},
		{"custom-response", "default", customSettings, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, true},
		{"invalid-settings", "default", "invalid-json", constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, true},
	}
	channelIDs := make([]int, 0, len(cases))
	t.Cleanup(func() {
		require.NoError(t, db.Where("channel_id IN ?", channelIDs).Delete(&model.Ability{}).Error)
		require.NoError(t, db.Where("id IN ?", channelIDs).Delete(&model.Channel{}).Error)
	})
	for _, tc := range cases {
		channel := model.Channel{Type: tc.channelType, Status: tc.status, Name: tc.name, Key: "unused", OtherSettings: tc.settings}
		require.NoError(t, db.Create(&channel).Error)
		channelIDs = append(channelIDs, channel.Id)
		require.NoError(t, db.Create(&model.Ability{Group: tc.group, Model: tc.name, ChannelId: channel.Id, Enabled: tc.enabled}).Error)
	}
	catalog := client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200)
	var names []string
	for _, item := range catalog.Data["models"].([]any) {
		entry := item.(map[string]any)
		names = append(names, entry["id"].(string))
		assert.Equal(t, "openai_chat_completions", entry["protocol"])
		assert.Empty(t, entry["metadata"], "native protocol support does not prove tool, image or reasoning capabilities")
	}
	assert.Equal(t, []string{"chat-about-embeddings", "custom-chat", "glm-5.2", "opaque-alias", "verified-model", "verified-second"}, names)
	assert.Equal(t, "chat-about-embeddings", catalog.Data["default_model"])
	assert.Equal(t, catalog.Data["revision"], client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200).Data["revision"])
	vip := client.request("GET", "/catalog?tool_family=workbuddy&group=vip", nil, 200)
	assert.Equal(t, "group-isolated", vip.Data["models"].([]any)[0].(map[string]any)["id"], "chat endpoint in another group cannot leak into the selected group")
	var unchanged model.Channel
	require.NoError(t, db.First(&unchanged, channelIDs[len(channelIDs)-1]).Error)
	assert.Equal(t, "invalid-json", unchanged.OtherSettings, "catalog reads must not rewrite malformed channel settings")
	created := client.request("POST", "/connections", gin.H{"operation_id": uuid.NewString(), "tool_family": "workbuddy", "config_scope": "catalog-test", "group": "default", "models": []string{"glm-5.2"}, "default_model": "glm-5.2", "catalog_revision": catalog.Data["revision"]}, 200)
	pending := linkConnectionFrom(t, created)

	// A live route disappearing invalidates an unconfirmed selection and cannot
	// be used by posting a previously displayed model with a fresh revision.
	require.NoError(t, db.Model(&model.Channel{}).Where("id = ?", channelIDs[0]).Update("status", common.ChannelStatusManuallyDisabled).Error)
	current := client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200)
	assert.NotEqual(t, catalog.Data["revision"], current.Data["revision"])
	request := gin.H{"operation_id": uuid.NewString(), "tool_family": "workbuddy", "config_scope": "default", "group": "default", "models": []string{"glm-5.2"}, "default_model": "glm-5.2", "catalog_revision": catalog.Data["revision"]}
	assert.Equal(t, "LINK_CATALOG_CHANGED", client.request("POST", "/connections", request, 409).Code)
	request["operation_id"], request["catalog_revision"] = uuid.NewString(), current.Data["revision"]
	assert.Equal(t, "LINK_INVALID_REQUEST", client.request("POST", "/connections", request, 400).Code)
	client.request("POST", "/connections/"+pending["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "commit", "expected_revision": pending["revision"]}, 400)
	linkAction(t, client, pending, "abort", nil)

	// A broken or unrelated optional file is not a model availability policy.
	path := filepath.Join(t.TempDir(), "optional.json")
	t.Setenv("LINK_MODEL_CATALOG_FILE", path)
	for _, content := range []string{"invalid-json", `{"models":[]}`} {
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
		assert.Equal(t, current.Data["revision"], client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200).Data["revision"])
	}
	capabilities := `{"models":[{"id":"verified-model","protocol":"openai_chat_completions","tool_families":["workbuddy"],"groups":["default"],"metadata":{"workbuddy":{"supportsToolCall":false,"supportsImages":"true","supportsReasoning":true,"maxInputTokens":0,"maxOutputTokens":2048}}}]}`
	require.NoError(t, os.WriteFile(path, []byte(capabilities), 0600))
	withMetadata := client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200)
	assert.NotEqual(t, current.Data["revision"], withMetadata.Data["revision"])
	for _, item := range withMetadata.Data["models"].([]any) {
		entry := item.(map[string]any)
		if entry["id"] == "verified-model" {
			assert.Equal(t, map[string]any{"workbuddy": map[string]any{"supportsToolCall": false, "supportsReasoning": true, "maxOutputTokens": float64(2048)}}, entry["metadata"])
		}
	}
}

func testLinkLiveToolCatalogs(t *testing.T, db *gorm.DB, client *linkTestClient) {
	t.Helper()
	t.Setenv("LINK_MODEL_CATALOG_FILE", "")
	priorPassThrough := model_setting.GetGlobalSettings().PassThroughRequestEnabled
	model_setting.GetGlobalSettings().PassThroughRequestEnabled = false
	t.Cleanup(func() { model_setting.GetGlobalSettings().PassThroughRequestEnabled = priorPassThrough })
	passthrough := `{"pass_through_body_enabled":true}`
	cases := []struct {
		name, group, setting, other string
		channelType, status         int
		code, desktop, chat         bool
	}{
		{"claude-opus-4-8", "default", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true, true, true},
		{"new-chat-model", "default", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true, false, true},
		{"claude-gpt-mixed", "default", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true, false, true},
		{"opus", "default", "", "", constant.ChannelTypeAnthropic, common.ChannelStatusEnabled, true, false, true},
		{"claude-disabled", "default", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusManuallyDisabled, false, false, false},
		{"claude-other-group", "vip", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, false, false, false},
		{"claude-xai", "default", "", "", constant.ChannelTypeXai, common.ChannelStatusEnabled, false, false, true},
		{"claude-passthrough", "default", passthrough, "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, false, false, true},
		{"claude-aws-passthrough", "default", passthrough, "", constant.ChannelTypeAws, common.ChannelStatusEnabled, false, false, false},
		{"claude-mixed-routes", "default", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, false, false, true},
		{"claude-mixed-routes", "default", "", "", constant.ChannelTypeXai, common.ChannelStatusEnabled, false, false, true},
		{"claude-group-isolated", "default", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true, true, true},
		{"claude-chat-only", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/chat/completions","upstream_path":"/chat"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, false, false, true},
		{"claude-route", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/messages","upstream_path":"/messages"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, true, true, false},
		{"claude-converted-route", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/messages","upstream_path":"/chat","converter":"anthropic_messages_to_openai_chat_completions"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, true, true, false},
		{"claude-blocked-route", "default", passthrough, `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/messages","upstream_path":"/chat","converter":"anthropic_messages_to_openai_chat_completions"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, false, false, false},
		{"claude-malformed-setting", "default", "invalid-json", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, false, false, false},
		{"gemini-2.5-flash", "default", "", "", constant.ChannelTypeVertexAi, common.ChannelStatusEnabled, false, false, true},
		{"amazon.nova-pro-v1:0", "default", "", "", constant.ChannelTypeAws, common.ChannelStatusEnabled, false, false, true},
		{"sonnet[1m]", "default", "", "", constant.ChannelTypeAnthropic, common.ChannelStatusEnabled, true, false, true},
		{"claude-sonnet-4[1M]", "default", "", "", constant.ChannelTypeAnthropic, common.ChannelStatusEnabled, true, false, true},
		{" claude-sonnet-4 ", "default", "", "", constant.ChannelTypeAnthropic, common.ChannelStatusEnabled, true, false, true},
		{"claude-chat-mixed", "default", "", "", constant.ChannelTypeOpenAI, common.ChannelStatusEnabled, true, true, false},
		{"claude-chat-mixed", "default", passthrough, "", constant.ChannelTypeAnthropic, common.ChannelStatusEnabled, true, true, false},
		{"claude-native-passthrough", "default", passthrough, "", constant.ChannelTypeAnthropic, common.ChannelStatusEnabled, true, true, false},
		{"chat-converted", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/chat/completions","upstream_path":"/messages","converter":"openai_chat_completions_to_anthropic_messages"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, false, false, true},
		{"chat-converted-passthrough", "default", passthrough, `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/chat/completions","upstream_path":"/messages","converter":"openai_chat_completions_to_anthropic_messages"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, false, false, false},
		{"claude-native-a", "default", passthrough, "", constant.ChannelTypeDeepSeek, common.ChannelStatusEnabled, true, true, true},
		{"claude-native-b", "default", passthrough, "", constant.ChannelTypeMoonshot, common.ChannelStatusEnabled, true, true, true},
		{"native-chat-c", "default", passthrough, "", constant.ChannelTypeSiliconFlow, common.ChannelStatusEnabled, false, false, true},
		{"claude-native-d", "default", passthrough, "", constant.ChannelTypeMiniMax, common.ChannelStatusEnabled, true, true, true},
		{"claude-native-e", "default", passthrough, "", constant.ChannelTypeZhipu_v4, common.ChannelStatusEnabled, true, true, true},
		{"claude-native-f", "default", passthrough, "", constant.ChannelTypeOllama, common.ChannelStatusEnabled, true, true, false},
		{"claude-native-g", "default", passthrough, `{"ollama_openai_chat":true}`, constant.ChannelTypeOllama, common.ChannelStatusEnabled, true, true, true},
		{"native-chat-h", "default", "", "", constant.ChannelTypeDeepSeek, common.ChannelStatusEnabled, true, false, true},
		{"native-chat-i", "default", "", "", constant.ChannelTypeSiliconFlow, common.ChannelStatusEnabled, true, false, true},
		{"native-chat-j", "default", "", `{"ollama_openai_chat":true}`, constant.ChannelTypeOllama, common.ChannelStatusEnabled, true, false, true},
		{"claude-invalid-converter", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/messages","upstream_path":"/chat","converter":"claude_messages_to_openai_chat"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, false, false, false},
		{constant.DeepSeekSearchModel, "default", "", "", constant.ChannelTypeDeepSeek, common.ChannelStatusEnabled, false, false, false},
		{constant.DeepSeekFetchModel, "default", "", "", constant.ChannelTypeDeepSeek, common.ChannelStatusEnabled, false, false, false},
		{constant.DeepSeekSearchModel, "default", "", "", constant.ChannelTypeNewAPI, common.ChannelStatusEnabled, false, false, false},
		{constant.DeepSeekFetchModel, "default", "", "", constant.ChannelTypeNewAPI, common.ChannelStatusEnabled, false, false, false},
		{constant.DeepSeekSearchModel, "vip", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/messages","upstream_path":"/messages"},{"incoming_path":"/v1/chat/completions","upstream_path":"/chat"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, false, false, false},
		{constant.DeepSeekFetchModel, "vip", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/messages","upstream_path":"/messages"},{"incoming_path":"/v1/chat/completions","upstream_path":"/chat"}]}}`, constant.ChannelTypeAdvancedCustom, common.ChannelStatusEnabled, false, false, false},
	}
	var channelIDs []int
	t.Cleanup(func() {
		require.NoError(t, db.Where("channel_id IN ?", channelIDs).Delete(&model.Ability{}).Error)
		require.NoError(t, db.Where("id IN ?", channelIDs).Delete(&model.Channel{}).Error)
	})
	for _, tc := range cases {
		channel := model.Channel{Type: tc.channelType, Status: tc.status, Name: tc.name, Key: "unused", Setting: &tc.setting, OtherSettings: tc.other}
		require.NoError(t, db.Create(&channel).Error)
		channelIDs = append(channelIDs, channel.Id)
		require.NoError(t, db.Create(&model.Ability{Group: tc.group, Model: tc.name, ChannelId: channel.Id, Enabled: true}).Error)
	}
	// An incompatible route in another group cannot hide this group's model.
	require.NoError(t, db.Create(&model.Ability{Group: "vip", Model: "claude-group-isolated", ChannelId: channelIDs[6], Enabled: true}).Error)
	// An advanced channel without this incoming path is not a selectable competitor.
	require.NoError(t, db.Create(&model.Ability{Group: "default", Model: "claude-opus-4-8", ChannelId: channelIDs[12], Enabled: true}).Error)
	for _, tool := range []string{"hermes", "workbuddy", "claude_code", "claude_desktop"} {
		t.Run(tool, func(t *testing.T) {
			catalog := client.request("GET", "/catalog?tool_family="+tool+"&group=default", nil, 200)
			names := make(map[string]bool)
			for _, item := range catalog.Data["models"].([]any) {
				entry := item.(map[string]any)
				names[entry["id"].(string)] = true
				assert.Empty(t, entry["metadata"], "a live route needs no manually maintained compatibility entry")
				protocol := "anthropic_messages"
				if tool == "hermes" || tool == "workbuddy" {
					protocol = "openai_chat_completions"
				}
				assert.Equal(t, protocol, entry["protocol"])
			}
			for _, tc := range cases {
				want := tc.code
				if tool == "claude_desktop" {
					want = tc.desktop
				}
				if tool == "hermes" || tool == "workbuddy" {
					want = tc.chat
				}
				assert.Equal(t, want, names[tc.name], "%s: %s", tool, tc.name)
			}
			path := filepath.Join(t.TempDir(), "optional.json")
			t.Setenv("LINK_MODEL_CATALOG_FILE", path)
			for _, content := range []string{"invalid-json", `{"models":[]}`} {
				require.NoError(t, os.WriteFile(path, []byte(content), 0600))
				assert.Equal(t, catalog.Data["revision"], client.request("GET", "/catalog?tool_family="+tool+"&group=default", nil, 200).Data["revision"])
			}
			created := client.request("POST", "/connections", gin.H{"operation_id": uuid.NewString(), "tool_family": tool, "config_scope": "live-catalog", "group": "default", "models": []string{"claude-opus-4-8"}, "default_model": "claude-opus-4-8", "catalog_revision": catalog.Data["revision"]}, 200)
			linkAction(t, client, linkConnectionFrom(t, created), "abort", nil)
		})
	}
	var untouched model.Channel
	require.NoError(t, db.First(&untouched, channelIDs[16]).Error)
	require.NotNil(t, untouched.Setting)
	assert.Equal(t, "invalid-json", *untouched.Setting, "catalog reads must not repair or overwrite channel settings")
	beforeRemoval := client.request("GET", "/catalog?tool_family=claude_desktop&group=default", nil, 200)
	created := client.request("POST", "/connections", gin.H{"operation_id": uuid.NewString(), "tool_family": "claude_desktop", "config_scope": "removed-route", "group": "default", "models": []string{"claude-opus-4-8"}, "default_model": "claude-opus-4-8", "catalog_revision": beforeRemoval.Data["revision"]}, 200)
	pending := linkConnectionFrom(t, created)
	require.NoError(t, db.Model(&model.Channel{}).Where("id = ?", channelIDs[0]).Update("status", common.ChannelStatusManuallyDisabled).Error)
	assert.NotEqual(t, beforeRemoval.Data["revision"], client.request("GET", "/catalog?tool_family=claude_desktop&group=default", nil, 200).Data["revision"])
	client.request("POST", "/connections/"+pending["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "commit", "expected_revision": pending["revision"]}, 400)
	linkAction(t, client, pending, "abort", nil)
	require.NoError(t, db.Model(&model.Channel{}).Where("id = ?", channelIDs[0]).Update("status", common.ChannelStatusEnabled).Error)
	model_setting.GetGlobalSettings().PassThroughRequestEnabled = true
	for _, tool := range []string{"claude_code", "claude_desktop", "hermes", "workbuddy"} {
		catalog := client.request("GET", "/catalog?tool_family="+tool+"&group=default", nil, 200)
		var names []string
		for _, item := range catalog.Data["models"].([]any) {
			names = append(names, item.(map[string]any)["id"].(string))
		}
		assert.NotContains(t, names, constant.DeepSeekSearchModel)
		assert.NotContains(t, names, constant.DeepSeekFetchModel)
		if tool == "hermes" || tool == "workbuddy" {
			assert.Contains(t, names, "claude-opus-4-8", "native chat routes remain usable with global passthrough")
			assert.NotContains(t, names, "claude-native-passthrough", "chat requests still require conversion for an Anthropic channel")
			assert.NotContains(t, names, "claude-chat-mixed", "one compatible route cannot hide a selectable incompatible route")
			assert.NotContains(t, names, "chat-converted", "global passthrough cannot skip a required advanced route conversion")
			assert.Contains(t, names, "native-chat-h", "DeepSeek has a native chat request body")
			assert.Contains(t, names, "native-chat-i", "SiliconFlow has a native chat request body")
			assert.Contains(t, names, "native-chat-j", "Ollama explicitly configured for OpenAI chat needs no envelope conversion")
			assert.NotContains(t, names, "claude-native-f", "default Ollama chat still requires its native envelope")
		} else {
			assert.NotContains(t, names, "claude-opus-4-8")
			assert.NotContains(t, names, "claude-converted-route")
			assert.Contains(t, names, "claude-native-a", "native messages endpoints remain usable with passthrough")
			assert.Contains(t, names, "claude-native-b")
			assert.Contains(t, names, "claude-native-d")
			assert.Contains(t, names, "claude-native-e")
			assert.Contains(t, names, "claude-native-f")
		}
	}
	for _, tool := range []string{"hermes", "workbuddy", "claude_code"} {
		catalog := client.request("GET", "/catalog?tool_family="+tool+"&group=vip", nil, 200)
		var names []string
		for _, item := range catalog.Data["models"].([]any) {
			names = append(names, item.(map[string]any)["id"].(string))
		}
		assert.Contains(t, names, constant.DeepSeekSearchModel, "an explicit generation route can serve this alias in another group")
		assert.Contains(t, names, constant.DeepSeekFetchModel)
	}
}

func testLinkWorkBuddyWorkflow(t *testing.T, db *gorm.DB, client, otherDevice, otherUser *linkTestClient) {
	t.Helper()
	t.Run("live_routes", func(t *testing.T) { testLinkWorkBuddyLiveCatalog(t, db, client) })
	catalogPath := filepath.Join(t.TempDir(), "workbuddy-catalog.json")
	entries := []gin.H{
		{"id": "verified-second", "protocol": "openai_chat_completions", "tool_families": []string{"workbuddy"}, "groups": []string{"default", "vip"}, "metadata": gin.H{"workbuddy": gin.H{"supportsToolCall": true, "supportsImages": false, "supportsReasoning": false, "maxInputTokens": 8192}}},
		{"id": "verified-model", "protocol": "openai_chat_completions", "tool_families": []string{"workbuddy", "hermes"}, "groups": []string{"default", "vip"}},
		{"id": "not-on-channel", "protocol": "openai_chat_completions", "tool_families": []string{"workbuddy"}, "groups": []string{"default", "vip"}},
	}
	raw, err := common.Marshal(gin.H{"models": entries})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(catalogPath, raw, 0600))
	t.Setenv("LINK_MODEL_CATALOG_FILE", catalogPath)
	catalog := client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200)
	assert.Equal(t, "workbuddy", catalog.Data["tool_family"])
	assert.Equal(t, "verified-model", catalog.Data["default_model"])
	models := catalog.Data["models"].([]any)
	require.Len(t, models, 2)
	for _, item := range models {
		assert.Equal(t, "openai_chat_completions", item.(map[string]any)["protocol"])
	}
	assert.Equal(t, map[string]any{"workbuddy": map[string]any{"supportsToolCall": true, "supportsImages": false, "supportsReasoning": false, "maxInputTokens": float64(8192)}}, models[1].(map[string]any)["metadata"], "verified capability metadata must reach the adapter unchanged")
	hermesCatalog := client.request("GET", "/catalog?tool_family=hermes&group=default", nil, 200)
	assert.Len(t, hermesCatalog.Data["models"], 2, "Hermes uses live chat routes independently of optional compatibility metadata")
	assert.NotEqual(t, catalog.Data["revision"], hermesCatalog.Data["revision"])
	entries[0]["protocol"] = "openai_responses"
	invalid, err := common.Marshal(gin.H{"models": entries})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(catalogPath, invalid, 0600))
	invalidMetadata := client.request("GET", "/catalog?tool_family=workbuddy&group=default", nil, 200)
	assert.Len(t, invalidMetadata.Data["models"], 2, "bad optional metadata cannot hide a native chat route")
	assert.Empty(t, invalidMetadata.Data["models"].([]any)[1].(map[string]any)["metadata"])
	require.NoError(t, os.WriteFile(catalogPath, raw, 0600))

	hermesCreated := client.request("POST", "/connections", gin.H{"operation_id": uuid.NewString(), "tool_family": "hermes", "config_scope": "default", "group": "default", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": hermesCatalog.Data["revision"]}, 200)
	hermesConn := linkConnectionFrom(t, linkAction(t, client, linkConnectionFrom(t, hermesCreated), "commit", nil))
	create := gin.H{"operation_id": uuid.NewString(), "tool_family": "workbuddy", "config_scope": "default", "group": "default", "models": []string{"verified-model", "verified-second"}, "default_model": "verified-second", "catalog_revision": catalog.Data["revision"]}
	created := client.request("POST", "/connections", create, 200)
	retried := client.request("POST", "/connections", create, 200)
	assert.Equal(t, created.Data["token_id"], retried.Data["token_id"])
	assert.Equal(t, created.Data["api_key"], retried.Data["api_key"])
	conn := linkConnectionFrom(t, linkAction(t, client, linkConnectionFrom(t, created), "commit", nil))
	assert.Equal(t, "workbuddy", conn["tool_family"])
	assert.NotEqual(t, hermesConn["id"], conn["id"], "same device and config scope must keep independent tool connections")
	assert.NotEqual(t, hermesCreated.Data["token_id"], created.Data["token_id"])
	tokenID := int(created.Data["token_id"].(float64))
	var original, candidate model.Token
	require.NoError(t, db.First(&original, tokenID).Error)
	assert.True(t, original.AllowUserQuotaQuery, "new desktop keys follow the native key creation default")
	// A later website restriction must survive pause/resume, switching and retirement.
	require.NoError(t, db.Model(&model.Token{}).Where("id = ?", tokenID).Update("allow_user_quota_query", false).Error)
	endpoint := "/connections/" + conn["id"].(string)
	for _, unauthorized := range []*linkTestClient{otherDevice, otherUser} {
		unauthorized.request("GET", endpoint, nil, 404)
		unauthorized.request("GET", "/operations/"+create["operation_id"].(string), nil, 404)
		unauthorized.request("POST", endpoint+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "disconnect", "expected_revision": conn["revision"]}, 404)
	}
	// No trusted WorkBuddy executor exists; a management session cannot claim a tool run.
	client.request("POST", endpoint+"/tool-verifications", gin.H{"expected_revision": conn["revision"], "target": "workbuddy", "model": "verified-second", "protocol": "openai_chat_completions"}, 400)
	client.request("POST", endpoint+"/tool-verifications", gin.H{"expected_revision": conn["revision"], "target": "hermes", "model": "verified-second", "protocol": "openai_chat_completions"}, 409)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "pause", nil))
	assert.Equal(t, "paused", conn["status"])
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "resume", nil))
	assert.Equal(t, "active", conn["status"])
	require.NoError(t, db.First(&original, tokenID).Error)
	assert.False(t, original.AllowUserQuotaQuery, "pause/resume must not reset an existing key's privacy setting")
	vip := client.request("GET", "/catalog?tool_family=workbuddy&group=vip", nil, 200)
	prepared := linkAction(t, client, conn, "prepare_switch", gin.H{"group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": vip.Data["revision"]})
	conn = linkConnectionFrom(t, prepared)
	candidateID := int(prepared.Data["token_id"].(float64))
	assert.NotEqual(t, tokenID, candidateID)
	require.NoError(t, db.First(&original, tokenID).Error)
	assert.Equal(t, common.TokenStatusEnabled, original.Status, "old key remains usable until switch commits")
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "commit", nil))
	require.NoError(t, db.First(&original, tokenID).Error)
	require.NoError(t, db.First(&candidate, candidateID).Error)
	assert.Equal(t, "default", original.Group)
	assert.Equal(t, common.TokenStatusDisabled, original.Status)
	assert.False(t, original.AllowUserQuotaQuery)
	assert.Equal(t, "vip", candidate.Group)
	assert.Equal(t, common.TokenStatusEnabled, candidate.Status)
	assert.True(t, candidate.UnlimitedQuota)
	assert.True(t, candidate.AllowUserQuotaQuery, "switching creates independent native defaults instead of copying old key restrictions")
	assert.Equal(t, int64(-1), candidate.ExpiredTime)
	assert.False(t, candidate.ModelLimitsEnabled)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "disconnect", nil))
	assert.Equal(t, "disconnected", conn["status"])
	require.NoError(t, db.First(&candidate, candidateID).Error)
	assert.Equal(t, common.TokenStatusDisabled, candidate.Status)
	assert.True(t, candidate.AllowUserQuotaQuery, "disconnect changes status only")
	var hermesToken model.Token
	require.NoError(t, db.First(&hermesToken, int(hermesCreated.Data["token_id"].(float64))).Error)
	assert.Equal(t, common.TokenStatusEnabled, hermesToken.Status, "WorkBuddy lifecycle cannot disable another tool's key")
	assert.Equal(t, "active", client.request("GET", "/connections/"+hermesConn["id"].(string), nil, 200).Data["status"])
	linkAction(t, client, hermesConn, "disconnect", nil)
}

// This is the released connection schema before the registry protocol binding.
// An isolated table lets the same real-database test exercise upgrade and fresh
// creation without altering other fixtures or relying on an empty database.
type linkConnectionBeforeRegistry struct {
	ID               string `gorm:"type:varchar(36);primaryKey"`
	ScopeHash        string `gorm:"type:char(64);not null;uniqueIndex"`
	UserID           int    `gorm:"not null;index"`
	DeviceID         string `gorm:"type:varchar(36);not null;index"`
	ToolFamily       string `gorm:"type:varchar(32);not null"`
	ConfigScope      string `gorm:"type:varchar(128);not null"`
	Status           string `gorm:"type:varchar(20);not null"`
	Revision         int64  `gorm:"not null"`
	ActiveTokenID    int
	CandidateTokenID int
	CreatedAt        int64
	UpdatedAt        int64
}

func testLinkRegistryMigration(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, upgrade := range []bool{false, true} {
		name := "registry_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
		t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(name)) })
		before := linkConnectionBeforeRegistry{ID: uuid.NewString(), ScopeHash: strings.Repeat("a", 64), UserID: 15, DeviceID: uuid.NewString(), ToolFamily: "hermes", ConfigScope: "default", Status: "active", Revision: 7, ActiveTokenID: 31, CandidateTokenID: 32, CreatedAt: 1700000000, UpdatedAt: 1700000001}
		if upgrade {
			require.NoError(t, db.Table(name).AutoMigrate(&linkConnectionBeforeRegistry{}))
			require.NoError(t, db.Table(name).Create(&before).Error)
		}
		for range 2 {
			require.NoError(t, db.Table(name).AutoMigrate(&model.LinkConnection{}))
		}
		if !upgrade {
			require.NoError(t, db.Table(name).Create(&before).Error)
		}
		var preserved linkConnectionBeforeRegistry
		require.NoError(t, db.Table(name).First(&preserved, "id = ?", before.ID).Error)
		assert.Equal(t, before, preserved, "all released connection fields survive both migrations")
		var current model.LinkConnection
		require.NoError(t, db.Table(name).First(&current, "id = ?", before.ID).Error)
		assert.Empty(t, current.ToolProtocol, "old connections are not assigned an invented protocol by DDL")
		require.True(t, db.Migrator().HasColumn(name, "tool_protocol"))
		for _, field := range []string{"scope_hash", "user_id", "device_id"} {
			assert.True(t, db.Migrator().HasIndex(name, "idx_"+name+"_"+field), "preserve %s index", field)
		}
		current.ID = uuid.NewString()
		assert.Error(t, db.Table(name).Create(&current).Error, "scope uniqueness survives migration")
		current.ID, current.ScopeHash = before.ID, strings.Repeat("b", 64)
		assert.Error(t, db.Table(name).Create(&current).Error, "primary-key uniqueness survives migration")
		require.NoError(t, db.Table(name).Where("id = ?", before.ID).Update("tool_protocol", "openai_chat_completions").Error)
		for range 2 {
			require.NoError(t, db.Table(name).AutoMigrate(&model.LinkConnection{}))
		}
		current = model.LinkConnection{}
		require.NoError(t, db.Table(name).First(&current, "id = ?", before.ID).Error)
		assert.Equal(t, "openai_chat_completions", current.ToolProtocol, "restart retains the pinned protocol")
	}
}

func testLinkRegisteredResponsesCatalog(t *testing.T, db *gorm.DB, client *linkTestClient) {
	t.Helper()
	registry := filepath.Join(t.TempDir(), "responses-tools.json")
	require.NoError(t, os.WriteFile(registry, []byte(`{"version":1,"tools":[{"id":"responses_agent","protocol":"openai_responses"}]}`), 0600))
	t.Setenv("LINK_TOOL_REGISTRY_FILE", registry)
	t.Setenv("LINK_MODEL_CATALOG_FILE", "")
	priorPassThrough := model_setting.GetGlobalSettings().PassThroughRequestEnabled
	t.Cleanup(func() { model_setting.GetGlobalSettings().PassThroughRequestEnabled = priorPassThrough })
	model_setting.GetGlobalSettings().PassThroughRequestEnabled = false
	passthrough := `{"pass_through_body_enabled":true}`
	cases := []struct {
		name, group, setting, settings string
		channelType                    int
		normal, globalPass             bool
	}{
		{"responses-chat-tagged", "default", "", "", constant.ChannelTypeOpenAI, true, true},
		{"responses-anthropic", "default", "", "", constant.ChannelTypeAnthropic, true, false},
		{"responses-gemini", "default", "", "", constant.ChannelTypeGemini, true, false},
		{"responses-anthropic-raw", "default", passthrough, "", constant.ChannelTypeAnthropic, false, false},
		{"responses-aws", "default", "", "", constant.ChannelTypeAws, false, false},
		{"responses-silicon", "default", "", "", constant.ChannelTypeSiliconFlow, false, false},
		{"responses-codex", "default", "", "", constant.ChannelTypeCodex, true, false},
		{"responses-native-route", "default", passthrough, `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/responses","upstream_path":"/responses"}]}}`, constant.ChannelTypeAdvancedCustom, true, true},
		{"responses-converted", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/responses","upstream_path":"/chat","converter":"openai_responses_to_openai_chat_completions"}]}}`, constant.ChannelTypeAdvancedCustom, true, false},
		{"responses-first-route", "default", passthrough, `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/responses","upstream_path":"/chat","converter":"openai_responses_to_openai_chat_completions"},{"incoming_path":"/v1/responses","upstream_path":"/responses"}]}}`, constant.ChannelTypeAdvancedCustom, false, false},
		{"responses-mixed", "default", "", "", constant.ChannelTypeOpenAI, false, false},
		{"responses-mixed", "default", "", "", constant.ChannelTypeAws, false, false},
		{"responses-isolated", "default", "", "", constant.ChannelTypeOpenAI, true, true},
		{"responses-isolated", "vip", "", "", constant.ChannelTypeAws, true, true},
		{"responses-unmatched-invalid", "default", "", "", constant.ChannelTypeOpenAI, true, true},
		{"responses-unmatched-invalid", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/chat/completions","upstream_path":""}]}}`, constant.ChannelTypeAdvancedCustom, true, true},
		{"responses-matched-invalid", "default", "", "", constant.ChannelTypeOpenAI, false, false},
		{"responses-matched-invalid", "default", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/responses","upstream_path":""}]}}`, constant.ChannelTypeAdvancedCustom, false, false},
		{constant.DeepSeekSearchModel, "default", "", "", constant.ChannelTypeDeepSeek, false, false},
		{constant.DeepSeekFetchModel, "default", "", "", constant.ChannelTypeDeepSeek, false, false},
		{constant.DeepSeekSearchModel, "default", "", "", constant.ChannelTypeNewAPI, false, false},
		{constant.DeepSeekFetchModel, "default", "", "", constant.ChannelTypeNewAPI, false, false},
		{constant.DeepSeekSearchModel, "vip", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/responses","upstream_path":"/responses"}]}}`, constant.ChannelTypeAdvancedCustom, false, false},
		{constant.DeepSeekFetchModel, "vip", "", `{"advanced_custom":{"advanced_routes":[{"incoming_path":"/v1/responses","upstream_path":"/responses"}]}}`, constant.ChannelTypeAdvancedCustom, false, false},
	}
	var ids []int
	t.Cleanup(func() {
		require.NoError(t, db.Where("channel_id IN ?", ids).Delete(&model.Ability{}).Error)
		require.NoError(t, db.Where("id IN ?", ids).Delete(&model.Channel{}).Error)
	})
	for _, tc := range cases {
		channel := model.Channel{Type: tc.channelType, Status: common.ChannelStatusEnabled, Name: tc.name, Key: "unused", OtherSettings: tc.settings}
		if tc.setting != "" {
			channel.Setting = &tc.setting
		}
		require.NoError(t, db.Create(&channel).Error)
		ids = append(ids, channel.Id)
		require.NoError(t, db.Create(&model.Ability{Group: tc.group, Model: tc.name, ChannelId: channel.Id, Enabled: true}).Error)
	}
	for _, globalPass := range []bool{false, true} {
		model_setting.GetGlobalSettings().PassThroughRequestEnabled = globalPass
		catalog := client.request("GET", "/catalog?tool_family=responses_agent&group=default", nil, 200)
		names := map[string]bool{}
		for _, raw := range catalog.Data["models"].([]any) {
			entry := raw.(map[string]any)
			names[entry["id"].(string)] = true
			assert.Equal(t, "openai_responses", entry["protocol"])
		}
		for _, tc := range cases {
			want := tc.normal
			if globalPass {
				want = tc.globalPass
			}
			assert.Equal(t, want, names[tc.name], "%s global pass-through=%v", tc.name, globalPass)
		}
		vip := client.request("GET", "/catalog?tool_family=responses_agent&group=vip", nil, 200)
		var aliases []string
		for _, raw := range vip.Data["models"].([]any) {
			aliases = append(aliases, raw.(map[string]any)["id"].(string))
		}
		assert.Contains(t, aliases, constant.DeepSeekSearchModel, "explicit advanced response routes remain authoritative")
		assert.Contains(t, aliases, constant.DeepSeekFetchModel)
	}
}

func testLinkConfigurableTools(t *testing.T, db *gorm.DB, client *linkTestClient) {
	t.Helper()
	t.Setenv("LINK_MODEL_CATALOG_FILE", "")
	registryPath := filepath.Join(t.TempDir(), "tools.json")
	t.Setenv("LINK_TOOL_REGISTRY_FILE", registryPath)
	definition := gin.H{"id": "registry_chat", "protocol": "openai_chat_completions", "verification_targets": []string{"registry-chat"}}
	writeRegistry := func(entries ...gin.H) {
		t.Helper()
		if entries == nil {
			entries = []gin.H{}
		}
		raw, err := common.Marshal(gin.H{"version": 1, "tools": entries})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(registryPath+".next", raw, 0600))
		require.NoError(t, os.Rename(registryPath+".next", registryPath))
	}
	writeRegistry(definition)
	catalog := client.request("GET", "/catalog?tool_family=registry_chat&group=default", nil, 200)
	client.request("GET", "/catalog?tool_family=unregistered&group=default", nil, 400)
	client.request("GET", "/catalog?tool_family=registry_chat&group=not-authorized", nil, 403)
	create := gin.H{"operation_id": uuid.NewString(), "tool_family": "registry_chat", "config_scope": "default", "group": "default", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": catalog.Data["revision"]}
	created := client.request("POST", "/connections", create, 200)
	conn := linkConnectionFrom(t, created)
	var persisted model.LinkConnection
	require.NoError(t, db.First(&persisted, "id = ?", conn["id"]).Error)
	assert.Equal(t, "openai_chat_completions", persisted.ToolProtocol)
	writeRegistry(definition, gin.H{"id": "unrelated_agent", "protocol": "anthropic_messages"})
	assert.Equal(t, catalog.Data["revision"], client.request("GET", "/catalog?tool_family=registry_chat&group=default", nil, 200).Data["revision"], "unrelated additions do not invalidate a displayed selection")
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "commit", nil))
	tokenID := int(created.Data["token_id"].(float64))
	// A metadata-only definition change invalidates selections, not existing keys.
	definition["verification_targets"] = []string{"registry-chat", "registry-chat-alt"}
	writeRegistry(definition)
	changed := client.request("GET", "/catalog?tool_family=registry_chat&group=default", nil, 200)
	assert.NotEqual(t, catalog.Data["revision"], changed.Data["revision"])
	stale := gin.H{"operation_id": uuid.NewString(), "tool_family": "registry_chat", "config_scope": "stale", "group": "default", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": catalog.Data["revision"]}
	assert.Equal(t, "LINK_CATALOG_CHANGED", client.request("POST", "/connections", stale, 409).Code)
	for _, mode := range []string{"disabled", "removed", "malformed", "protocol_changed"} {
		t.Run(mode, func(t *testing.T) {
			status := 400
			switch mode {
			case "disabled":
				definition["enabled"] = false
				writeRegistry(definition)
				delete(definition, "enabled")
			case "removed":
				writeRegistry()
			case "malformed":
				require.NoError(t, os.WriteFile(registryPath, []byte("{"), 0600))
				status = 503
			case "protocol_changed":
				definition["protocol"] = "anthropic_messages"
				writeRegistry(definition)
				definition["protocol"] = "openai_chat_completions"
				status = 409
			}
			// Successful operation replay must not reauthorize or issue a replacement key.
			replay := client.request("POST", "/connections", create, 200)
			assert.Equal(t, created.Data["token_id"], replay.Data["token_id"])
			client.request("GET", "/connections/"+conn["id"].(string), nil, 200)
			client.request("GET", "/operations/"+create["operation_id"].(string), nil, 200)
			for _, action := range []string{"resume", "update_models", "prepare_switch"} {
				body := gin.H{"operation_id": uuid.NewString(), "action": action, "expected_revision": conn["revision"], "group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": changed.Data["revision"]}
				client.request("POST", "/connections/"+conn["id"].(string)+"/actions", body, status)
			}
			var token model.Token
			require.NoError(t, db.First(&token, tokenID).Error)
			assert.Equal(t, common.TokenStatusEnabled, token.Status, "registry does not implicitly revoke an already issued inference key")
			conn = linkConnectionFrom(t, linkAction(t, client, conn, "pause", nil))
			writeRegistry(definition)
			conn = linkConnectionFrom(t, linkAction(t, client, conn, "resume", nil))
		})
	}
	// Candidate commit is admitted again; removal still allows abort and disconnect.
	vip := client.request("GET", "/catalog?tool_family=registry_chat&group=vip", nil, 200)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "prepare_switch", gin.H{"group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": vip.Data["revision"]}))
	writeRegistry()
	client.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "commit", "expected_revision": conn["revision"]}, 400)
	conn = linkConnectionFrom(t, linkAction(t, client, conn, "abort", nil))
	linkAction(t, client, conn, "disconnect", nil)
	// Only known released tool IDs can recover an empty protocol from old data.
	writeRegistry(definition)
	builtin := client.request("GET", "/catalog?tool_family=hermes&group=default", nil, 200)
	old := client.request("POST", "/connections", gin.H{"operation_id": uuid.NewString(), "tool_family": "hermes", "config_scope": "registry-legacy", "group": "default", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": builtin.Data["revision"]}, 200)
	legacy := linkConnectionFrom(t, old)
	require.NoError(t, db.Model(&model.LinkConnection{}).Where("id = ?", legacy["id"]).Update("tool_protocol", "").Error)
	legacy = linkConnectionFrom(t, linkAction(t, client, legacy, "commit", nil))
	persisted = model.LinkConnection{}
	require.NoError(t, db.First(&persisted, "id = ?", legacy["id"]).Error)
	assert.Equal(t, "openai_chat_completions", persisted.ToolProtocol)
	linkAction(t, client, legacy, "disconnect", nil)
}

func TestLinkAPIWorkflowAndDatabaseCompatibility(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			var driver gorm.Dialector
			switch dialect {
			case "sqlite":
				driver = sqlite.Open(filepath.Join(t.TempDir(), "link.db") + "?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)&_txlock=immediate")
			case "mysql":
				dsn := os.Getenv("TEST_MYSQL_DSN")
				if dsn == "" {
					t.Skip("TEST_MYSQL_DSN is not configured")
				}
				driver = mysql.Open(dsn)
			case "postgres":
				dsn := os.Getenv("TEST_POSTGRES_DSN")
				if dsn == "" {
					t.Skip("TEST_POSTGRES_DSN is not configured")
				}
				driver = postgres.Open(dsn)
			}
			db, err := gorm.Open(driver, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(4)
			t.Cleanup(func() { _ = sqlDB.Close() })
			priorDB, priorLOG, priorRedis, priorSecret := model.DB, model.LOG_DB, common.RedisEnabled, common.SessionSecret
			mainType, logType := common.MainDatabaseType(), common.LogDatabaseType()
			oldGroups := setting.UserUsableGroups2JSONString()
			model.DB = db
			model.LOG_DB = db
			common.RedisEnabled = false
			common.SessionSecret = "link-test-secret-not-a-real-credential"
			common.SetDatabaseTypes(common.DatabaseType(dialect), common.DatabaseType(dialect))
			t.Cleanup(func() {
				model.DB = priorDB
				model.LOG_DB = priorLOG
				common.RedisEnabled = priorRedis
				common.SessionSecret = priorSecret
				common.SetDatabaseTypes(mainType, logType)
				require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(oldGroups))
			})
			require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(`{"default":"Default","vip":"VIP"}`))
			t.Setenv("LINK_PUBLIC_URL", "http://127.0.0.1:3000")
			t.Setenv("LINK_TOOL_REGISTRY_FILE", "")
			t.Run("registry_connection_migration", func(t *testing.T) { testLinkRegistryMigration(t, db) })
			catalog := filepath.Join(t.TempDir(), "catalog.json")
			require.NoError(t, os.WriteFile(catalog, []byte(`{"models":[{"id":"verified-model","protocol":"openai_responses","tool_families":["codex"],"groups":["default","vip"],"price_text":"untrusted static quote","metadata":{"codex":{"slug":"verified-model"}}},{"id":"verified-second","protocol":"openai_responses","tool_families":["codex"],"groups":["default","vip"],"metadata":{"codex":{"slug":"verified-second"}}}]}`), 0600))
			t.Setenv("LINK_MODEL_CATALOG_FILE", catalog)
			// Representative pre-extension database with existing account and key, then upgrade twice.
			require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.UserSession{}, &model.AuthFlow{}, &model.UserAccessToken{}, &model.Ability{}, &model.Channel{}, &model.Log{}, &model.AuditLog{}))
			suffix := uuid.NewString()[:8]
			user := &model.User{Username: "link-" + suffix, Password: "unused", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1, Group: "default", AffCode: "link-" + suffix}
			require.NoError(t, db.Create(user).Error)
			existing := model.Token{UserId: user.Id, Key: strings.Repeat(strings.ReplaceAll(uuid.NewString(), "-", ""), 4), Name: "existing", Status: common.TokenStatusEnabled, UnlimitedQuota: false, RemainQuota: 153, ExpiredTime: -1, Group: "auto", CrossGroupRetry: true, UsedQuota: 23}
			require.NoError(t, existing.SetAutoGroups([]string{"default", "vip"}))
			require.NoError(t, db.Create(&existing).Error)
			for range 2 {
				require.NoError(t, db.AutoMigrate(&model.LinkSession{}, &model.LinkRefreshUse{}, &model.LinkConnection{}, &model.LinkKey{}, &model.LinkOperation{}, &model.LinkToolVerification{}))
			}
			var preserved model.Token
			require.NoError(t, db.First(&preserved, existing.Id).Error)
			assert.Equal(t, existing.Key, preserved.Key)
			assert.Equal(t, existing.UsedQuota, preserved.UsedQuota)
			assert.Equal(t, existing.AutoGroups, preserved.AutoGroups)
			assert.Equal(t, existing.Group, preserved.Group)
			assert.Equal(t, existing.RemainQuota, preserved.RemainQuota)
			assert.Equal(t, existing.CrossGroupRetry, preserved.CrossGroupRetry)
			assert.False(t, preserved.AllowUserQuotaQuery, "migrations must not enable account quota queries on an existing key")
			assert.True(t, db.Migrator().HasIndex(&model.Token{}, "Key"))
			duplicateToken := existing
			duplicateToken.Id = 0
			assert.Error(t, db.Create(&duplicateToken).Error, "native key uniqueness survives extension migrations")
			channel := &model.Channel{Type: constant.ChannelTypeOpenAI, Name: "link-test-" + suffix, Key: "unused", Status: common.ChannelStatusEnabled}
			require.NoError(t, db.Create(channel).Error)
			for _, g := range []string{"default", "vip"} {
				for _, modelID := range []string{"verified-model", "verified-second"} {
					require.NoError(t, db.Create(&model.Ability{Group: g, Model: modelID, ChannelId: channel.Id, Enabled: true}).Error)
				}
			}
			t.Cleanup(func() {
				for _, entity := range []any{&model.LinkSession{}, &model.LinkRefreshUse{}, &model.LinkOperation{}, &model.LinkToolVerification{}, &model.LinkKey{}, &model.LinkConnection{}, &model.Token{}, &model.UserSession{}, &model.UserAccessToken{}} {
					_ = db.Unscoped().Where("user_id = ?", user.Id).Delete(entity).Error
				}
				_ = db.Where("channel_id = ?", channel.Id).Delete(&model.Ability{}).Error
				_ = db.Delete(channel).Error
				_ = db.Where("user_id = ?", user.Id).Delete(&model.AuthFlow{}).Error
				_ = db.Unscoped().Delete(user).Error
			})
			var version string
			query := "select version()"
			if dialect == "sqlite" {
				query = "select sqlite_version()"
			}
			require.NoError(t, db.Raw(query).Scan(&version).Error)
			t.Logf("database=%s version=%s", dialect, version)
			router := linkTestRouter()
			testLinkAuthorizationGuards(t, db, router, user)
			device := uuid.NewString()
			client := linkTestLogin(t, router, user, device)
			t.Run("current_account_prices", func(t *testing.T) {
				testLinkLivePrices(t, db, user, client, catalog, channel.Id)
			})
			// Desktop access cannot masquerade as browser or inference credentials.
			client.request("POST", "/auth/complete", gin.H{"flow_token": "invalid"}, 401)
			unauth := &linkTestClient{t: t, router: router, access: "sk-" + existing.Key}
			unauth.request("GET", "/bootstrap", nil, 401)
			boot := client.request("GET", "/bootstrap", nil, 200)
			assert.Equal(t, device, boot.Data["device_id"])
			catalogResult := client.request("GET", "/catalog?tool_family=codex&group=default", nil, 200)
			for _, item := range catalogResult.Data["models"].([]any) {
				assert.Equal(t, "价格资料不完整；以平台计费说明为准", item.(map[string]any)["price_text"], "static compatibility metadata must not masquerade as current account pricing")
			}
			create := gin.H{"operation_id": uuid.NewString(), "tool_family": "codex", "config_scope": "default", "group": "default", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": catalogResult.Data["revision"]}
			rawCreate, err := common.Marshal(create)
			require.NoError(t, err)
			results := make(chan *httptest.ResponseRecorder, 2)
			var workers sync.WaitGroup
			startConcurrent := make(chan struct{})
			for range 2 {
				workers.Go(func() {
					<-startConcurrent
					r := httptest.NewRequest("POST", "http://127.0.0.1:3000/api/link/v1/connections", bytes.NewReader(rawCreate))
					r.RemoteAddr = "127.0.0.1:1234"
					r.Header.Set("Authorization", "Bearer "+client.access)
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					router.ServeHTTP(w, r)
					results <- w
				})
			}
			close(startConcurrent)
			workers.Wait()
			close(results)
			var created linkTestEnvelope
			var concurrentToken any
			for response := range results {
				require.Equal(t, 200, response.Code, response.Body.String())
				require.NoError(t, common.Unmarshal(response.Body.Bytes(), &created))
				if concurrentToken != nil {
					assert.Equal(t, concurrentToken, created.Data["token_id"])
				}
				concurrentToken = created.Data["token_id"]
			}
			var keyCount int64
			require.NoError(t, db.Model(&model.Token{}).Where("user_id = ?", user.Id).Count(&keyCount).Error)
			assert.Equal(t, int64(2), keyCount)
			conn := linkConnectionFrom(t, created)
			require.Equal(t, "pending", conn["status"])
			var persistedConnection model.LinkConnection
			require.NoError(t, db.First(&persistedConnection, "id = ?", conn["id"]).Error)
			for range 2 {
				require.NoError(t, db.AutoMigrate(&model.LinkSession{}, &model.LinkRefreshUse{}, &model.LinkConnection{}, &model.LinkKey{}, &model.LinkOperation{}, &model.LinkToolVerification{}))
			}
			var migratedConnection model.LinkConnection
			require.NoError(t, db.First(&migratedConnection, "id = ?", conn["id"]).Error)
			assert.Equal(t, persistedConnection, migratedConnection, "repeat migration preserves live connection and revision")
			duplicateConnection := persistedConnection
			duplicateConnection.ID = uuid.NewString()
			assert.Error(t, db.Create(&duplicateConnection).Error, "account/device/tool scope stays unique")
			apiKey := created.Data["api_key"].(string)
			firstID := int(created.Data["token_id"].(float64))
			retried := client.request("POST", "/connections", create, 200)
			assert.Equal(t, apiKey, retried.Data["api_key"])
			assert.Equal(t, created.Data["token_id"], retried.Data["token_id"])
			conflict := gin.H{}
			for k, v := range create {
				conflict[k] = v
			}
			conflict["group"] = "vip"
			assert.Equal(t, "LINK_OPERATION_CONFLICT", client.request("POST", "/connections", conflict, 409).Code)
			op := client.request("GET", "/operations/"+create["operation_id"].(string), nil, 200)
			assert.NotContains(t, op.Data, "api_key")
			secondDevice := linkTestLogin(t, router, user, uuid.NewString())
			secondDevice.request("GET", "/connections/"+conn["id"].(string), nil, 404)
			other := &model.User{Username: "other-" + suffix, Password: "unused", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1, Group: "default", AffCode: "other-" + suffix}
			require.NoError(t, db.Create(other).Error)
			t.Cleanup(func() {
				_ = db.Where("user_id = ?", other.Id).Delete(&model.LinkSession{}).Error
				_ = db.Where("user_id = ?", other.Id).Delete(&model.UserSession{}).Error
				_ = db.Where("user_id = ?", other.Id).Delete(&model.AuthFlow{}).Error
				_ = db.Unscoped().Delete(other).Error
			})
			otherClient := linkTestLogin(t, router, other, device)
			otherClient.request("GET", "/connections/"+conn["id"].(string), nil, 404)
			otherClient.request("GET", "/operations/"+create["operation_id"].(string), nil, 404)
			otherClient.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "disconnect", "expected_revision": conn["revision"]}, 404)
			desktopSession, err := model.ValidateLinkSession(client.access)
			require.NoError(t, err)
			require.Equal(t, user.Id, desktopSession.UserID)
			invalidPAT, err := model.ValidateAccessToken(client.access)
			require.NoError(t, err)
			assert.Nil(t, invalidPAT)
			_, err = model.ValidateUserToken(client.access)
			assert.Error(t, err)
			pat := model.AccessTokenPrefix + uuid.NewString()
			grant := model.UserAccessToken{UserId: user.Id, Name: "existing scoped PAT", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
			require.NoError(t, grant.SetScopes([]string{"self:read"}))
			require.NoError(t, db.Create(&grant).Error)
			patClient := &linkTestClient{t: t, router: router, access: pat}
			assert.Equal(t, "AUTH_SESSION_REQUIRED", patClient.request("POST", "/auth/complete", gin.H{"flow_token": "invalid"}, 403).Code)
			_, _, err = model.CompleteLinkAuthorization("invalid", model.AuthSessionIdentity{UserID: user.Id, SessionID: model.AccessTokenSessionID(grant.Id), UserAuthVersion: user.AuthVersion, SessionVersion: model.AccessTokenSessionVersion})
			assert.ErrorIs(t, err, model.ErrLinkUnauthorized)
			patClient.request("GET", "/bootstrap", nil, 401)
			committed := linkAction(t, client, conn, "commit", nil)
			conn = linkConnectionFrom(t, committed)
			testLinkToolVerification(t, db, client, secondDevice, otherClient, conn, user.Id, firstID, "codex-cli", "openai_responses", "/v1/responses")
			t.Run("live_tool_catalogs", func(t *testing.T) { testLinkLiveToolCatalogs(t, db, client) })
			t.Run("configurable_tools", func(t *testing.T) { testLinkConfigurableTools(t, db, client) })
			t.Run("registered_responses_catalog", func(t *testing.T) { testLinkRegisteredResponsesCatalog(t, db, client) })
			t.Run("hermes", func(t *testing.T) {
				testLinkHermesWorkflow(t, db, client, secondDevice, otherClient, user.Id)
			})
			t.Run("workbuddy", func(t *testing.T) {
				testLinkWorkBuddyWorkflow(t, db, client, secondDevice, otherClient)
			})
			updatedModels := linkAction(t, client, conn, "update_models", gin.H{"models": []string{"verified-model", "verified-second"}, "default_model": "verified-second", "catalog_revision": catalogResult.Data["revision"]})
			conn = linkConnectionFrom(t, updatedModels)
			active := conn["active"].(map[string]any)
			assert.Equal(t, "verified-second", active["default_model"])
			assert.Equal(t, false, active["model_limits_enabled"], "directory selection does not narrow native inference permissions")
			assert.NotContains(t, updatedModels.Data, "api_key")
			client.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "update_models", "expected_revision": conn["revision"], "models": []string{"unavailable"}, "default_model": "unavailable", "catalog_revision": catalogResult.Data["revision"]}, 400)
			assert.Equal(t, "active", conn["status"])
			// Website restrictions stay on the original record; switching creates independent defaults.
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", firstID).Updates(map[string]any{"unlimited_quota": false, "remain_quota": 123, "expired_time": time.Now().Add(time.Hour).Unix(), "model_limits_enabled": true, "model_limits": "verified-model,verified-second"}).Error)
			vip := client.request("GET", "/catalog?tool_family=codex&group=vip", nil, 200)
			for _, restriction := range []map[string]any{
				{"remain_quota": 0, "status": common.TokenStatusExhausted},
				{"expired_time": time.Now().Unix() - 1, "status": common.TokenStatusExpired},
				{"model_limits": "different-model"},
			} {
				require.NoError(t, db.Model(&model.Token{}).Where("id = ?", firstID).Updates(map[string]any{"status": common.TokenStatusEnabled, "remain_quota": 123, "expired_time": time.Now().Add(time.Hour).Unix(), "model_limits": "verified-model,verified-second"}).Error)
				require.NoError(t, db.Model(&model.Token{}).Where("id = ?", firstID).Updates(restriction).Error)
				for _, action := range []string{"resume", "update_models"} {
					client.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": action, "expected_revision": conn["revision"], "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": catalogResult.Data["revision"]}, 409)
				}
				switchResult := linkAction(t, client, conn, "prepare_switch", gin.H{"group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": vip.Data["revision"]})
				conn = linkConnectionFrom(t, switchResult)
				newKey := conn["candidate"].(map[string]any)
				assert.Equal(t, true, newKey["unlimited_quota"])
				assert.Equal(t, float64(-1), newKey["expired_time"])
				assert.Equal(t, false, newKey["model_limits_enabled"])
				conn = linkConnectionFrom(t, linkAction(t, client, conn, "abort", nil))
			}
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", firstID).Updates(map[string]any{"status": common.TokenStatusEnabled, "remain_quota": 123, "expired_time": time.Now().Add(time.Hour).Unix(), "model_limits": "verified-model,verified-second"}).Error)
			prepared := linkAction(t, client, conn, "prepare_switch", gin.H{"group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": vip.Data["revision"]})
			conn = linkConnectionFrom(t, prepared)
			candidateID := int(prepared.Data["token_id"].(float64))
			var original, candidate model.Token
			require.NoError(t, db.First(&original, firstID).Error)
			candidate = model.Token{}
			require.NoError(t, db.First(&candidate, candidateID).Error)
			assert.Equal(t, common.TokenStatusEnabled, original.Status)
			assert.Equal(t, "default", original.Group)
			assert.Equal(t, "vip", candidate.Group)
			assert.True(t, candidate.UnlimitedQuota)
			assert.Equal(t, int64(-1), candidate.ExpiredTime)
			assert.False(t, candidate.ModelLimitsEnabled)
			aborted := linkAction(t, client, conn, "abort", nil)
			conn = linkConnectionFrom(t, aborted)
			candidate = model.Token{}
			require.NoError(t, db.First(&candidate, candidateID).Error)
			assert.Equal(t, common.TokenStatusDisabled, candidate.Status)
			require.NoError(t, db.First(&original, firstID).Error)
			assert.Equal(t, common.TokenStatusEnabled, original.Status)
			prepared = linkAction(t, client, conn, "prepare_switch", gin.H{"group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": vip.Data["revision"]})
			conn = linkConnectionFrom(t, prepared)
			candidateID = int(prepared.Data["token_id"].(float64))
			require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(`{"default":"Default"}`))
			client.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "commit", "expected_revision": conn["revision"]}, 403)
			require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(`{"default":"Default","vip":"VIP"}`))
			committed = linkAction(t, client, conn, "commit", nil)
			conn = linkConnectionFrom(t, committed)
			require.NoError(t, db.First(&original, firstID).Error)
			assert.Equal(t, common.TokenStatusDisabled, original.Status)
			assert.Equal(t, 123, original.RemainQuota)
			assert.Equal(t, "default", original.Group)
			paused := linkAction(t, client, conn, "pause", nil)
			conn = linkConnectionFrom(t, paused)
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", candidateID).Updates(map[string]any{"unlimited_quota": false, "remain_quota": 0}).Error)
			client.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "resume", "expected_revision": conn["revision"]}, 409)
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", candidateID).Updates(map[string]any{"unlimited_quota": true}).Error)
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", candidateID).Update("expired_time", time.Now().Unix()-1).Error)
			client.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "resume", "expected_revision": conn["revision"]}, 409)
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", candidateID).Updates(map[string]any{"expired_time": -1, "model_limits_enabled": true, "model_limits": "different-model"}).Error)
			client.request("POST", "/connections/"+conn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "resume", "expected_revision": conn["revision"]}, 409)
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", candidateID).Update("model_limits_enabled", false).Error)
			resumed := linkAction(t, client, conn, "resume", nil)
			conn = linkConnectionFrom(t, resumed)
			client.request("POST", "/auth/logout", gin.H{}, 200)
			client.request("GET", "/bootstrap", nil, 401)
			candidate = model.Token{}
			require.NoError(t, db.First(&candidate, candidateID).Error)
			assert.Equal(t, common.TokenStatusEnabled, candidate.Status)
			client = linkTestLogin(t, router, user, device)
			disconnected := linkAction(t, client, conn, "disconnect", nil)
			conn = linkConnectionFrom(t, disconnected)
			assert.Equal(t, "disconnected", conn["status"])
			candidate = model.Token{}
			require.NoError(t, db.First(&candidate, candidateID).Error)
			assert.Equal(t, common.TokenStatusDisabled, candidate.Status)
			// An externally deleted candidate is never regenerated by retry or commit.
			create["operation_id"] = uuid.NewString()
			recreated := client.request("POST", "/connections", create, 200)
			pending := linkConnectionFrom(t, recreated)
			deletedID := int(recreated.Data["token_id"].(float64))
			require.NoError(t, db.Delete(&model.Token{}, deletedID).Error)
			deletedRetry := client.request("POST", "/connections", create, 200)
			assert.NotContains(t, deletedRetry.Data, "api_key")
			assert.Equal(t, recreated.Data["token_id"], deletedRetry.Data["token_id"])
			client.request("POST", "/connections/"+pending["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "commit", "expected_revision": pending["revision"]}, 409)
			linkAction(t, client, pending, "abort", nil)
			// An explicitly selected new group still cannot replace a deleted source record.
			create["operation_id"] = uuid.NewString()
			create["config_scope"] = "deleted-source"
			sourceResult := client.request("POST", "/connections", create, 200)
			sourceConn := linkConnectionFrom(t, sourceResult)
			sourceConn = linkConnectionFrom(t, linkAction(t, client, sourceConn, "commit", nil))
			require.NoError(t, db.Delete(&model.Token{}, int(sourceResult.Data["token_id"].(float64))).Error)
			client.request("POST", "/connections/"+sourceConn["id"].(string)+"/actions", gin.H{"operation_id": uuid.NewString(), "action": "prepare_switch", "expected_revision": sourceConn["revision"], "group": "vip", "models": []string{"verified-model"}, "default_model": "verified-model", "catalog_revision": vip.Data["revision"]}, 409)
			sourceView := client.request("GET", "/connections/"+sourceConn["id"].(string), nil, 200)
			assert.Nil(t, sourceView.Data["candidate"])
			oldAccess, oldRefresh := client.access, client.refresh
			refreshed := client.request("POST", "/auth/refresh", gin.H{"refresh_token": oldRefresh}, 200)
			stale := &linkTestClient{t: t, router: router, access: oldAccess}
			stale.request("GET", "/bootstrap", nil, 401)
			client.access = refreshed.Data["access_token"].(string)
			client.request("GET", "/bootstrap", nil, 200)
			// Even an older-generation consumed credential revokes the current family.
			refreshed = client.request("POST", "/auth/refresh", gin.H{"refresh_token": refreshed.Data["refresh_token"]}, 200)
			client.access = refreshed.Data["access_token"].(string)
			client.request("GET", "/bootstrap", nil, 200)
			client.request("POST", "/auth/refresh", gin.H{"refresh_token": oldRefresh}, 401)
			client.request("GET", "/bootstrap", nil, 401)
			// Cleanup cannot remove live replay evidence; expired families can be removed.
			var liveUses int64
			require.NoError(t, db.Model(&model.LinkRefreshUse{}).Where("user_id = ?", user.Id).Count(&liveUses).Error)
			require.Greater(t, liveUses, int64(0))
			require.NoError(t, model.DeleteExpiredLinkSessions(time.Now().Unix()))
			var preservedUses int64
			require.NoError(t, db.Model(&model.LinkRefreshUse{}).Where("user_id = ?", user.Id).Count(&preservedUses).Error)
			assert.Equal(t, liveUses, preservedUses)
			require.NoError(t, db.Model(&model.LinkRefreshUse{}).Where("user_id = ?", user.Id).Update("expires_at", time.Now().Unix()-1).Error)
			require.NoError(t, model.DeleteExpiredLinkSessions(time.Now().Unix()))
			require.NoError(t, db.Model(&model.LinkRefreshUse{}).Where("user_id = ?", user.Id).Count(&preservedUses).Error)
			assert.Zero(t, preservedUses)
			// Expiry and account security invalidation are checked from current storage.
			client = linkTestLogin(t, router, user, device)
			require.NoError(t, db.Model(&model.LinkSession{}).Where("id = ?", client.sessionID).Update("access_expires_at", time.Now().Unix()-1).Error)
			client.request("GET", "/bootstrap", nil, 401)
			client = linkTestLogin(t, router, user, device)
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.Id).Update("auth_version", user.AuthVersion+1).Error)
			client.request("GET", "/bootstrap", nil, 401)
			client.request("POST", "/auth/refresh", gin.H{"refresh_token": client.refresh}, 401)
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", other.Id).Update("status", common.UserStatusDisabled).Error)
			otherClient.request("GET", "/bootstrap", nil, 401)
			otherClient.request("POST", "/auth/refresh", gin.H{"refresh_token": otherClient.refresh}, 401)
		})
	}
}

func TestLinkTransportAndRedirectValidation(t *testing.T) {
	router := gin.New()
	router.Use(middleware.LinkTransport())
	router.GET("/", func(c *gin.Context) { c.Status(204) })
	for _, tc := range []struct {
		host, remote, forwarded string
		status                  int
	}{
		{"http://127.0.0.1:3000/", "127.0.0.1:99", "", 204},
		{"http://platform.example/", "198.51.100.2:99", "https", 400},
		{"http://platform.example/", "127.0.0.1:99", "https", 204},
		{"http://platform.example/", "127.0.0.1:99", "", 400},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.host, nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-Proto", tc.forwarded)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		assert.Equal(t, tc.status, w.Code)
	}
	assert.True(t, service.ValidateLinkRedirect("http://127.0.0.1:1234/callback"))
	for _, raw := range []string{"https://attacker.example/callback", "http://localhost:1234/callback", "http://127.0.0.1/callback", "http://127.0.0.1:0/callback", "http://127.0.0.1:65536/callback", "http://127.0.0.1:1234/callback?next=evil", "http://user@127.0.0.1:1234/callback"} {
		assert.False(t, service.ValidateLinkRedirect(raw), raw)
	}
	privacy := gin.New()
	privacy.Use(middleware.LinkBrowserPrivacy(), middleware.Cache())
	privacy.GET("/link/authorize", func(c *gin.Context) { c.String(200, "test") })
	w := httptest.NewRecorder()
	privacy.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/link/authorize?flow_token=synthetic", nil))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

func TestLinkPublicURLOriginNormalization(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"https://PLATFORM.example:443/", "https://platform.example"},
		{"https://PLATFORM.example:8443/", "https://platform.example:8443"},
		{"http://LOCALHOST:80/", "http://localhost"},
		{"http://127.0.0.1:3000/", "http://127.0.0.1:3000"},
		{"http://[::1]:80/", "http://[::1]"},
	} {
		t.Run(tc.configured, func(t *testing.T) {
			t.Setenv("LINK_PUBLIC_URL", tc.configured)
			got, err := service.LinkPublicURL()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
	for _, configured := range []string{"https://*.example", "http://platform.example", "https://platform.example/path", "https://platform.example?secret=value", "https://user@platform.example", "https://platform.example/%2f"} {
		t.Run(configured, func(t *testing.T) {
			t.Setenv("LINK_PUBLIC_URL", configured)
			_, err := service.LinkPublicURL()
			require.Error(t, err)
		})
	}
}

func TestLinkDatabaseErrorDoesNotExposeKey(t *testing.T) {
	const syntheticKey = "synthetic-inference-key-not-a-real-credential"
	var logs bytes.Buffer
	common.LogWriterMu.Lock()
	previousWriter, previousErrorWriter := gin.DefaultWriter, gin.DefaultErrorWriter
	gin.DefaultWriter, gin.DefaultErrorWriter = &logs, &logs
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter, gin.DefaultErrorWriter = previousWriter, previousErrorWriter
		common.LogWriterMu.Unlock()
	})
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Set("id", 42)
	linkError(context, &mysqldriver.MySQLError{Number: 1062, Message: "Duplicate entry '" + syntheticKey + "' for key 'tokens.idx_tokens_key'"})

	assert.Equal(t, http.StatusInternalServerError, response.Code)
	var body linkTestEnvelope
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &body))
	assert.False(t, body.Success)
	assert.Equal(t, "LINK_INTERNAL_ERROR", body.Code)
	assert.NotContains(t, response.Body.String(), syntheticKey)
	assert.NotContains(t, logs.String(), syntheticKey)
	assert.NotContains(t, logs.String(), "Duplicate entry")
	assert.Contains(t, logs.String(), "link operation failed")
	assert.Contains(t, logs.String(), "user=42 code=LINK_INTERNAL_ERROR")
}
