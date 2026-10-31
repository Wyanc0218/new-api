package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/relayconvert/reasoning"
	"github.com/QuantumNous/new-api/setting/billing_setting"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/gorm"
)

var linkPKCEPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var linkScopePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func LinkPublicURL() (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(os.Getenv("LINK_PUBLIC_URL")))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, model.LinkFailure(503, "LINK_NOT_CONFIGURED", "Client authorization origin is not configured")
	}
	// Match the browser Origin serialization (lowercase host, no default port).
	normalized, err := common.NormalizeOrigin(u.String())
	if err != nil {
		return nil, model.LinkFailure(503, "LINK_NOT_CONFIGURED", "Client authorization origin is not configured")
	}
	u, _ = url.Parse(normalized) // NormalizeOrigin has already validated this URL.
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) && normalized != common.LinkInsecureTestOrigin() {
		return nil, model.LinkFailure(503, "LINK_NOT_CONFIGURED", "Client authorization requires HTTPS")
	}
	u.Path = ""
	return u, nil
}
func ValidateLinkRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" || u.Path != "/callback" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port > 0 && port <= 65535 && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}
func ValidLinkUUID(value string) bool {
	u, err := uuid.Parse(value)
	return err == nil && u.String() == value && u != uuid.Nil
}

type LinkStartRequest struct {
	DeviceID            string `json:"device_id"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
}
type LinkStartResult struct {
	FlowToken    string `json:"flow_token"`
	AuthorizeURL string `json:"authorize_url"`
	ExpiresAt    int64  `json:"expires_at"`
}

func StartLinkAuthorization(r LinkStartRequest) (*LinkStartResult, error) {
	origin, err := LinkPublicURL()
	if err != nil {
		return nil, err
	}
	challenge, err := base64.RawURLEncoding.DecodeString(r.CodeChallenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != r.CodeChallenge || r.CodeChallengeMethod != "S256" || !ValidLinkUUID(r.DeviceID) || !ValidateLinkRedirect(r.RedirectURI) || !linkPKCEPattern.MatchString(r.State) {
		return nil, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Invalid authorization request")
	}
	payload, err := common.Marshal(model.LinkAuthPayload{DeviceID: r.DeviceID, CodeChallenge: r.CodeChallenge, RedirectURI: r.RedirectURI, State: r.State})
	if err != nil {
		return nil, err
	}
	expiry := time.Now().Add(5 * time.Minute)
	token, _, err := model.CreateAuthFlow(model.AuthFlowCreate{Purpose: "link_start", Payload: string(payload), ExpiresAt: expiry})
	if err != nil {
		return nil, err
	}
	origin.Path = "/link/authorize"
	q := origin.Query()
	q.Set("flow_token", token)
	origin.RawQuery = q.Encode()
	return &LinkStartResult{token, origin.String(), expiry.Unix()}, nil
}
func CompleteLinkAuthorization(flow string, identity AuthIdentity) (string, error) {
	code, payload, err := model.CompleteLinkAuthorization(flow, identity)
	if err != nil {
		return "", err
	}
	if !ValidateLinkRedirect(payload.RedirectURI) {
		return "", model.ErrLinkUnauthorized
	}
	u, _ := url.Parse(payload.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", payload.State)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func ExchangeLinkAuthorization(code, verifier, redirectURI, deviceID string) (*model.LinkAuthBundle, int, error) {
	if !linkPKCEPattern.MatchString(verifier) || !ValidateLinkRedirect(redirectURI) || !ValidLinkUUID(deviceID) || len(code) > 256 {
		return nil, 0, model.ErrLinkUnauthorized
	}
	return model.ExchangeLinkAuthorization(code, verifier, redirectURI, deviceID)
}

type LinkUser struct {
	ID             int     `json:"id"`
	Username       string  `json:"username"`
	DisplayName    string  `json:"display_name"`
	Quota          int     `json:"quota"`
	QuotaPerUnit   float64 `json:"quota_per_unit"`
	BalanceDisplay string  `json:"balance_display"`
	RefreshedAt    int64   `json:"refreshed_at"`
}

func GetLinkUser(id int) (*LinkUser, error) {
	user, err := model.GetSelfUserById(id)
	if err != nil {
		return nil, err
	}
	quota, err := model.GetUserQuota(id, false)
	if err != nil {
		return nil, err
	}
	display := fmt.Sprintf("%d", quota)
	if operation_setting.GetQuotaDisplayType() != operation_setting.QuotaDisplayTypeTokens {
		if common.QuotaPerUnit <= 0 {
			return nil, model.LinkFailure(503, "LINK_BALANCE_UNAVAILABLE", "Platform quota unit is invalid")
		}
		value := decimal.NewFromInt(int64(quota)).Div(decimal.NewFromFloat(common.QuotaPerUnit)).Mul(decimal.NewFromFloat(operation_setting.GetUsdToCurrencyRate(operation_setting.USDExchangeRate)))
		display = operation_setting.GetCurrencySymbol() + value.StringFixed(6)
	}
	return &LinkUser{ID: user.Id, Username: user.Username, DisplayName: user.DisplayName, Quota: quota, QuotaPerUnit: common.QuotaPerUnit, BalanceDisplay: display, RefreshedAt: time.Now().Unix()}, nil
}

type LinkGroup struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

func GetLinkGroups(id int) ([]LinkGroup, error) {
	user, err := model.GetSelfUserById(id)
	if err != nil {
		return nil, err
	}
	usable := GetUserUsableGroups(user.Group)
	names := make([]string, 0, len(usable))
	for name := range usable {
		if IsUserSelectableGroup(user.Group, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	result := make([]LinkGroup, 0, len(names))
	for _, name := range names {
		result = append(result, LinkGroup{name, usable[name]})
	}
	return result, nil
}

func LinkDefaultGroup(groups []LinkGroup) string {
	configured := strings.TrimSpace(os.Getenv("LINK_DEFAULT_GROUP"))
	if slices.ContainsFunc(groups, func(g LinkGroup) bool { return g.ID == configured }) {
		return configured
	}
	return ""
}

type LinkCatalogEntry struct {
	Metadata     map[string]any `json:"metadata"`
	Description  string         `json:"description,omitempty"`
	PriceText    string         `json:"price_text,omitempty"`
	ID           string         `json:"id"`
	Label        string         `json:"label"`
	Protocol     string         `json:"protocol"`
	ToolFamilies []string       `json:"tool_families,omitempty"`
	Groups       []string       `json:"groups,omitempty"`
}
type LinkCatalog struct {
	Revision     string             `json:"revision"`
	ToolFamily   string             `json:"tool_family"`
	Group        string             `json:"group"`
	Models       []LinkCatalogEntry `json:"models"`
	DefaultModel string             `json:"default_model"`
}

func GetLinkCatalog(userID int, tool, group string) (*LinkCatalog, error) {
	user, err := model.GetSelfUserById(userID)
	if err != nil {
		return nil, err
	}
	registry, err := common.LoadLinkToolRegistry()
	if err != nil {
		return nil, model.ErrLinkToolRegistry
	}
	definition, enabled := registry.Tool(tool)
	if !enabled {
		return nil, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Select a supported tool and explicit price group")
	}
	return linkCatalogForUser(model.DB, user, definition, group)
}
func linkCatalogForUser(tx *gorm.DB, user *model.User, definition common.LinkToolDefinition, group string) (*LinkCatalog, error) {
	tool := definition.ID
	if group == "" || group == "auto" || len(group) > 64 {
		return nil, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Select a supported tool and explicit price group")
	}
	if !IsUserSelectableGroup(user.Group, group) {
		return nil, model.LinkFailure(403, "LINK_FORBIDDEN", "Price group is not available to this account")
	}
	if definition.Profile != common.LinkProfileCodex {
		return linkLiveCatalog(tx, user, definition, group)
	}
	file, err := os.Open(os.Getenv("LINK_MODEL_CATALOG_FILE"))
	if err != nil {
		return nil, model.LinkFailure(503, "LINK_CATALOG_UNAVAILABLE", "Verified model catalog is unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return nil, model.LinkFailure(503, "LINK_CATALOG_UNAVAILABLE", "Verified model catalog is invalid")
	}
	var configured struct {
		Revision string             `json:"revision"`
		Models   []LinkCatalogEntry `json:"models"`
	}
	if err = common.Unmarshal(raw, &configured); err != nil {
		return nil, model.LinkFailure(503, "LINK_CATALOG_UNAVAILABLE", "Verified model catalog is invalid")
	}
	var available []string
	if err := tx.Model(&model.Ability{}).Where(&model.Ability{Group: group, Enabled: true}).Distinct("model").Pluck("model", &available).Error; err != nil {
		return nil, err
	}
	result := &LinkCatalog{ToolFamily: tool, Group: group, Models: []LinkCatalogEntry{}}
	protocol := definition.Protocol
	seen := map[string]bool{}
	for _, entry := range configured.Models {
		if !slices.Contains(entry.ToolFamilies, tool) || !slices.Contains(entry.Groups, group) {
			continue
		}
		if entry.ID == "" || len(entry.ID) > 255 || seen[entry.ID] || entry.Protocol != protocol {
			return nil, model.LinkFailure(503, "LINK_CATALOG_UNAVAILABLE", "Verified model catalog has conflicting entries")
		}
		seen[entry.ID] = true
		if !slices.Contains(available, entry.ID) {
			continue
		}
		if entry.Metadata == nil {
			entry.Metadata = map[string]any{}
		}
		entry.ToolFamilies = nil
		entry.Groups = nil
		if entry.Label == "" {
			entry.Label = entry.ID
		}
		// Compatibility metadata never supplies prices. Use the same live
		// settings as relay billing without opening a second DB transaction.
		entry.PriceText = linkModelPriceText(user.Group, group, entry.ID)
		result.Models = append(result.Models, entry)
	}
	if len(result.Models) == 0 {
		return nil, model.LinkFailure(409, "LINK_NO_MODELS", "No verified model is currently available for this tool and group")
	}
	result.DefaultModel = result.Models[0].ID
	// Include the live intersection, so permission/channel changes invalidate selections.
	material, _ := common.Marshal(struct {
		Raw         string
		Tool, Group string
		Models      []LinkCatalogEntry
		Definition  common.LinkToolDefinition
	}{string(raw), tool, group, result.Models, definition})
	sum := sha256.Sum256(material)
	result.Revision = hex.EncodeToString(sum[:])
	return result, nil
}

// Exact Claude Desktop 2.19675.0 gateway name filter. Family metadata is optional;
// these names are rejected by the native client even when discovery is disabled.
var linkClaudeDesktopOtherModels = regexp.MustCompile(`ark-code|astron|command-r|deepseek|doubao|gemini|gemma|glm|gpt|grok|hermes|hy3|kimi|lfm|\bling\b|llama|longcat|mimo|minimax|mistral|mixtral|moonshot|nemotron|openai|phi-|qianfan|qwen|tc-code|\bunic\b|yi-|stepfun|step-3|seed-|bytedance|hunyuan|granite|amazon\.nova|nova-|devstral|ministral|ernie|codex|arcee|trinity|abab|phi\d|\bk2\.|\bm2\.|jamba|arctic|solar|mercury|zamba|kat-coder|\bds-|dpsk`)

func linkClaudeDesktopModel(name string) bool {
	// Native schema/normalization trims IDs and strips the optional 1M shorthand.
	// A fixed platform model ID must survive unchanged, without inferred capability.
	if name != strings.TrimSpace(name) || strings.HasSuffix(strings.ToLower(name), "[1m]") {
		return false
	}
	name = strings.ToLower(name)
	families := []string{"sonnet", "opus", "haiku", "fable", "mythos"}
	if slices.Contains(families, name) || linkClaudeDesktopOtherModels.MatchString(name) {
		return false
	}
	return strings.Contains(name, "claude") || strings.Contains(name, "anthropic") || slices.ContainsFunc(families, func(family string) bool { return strings.Contains(name, family) })
}

// Model availability follows current routes. Optional compatibility metadata can
// enrich a model but must not hide a newly enabled route behind a second allowlist.
func linkLiveCatalog(tx *gorm.DB, user *model.User, definition common.LinkToolDefinition, group string) (*LinkCatalog, error) {
	tool, protocol := definition.ID, definition.Protocol
	requestPath := "/v1/chat/completions"
	switch protocol {
	case common.LinkProtocolMessages:
		requestPath = "/v1/messages"
	case common.LinkProtocolResponses:
		requestPath = "/v1/responses"
	}
	var abilities []model.Ability
	if err := tx.Where(&model.Ability{Group: group, Enabled: true}).Find(&abilities).Error; err != nil {
		return nil, err
	}
	channelIDs := make([]int, 0, len(abilities))
	seenChannels := make(map[int]bool)
	for _, ability := range abilities {
		if !seenChannels[ability.ChannelId] {
			channelIDs = append(channelIDs, ability.ChannelId)
			seenChannels[ability.ChannelId] = true
		}
	}
	var channels []model.Channel
	if len(channelIDs) > 0 {
		// Do not load upstream credentials or use GetOtherSettings, whose invalid
		// JSON recovery can write the channel outside this transaction.
		if err := tx.Select("id", "type", "settings", "setting", "model_mapping").Where("id IN ? AND status = ?", channelIDs, common.ChannelStatusEnabled).Find(&channels).Error; err != nil {
			return nil, err
		}
	}
	byID := make(map[int]model.Channel, len(channels))
	for _, channel := range channels {
		byID[channel.Id] = channel
	}
	available := make(map[string]bool)
	blocked := make(map[string]bool)
	for _, ability := range abilities {
		channel, enabled := byID[ability.ChannelId]
		if !enabled || ability.Model == "" || len(ability.Model) > 255 {
			continue
		}
		endpoints := common.GetEndpointTypesByChannelType(channel.Type, ability.Model)
		var advanced *dto.AdvancedCustomConfig
		if channel.Type == constant.ChannelTypeAdvancedCustom {
			var settings dto.ChannelOtherSettings
			if common.UnmarshalJsonStr(channel.OtherSettings, &settings) != nil || settings.AdvancedCustom == nil {
				continue
			}
			endpoints = settings.AdvancedCustom.SupportedEndpointTypesForModel(ability.Model)
			advanced = settings.AdvancedCustom
		} else {
			// Dedicated Search/Fetch routing names are not generation models,
			// even when the channel adaptor also implements Messages/Responses.
			// Explicit advanced routes above remain authoritative for aliases.
			if len(endpoints) == 1 && (endpoints[0] == constant.EndpointTypeDeepSeekToolsSearch || endpoints[0] == constant.EndpointTypeDeepSeekToolsFetch) {
				blocked[ability.Model] = true
				continue
			}
			// Generic OpenAI channel capabilities include chat even for known
			// non-chat models. Follow the platform's image classification and
			// controller/channel-test.go task detection. Explicit custom routes
			// above remain authoritative; unfamiliar aliases are not guessed.
			name := strings.ToLower(ability.Model)
			if common.IsImageGenerationModel(name) || strings.Contains(name, "rerank") || strings.Contains(name, "embed") || strings.HasPrefix(name, "m3e") || strings.Contains(name, "bge-") || channel.Type == constant.ChannelTypeMokaAI {
				blocked[ability.Model] = true
				continue
			}
			if constant.IsAdvancedCustomChannel(channel.Type) {
				advanced = common.GetAdvancedCustomPreset(channel.Type)
			}
		}
		if definition.Profile == common.LinkProfileClaudeDesktop && !linkClaudeDesktopModel(ability.Model) {
			continue
		}
		supported := slices.Contains(endpoints, constant.EndpointTypeOpenAI)
		var setting dto.ChannelSettings
		if channel.Setting != nil && *channel.Setting != "" && common.UnmarshalJsonStr(*channel.Setting, &setting) != nil {
			blocked[ability.Model] = true
			continue
		}
		passThrough := model_setting.GetGlobalSettings().PassThroughRequestEnabled || setting.PassThroughBodyEnabled
		apiType, known := common.ChannelType2APIType(channel.Type)
		if !known && (channel.Type == constant.ChannelTypeAzure || channel.Type == constant.ChannelTypeCustom) {
			known = true
		}
		if advanced != nil {
			// The router excludes advanced routes with no matching incoming path.
			// Check the first matching route, just as the actual adaptor does.
			route, matched := advanced.MatchPathForModel(requestPath, ability.Model)
			if !matched {
				continue
			}
			if advanced.Validate() != nil {
				blocked[ability.Model] = true
				continue
			}
			supported = !(passThrough || route.PassThroughBodyEnabled) || route.SupportsPassThroughBody()
		} else if protocol == common.LinkProtocolResponses {
			// Endpoint lists describe preferred presentation, not the adaptor's
			// request/response conversion contract. These implementations handle
			// native responses bodies and responses streams without conversion.
			supported = known && slices.Contains([]int{
				constant.APITypeOpenAI, constant.APITypeOpenRouter, constant.APITypeXinference,
				constant.APITypeNewAPI, constant.APITypeSub2API, constant.APITypeAli,
				constant.APITypeZhipuV4, constant.APITypeOllama, constant.APITypePerplexity,
				constant.APITypeDeepSeek, constant.APITypeVolcEngine, constant.APITypeXai,
				constant.APITypeCloudflare,
			}, apiType)
			if !passThrough && known && slices.Contains([]int{constant.APITypeAnthropic, constant.APITypeGemini, constant.APITypeCodex}, apiType) {
				// Anthropic/Gemini convert both directions. The Codex channel
				// requires normalized responses fields even though its body shape
				// is otherwise native; raw passthrough skips those requirements.
				supported = true
			}
		} else if protocol == common.LinkProtocolMessages {
			// These adaptors route Claude bodies to a native messages endpoint;
			// they do not require chat/envelope conversion even with passthrough.
			supported = known && slices.Contains([]int{
				constant.APITypeAnthropic, constant.APITypeNewAPI, constant.APITypeSub2API,
				constant.APITypeDeepSeek, constant.APITypeMoonshot, constant.APITypeMiniMax,
				constant.APITypeZhipuV4, constant.APITypeOllama,
			}, apiType)
			if !supported && !passThrough && known && (slices.Contains(endpoints, constant.EndpointTypeOpenAI) || slices.Contains(endpoints, constant.EndpointTypeAnthropic)) {
				// Preferred endpoint lists are not a conversion capability matrix.
				// These adaptors implement ConvertClaudeRequest; OpenAI converts
				// messages to chat by default without a per-model switch.
				switch apiType {
				case constant.APITypeOpenAI, constant.APITypeOpenRouter, constant.APITypeXinference,
					constant.APITypeGemini, constant.APITypeAli, constant.APITypeZhipuV4,
					constant.APITypeOllama, constant.APITypePerplexity, constant.APITypeSiliconFlow,
					constant.APITypeDeepSeek, constant.APITypeVolcEngine,
					constant.APITypeBaiduV2, constant.APITypeMoonshot, constant.APITypeMiniMax:
					supported = true
				case constant.APITypeAws, constant.APITypeVertexAi:
					// These adaptors dispatch other upstream models to Nova/Gemini
					// while ConvertClaudeRequest always produces a Claude body.
					// Do not infer the dispatch target across model-mapping chains.
					unmapped := channel.ModelMapping == nil || strings.TrimSpace(*channel.ModelMapping) == "" || strings.TrimSpace(*channel.ModelMapping) == "{}"
					supported = unmapped && strings.HasPrefix(ability.Model, "claude")
					if apiType == constant.APITypeAws && unmapped {
						supported = supported || strings.HasPrefix(ability.Model, "anthropic.claude") || strings.Contains(ability.Model, ".anthropic.claude")
					}
				}
			}
		} else {
			supported = supported && known
			if passThrough {
				// These adaptors use native OpenAI chat bodies at their chat endpoint.
				// Field normalization is distinct from conversion into Claude/Gemini
				// or AWS/Vertex envelopes, which raw-body passthrough cannot supply.
				nativeChat := slices.Contains([]int{
					constant.APITypeOpenAI, constant.APITypeOpenRouter, constant.APITypeXinference,
					constant.APITypeNewAPI, constant.APITypeSub2API, constant.APITypeAli,
					constant.APITypeZhipuV4, constant.APITypePerplexity, constant.APITypeSiliconFlow,
					constant.APITypeMistral, constant.APITypeDeepSeek, constant.APITypeVolcEngine,
					constant.APITypeBaiduV2, constant.APITypeXai, constant.APITypeMoonshot,
					constant.APITypeSubmodel, constant.APITypeMiniMax, constant.APITypeCloudflare,
				}, apiType)
				if apiType == constant.APITypeOllama {
					var settings dto.ChannelOtherSettings
					nativeChat = common.UnmarshalJsonStr(channel.OtherSettings, &settings) == nil && settings.OllamaOpenAIChat
				}
				supported = supported && nativeChat
			}
		}
		if !supported {
			// Ordinary channels are not filtered by request path at selection.
			// One working route cannot hide another randomly selectable failure.
			blocked[ability.Model] = true
		}
		if supported {
			available[ability.Model] = true
		}
	}
	for name := range blocked {
		delete(available, name)
	}
	if len(available) == 0 {
		return nil, model.LinkFailure(409, "LINK_NO_MODELS", "No compatible model is currently available for this tool and price group")
	}

	// An optional compatibility file enriches capabilities only. Missing, invalid
	// or conflicting optional metadata must not hide otherwise available models.
	metadata := make(map[string]map[string]any)
	if file, err := os.Open(os.Getenv("LINK_MODEL_CATALOG_FILE")); err == nil {
		defer file.Close()
		raw, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		var configured struct {
			Models []LinkCatalogEntry `json:"models"`
		}
		if readErr == nil && len(raw) <= 1024*1024 && common.Unmarshal(raw, &configured) == nil {
			seen := make(map[string]bool)
			for _, entry := range configured.Models {
				if !available[entry.ID] || !slices.Contains(entry.ToolFamilies, tool) || !slices.Contains(entry.Groups, group) {
					continue
				}
				if seen[entry.ID] {
					delete(metadata, entry.ID)
					continue
				}
				seen[entry.ID] = true
				if entry.Protocol != protocol {
					continue
				}
				if definition.Profile != common.LinkProfileWorkBuddy {
					metadata[entry.ID] = entry.Metadata
					continue
				}
				capabilities, ok := entry.Metadata["workbuddy"].(map[string]any)
				if !ok {
					continue
				}
				verified := make(map[string]any)
				for _, key := range []string{"supportsToolCall", "supportsImages", "supportsReasoning"} {
					if value, ok := capabilities[key].(bool); ok {
						verified[key] = value
					}
				}
				for _, key := range []string{"maxInputTokens", "maxOutputTokens"} {
					if value, ok := capabilities[key].(float64); ok && value > 0 && value <= 9007199254740991 && math.Trunc(value) == value {
						verified[key] = value
					}
				}
				if len(verified) > 0 {
					metadata[entry.ID] = verified
				}
			}
		}
	}
	names := make([]string, 0, len(available))
	for name := range available {
		names = append(names, name)
	}
	slices.Sort(names)
	result := &LinkCatalog{ToolFamily: tool, Group: group, Models: []LinkCatalogEntry{}, DefaultModel: names[0]}
	for _, name := range names {
		entry := LinkCatalogEntry{ID: name, Label: name, Protocol: protocol, Metadata: map[string]any{}, PriceText: linkModelPriceText(user.Group, group, name)}
		if capabilities := metadata[name]; capabilities != nil {
			if definition.Profile == common.LinkProfileWorkBuddy {
				entry.Metadata["workbuddy"] = capabilities
			} else {
				entry.Metadata = capabilities
			}
		}
		result.Models = append(result.Models, entry)
	}
	material, _ := common.Marshal(struct {
		Catalog    *LinkCatalog
		Definition common.LinkToolDefinition
	}{result, definition})
	sum := sha256.Sum256(material)
	result.Revision = hex.EncodeToString(sum[:])
	return result, nil
}

// linkModelPriceText quotes the fixed text/request portion of current billing.
// Request-dependent expressions and unresolved modifier aliases cannot be
// truthfully reduced to a single unit price without the actual request.
func linkModelPriceText(userGroup, group, name string) string {
	const fallback = "以平台计费说明为准"
	if reasoning.ParseModelModifiers(name).HasModifiers() || ratio_setting.FormatMatchingModelName(name) != name || common.IsImageGenerationModel(name) {
		return "计价依赖模型别名或请求参数；" + fallback
	}
	if billing_setting.GetBillingMode(name) == billing_setting.BillingModeTieredExpr {
		return "条件计费，价格取决于实际请求；" + fallback
	}
	groupRatio, ok := ratio_setting.GetGroupGroupRatio(userGroup, group)
	if !ok {
		groupRatio, ok = ratio_setting.GetGroupRatioCopy()[group]
	}
	if !ok || !validLinkPrice(groupRatio) {
		return "价格资料不完整；" + fallback
	}
	groupMultiplier := decimal.NewFromFloat(groupRatio)
	const note = "；已含当前账号及所选组倍率，工具等附加费用另计，以请求时平台结算为准"
	if price, fixed := ratio_setting.GetModelPrice(name, false); fixed {
		if !validLinkPrice(price) {
			return "价格资料不完整；" + fallback
		}
		return "基础价 " + linkPriceAmount(decimal.NewFromFloat(price).Mul(groupMultiplier)) + " 美元/次" + note
	}
	// Self-use fallback is not an administrator-configured quote. The relay
	// resolves an unpriced alias elsewhere; this path intentionally declines it.
	if !ratio_setting.HasConfiguredModelRatio(name) {
		return "价格资料不完整；" + fallback
	}
	ratio, _, _ := ratio_setting.GetModelRatio(name)
	completion := ratio_setting.GetCompletionRatio(name)
	cache, _ := ratio_setting.GetCacheRatio(name)
	creation, creationConfigured := ratio_setting.GetCreateCacheRatio(name)
	if common.QuotaPerUnit <= 0 || !validLinkPrice(common.QuotaPerUnit) || !validLinkPrice(ratio) || !validLinkPrice(completion) || !validLinkPrice(cache) || !validLinkPrice(creation) {
		return "价格资料不完整；" + fallback
	}
	input := decimal.NewFromFloat(ratio).Mul(groupMultiplier).Mul(decimal.NewFromInt(1_000_000)).DivRound(decimal.NewFromFloat(common.QuotaPerUnit), 32)
	if input.IsZero() && ratio != 0 && groupRatio != 0 {
		return "单价过小，无法可靠展示；" + fallback
	}
	parts := []string{"输入 " + linkPriceAmount(input), "输出 " + linkPriceAmount(input.Mul(decimal.NewFromFloat(completion))), "缓存读取 " + linkPriceAmount(input.Mul(decimal.NewFromFloat(cache)))}
	configured := model.PricingValues{}
	if creationConfigured {
		configured["CreateCacheRatio"] = creation
	}
	write := input.Mul(decimal.NewFromFloat(creation))
	switch model.ResolveCacheWriteMode(name, configured) {
	case model.CacheWriteStandard:
		parts = append(parts, "缓存写入 "+linkPriceAmount(write))
	case model.CacheWriteClaudeTTL:
		// Native legacy billing uses the same 1-hour / 5-minute ratio (6/3.75).
		parts = append(parts, "缓存写入（5 分钟） "+linkPriceAmount(write), "缓存写入（1 小时） "+linkPriceAmount(write.Mul(decimal.RequireFromString("1.6"))))
	}
	return "文本基础价（美元/百万令牌）：" + strings.Join(parts, "，") + note
}

func validLinkPrice(value float64) bool {
	return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func linkPriceAmount(value decimal.Decimal) string {
	rounded := value.Round(8)
	if rounded.IsZero() && value.IsPositive() {
		return "<0.00000001"
	}
	return rounded.String()
}

func ApplyLinkAction(session *model.LinkSession, id string, r model.LinkActionRequest) (*model.LinkOperationResult, error) {
	if !ValidLinkUUID(r.OperationID) || (!ValidLinkUUID(id) && id != "") {
		return nil, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Valid operation and connection IDs are required")
	}
	if id == "" {
		r.Action = "create"
		if r.ConfigScope == "" {
			r.ConfigScope = "default"
		}
		if !common.ValidLinkToolID(r.ToolFamily) || !linkScopePattern.MatchString(r.ConfigScope) {
			return nil, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Invalid tool or configuration scope")
		}
	}
	if id != "" && !slices.Contains([]string{"prepare_switch", "commit", "abort", "disconnect", "pause", "resume", "update_models"}, r.Action) {
		return nil, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Unknown connection action")
	}
	if id != "" && r.ExpectedRevision < 1 {
		return nil, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Connection revision is required")
	}
	if result, err := model.RetryLinkOperation(session, id, r); result != nil || err != nil {
		return result, err
	}
	// Completed idempotent results and cleanup actions remain available even
	// after a tool is disabled or the administrator's registry file is invalid.
	admit := slices.Contains([]string{"create", "prepare_switch", "update_models", "commit", "resume"}, r.Action)
	var registry *common.LinkToolRegistry
	if admit {
		var err error
		registry, err = common.LoadLinkToolRegistry()
		if err != nil {
			return nil, model.ErrLinkToolRegistry
		}
	}
	validate := func(tx *gorm.DB, user *model.User, conn *model.LinkConnection) error {
		if !admit {
			return nil
		}
		tool, group := r.ToolFamily, r.Group
		selected, defaultModel := r.Models, r.DefaultModel
		if conn != nil && r.Action != "create" {
			tool = conn.ToolFamily
			if r.Action == "update_models" || r.Action == "commit" || r.Action == "resume" {
				tokenID := conn.ActiveTokenID
				if r.Action == "commit" {
					tokenID = conn.CandidateTokenID
				}
				var key model.LinkKey
				if err := tx.Where("token_id = ? AND user_id = ?", tokenID, session.UserID).First(&key).Error; err != nil {
					return model.ErrLinkToken
				}
				group = key.Group
				if r.Action != "update_models" {
					if err := common.UnmarshalJsonStr(key.Models, &selected); err != nil {
						return err
					}
					defaultModel = key.DefaultModel
				}
			}
		}
		definition, enabled := registry.Tool(tool)
		if !enabled {
			return model.LinkFailure(400, "LINK_INVALID_REQUEST", "Select a supported tool and explicit price group")
		}
		if conn.Revision == 0 && r.Action == "create" {
			conn.ToolProtocol = definition.Protocol
		} else if !conn.MatchesLinkToolProtocol(definition) {
			return model.ErrLinkState
		} else if conn.ToolProtocol == "" {
			conn.ToolProtocol = definition.Protocol
		}
		catalog, err := linkCatalogForUser(tx, user, definition, group)
		if err != nil {
			return err
		}
		if r.Action != "commit" && r.Action != "resume" && catalog.Revision != r.CatalogRevision {
			return model.LinkFailure(409, "LINK_CATALOG_CHANGED", "Model catalog changed; reload your selection")
		}
		if len(selected) == 0 || len(selected) > 100 || !slices.Contains(selected, defaultModel) {
			return model.LinkFailure(400, "LINK_INVALID_REQUEST", "Select models and a default model")
		}
		seen := map[string]bool{}
		for _, name := range selected {
			if seen[name] || !slices.ContainsFunc(catalog.Models, func(e LinkCatalogEntry) bool { return e.ID == name }) {
				return model.LinkFailure(400, "LINK_INVALID_REQUEST", "Selection contains an unavailable model")
			}
			seen[name] = true
		}
		return nil
	}
	return model.ApplyLinkAction(session, id, r, validate)
}
