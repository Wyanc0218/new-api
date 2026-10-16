package common

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

const (
	LinkProtocolChat      = "openai_chat_completions"
	LinkProtocolMessages  = "anthropic_messages"
	LinkProtocolResponses = "openai_responses"

	LinkProfileGeneric       = "generic"
	LinkProfileCodex         = "codex"
	LinkProfileClaudeDesktop = "claude_desktop"
	LinkProfileWorkBuddy     = "workbuddy"
)

var linkToolIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var ErrLinkToolRegistry = errors.New("client tool registry is unavailable")

// Definitions are server-owned admission policy, not executable tool adapters.
// A client cannot choose a protocol, native profile or verification target that
// the administrator has not registered for its family.
type LinkToolDefinition struct {
	ID                  string
	Enabled             bool
	Protocol            string
	VerificationTargets []string
	Profile             string
}

type LinkToolRegistry struct {
	tools   map[string]LinkToolDefinition
	targets map[string]string
}

func ValidLinkToolID(id string) bool { return linkToolIDPattern.MatchString(id) }

// Native contracts remain immutable. New tools use the generic protocol path;
// their local installation/configuration still requires a client-side adapter.
func BuiltinLinkTool(id string) (LinkToolDefinition, bool) {
	tool := LinkToolDefinition{ID: id, Enabled: true, Profile: LinkProfileGeneric}
	switch id {
	case "codex":
		tool.Protocol, tool.Profile = LinkProtocolResponses, LinkProfileCodex
		tool.VerificationTargets = []string{"codex-cli"}
	case "claude_code":
		tool.Protocol = LinkProtocolMessages
		tool.VerificationTargets = []string{"claude-code"}
	case "claude_desktop":
		tool.Protocol, tool.Profile = LinkProtocolMessages, LinkProfileClaudeDesktop
	case "hermes":
		tool.Protocol = LinkProtocolChat
		tool.VerificationTargets = []string{"hermes"}
	case "workbuddy":
		tool.Protocol, tool.Profile = LinkProtocolChat, LinkProfileWorkBuddy
	default:
		return LinkToolDefinition{}, false
	}
	return tool, true
}

func (registry *LinkToolRegistry) Tool(id string) (LinkToolDefinition, bool) {
	tool, ok := registry.tools[id]
	tool.VerificationTargets = slices.Clone(tool.VerificationTargets)
	return tool, ok && tool.Enabled
}

func (registry *LinkToolRegistry) VerificationTool(target, protocol string) (LinkToolDefinition, bool) {
	tool, ok := registry.Tool(registry.targets[target])
	return tool, ok && tool.Protocol == protocol
}

// Load one bounded, immutable snapshot per operation. Atomic file replacement
// makes changes visible to the next operation without restarting the gateway.
// A configured but unreadable/invalid file never falls back to built-in access.
func LoadLinkToolRegistry() (*LinkToolRegistry, error) {
	registry := &LinkToolRegistry{tools: make(map[string]LinkToolDefinition), targets: make(map[string]string)}
	for _, id := range []string{"codex", "claude_code", "claude_desktop", "hermes", "workbuddy"} {
		tool, _ := BuiltinLinkTool(id)
		registry.tools[id] = tool
	}
	if path := os.Getenv("LINK_TOOL_REGISTRY_FILE"); path != "" {
		info, err := os.Stat(path)
		if !filepath.IsAbs(path) || err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
			return nil, ErrLinkToolRegistry
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, ErrLinkToolRegistry
		}
		defer file.Close()
		info, err = file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
			return nil, ErrLinkToolRegistry
		}
		raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
		if err != nil || len(raw) > 64*1024 {
			return nil, ErrLinkToolRegistry
		}
		var document map[string]RawMessage
		if Unmarshal(raw, &document) != nil || len(document) != 2 {
			return nil, ErrLinkToolRegistry
		}
		var version int
		var entries []map[string]RawMessage
		if Unmarshal(document["version"], &version) != nil || version != 1 || Unmarshal(document["tools"], &entries) != nil || entries == nil || len(entries) > 128 {
			return nil, ErrLinkToolRegistry
		}
		seen := make(map[string]bool)
		for _, entry := range entries {
			for key := range entry {
				if !slices.Contains([]string{"id", "enabled", "protocol", "verification_targets"}, key) {
					return nil, ErrLinkToolRegistry
				}
			}
			var id string
			if Unmarshal(entry["id"], &id) != nil || !ValidLinkToolID(id) || seen[id] {
				return nil, ErrLinkToolRegistry
			}
			seen[id] = true
			tool, builtin := BuiltinLinkTool(id)
			if !builtin {
				tool = LinkToolDefinition{ID: id, Enabled: true, Profile: LinkProfileGeneric}
			}
			if rawEnabled, exists := entry["enabled"]; exists {
				var enabled *bool
				if Unmarshal(rawEnabled, &enabled) != nil || enabled == nil {
					return nil, ErrLinkToolRegistry
				}
				tool.Enabled = *enabled
			}
			if rawProtocol, exists := entry["protocol"]; exists {
				var protocol string
				if Unmarshal(rawProtocol, &protocol) != nil || (builtin && protocol != tool.Protocol) {
					return nil, ErrLinkToolRegistry
				}
				tool.Protocol = protocol
			}
			if !slices.Contains([]string{LinkProtocolChat, LinkProtocolMessages, LinkProtocolResponses}, tool.Protocol) {
				return nil, ErrLinkToolRegistry
			}
			if rawTargets, exists := entry["verification_targets"]; exists {
				var targets []string
				if Unmarshal(rawTargets, &targets) != nil || targets == nil || len(targets) > 32 || (builtin && !slices.Equal(targets, tool.VerificationTargets)) {
					return nil, ErrLinkToolRegistry
				}
				tool.VerificationTargets = targets
			}
			slices.Sort(tool.VerificationTargets)
			registry.tools[id] = tool
		}
	}
	for id, tool := range registry.tools {
		for _, target := range tool.VerificationTargets {
			if !ValidLinkToolID(target) || registry.targets[target] != "" {
				return nil, ErrLinkToolRegistry
			}
			// Disabled definitions also reserve their targets; another family
			// cannot take over an existing verification target.
			registry.targets[target] = id
		}
	}
	return registry, nil
}
