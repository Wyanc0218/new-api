package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkToolRegistryPolicy(t *testing.T) {
	t.Setenv("LINK_TOOL_REGISTRY_FILE", "")
	defaults, err := LoadLinkToolRegistry()
	require.NoError(t, err)
	for _, id := range []string{"codex", "claude_code", "claude_desktop", "hermes", "workbuddy"} {
		tool, enabled := defaults.Tool(id)
		assert.True(t, enabled, id)
		assert.Equal(t, id, tool.ID)
	}
	_, enabled := defaults.Tool("future_tool")
	assert.False(t, enabled, "unregistered tools must be rejected")
	_, enabled = defaults.VerificationTool("hermes", LinkProtocolMessages)
	assert.False(t, enabled, "a target cannot choose another protocol")

	file := filepath.Join(t.TempDir(), "tools.json")
	t.Setenv("LINK_TOOL_REGISTRY_FILE", file)
	require.NoError(t, os.WriteFile(file, []byte(`{"version":1,"tools":[{"id":"future_tool","protocol":"openai_chat_completions","verification_targets":["future-b","future-a"]},{"id":"hermes","enabled":false}]}`), 0600))
	registry, err := LoadLinkToolRegistry()
	require.NoError(t, err)
	tool, enabled := registry.Tool("future_tool")
	require.True(t, enabled)
	assert.Equal(t, LinkProfileGeneric, tool.Profile)
	assert.Equal(t, []string{"future-a", "future-b"}, tool.VerificationTargets)
	_, enabled = registry.Tool("hermes")
	assert.False(t, enabled)
	_, enabled = registry.VerificationTool("hermes", LinkProtocolChat)
	assert.False(t, enabled)
	target, enabled := registry.VerificationTool("future-a", LinkProtocolChat)
	require.True(t, enabled)
	assert.Equal(t, "future_tool", target.ID)

	// Exposed values and the next file replacement cannot mutate an operation's
	// existing snapshot. A subsequent operation observes the new policy instead.
	tool.VerificationTargets[0] = "overwritten"
	unchanged, _ := registry.Tool("future_tool")
	assert.Equal(t, []string{"future-a", "future-b"}, unchanged.VerificationTargets)
	require.NoError(t, os.WriteFile(file+".next", []byte(`{"version":1,"tools":[]}`), 0600))
	require.NoError(t, os.Rename(file+".next", file))
	current, err := LoadLinkToolRegistry()
	require.NoError(t, err)
	_, enabled = current.Tool("future_tool")
	assert.False(t, enabled)
	_, enabled = registry.Tool("future_tool")
	assert.True(t, enabled)
	_, enabled = current.Tool("hermes")
	assert.True(t, enabled, "omitted built-ins retain their default policy")
}

func TestLinkToolRegistryRejectsInvalidConfiguration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tools.json")
	t.Setenv("LINK_TOOL_REGISTRY_FILE", file)
	for name, input := range map[string]string{
		"malformed":                  `{`,
		"null":                       `null`,
		"unknown document field":     `{"version":1,"tools":[],"allow_all":true}`,
		"missing version":            `{"tools":[]}`,
		"unsupported version":        `{"version":2,"tools":[]}`,
		"null version":               `{"version":null,"tools":[]}`,
		"boolean version":            `{"version":true,"tools":[]}`,
		"null tools":                 `{"version":1,"tools":null}`,
		"null tool":                  `{"version":1,"tools":[null]}`,
		"duplicate family":           `{"version":1,"tools":[{"id":"hermes"},{"id":"hermes"}]}`,
		"uppercase family":           `{"version":1,"tools":[{"id":"Future","protocol":"openai_responses"}]}`,
		"family too long":            `{"version":1,"tools":[{"id":"abcdefghijklmnopqrstuvwxyzabcdefg","protocol":"openai_responses"}]}`,
		"missing protocol":           `{"version":1,"tools":[{"id":"future"}]}`,
		"unsupported protocol":       `{"version":1,"tools":[{"id":"future","protocol":"custom"}]}`,
		"null enabled":               `{"version":1,"tools":[{"id":"hermes","enabled":null}]}`,
		"nonboolean enabled":         `{"version":1,"tools":[{"id":"hermes","enabled":"true"}]}`,
		"executable profile":         `{"version":1,"tools":[{"id":"future","protocol":"openai_responses","profile":"codex"}]}`,
		"native protocol override":   `{"version":1,"tools":[{"id":"hermes","protocol":"anthropic_messages"}]}`,
		"native target override":     `{"version":1,"tools":[{"id":"hermes","verification_targets":["other"]}]}`,
		"reserved target takeover":   `{"version":1,"tools":[{"id":"hermes","enabled":false},{"id":"future","protocol":"openai_chat_completions","verification_targets":["hermes"]}]}`,
		"target repeated in family":  `{"version":1,"tools":[{"id":"future","protocol":"openai_responses","verification_targets":["target","target"]}]}`,
		"target repeated globally":   `{"version":1,"tools":[{"id":"future","protocol":"openai_responses","verification_targets":["target"]},{"id":"another","protocol":"anthropic_messages","verification_targets":["target"]}]}`,
		"target contains whitespace": `{"version":1,"tools":[{"id":"future","protocol":"openai_responses","verification_targets":["bad target"]}]}`,
		"target too long":            `{"version":1,"tools":[{"id":"future","protocol":"openai_responses","verification_targets":["abcdefghijklmnopqrstuvwxyzabcdefg"]}]}`,
		"null targets":               `{"version":1,"tools":[{"id":"future","protocol":"openai_responses","verification_targets":null}]}`,
		"unknown request path":       `{"version":1,"tools":[{"id":"future","protocol":"openai_responses","request_path":"/any"}]}`,
		"oversized file":             `{"version":1,"tools":[]}` + strings.Repeat(" ", 64*1024),
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(file, []byte(input), 0600))
			registry, err := LoadLinkToolRegistry()
			require.ErrorIs(t, err, ErrLinkToolRegistry)
			assert.Nil(t, registry, "invalid configuration must not restore built-in permissions")
		})
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing.json"), t.TempDir(), "relative-tools.json"} {
		t.Setenv("LINK_TOOL_REGISTRY_FILE", path)
		registry, err := LoadLinkToolRegistry()
		require.ErrorIs(t, err, ErrLinkToolRegistry)
		assert.Nil(t, registry)
	}
}
