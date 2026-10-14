package service

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/gin-gonic/gin"
)

const LinkVerificationHeader = "X-Xingyin-Verification"

func ClaimLinkRelayVerification(c *gin.Context, info *relaycommon.RelayInfo, challenge string) (string, error) {
	// The native non-stream helpers do not expose a reliable terminal outcome.
	// Verification only uses explicit stream completion; ordinary requests are unchanged.
	if !info.IsStream {
		return "", model.ErrLinkVerification
	}
	protocol := ""
	switch c.Request.URL.Path {
	case "/v1/responses":
		protocol = "openai_responses"
	case "/v1/messages":
		protocol = "anthropic_messages"
	case "/v1/chat/completions":
		protocol = "openai_chat_completions"
	default:
		return "", model.ErrLinkVerification
	}
	return model.ClaimLinkToolVerification(challenge, info.UserId, info.TokenId, info.OriginModelName, protocol, c.GetString(common.RequestIdKey))
}

func FinishLinkRelayVerification(c *gin.Context, info *relaycommon.RelayInfo, id string, success bool) {
	if id == "" {
		return
	}
	success = success && info.IsStream && c.Writer.Status() >= 200 && c.Writer.Status() < 300
	if info.IsStream {
		outcome := info.StreamStatus.OutcomeSnapshot()
		// Official clients can close the HTTP stream immediately after its terminal
		// event. Completion plus the independently checked CLI echo proves this
		// attempt; cancellation before the terminal event still fails closed.
		ended := info.StreamStatus.IsNormalEnd() || outcome.EndReason == relaycommon.StreamEndReasonClientGone
		success = success && !outcome.HasErrors && outcome.Response == relaycommon.ResponseOutcomeCompleted && ended
	}
	if err := model.FinishLinkToolVerification(id, c.GetString(common.RequestIdKey), success); err != nil {
		// Receipt failure cannot alter the already delivered response or billing.
		common.SysError(common.LogText("tool verification receipt could not be recorded"))
	}
}
