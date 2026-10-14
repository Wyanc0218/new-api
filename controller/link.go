package controller

import (
	"errors"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

func linkError(c *gin.Context, err error) {
	var failure *model.LinkError
	if errors.Is(err, model.ErrAuthFlowInvalid) || errors.Is(err, model.ErrAuthFlowConsumed) || errors.Is(err, model.ErrAuthFlowExpired) {
		err = model.ErrLinkUnauthorized
	}
	if !errors.As(err, &failure) {
		failure = &model.LinkError{Status: 500, Code: "LINK_INTERNAL_ERROR", Message: "Client operation failed"}
		// Driver errors can include raw key values even when SQL logging is silent.
		common.SysError(common.LogText("link operation failed"))
	}
	// Audit only non-secret identity and error code, never request bodies or raw tokens.
	common.SysLog(common.LogText("link request rejected user=%d code=%s", c.GetInt("id"), failure.Code))
	message := common.NewMessage(failure.Message)
	fields := message.Fields()
	fields["success"], fields["code"], fields["message"] = false, failure.Code, message.Error()
	c.JSON(failure.Status, fields)
}
func linkBind(c *gin.Context, v any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024)
	if err := common.DecodeJson(c.Request.Body, v); err != nil {
		linkError(c, model.LinkFailure(400, "LINK_INVALID_REQUEST", "Invalid request body"))
		return false
	}
	return true
}
func LinkAuthStart(c *gin.Context) {
	var request service.LinkStartRequest
	if !linkBind(c, &request) {
		return
	}
	result, err := service.StartLinkAuthorization(request)
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, result)
}
func LinkAuthComplete(c *gin.Context) {
	identity, ok := middleware.GetSessionAuthIdentity(c)
	if !ok {
		linkError(c, model.LinkFailure(403, "LINK_FORBIDDEN", "A browser login session is required"))
		return
	}
	var request struct {
		FlowToken string `json:"flow_token"`
	}
	if !linkBind(c, &request) {
		return
	}
	origin, err := service.LinkPublicURL()
	if err != nil {
		linkError(c, err)
		return
	}
	// Bearer authorization is required; the origin check additionally binds the browser handoff.
	if c.GetHeader("Origin") != "" && strings.TrimRight(c.GetHeader("Origin"), "/") != origin.String() {
		linkError(c, model.LinkFailure(403, "LINK_FORBIDDEN", "Browser origin mismatch"))
		return
	}
	callback, err := service.CompleteLinkAuthorization(request.FlowToken, identity)
	if err != nil {
		linkError(c, err)
		return
	}
	common.SysLog(common.LogText("link authorization completed user=%d", identity.UserID))
	common.ApiSuccess(c, gin.H{"callback_url": callback})
}
func linkAuthResponse(c *gin.Context, bundle *model.LinkAuthBundle, uid int) {
	user, err := service.GetLinkUser(uid)
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, struct {
		*model.LinkAuthBundle
		User *service.LinkUser `json:"user"`
	}{bundle, user})
}
func LinkAuthExchange(c *gin.Context) {
	var request struct {
		Code        string `json:"code"`
		Verifier    string `json:"code_verifier"`
		RedirectURI string `json:"redirect_uri"`
		DeviceID    string `json:"device_id"`
	}
	if !linkBind(c, &request) {
		return
	}
	bundle, uid, err := service.ExchangeLinkAuthorization(request.Code, request.Verifier, request.RedirectURI, request.DeviceID)
	if err != nil {
		linkError(c, err)
		return
	}
	linkAuthResponse(c, bundle, uid)
}
func LinkAuthRefresh(c *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !linkBind(c, &request) {
		return
	}
	bundle, uid, err := model.RefreshLinkSession(request.RefreshToken)
	if err != nil {
		linkError(c, err)
		return
	}
	linkAuthResponse(c, bundle, uid)
}
func LinkAuthLogout(c *gin.Context) {
	session := middleware.GetLinkSession(c)
	if err := model.LogoutLinkSession(session); err != nil {
		linkError(c, err)
		return
	}
	common.SysLog(common.LogText("link session revoked user=%d session=%s", session.UserID, session.ID))
	common.ApiSuccess(c, gin.H{"logged_out": true})
}
func LinkBootstrap(c *gin.Context) {
	session := middleware.GetLinkSession(c)
	user, err := service.GetLinkUser(session.UserID)
	if err != nil {
		linkError(c, err)
		return
	}
	groups, err := service.GetLinkGroups(session.UserID)
	if err != nil {
		linkError(c, err)
		return
	}
	connections, err := model.ListLinkConnections(session)
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"user": user, "device_id": session.DeviceID, "groups": groups, "default_group": service.LinkDefaultGroup(groups), "connections": connections})
}
func LinkCatalog(c *gin.Context) {
	session := middleware.GetLinkSession(c)
	result, err := service.GetLinkCatalog(session.UserID, c.Query("tool_family"), c.Query("group"))
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, result)
}
func LinkConnectionCreate(c *gin.Context) { linkConnectionAction(c, "") }
func LinkConnectionAction(c *gin.Context) { linkConnectionAction(c, c.Param("id")) }
func linkConnectionAction(c *gin.Context, id string) {
	var request model.LinkActionRequest
	if !linkBind(c, &request) {
		return
	}
	session := middleware.GetLinkSession(c)
	result, err := service.ApplyLinkAction(session, id, request)
	if err != nil {
		linkError(c, err)
		return
	}
	common.SysLog(common.LogText("link action completed user=%d connection=%s operation=%s action=%s", session.UserID, result.Connection.ID, result.OperationID, request.Action))
	common.ApiSuccess(c, result)
}
func LinkConnectionGet(c *gin.Context) {
	result, err := model.GetLinkConnection(middleware.GetLinkSession(c), c.Param("id"))
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, result)
}
func LinkOperationGet(c *gin.Context) {
	result, err := model.GetLinkOperation(middleware.GetLinkSession(c), c.Param("id"))
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, result)
}
