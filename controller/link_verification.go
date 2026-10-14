package controller

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

func LinkToolVerificationCreate(c *gin.Context) {
	var request model.LinkToolVerificationRequest
	if !linkBind(c, &request) {
		return
	}
	result, err := model.CreateLinkToolVerification(middleware.GetLinkSession(c), c.Param("id"), request)
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, result)
}

func LinkToolVerificationGet(c *gin.Context) {
	result, err := model.GetLinkToolVerification(middleware.GetLinkSession(c), c.Param("id"))
	if err != nil {
		linkError(c, err)
		return
	}
	common.ApiSuccess(c, result)
}
