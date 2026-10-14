package router

import (
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/gin-gonic/gin"
)

func registerLinkRoutes(api *gin.RouterGroup) {
	link := api.Group("/link/v1", middleware.LinkTransport(), middleware.DisableCache())
	link.POST("/auth/start", middleware.CriticalRateLimit(), controller.LinkAuthStart)
	link.POST("/auth/complete", middleware.CriticalRateLimit(), middleware.UserAuth(), controller.LinkAuthComplete)
	link.POST("/auth/exchange", middleware.CriticalRateLimit(), controller.LinkAuthExchange)
	link.POST("/auth/refresh", middleware.CriticalRateLimit(), controller.LinkAuthRefresh)
	client := link.Group("", middleware.LinkAuth())
	client.POST("/auth/logout", controller.LinkAuthLogout)
	client.GET("/bootstrap", controller.LinkBootstrap)
	client.GET("/catalog", controller.LinkCatalog)
	client.POST("/connections", controller.LinkConnectionCreate)
	client.GET("/connections/:id", controller.LinkConnectionGet)
	client.POST("/connections/:id/actions", controller.LinkConnectionAction)
	client.GET("/operations/:id", controller.LinkOperationGet)
	client.POST("/connections/:id/tool-verifications", controller.LinkToolVerificationCreate)
	client.GET("/tool-verifications/:id", controller.LinkToolVerificationGet)
}
