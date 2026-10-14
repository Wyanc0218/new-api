package controller

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestLinkInsecureTestOriginScope(t *testing.T) {
	const testOrigin = "http://203.0.113.40:13003"
	gin.SetMode(gin.TestMode)
	t.Setenv("TRUSTED_PROXIES", "none")
	for _, tc := range []struct {
		name, publicURL, testURL, requestHost string
		configured, allowed                   bool
	}{
		{"default refuses public HTTP", testOrigin, "", "203.0.113.40:13003", false, false},
		{"explicit identical origin", testOrigin, testOrigin, "203.0.113.40:13003", true, true},
		{"wrong request host", testOrigin, testOrigin, "203.0.113.41:13003", true, false},
		{"wrong request port", testOrigin, testOrigin, "203.0.113.40:13004", true, false},
		{"host path rejected", testOrigin, testOrigin, "203.0.113.40:13003/", true, false},
		{"missing public origin", "", testOrigin, "203.0.113.40:13003", false, false},
		{"mismatched public host", "http://203.0.113.41:13003", testOrigin, "203.0.113.40:13003", false, false},
		{"mismatched public port", "http://203.0.113.40:13004", testOrigin, "203.0.113.40:13003", false, false},
		{"HTTPS is not an HTTP exception", testOrigin, "https://203.0.113.40:13003", "203.0.113.40:13003", false, false},
		{"normalizes default port and host case", "http://PLATFORM.example:80/", "http://platform.example", "PLATFORM.example:80", true, true},
		{"normalizes trailing slash", testOrigin + "/", testOrigin, "203.0.113.40:13003", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LINK_PUBLIC_URL", tc.publicURL)
			t.Setenv("LINK_INSECURE_TEST_ORIGIN", tc.testURL)
			_, err := service.LinkPublicURL()
			if tc.configured {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			router := gin.New()
			router.Use(middleware.LinkTransport())
			router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			request := httptest.NewRequest(http.MethodGet, testOrigin+"/", nil)
			request.Host = tc.requestHost
			request.RemoteAddr = "198.51.100.2:1234"
			// None of these spoofable headers may authorize another destination.
			request.Header.Set("X-Forwarded-Host", "203.0.113.40:13003")
			request.Header.Set("X-Forwarded-Proto", "https")
			request.Header.Set("X-Forwarded-For", "127.0.0.1")
			request.Header.Set("Forwarded", "host=203.0.113.40:13003;proto=https")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			want := http.StatusBadRequest
			if tc.allowed {
				want = http.StatusNoContent
			}
			assert.Equal(t, want, response.Code)
			assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		})
	}

	for _, raw := range []string{
		"http://*.example", testOrigin + "/path", testOrigin + "/%2f", testOrigin + "?",
		testOrigin + "?key=value", testOrigin + "#", testOrigin + "#fragment",
		"http://user@203.0.113.40:13003", "http://203.0.113.40:65536", "http://203.0.113.40:0",
		"http://203.0.113.40:", testOrigin + ",http://other.example", "not-an-origin",
	} {
		t.Run("invalid "+raw, func(t *testing.T) {
			// Identical invalid settings must not accidentally enable the exception.
			t.Setenv("LINK_PUBLIC_URL", raw)
			t.Setenv("LINK_INSECURE_TEST_ORIGIN", raw)
			assert.Empty(t, common.LinkInsecureTestOrigin())
			_, err := service.LinkPublicURL()
			require.Error(t, err)
		})
	}
}

func TestLinkInsecureTestAuthorizationURL(t *testing.T) {
	t.Setenv("LINK_PUBLIC_URL", "http://203.0.113.40:13003/")
	t.Setenv("LINK_INSECURE_TEST_ORIGIN", "http://203.0.113.40:13003")
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "authorization.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	previousDB := model.DB
	model.DB = db
	t.Cleanup(func() {
		model.DB = previousDB
		_ = sqlDB.Close()
	})
	require.NoError(t, db.AutoMigrate(&model.AuthFlow{}))
	challenge := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	result, err := service.StartLinkAuthorization(service.LinkStartRequest{
		DeviceID: uuid.NewString(), CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]),
		CodeChallengeMethod: "S256", RedirectURI: "http://127.0.0.1:12345/callback", State: strings.Repeat("s", 43),
	})
	require.NoError(t, err)
	parsed, err := url.Parse(result.AuthorizeURL)
	require.NoError(t, err)
	assert.Equal(t, "http", parsed.Scheme)
	assert.Equal(t, "203.0.113.40:13003", parsed.Host)
	assert.Equal(t, "/link/authorize", parsed.Path)
	assert.Equal(t, result.FlowToken, parsed.Query().Get("flow_token"))
	assert.Len(t, parsed.Query(), 1)
}
