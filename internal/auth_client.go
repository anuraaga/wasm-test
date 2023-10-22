package internal

import (
	"strconv"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

const (
	XAuthServiceAuthResponseJWTHeader = "x-auth-jwt"
)

type AuthClient struct {
	XRequestID string
	Conf       *Config
	Metrics    *Metrics
}

func (d *AuthClient) RequestJWT(origReqHeaders map[string]string) {
	proxywasm.LogCriticalf("%s: Requesting JWT from Auth Service", d.XRequestID)

	// Now actually call the Auth Service.
	_, err := proxywasm.DispatchHttpCall(
		d.Conf.AuthClusterName,
		[][2]string{
			{"accept", "*/*"},
			{":authority", d.Conf.AuthAuthority},
			{":method", "GET"},
			{":path", "/foo/bar"},        // get Httpbin to return some fake data
		},
		nil,
		nil,
		d.Conf.AuthTimeout,
		d.authCallback,
	)
	if err != nil {
		proxywasm.LogCriticalf("%s: failed to call AuthService: %v", d.XRequestID, err)
		// We want to resume the intercepted request even if we couldn't get an authentication header
		_ = proxywasm.ResumeHttpRequest()
	}
}

func (d *AuthClient) authCallback(_, _, _ int) {
	proxywasm.LogInfof("%s: Got response from AuthService", d.XRequestID)
	responseStatus := uint32(500)

	// We want to always resume the intercepted request regardless of success/fail to avoid indefinitely blocking anything
	defer func() {
		if responseStatus != 200 {
			responseErr := proxywasm.SendHttpResponse(responseStatus, [][2]string{{"generated-by", "My WASM plugin"}}, []byte("Failed to add JWT"), -1)
			if responseErr == nil {
				return // Need to skip calling ResumeHttpRequest to avoid sending this to upstream service
			}
			proxywasm.LogErrorf("%s: failed to send %d back to client: %v", d.XRequestID, responseStatus, responseErr)
		}
		if err := proxywasm.ResumeHttpRequest(); err != nil {
			proxywasm.LogCriticalf("%s: failed to ResumeHttpRequest after calling auth: %v", d.XRequestID, err)
		}
	}()

	// Get the response headers from our call to AuthService
	headers, err := proxywasm.GetHttpCallResponseHeaders()
	if err != nil {
		proxywasm.LogCriticalf("%s: failed to GetHttpCallResponseHeaders from auth response: %v", d.XRequestID, err)
		return
	}

	// Convert to map to make it easier to get specific headers
	authResponseHeaders := headerArrayToMap(headers)
	d.Metrics.Increment("execution_count", [][2]string{{"authority", "app.com"}})

	// Note we're using `:status` instead of just `status`. This is the same for any HTTP-transport-specific headers like ':method', ':path', ':authority', ...
	// You don't need the ':' prefix for headers like 'user-agent', 'accept, ...
	if authResponseHeaders[":status"] == "200" {

		h := "x-test"

		proxywasm.LogWarnf("%s: adding new header val %s to original request: %s", d.XRequestID, "foo", authResponseHeaders)
		if err := proxywasm.AddHttpRequestHeader(h, "foo"); err != nil {
			// proxywasm.LogCriticalf("%s: failed to add header '%v' to request: %v", fc.XRequestID, h, err)
			d.Metrics.Increment("error_count", nil)
			return
		}

		d.Metrics.Increment("success_count", nil)
		
		responseStatus = 200
		return
	}

	if len(authResponseHeaders[":status"]) > 0 {
		status, err := strconv.ParseInt(authResponseHeaders[":status"], 10, 0)
		if err == nil {
			responseStatus = uint32(status)
		}
	}
	proxywasm.LogErrorf("%s: AuthService failed this request - status:%s", d.XRequestID, authResponseHeaders[":status"])
}
