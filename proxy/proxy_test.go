package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"os"
	"encoding/json"
	"github.com/markbates/goth/gothic"
	"github.com/stretchr/testify/assert"
	"time"
)

func TestMain(m *testing.M) {
	c = Config{}
	retCode := m.Run()
	os.Exit(retCode)
}
func TestProxy(t *testing.T) {
	t.Run("retrieve proxy informations", func(t *testing.T) {
		handler := http.HandlerFunc(infoHandler)
		req, err := http.NewRequest("GET", "/info", nil)
		assert.Nil(t, err)

		c.ProxyName = "myproxy"
		c.ProxyDescription = "this is a super proxy"
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)

		assert.Equal(t, res.Code, http.StatusOK)
		assert.Equal(t, res.Header().Get("Content-Type"), "application/json")

		proxyInfo := struct {
			Name        string
			Description string
		}{}
		err = json.NewDecoder(res.Body).Decode(&proxyInfo)
		assert.Nil(t, err)

		assert.Equal(t, proxyInfo.Name, "myproxy")
		assert.Equal(t, proxyInfo.Description, "this is a super proxy")
	})
	t.Run("/me", func(t *testing.T) {
		userInfo := UserInfo{
			Email: "fred@queen.com",
			UserName: "fred",
			Scope: []string{"openid"},
			TokenType: "bearer",
			AccessToken: "token",
			UserID: "1",
		}
		handler := http.HandlerFunc(meHandler)
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := json.Marshal(userInfo)
			w.Write(b)
		}))
		req, err := http.NewRequest("GET", "/", nil)
		assert.Nil(t, err)
		req.Header.Set(CF_FORWARDED_URL, backend.URL)
		t.Run("unauthorized when session expired", func(t *testing.T) {
			sess, err := gothic.Store.Get(req, "uaa-proxy-session")
			assert.Nil(t, err)
			sess.Values["logged"] = true

			userInfo.Expiration = time.Now().Unix() - 10
			rawUserInfo, _ := json.Marshal(userInfo)
			sess.Values["user_info"] = string(rawUserInfo)

			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)

			assert.Equal(t, res.Code, http.StatusUnauthorized)
			body, err := ioutil.ReadAll(res.Body)
			assert.Nil(t, err)
			assert.Equal(t, body, []byte("401 Unauthorized session expired."))
		})
		t.Run("unauthorized when not connected", func(t *testing.T) {
			sess, err := gothic.Store.Get(req, "uaa-proxy-session")
			assert.Nil(t, err)
			sess.Values["logged"] = false

			userInfo.Expiration = time.Now().Unix() + 10
			rawUserInfo, _ := json.Marshal(userInfo)
			sess.Values["user_info"] = string(rawUserInfo)

			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)

			assert.Equal(t, res.Code, http.StatusUnauthorized)
			body, err := ioutil.ReadAll(res.Body)
			assert.Nil(t, err)
			assert.Equal(t, body, []byte("401 Unauthorized session expired."))
		})
		t.Run("authorized when connected and session didn't expired", func(t *testing.T) {
			sess, err := gothic.Store.Get(req, "uaa-proxy-session")
			assert.Nil(t, err)
			sess.Values["logged"] = true

			userInfo.Expiration = time.Now().Unix() + 10
			rawUserInfo, _ := json.Marshal(userInfo)
			sess.Values["user_info"] = string(rawUserInfo)

			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)

			assert.Equal(t, res.Code, http.StatusOK)
			body, err := ioutil.ReadAll(res.Body)
			assert.Nil(t, err)
			var userInfoRes UserInfo
			err = json.Unmarshal([]byte(body), &userInfoRes)
			assert.Nil(t, err)
			assert.Equal(t, userInfo, userInfoRes)
		})
	})
	t.Run("authentication", func(t *testing.T) {
		handler := http.HandlerFunc(rootHandler)
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(r.Header.Get("X-Auth-User")))
			w.Write([]byte(r.Header.Get("X-Auth-User-Email")))
			w.Write([]byte(r.Header.Get("X-Auth-User-Name")))
			w.Write([]byte(r.Header.Get("X-Auth-User-Id")))
			w.Write([]byte(r.Header.Get("X-Auth-User-Scopes")))
			w.Write([]byte(r.Header.Get("Authorization")))
		}))

		req, err := http.NewRequest("GET", "/", nil)
		assert.Nil(t, err)
		req.Header.Set(CF_FORWARDED_URL, backend.URL)

		t.Run("not connected", func(t *testing.T) {
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)

			assert.Equal(t, res.Code, http.StatusTemporaryRedirect)
			assert.Equal(t, res.Header().Get("Location"), "/auth")
		})
		t.Run("connected", func(t *testing.T) {
			t.Run("authorized when user have needed scopes", func(t *testing.T) {
				c.Scopes = []string{"openid"}
				sess, err := gothic.Store.Get(req, "uaa-proxy-session")
				assert.Nil(t, err)
				userInfo := UserInfo{
					Email: "fred@queen.com",
					UserName: "fred",
					Scope: []string{"openid"},
					TokenType: "bearer",
					Expiration: time.Now().Add(10 * time.Second).Unix(),
					AccessToken: "token",
					UserID: "1",
				}
				rawUserInfo, _ := json.Marshal(userInfo)
				sess.Values["user_info"] = string(rawUserInfo)
				sess.Values["logged"] = true

				// Set some invalid value so we can be sure that it's
				// being overwritten internally.
				req.Header.Set("X-Auth-User", "auth-user-from-client")

				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)

				assert.Equal(t, res.Code, http.StatusOK)

				// Be sure there's only one X-Auth-User header and
				// it's what we expect
				assert.Equal(t, len(req.Header["X-Auth-User"]), 1)
				assert.Equal(t, req.Header.Get("X-Auth-User"), "fred@queen.com")

				assert.Equal(t, len(req.Header["Authorization"]), 1)
				assert.Equal(t, req.Header.Get("Authorization"), "bearer token")

				assert.Equal(t, len(req.Header["X-Auth-User-Email"]), 1)
				assert.Equal(t, req.Header.Get("X-Auth-User-Email"), "fred@queen.com")

				assert.Equal(t, len(req.Header["X-Auth-User-Name"]), 1)
				assert.Equal(t, req.Header.Get("X-Auth-User-Name"), "fred")

				assert.Equal(t, len(req.Header["X-Auth-User-Id"]), 1)
				assert.Equal(t, req.Header.Get("X-Auth-User-Id"), "1")

				assert.Equal(t, len(req.Header["X-Auth-User-Scopes"]), 1)
				assert.Equal(t, req.Header.Get("X-Auth-User-Scopes"), "openid")

				body, err := ioutil.ReadAll(res.Body)
				assert.Nil(t, err)
				assert.Equal(t, body, []byte("fred@queen.comfred@queen.comfred1openidbearer token"))
			})
			t.Run("unauthorized when user doesn't have needed scopes", func(t *testing.T) {
				c.Scopes = []string{"openid", "cloud_controller.admin"}
				sess, err := gothic.Store.Get(req, "uaa-proxy-session")
				assert.Nil(t, err)
				userInfo := UserInfo{
					Email: "fred@queen.com",
					UserName: "fred",
					Expiration: time.Now().Add(10 * time.Second).Unix(),
					Scope: []string{"openid"},
					UserID: "1",
				}
				rawUserInfo, _ := json.Marshal(userInfo)
				sess.Values["user_info"] = string(rawUserInfo)
				sess.Values["logged"] = true

				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)

				assert.Equal(t, res.Code, http.StatusUnauthorized)

				body, err := ioutil.ReadAll(res.Body)
				assert.Nil(t, err)
				assert.Equal(t, body, []byte("401 Unauthorized missing one or more scopes in 'openid, cloud_controller.admin'."))
			})
			t.Run("redirected to logout when session expired", func(t *testing.T) {
				c.Scopes = []string{"openid"}
				sess, err := gothic.Store.Get(req, "uaa-proxy-session")
				assert.Nil(t, err)
				userInfo := UserInfo{
					Email: "fred@queen.com",
					UserName: "fred",
					Expiration: time.Now().Unix() - 10,
					Scope: []string{"openid"},
					UserID: "1",
				}
				rawUserInfo, _ := json.Marshal(userInfo)
				sess.Values["user_info"] = string(rawUserInfo)
				sess.Values["logged"] = true

				res := httptest.NewRecorder()
				handler.ServeHTTP(res, req)

				assert.Equal(t, res.Code, http.StatusTemporaryRedirect)
				assert.Equal(t, res.Header().Get("Location"), "/logout")
			})
		})
	})

}
