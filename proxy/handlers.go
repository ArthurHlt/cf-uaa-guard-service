package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/cloudfoundry"
	"encoding/json"
	"strings"
	"errors"
	"encoding/base64"
	"time"
)

type UserInfo struct {
	Scope       []string `json:"scope"`
	UserID      string   `json:"user_id"`
	UserName    string   `json:"user_name"`
	Expiration  int64    `json:"exp"`
	Email       string   `json:"email"`
	TokenType   string   `json:"token_type"`
	AccessToken string   `json:"access_token"`
}
// Check if the user is logged in, otherwise forward to login page.
func rootHandler(res http.ResponseWriter, req *http.Request) {
	s, _ := gothic.Store.Get(req, "uaa-proxy-session")
	if s.Values["logged"] != true {
		http.Redirect(res, req, "/auth", http.StatusTemporaryRedirect)
		return
	}
	var userInfo UserInfo
	rawUserInfo := s.Values["user_info"].(string)
	json.Unmarshal([]byte(rawUserInfo), &userInfo)
	if sessionExpired(req) {
		http.Redirect(res, req, "/logout", http.StatusTemporaryRedirect)
		return
	}
	if !hasAllScopes(userInfo.Scope) {
		res.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(res, "401 Unauthorized missing one or more scopes in '" + strings.Join(c.Scopes, ", ") + "'.")
		return
	}
	newProxy(userInfo).ServeHTTP(res, req)
}
func sessionExpired(req *http.Request) bool {
	s, _ := gothic.Store.Get(req, "uaa-proxy-session")
	if s.Values["logged"] != true {
		return true
	}
	var userInfo UserInfo
	rawUserInfo := s.Values["user_info"].(string)
	json.Unmarshal([]byte(rawUserInfo), &userInfo)
	now := time.Now().Unix()
	return now >= userInfo.Expiration
}
func AccessTokenToUserInfo(accessToken string) (UserInfo, error) {
	// access token from cf is jwt, jwt as 3 parts separate by "." second part is user information
	splitToken := strings.Split(accessToken, ".")
	if len(splitToken) != 3 {
		return UserInfo{}, errors.New("This is not a jwt access token.")
	}
	data, err := base64.RawStdEncoding.DecodeString(splitToken[1])
	if err != nil {
		return UserInfo{}, err
	}
	var userInfo UserInfo
	err = json.Unmarshal(data, &userInfo)
	if err != nil {
		return UserInfo{}, err
	}
	userInfo.TokenType = "bearer"
	userInfo.AccessToken = accessToken
	return userInfo, nil
}
func hasAllScopes(actualScopes []string) bool {
	for _, scopeReq := range c.Scopes {
		if !hasScope(actualScopes, scopeReq) {
			return false
		}
	}
	return true
}
func hasScope(actualScopes []string, scopeReq string) bool {
	for _, scope := range actualScopes {
		if scope == scopeReq {
			return true
		}
	}
	return false
}

// Handle auth redirect
// TO FIX: setProviders is called to change the callback url on each request
func authHandler(res http.ResponseWriter, req *http.Request) {
	forwardedURL := req.Header.Get(CF_FORWARDED_URL)
	if forwardedURL != "" {
		parsedUrl, _ := url.Parse(forwardedURL)
		req.URL.RawQuery = parsedUrl.RawQuery
		setProviders("https://" + parsedUrl.Host + "/auth/callback")
	}
	gothic.BeginAuthHandler(res, req)
}

func logoutHandler(res http.ResponseWriter, req *http.Request) {
	s, _ := gothic.Store.Get(req, "uaa-proxy-session")
	if s.Values["logged"] != true {
		http.Redirect(res, req, "/auth", http.StatusTemporaryRedirect)
		return
	}
	s.Values["user_info"] = ""
	s.Values["logged"] = false
	s.Store().Save(req, res, s)
	http.Redirect(res, req, "/auth", http.StatusTemporaryRedirect)
}
func meHandler(res http.ResponseWriter, req *http.Request) {
	if sessionExpired(req) {
		res.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(res, "401 Unauthorized session expired.")
		return
	}
	s, _ := gothic.Store.Get(req, "uaa-proxy-session")
	res.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(res, s.Values["user_info"].(string))
}
// give back in json name and description of this proxy (used to register plans in broker)
func infoHandler(res http.ResponseWriter, req *http.Request) {
	proxyInfo := struct {
		Name        string
		Description string
	}{
		Name: c.ProxyName,
		Description: c.ProxyDescription,
	}
	res.Header().Set("Content-Type", "application/json")
	b, _ := json.MarshalIndent(proxyInfo, "", "\t")
	fmt.Fprintln(res, string(b))
}

// Handle callbacks from oauth.
func callbackHandler(res http.ResponseWriter, req *http.Request) {

	user, err := gothic.CompleteUserAuth(res, req)
	if err != nil {
		fmt.Fprintln(res, err)
		return
	}

	s, err := gothic.Store.Get(req, "uaa-proxy-session")
	userInfo, err := AccessTokenToUserInfo(user.AccessToken)
	if err != nil {
		fmt.Fprintln(res, err)
		return
	}
	rawUserInfo, _ := json.MarshalIndent(userInfo, "", "\t")
	s.Values["user_info"] = string(rawUserInfo)
	s.Values["logged"] = true
	err = gothic.Store.Save(req, res, s)
	if err != nil {
		fmt.Fprintln(res, err)
		return
	}
	http.Redirect(res, req, "/", http.StatusTemporaryRedirect)
}

func newProxy(userInfo UserInfo) http.Handler {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			forwardedURL := req.Header.Get(CF_FORWARDED_URL)
			parsedUrl, err := url.Parse(forwardedURL)
			if err != nil {
				log.Fatalln(err.Error())
			}
			req.URL = parsedUrl
			req.Host = parsedUrl.Host
			req.Header.Set("Authorization", userInfo.TokenType + " " + userInfo.AccessToken)
			req.Header.Set("X-Auth-User", userInfo.Email)
			req.Header.Set("X-Auth-User-Email", userInfo.Email)
			req.Header.Set("X-Auth-User-Name", userInfo.UserName)
			req.Header.Set("X-Auth-User-Id", userInfo.UserID)
			req.Header.Set("X-Auth-User-Scopes", strings.Join(userInfo.Scope, ","))

			fmt.Println(req.Header)
		},
	}
	return proxy
}

func setProviders(callbackURL string) {
	provider := cloudfoundry.New(c.LoginURL, c.ClientKey, c.ClientSecret, callbackURL, c.Scopes...)
	provider.Client = DefaultHttpClient()
	goth.UseProviders(
		provider,
	)
}
