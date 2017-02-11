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
)

// Check if the user is logged in, otherwise forward to login page.
func rootHandler(res http.ResponseWriter, req *http.Request) {
	s, _ := gothic.Store.Get(req, "uaa-proxy-session")
	if s.Values["logged"] != true {
		http.Redirect(res, req, "/auth", http.StatusTemporaryRedirect)
		return
	}

	newProxy(s.Values["user_email"].(string)).ServeHTTP(res, req)
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
	s.Values["user_email"] = user.Email
	s.Values["logged"] = true
	gothic.Store.Save(req, res, s)

	http.Redirect(res, req, "/", http.StatusTemporaryRedirect)
}

func newProxy(remote_user string) http.Handler {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			forwardedURL := req.Header.Get(CF_FORWARDED_URL)
			parsedUrl, err := url.Parse(forwardedURL)
			if err != nil {
				log.Fatalln(err.Error())
			}
			req.URL = parsedUrl
			req.Host = parsedUrl.Host
			req.Header.Set("X-Auth-User", remote_user)

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
