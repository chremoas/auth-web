package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/antihax/goesi"
	"github.com/astaxie/beego/session"
	"github.com/gregjones/httpcache"
	"gopkg.in/yaml.v2"
)

const htmlIndex = `<html><body>
<a href="/login">Log in with EVE</a>
</body></html>
`

type Configuration struct {
	Application struct {
		Namespace  string
		Name       string
		ListenHost string `yaml:"listenHost"`
		ListenPort string `yaml:"listenPort"`
		OAuth      struct {
			ClientId     string `yaml:"clientId"`
			ClientSecret string `yaml:"clientSecret"`
			CallBackUrl  string `yaml:"callBackUrl"`
		} `yaml:"oauth"`
		Debug bool
	}
}

type authError struct {
	message string
}

func (ae authError) Error() string {
	return ae.message
}

type key int

const authenticatorKey key = 1
const apiClientKey key = 2

// pull the SSO Authenticator pointer from the context.
func authenticatorFromContext(ctx context.Context) *goesi.SSOAuthenticator {
	return ctx.Value(authenticatorKey).(*goesi.SSOAuthenticator)
}

// Add SSO Authenticator pointer to the context.
func contextWithAuthenticator(ctx context.Context, a *goesi.SSOAuthenticator) context.Context {
	return context.WithValue(ctx, authenticatorKey, a)
}

// pull the API Client pointer from the context.
func apiClientFromContext(ctx context.Context) *goesi.APIClient {
	return ctx.Value(apiClientKey).(*goesi.APIClient)
}

// Add API Client pointer to the context.
func contextWithAPIClient(ctx context.Context, a *goesi.APIClient) context.Context {
	return context.WithValue(ctx, apiClientKey, a)
}

// Add custom middleware for SSO Authenticator
func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := contextWithAuthenticator(req.Context(), authenticator)
		ctx = contextWithAPIClient(ctx, apiClient)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

var globalSessions *session.Manager
var apiClient *goesi.APIClient
var httpClient *http.Client
var configuration *Configuration
var authenticator *goesi.SSOAuthenticator

// Then, initialize the session manager
func init() {
	globalSessions, _ = session.NewManager("memory", &session.ManagerConfig{CookieName: "gosessionid", EnableSetCookie: true, Gclifetime: 600})
	go globalSessions.GC()

	data, err := ioutil.ReadFile("application.yaml")

	//<editor-fold desc="Configuration Launch Sanity check">
	//TODO: Candidate for shared function for all my services.
	if err != nil {
		panic("Could not read application.yaml for configuration data.")
	}

	err = yaml.Unmarshal([]byte(data), &configuration)

	if err != nil {
		message, _ := fmt.Printf("Parsing application.yaml failed: %s", err)
		panic(message)
	}
	//</editor-fold>

	// Get a caching HTTP Client
	httpClient = httpcache.NewMemoryCacheTransport().Client()

	// Get the ESI API Client
	apiClient = goesi.NewAPIClient(httpClient, "aba-auth-web maurer.it@gmail.com")

	// Allocate an SSO Authenticator
	authenticator = goesi.NewSSOAuthenticator(
		httpClient,
		configuration.Application.OAuth.ClientId,
		configuration.Application.OAuth.ClientSecret,

		//TODO: Make this configurable as well so https can be a thing
		"http://"+configuration.Application.ListenHost+":"+
			configuration.Application.ListenPort+
			configuration.Application.OAuth.CallBackUrl,
		nil,
	)
}

func main() {
	// Allocate a multiplexer
	mux := http.NewServeMux()

	// Add our paths and handlers
	mux.Handle("/", http.HandlerFunc(handleMain))
	mux.Handle("/login", http.HandlerFunc(handleEveLogin))
	mux.Handle("/sso/callback", http.HandlerFunc(handleEveCallback))
	mux.Handle("/test", http.HandlerFunc(handleValidateAgain))

	//TODO: This doesn't handle a sigint very gracefully
	fmt.Println(http.ListenAndServe(configuration.Application.ListenHost+":"+configuration.Application.ListenPort, middleware(mux)))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func handleEveLogin(w http.ResponseWriter, r *http.Request) {
	// Get the users session
	sess, _ := globalSessions.SessionStart(w, r)

	// Get the authenticator from the request context
	ssoauth := authenticatorFromContext(r.Context())

	// Generate a random 16 byte state.
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	// Save the state to the session to validate with the response.
	sess.Set("state", state)

	// Build the authorize URL
	redirectUrl := ssoauth.AuthorizeURL(state, true, nil)

	// Redirect the user to CCP SSO
	http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
}

func handleEveCallback(w http.ResponseWriter, r *http.Request) {
	sess, _ := globalSessions.SessionStart(w, r)
	err := doAuth(w, r, sess)
	if err != nil {
		return
	}

	if configuration.Application.Debug {
		//Don't try to pull this out... it'll never be there... doAuth function
		//fmt.Print("Token: ")
		//fmt.Println(goesi.TokenToJSON(sess.Get("token")))

		fmt.Print("VerifyResponse: ")
		verifyResponse, _ := json.Marshal(sess.Get("verifyResponse"))
		fmt.Println(string(verifyResponse))

		fmt.Print("Character: ")
		fmt.Println(sess.Get("character"))

		fmt.Print("Corporation: ")
		fmt.Println(sess.Get("corporation"))

		fmt.Print("Alliance: ")
		fmt.Println(sess.Get("alliance"))
	}
}

func handleValidateAgain(w http.ResponseWriter, r *http.Request) {
	// Get the users session
	sess, _ := globalSessions.SessionStart(w, r)

	// Get the authenticator from the request context
	ssoauth := authenticatorFromContext(r.Context())
	tokenTxt, ok := sess.Get("token").(goesi.CRESTToken)
	if !ok {
		fmt.Fprintf(w, "no token found\n")
		return
	}

	tokenSource, err := ssoauth.TokenSource(&tokenTxt)
	if err != nil {
		fmt.Fprintf(w, "Had some kind of error getting the tokenSource '%s'\n", err)
		return
	}

	v, err := ssoauth.Verify(tokenSource)
	if err != nil {
		fmt.Fprintf(w, "Had some kind of error getting the verification '%s'\n", err)
		return
	}

	fmt.Fprintf(w, "Sup %s?", v.CharacterName)

}

func doAuth(w http.ResponseWriter, r *http.Request, sess session.Store) error {
	if sess == nil {
		fmt.Printf("No session, redirecting to /\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return authError{message: "Invalid session"}
	}

	//If our character is set we've already gone through this procedure... pull the stuff from the session
	if sess.Get("character") == nil {
		state := r.FormValue("state")
		code := r.FormValue("code")
		stateValidate := sess.Get("state")

		ssoauth := authenticatorFromContext(r.Context())
		api := apiClientFromContext(r.Context())

		//
		if state != stateValidate {
			fmt.Printf("Invalid oauth state, expected '%s', got '%s'\n", stateValidate, state)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return authError{message: fmt.Sprintf("Invalid oauth state, expected '%s', got '%s'\n", stateValidate, state)}
		}

		token, err := ssoauth.TokenExchange(code)
		if err != nil {
			fmt.Printf("Code exchange failed with '%s'\n", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return authError{message: fmt.Sprintf("Code exchange failed with '%s'\n", err)}
		}

		tokenSource, err := ssoauth.TokenSource(token)
		if err != nil {
			fmt.Printf("Token retrieve failed with '%s'\n", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return authError{message: fmt.Sprintf("Token retrieve failed with '%s'\n", err)}
		}

		verifyReponse, err := ssoauth.Verify(tokenSource)
		if err != nil {
			fmt.Printf("Had some kind of error getting the verify response '%s'\n", err)
		}

		character, _, err := api.V4.CharacterApi.GetCharactersCharacterId(int32(verifyReponse.CharacterID), nil)
		if err != nil {
			fmt.Printf("Had some kind of error getting the character '%s'\n", err)
		}

		corporation, _, err := api.V3.CorporationApi.GetCorporationsCorporationId(character.CorporationId, nil)
		if err != nil {
			fmt.Printf("Had some kind of error getting the corporation '%s'\n", err)
		}

		alliance, _, err := api.V2.AllianceApi.GetAlliancesAllianceId(corporation.AllianceId, nil)
		if err != nil {
			fmt.Printf("Had some kind of error getting the alliance '%s'\n", err)
		}

		sess.Set("token", *token)
		sess.Set("verifyResponse", verifyReponse)
		sess.Set("character", character)
		sess.Set("corporation", corporation)
		sess.Set("alliance", alliance)
	}

	return nil
}
