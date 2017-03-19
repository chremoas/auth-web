package main

import (
	"github.com/astaxie/beego/session"
	"fmt"
	"net/http"
	"github.com/antihax/goesi"
	"github.com/gregjones/httpcache"
	"encoding/json"
	"golang.org/x/oauth2"
	"io/ioutil"
	"gopkg.in/yaml.v2"
)

const htmlIndex = `<html><body>
<a href="/login">Log in with EVE</a>
</body></html>
`

type Configuration struct {
	Application struct {
		Namespace string
		Name      string
		ListenHost string `yaml:"listenHost"`
		ListenPort string `yaml:"listenPort"`
		OAuth struct {
			ClientId string `yaml:"clientId"`
			ClientSecret string `yaml:"clientSecret"`
			CallBackUrl string `yaml:"callBackUrl"`
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

var globalSessions *session.Manager
var apiClient *goesi.APIClient
var httpClient *http.Client
var configuration *Configuration

// Then, initialize the session manager
func init() {
	globalSessions, _ = session.NewManager("memory", &session.ManagerConfig{CookieName:"gosessionid", EnableSetCookie: true, Gclifetime:600})
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

	httpClient = httpcache.NewMemoryCacheTransport().Client()
	apiClient = goesi.NewAPIClient(httpClient, "aba-auth-web maurer.it@gmail.com")
}

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleEveLogin)
	http.HandleFunc("/sso/callback", handleEveCallback)

	//TODO: This doesn't handle a sigint very gracefully
	fmt.Println(http.ListenAndServe(configuration.Application.ListenHost + ":" + configuration.Application.ListenPort, nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func handleEveLogin(w http.ResponseWriter, r *http.Request) {
	var ssoauth *goesi.SSOAuthenticator

	sess, _ := globalSessions.SessionStart(w, r)
	tmpSsoAuth := sess.Get("ssoauth")

	if tmpSsoAuth == nil {
		//TODO: Gather requested auth scopes from the http.Request and replace the scopes string array with that.
		ssoauth = goesi.NewSSOAuthenticator(
			httpClient,
			configuration.Application.OAuth.ClientId,
			configuration.Application.OAuth.ClientSecret,
			//TODO: Make this configurable as well so https can be a thing
			"http://" + configuration.Application.ListenHost + ":" +
					configuration.Application.ListenPort +
					configuration.Application.OAuth.CallBackUrl,
			nil,
		)
	} else {
		ssoauth = tmpSsoAuth.(*goesi.SSOAuthenticator)
	}

	sess.Set("ssoauth", ssoauth)

	state := sess.SessionID()[0:8]
	redirectUrl := ssoauth.AuthorizeURL(state, true, nil)

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

		fmt.Print("TokenSource: ")
		tokenSource := sess.Get("tokenSource").(oauth2.TokenSource)
		token, _ := tokenSource.Token()
		marshalledTS, _ := json.Marshal(token)
		fmt.Println(string(marshalledTS))

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

func doAuth (w http.ResponseWriter, r *http.Request, sess session.Store) (error) {
	var ssoauth *goesi.SSOAuthenticator

	if sess == nil {
		fmt.Printf("No session, redirecting to /\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return authError{message:"Invalid session"}
	}

	//If our tokenSource is set we've already gone through this procedure... pull the stuff from the session
	if sess.Get("tokenSource") == nil {
		state := r.FormValue("state")
		code := r.FormValue("code")
		tmpSsoAuth := sess.Get("ssoauth")
		if tmpSsoAuth == nil {
			fmt.Printf("Invalid session, redirecting to /\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return authError{message:"Invalid session"}
		} else {
			ssoauth = tmpSsoAuth.(*goesi.SSOAuthenticator)
		}

		if state != sess.SessionID()[0:8] {
			fmt.Printf("Invalid oauth state, expected '%s', got '%s'\n", sess.SessionID()[0:8], state)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return authError{message: fmt.Sprintf("Invalid oauth state, expected '%s', got '%s'\n", sess.SessionID()[0:8], state)}
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

		character, _, err := apiClient.V4.CharacterApi.GetCharactersCharacterId(int32(verifyReponse.CharacterID), nil)
		if err != nil {
			fmt.Printf("Had some kind of error getting the character '%s'\n", err)
		}

		corporation, _, err := apiClient.V3.CorporationApi.GetCorporationsCorporationId(character.CorporationId, nil)
		if err != nil {
			fmt.Printf("Had some kind of error getting the corporation '%s'\n", err)
		}

		alliance, _, err := apiClient.V2.AllianceApi.GetAlliancesAllianceId(corporation.AllianceId, nil)
		if err != nil {
			fmt.Printf("Had some kind of error getting the alliance '%s'\n", err)
		}

		//The Token is a one time use thing... no need to store it anywhere... ever
		//sess.Set("token", token)
		sess.Set("tokenSource", tokenSource)
		sess.Set("verifyResponse", verifyReponse)
		sess.Set("character", character)
		sess.Set("corporation", corporation)
		sess.Set("alliance", alliance)
	}

	return nil
}
