package webhook_test

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"os"
	"testing"
	"time"

	"github.com/handletec/webhook"
)

type WebHookRequest struct {
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
}

var r *WebHookRequest
var b []byte

func init() {

	r = &WebHookRequest{
		Action:    "create",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	var err error
	b, err = json.Marshal(r)
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

}

func TestAuthNone(t *testing.T) {

	whs := webhook.NewWebHooks()

	err := whs.Add(webhook.MethodPost, "https://echo.app.handletec.my", webhook.WithNoAuth())
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	//fmt.Println(whs)

	// custom TLS config, could add custom CA too if needed
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	headers := webhook.NewHeaders()
	headers.SetUserAgent("my-agent/v1-noaauth-post") // override user agent for easier identification

	err = whs.Broadcast(tlsConfig, webhook.WithData(b), webhook.WithHeaders(headers))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	log.Println("done broadcast")

}

func TestAuthBasic(t *testing.T) {

	whs := webhook.NewWebHooks()

	err := whs.Add(webhook.MethodPost, "https://echo.app.handletec.my", webhook.WithBasicAuth("hello", "world"))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	//fmt.Println(whs)

	// custom TLS config, could add custom CA too if needed
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	headers := webhook.NewHeaders()
	headers.SetUserAgent("my-agent/v1-basicauth-post") // override user agent for easier identification

	err = whs.Broadcast(tlsConfig, webhook.WithData(b), webhook.WithHeaders(headers))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	log.Println("done broadcast")

}

func TestAuthBearer(t *testing.T) {

	whs := webhook.NewWebHooks()

	err := whs.Add(webhook.MethodPost, "https://echo.app.handletec.my", webhook.WithBearerToken("mysupersecrettoken"))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	//fmt.Println(whs)

	// custom TLS config, could add custom CA too if needed
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	headers := webhook.NewHeaders()
	headers.SetUserAgent("my-agent/v1-hearer-post") // override user agent for easier identification

	err = whs.Broadcast(tlsConfig, webhook.WithData(b), webhook.WithHeaders(headers))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	log.Println("done broadcast")

}

func TestAuthToken(t *testing.T) {

	whs := webhook.NewWebHooks()

	err := whs.Add(webhook.MethodPost, "https://echo.app.handletec.my", webhook.WithToken("x-custom-api-key", "secret"))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	//fmt.Println(whs)

	// custom TLS config, could add custom CA too if needed
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	headers := webhook.NewHeaders()
	headers.SetUserAgent("my-agent/v1-token-post") // override user agent for easier identification

	err = whs.Broadcast(tlsConfig, webhook.WithData(b), webhook.WithHeaders(headers))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	log.Println("done broadcast")

}

func TestMethodGet(t *testing.T) {

	whs := webhook.NewWebHooks()

	err := whs.Add(webhook.MethodGet, "https://echo.app.handletec.my", webhook.WithNoAuth())
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}
	//fmt.Println(whs)

	// custom TLS config, could add custom CA too if needed
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	headers := webhook.NewHeaders()
	headers.SetUserAgent("my-agent/v1-noauth-get") // override user agent for easier identification

	/*
		query := webhook.NewQuery() // specify query parameter
		query.Add("action", r.Action)
		query.Add("timestamp", r.Timestamp)

		err = whs.Broadcast(tlsConfig, webhook.WithQuery(query), webhook.WithHeaders(headers))
		if nil != err {
			log.Println(err)
			os.Exit(1)
		}
	*/

	err = whs.Broadcast(tlsConfig, webhook.WithData(b), webhook.WithHeaders(headers))
	if nil != err {
		log.Println(err)
		os.Exit(1)
	}

	log.Println("done broadcast")

}
