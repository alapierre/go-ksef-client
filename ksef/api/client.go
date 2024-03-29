package api

import (
	"encoding/json"
	"fmt"
	"github.com/alapierre/go-ksef-client/ksef/util"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

type Client interface {
	PostXMLFromBytes(endpoint string, body []byte, result interface{}) error
	GetJson(endpoint, token string, result interface{}) error
	Get(endpoint, token string) ([]byte, error)
	GetJsonNoAuth(endpoint string, result interface{}) error
	PostJson(endpoint, token string, body interface{}, result interface{}) error
	PostJsonNoAuth(endpoint string, body interface{}, result interface{}) error
	PutJson(endpoint, token string, body interface{}, result interface{}) error
	Env() Environment
}

type Environment string

const (
	Test Environment = "https://ksef-test.mf.gov.pl/api"
	Demo             = "https://ksef-demo.mf.gov.pl/api"
	Prod             = "https://ksef.mf.gov.pl/api"
	Dev              = "http://localhost:8080/api"
)

type client struct {
	rest        *resty.Client
	environment Environment
}

func New(environment Environment) Client {
	restyClient := resty.New()
	return &client{rest: restyClient, environment: environment}
}

func (c *client) Env() Environment {
	return c.environment
}

func (c *client) PostXMLFromBytes(endpoint string, body []byte, result interface{}) error {

	log.Debugf("Posting XML, endpoint URL %s", endpoint)

	resp, err := prepareRequest(c).
		EnableTrace().
		SetBody(body).
		SetResult(result).
		SetHeader("Content-Type", "application/octet-stream; charset=utf-8").
		Post(string(c.environment) + endpoint)

	log.Debugf("Response status %s", resp.Status())
	printTraceInfo(endpoint, c, err, resp)
	return checkError(resp, err)
}

func (c *client) GetJson(endpoint, token string, result interface{}) error {
	log.Debugf("Send GET Request, endpoint URL %s", endpoint)

	resp, err := prepareRequest(c).
		SetResult(result).
		SetHeader("SessionToken", token).
		Get(string(c.environment) + endpoint)

	log.Debugf("Response status %s", resp.Status())
	printTraceInfo(endpoint, c, err, resp)
	return checkError(resp, err)
}

func (c *client) GetJsonNoAuth(endpoint string, result interface{}) error {
	log.Debugf("Send GET Request, endpoint URL %s", endpoint)

	resp, err := prepareRequest(c).
		SetResult(result).
		Get(string(c.environment) + endpoint)

	log.Debugf("Response status %s", resp.Status())
	printTraceInfo(endpoint, c, err, resp)
	return checkError(resp, err)
}

func (c *client) Get(endpoint, token string) ([]byte, error) {

	resp, err := prepareRequest(c).
		SetHeader("SessionToken", token).
		Get(string(c.environment) + endpoint)

	log.Debugf("Response status %s", resp.Status())

	printTraceInfo(endpoint, c, err, resp)

	if !resp.IsError() && err == nil {
		return resp.Body(), err
	}

	return nil, checkError(resp, err)
}

func (c *client) PostJson(endpoint, token string, body interface{}, result interface{}) error {

	log.Debugf("Posting JSON, endpoint URL %s", endpoint)

	resp, err := prepareRequest(c).
		SetBody(body).
		SetResult(result).
		SetHeader("SessionToken", token).
		Post(string(c.environment) + endpoint)

	log.Debugf("Response status %s", resp.Status())
	printTraceInfo(endpoint, c, err, resp)
	return checkError(resp, err)
}

func (c *client) PutJson(endpoint, token string, body interface{}, result interface{}) error {

	log.Debugf("Putting JSON, endpoint URL %s", endpoint)

	resp, err := prepareRequest(c).
		SetBody(body).
		SetResult(result).
		SetHeader("SessionToken", token).
		Put(string(c.environment) + endpoint)

	log.Debugf("Response status %s", resp.Status())
	printTraceInfo(endpoint, c, err, resp)
	return checkError(resp, err)
}

func (c *client) PostJsonNoAuth(endpoint string, body interface{}, result interface{}) error {

	log.Debugf("Posting JSON (no auth), endpoint URL %s", endpoint)

	resp, err := prepareRequest(c).
		SetBody(body).
		SetResult(result).
		Post(string(c.environment) + endpoint)

	log.Debugf("Response status %s", resp.Status())
	printTraceInfo(endpoint, c, err, resp)
	return checkError(resp, err)
}

func prepareRequest(c *client) *resty.Request {
	r := c.rest.R()
	if util.HttpTraceEnabled() {
		r.EnableTrace()
	}
	return r
}

func checkError(resp *resty.Response, err error) error {
	if resp.IsError() {

		body := resp.String()
		var errorMap map[string]any
		if body != "" {
			_ = json.Unmarshal([]byte(body), &errorMap)
		}

		return &RequestError{
			StatusCode:   resp.StatusCode(),
			Err:          err,
			Body:         body,
			ErrorDetails: errorMap,
		}
	}
	return err
}

func printTraceInfo(endpoint string, c *client, err error, resp *resty.Response) {

	if !util.HttpTraceEnabled() {
		return
	}

	fmt.Println("Response Info:")
	fmt.Println("  URL        :", string(c.environment)+endpoint)
	fmt.Println("  Error      :", err)
	fmt.Println("  Status Code:", resp.StatusCode())
	fmt.Println("  Status     :", resp.Status())
	fmt.Println("  Proto      :", resp.Proto())
	fmt.Println("  Time       :", resp.Time())
	fmt.Println("  Received At:", resp.ReceivedAt())
	fmt.Println("  Body       :\n", resp)
	fmt.Println()

	// Explore trace info
	fmt.Println("Request Trace Info:")
	ti := resp.Request.TraceInfo()
	fmt.Println("  DNSLookup     :", ti.DNSLookup)
	fmt.Println("  ConnTime      :", ti.ConnTime)
	fmt.Println("  TCPConnTime   :", ti.TCPConnTime)
	fmt.Println("  TLSHandshake  :", ti.TLSHandshake)
	fmt.Println("  ServerTime    :", ti.ServerTime)
	fmt.Println("  ResponseTime  :", ti.ResponseTime)
	fmt.Println("  TotalTime     :", ti.TotalTime)
	fmt.Println("  IsConnReused  :", ti.IsConnReused)
	fmt.Println("  IsConnWasIdle :", ti.IsConnWasIdle)
	fmt.Println("  ConnIdleTime  :", ti.ConnIdleTime)
	fmt.Println("  RequestAttempt:", ti.RequestAttempt)
	fmt.Println("  RemoteAddr    :", ti.RemoteAddr.String())
}

func printJson(src interface{}) {

	if !util.HttpTraceEnabled() {
		return
	}

	jsonData, err := json.Marshal(src)
	if err != nil {
		log.Errorf("Error marshalling the struct: %s", err)
	}
	fmt.Println(string(jsonData))
}
