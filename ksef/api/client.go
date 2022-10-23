package api

import "github.com/go-resty/resty/v2"

type Environment string

const (
	Test Environment = "https://ksef-test.mf.gov.pl/api"
	Demo             = "https://ksef-demo.mf.gov.pl/api"
	Prod             = "https://ksef.mf.gov.pl/api"
)

type Client struct {
	client      *resty.Client
	environment Environment
}

func New(environment Environment) *Client {
	client := resty.New()
	return &Client{client: client, environment: environment}
}

func (c Client) PostXMLFromBytes(endpoint string, body []byte) (*resty.Response, error) {
	return c.client.R().
		EnableTrace().
		SetBody(body).
		ForceContentType("application/octet-stream; charset=utf-8").
		Post(string(c.environment) + endpoint)
}

func (c Client) GetJson(endpoint, token string) {

}

func (c Client) PostJson(endpoint, token string, body interface{}) (*resty.Response, error) {
	return c.client.R().
		EnableTrace().
		SetBody(body).
		SetHeader("SessionToken", token).
		Post(string(c.environment) + endpoint)
}

func (c Client) PostJsonNoAuth(endpoint string, body interface{}, result interface{}) (*resty.Response, error) {
	return c.client.R().
		EnableTrace().
		SetBody(body).
		SetResult(result).
		Post(string(c.environment) + endpoint)
}
