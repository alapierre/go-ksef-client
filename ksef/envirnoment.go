package ksef

type Environment int

const (
	Test Environment = iota
	Demo
	Prod
)

func (e Environment) BaseURL() string {
	switch e {
	case Prod:
		return "https://ksef.mf.gov.pl"
	case Test:
		return "https://ksef-test.mf.gov.pl"
	case Demo:
		return "https://ksef-demo.mf.gov.pl"
	}
	panic("Invalid environment")
}
