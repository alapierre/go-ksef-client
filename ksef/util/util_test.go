package util

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestIsDebugEnabled_False(t *testing.T) {
	res := DebugEnabled()
	assert.False(t, res, "debug should be false")
}

func TestIsDebugEnabled_True(t *testing.T) {

	err := os.Setenv("KSEF_DEBUG", "true")

	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
		ForceColors:   true,
	})

	log.Debug("test logowania")
	log.Warn("test logowania")

	if err != nil {
		t.Errorf("can;t set env variable")
	}
	res := DebugEnabled()
	assert.True(t, res, "debug should be false")

}
