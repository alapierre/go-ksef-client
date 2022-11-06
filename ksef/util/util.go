package util

import (
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
)

func DebugEnabled() bool {
	return etb("KSEF_DEBUG")
}

func HttpTraceEnabled() bool {
	return etb("KSEF_HTTP_TRACE")
}

func etb(envName string) bool {
	v, ok := os.LookupEnv(envName)
	if !ok {
		return false
	}

	bv, err := strconv.ParseBool(v)

	return err == nil && bv
}

func GetEnvOrFailed(key string) string {
	v, ok := os.LookupEnv(key)
	if !ok {
		log.Fatal(key, " environment variable is not set")
	}
	return v
}
