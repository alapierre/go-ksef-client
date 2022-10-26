package api

import (
	"fmt"
	"testing"
	"time"
)

func Test_Time(t *testing.T) {

	res, err := time.Parse(time.RFC3339, "2022-10-23T17:53:52.560Z")
	if err != nil {
		return
	}

	fmt.Printf("timestamp is: %d\n", res.UnixMilli())

}
