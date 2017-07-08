package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"testing"
)

// TestParseResult tests the ParseFSecureOutput function.
func TestParseResult(t *testing.T) {

	r, err := ioutil.ReadFile("tests/av.virus")
	if err != nil {
		fmt.Print(err)
	}

	results, err := ParseFSecureOutput(string(r), nil)
	if err != nil {
		log.Fatal(err)
	}

	if true {
		t.Log("results: ", results.Engines)
	}

}
