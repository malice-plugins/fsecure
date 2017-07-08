package main

import (
	"fmt"
	"io/ioutil"
	"testing"
)

// TestParseResult tests the ParseFSecureOutput function.
func TestParseResult(t *testing.T) {

	r, err := ioutil.ReadFile("tests/av.virus")
	if err != nil {
		fmt.Print(err)
	}

	results := ParseFSecureOutput(string(r), nil)

	if true {
		t.Log("results: ", results.Engines)
	}

}

// TestParseVersion tests the parseFSecureVersion function.
func TestParseVersion(t *testing.T) {

	r, err := ioutil.ReadFile("tests/av.version")
	if err != nil {
		fmt.Print(err)
	}

	version, database := parseFSecureVersion(string(r))

	if true {
		t.Log("version: ", version)
		t.Log("database: ", database)
	}

}
