package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"
	"github.com/gorilla/mux"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	name     = "fsecure"
	category = "av"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	path string

	// es is the elasticsearch database object
	es elasticsearch.Database
)

type pluginResults struct {
	ID   string      `json:"id" structs:"id,omitempty"`
	Data ResultsData `json:"fsecure" structs:"f-secure"`
}

// FSecure json object
type FSecure struct {
	Results ResultsData `json:"fsecure"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool        `json:"infected" structs:"infected"`
	Result   string      `json:"result" structs:"result"`
	Engines  ScanEngines `json:"results" structs:"results"`
	Engine   string      `json:"engine" structs:"engine"`
	Database string      `json:"database" structs:"database"`
	Updated  string      `json:"updated" structs:"updated"`
	MarkDown string      `json:"markdown,omitempty" structs:"markdown,omitempty"`
	Error    string      `json:"error,omitempty" structs:"error,omitempty"`
}

// ScanEngines scan engine results
type ScanEngines struct {
	FSE      string `json:"fse" structs:"fse"`
	Aquarius string `json:"aquarius" structs:"aquarius"`
}

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"path":     path,
		}).Fatal(err)
	}
}

// AvScan performs antivirus scan
func AvScan(timeout int) FSecure {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	results, err := utils.RunCommand(
		ctx,
		"/opt/f-secure/fsav/bin/fsav",
		"--virus-action1=none",
		path,
	)
	log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
		"path":     path,
	}).Debug("FSecure output 1st try: ", results)

	if err != nil && err.Error() != "exit status 3" {
		// If fails try a second time
		results, err = utils.RunCommand(
			ctx,
			"/opt/f-secure/fsav/bin/fsav",
			"--virus-action1=none",
			path,
		)
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"path":     path,
		}).Debug("FSecure output 2nd try: ", results)
	}

	if err != nil {
		// FSecure exits with error status 3 if it finds a virus
		if err.Error() == "exit status 3" {
			err = nil
		}
	}

	return FSecure{Results: ParseFSecureOutput(results, err)}
}

// ParseFSecureOutput convert fsecure output into ResultsData struct
func ParseFSecureOutput(fsecureout string, err error) ResultsData {

	// root@70bc84b1553c:/malware# fsav --virus-action1=none eicar.com.txt
	// EVALUATION VERSION - FULLY FUNCTIONAL - FREE TO USE FOR 30 DAYS.
	// To purchase license, please check http://www.F-Secure.com/purchase/
	//
	// F-Secure Anti-Virus CLI version 1.0  build 0060
	//
	// Scan started at Mon Aug 22 02:43:50 2016
	// Database version: 2016-08-22_01
	//
	// eicar.com.txt: Infected: EICAR_Test_File [FSE]
	// eicar.com.txt: Infected: EICAR-Test-File (not a virus) [Aquarius]
	//
	// Scan ended at Mon Aug 22 02:43:50 2016
	// 1 file scanned
	// 1 file infected

	log.Debugln(fsecureout)

	if err != nil {
		return ResultsData{Error: err.Error()}
	}

	version, database := getFSecureVersion()

	fsecure := ResultsData{
		Infected: false,
		Engine:   version,
		Database: database,
		Updated:  getUpdatedDate(),
	}

	lines := strings.Split(fsecureout, "\n")

	for _, line := range lines {
		if strings.Contains(line, "Infected:") && strings.Contains(line, "[FSE]") {
			fsecure.Infected = true
			parts := strings.Split(line, "Infected:")
			fsecure.Engines.FSE = strings.TrimSpace(strings.TrimSuffix(parts[1], "[FSE]"))
			continue
		}
		if strings.Contains(line, "Infected:") && strings.Contains(line, "[Aquarius]") {
			fsecure.Infected = true
			parts := strings.Split(line, "Infected:")
			fsecure.Engines.Aquarius = strings.TrimSpace(strings.TrimSuffix(parts[1], "[Aquarius]"))
		}
	}
	fsecure.Result = strings.TrimSpace(fmt.Sprintf("%s %s", fsecure.Engines.Aquarius, fsecure.Engines.FSE))

	return fsecure
}

// getFSecureVersion get Anti-Virus scanner version
func getFSecureVersion() (version string, database string) {

	// root@4b01c723f943:/malware# /opt/f-secure/fsav/bin/fsav --version
	// EVALUATION VERSION - FULLY FUNCTIONAL - FREE TO USE FOR 30 DAYS.
	// To purchase license, please check http://www.F-Secure.com/purchase/
	//
	// F-Secure Linux Security version 11.00 build 79
	//
	// F-Secure Anti-Virus CLI Command line client version:
	// 	F-Secure Anti-Virus CLI version 1.0  build 0060
	//
	// F-Secure Anti-Virus CLI Daemon version:
	// 	F-Secure Anti-Virus Daemon version 1.0  build 0117
	//
	// Database version: 2016-09-19_01
	//
	// Scanner Engine versions:
	// 	F-Secure Corporation Hydra engine version 5.15 build 154
	// 	F-Secure Corporation Hydra database version 2016-09-16_01
	//
	// 	F-Secure Corporation Aquarius engine version 1.0 build 3
	// 	F-Secure Corporation Aquarius database version 2016-09-19_01
	//
	// Portions:
	// Copyright (c) 1994-2010 Lua.org, PUC-Rio.
	// Copyright (c) Reuben Thomas 2000-2010.
	//
	// For full license information on Hydra engine please see licenses-fselinux.txt in the databases folder

	exec.Command("/opt/f-secure/fsav/bin/fsavd").Output()
	versionOut, err := utils.RunCommand(nil, "/opt/f-secure/fsav/bin/fsav", "--version")
	assert(err)

	return parseFSecureVersion(versionOut)
}

func parseFSecureVersion(versionOut string) (version string, database string) {

	lines := strings.Split(versionOut, "\n")

	for _, line := range lines {

		if strings.Contains(line, "F-Secure Linux Security version") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "F-Secure Linux Security version"))
		}

		if strings.Contains(line, "Database version:") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				database = strings.TrimSpace(parts[1])
				break
			} else {
				log.Error("Umm... ", parts)
			}
		}

	}

	return
}

func parseUpdatedDate(date string) string {
	layout := "Mon, 02 Jan 2006 15:04:05 +0000"
	t, _ := time.Parse(layout, date)
	return fmt.Sprintf("%d%02d%02d", t.Year(), t.Month(), t.Day())
}

func getUpdatedDate() string {
	if _, err := os.Stat("/opt/malice/UPDATED"); os.IsNotExist(err) {
		return BuildTime
	}
	updated, err := ioutil.ReadFile("/opt/malice/UPDATED")
	assert(err)
	return string(updated)
}

func updateAV(ctx context.Context) error {
	fmt.Println("Updating FSecure DBs...")
	cmd := exec.Command("/opt/malice/update")
	cmdReader, err := cmd.StdoutPipe()
	scanner := bufio.NewScanner(cmdReader)
	go func() {
		for scanner.Scan() {
			fmt.Printf("update | %s\n", scanner.Text())
		}
	}()
	err = cmd.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting update", err)
		os.Exit(1)
	}
	err = cmd.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for update", err)
		os.Exit(1)
	}

	// Update UPDATED file
	t := time.Now().Format("20060102")
	err = ioutil.WriteFile("/opt/malice/UPDATED", []byte(t), 0644)
	return err
}

func generateMarkDownTable(f FSecure) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("").Parse(tpl))

	err := t.Execute(&tplOut, f)
	if err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func webService() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/scan", webAvScan).Methods("POST")
	log.Info("web service listening on port :3993")
	log.Fatal(http.ListenAndServe(":3993", router))
}

func webAvScan(w http.ResponseWriter, r *http.Request) {

	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("malware")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Please supply a valid file to scan.")
		log.Error(err)
	}
	defer file.Close()

	log.Debug("Uploaded fileName: ", header.Filename)

	tmpfile, err := ioutil.TempFile("/malware", "web_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	data, err := ioutil.ReadAll(file)
	assert(err)

	if _, err = tmpfile.Write(data); err != nil {
		log.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	// Do AV scan
	path = tmpfile.Name()
	fsecure := AvScan(60)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(fsecure); err != nil {
		log.Fatal(err)
	}
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "f-secure"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice F-Secure AntiVirus Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasticsearch",
			Value:       "",
			Usage:       "elasticsearch url for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH_URL",
			Destination: &es.URL,
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.BoolFlag{
			Name:   "callback, c",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  60,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update virus definitions",
			Action: func(c *cli.Context) error {
				// 10 minute timeout
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(600)*time.Second)
				defer cancel()
				return updateAV(ctx)
			},
		},
		{
			Name:  "web",
			Usage: "Create a F-Secure scan web service",
			Action: func(c *cli.Context) error {
				webService()
				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		var err error

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, err = filepath.Abs(c.Args().First())
			assert(err)

			if _, err = os.Stat(path); os.IsNotExist(err) {
				assert(err)
			}

			fsecure := AvScan(c.Int("timeout"))
			fsecure.Results.MarkDown = generateMarkDownTable(fsecure)

			// upsert into Database
			if len(c.String("elasticsearch")) > 0 {
				err := es.Init()
				if err != nil {
					return errors.Wrap(err, "failed to initalize elasticsearch")
				}
				err = es.StorePluginResults(database.PluginResults{
					ID:       utils.Getopt("MALICE_SCANID", utils.GetSHA256(path)),
					Name:     name,
					Category: category,
					Data:     structs.Map(fsecure.Results),
				})
				if err != nil {
					return errors.Wrapf(err, "failed to index malice/%s results", name)
				}
			}

			if c.Bool("table") {
				fmt.Println(fsecure.Results.MarkDown)
			} else {
				fsecure.Results.MarkDown = ""
				fsecureJSON, err := json.Marshal(fsecure)
				assert(err)
				if c.Bool("post") {
					request := gorequest.New()
					if c.Bool("proxy") {
						request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
					}
					request.Post(os.Getenv("MALICE_ENDPOINT")).
						Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", utils.GetSHA256(path))).
						Send(string(fsecureJSON)).
						End(printStatus)

					return nil
				}
				fmt.Println(string(fsecureJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("please supply a file to scan with malice/fsecure"))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}
