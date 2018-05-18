/*
AUTHORS:
       Copyright (C) 2003-2018 Opsview Limited. All rights reserved
  
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This plugin monitors Kubernetes (BETA)*/

package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"syscall"

	"github.com/opsview/go-plugin"
	"strings"
)

type PublicKey struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		Phase      string `json:"phase"`
		HostIP     string `json:"hostIP"`
		Conditions []Key  `json:"conditions"`
		Addresses  []Key2 `json:"addresses"`
		Capacity   struct {
			Memory string `json:"Memory"`
		} `json:"capacity"`
		Allocatable struct {
			Memory string `json:"Memory"`
		} `json:"allocatable"`
	} `json:"status"`
}

type Key struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Message string `json:"message"`
}
type Key2 struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

type Items struct {
	Items []PublicKey `json:"items"`
}

var opts struct {
	Hostname    string `short:"H" long:"hostname" description:"Host" required:"true"`
	Port        string `short:"P" long:"port" description:"Port" required:"true"`
	Mode        string `short:"m" long:"mode" description:"Mode" required:"true"`
	Warning     string `short:"w" long:"warning" description:"Warning"`
	Critical    string `short:"c" long:"critical" description:"Critical"`
	Node        string `short:"n" long:"node" description:"Node name"`
	Scheme      string `short:"s" long:"Scheme" description:"The protocol you want to use either http or https"`
	Ca          string `short:"a" long:"certificate authority" description:"file location to certificate authority"`
	Certificate string `short:"r" long:"client certificate" description:"file location to client certificate"`
	Key         string `short:"k" long:"client key" description:"file location to client key"`
}

func main() {
	check := checkPlugin()
	if err := check.ParseArgs(&opts); err != nil {
		check.ExitCritical("Error parsing arguments: %s", err)
	}
	defer check.Final()
	check.AllMetricsInOutput = true

	if opts.Scheme == "" {
		opts.Scheme = "http"
	}

	switch opts.Mode {
	case "OutOfDisk", "MemoryPressure", "DiskPressure", "Ready":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/api/v1/nodes"
		findPerf(check, Hostname, opts.Mode, opts.Node)
	case "PodStatus":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/api/v1/pods"
		findPerf(check, Hostname, opts.Mode, opts.Node)
	case "NodeStatus":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/api/v1/nodes"
		findStatus(check, Hostname, "Ready", opts.Node)
		findPerf(check, Hostname, "OutOfDisk", opts.Node)
		findPerf(check, Hostname, "MemoryPressure", opts.Node)
		findPerf(check, Hostname, "DiskPressure", opts.Node)
	case "NodeMemoryStats":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/api/v1/nodes"
		findNodeMemoryUsage(check, Hostname, opts.Node)
	case "FileDescriptors":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/metrics"
		value := findValue(check, Hostname, "process_open_fds [0-9]+")
		check.AddMetric("Number of Open File Descriptors", value, "", opts.Warning, opts.Critical)
	case "HttpRequestStats":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/metrics"
		value := findValue(check, Hostname, ",handler=\"prometheus\",method=\"get\"} [0-9]+")
		findDifference(check, "HTTP Requests", "", value, true, "", "")
		value = findValue(check, Hostname, "http_request_duration_microseconds{handler=\"prometheus\",quantile=\"0.5\"} [0-9]+")
		milli := micro2milli(check, value)
		check.AddMetric("HTTP Requests Latency", milli, "ms", opts.Warning, opts.Critical)
	case "ProcessCpuSeconds":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/metrics"
		value := findValue(check, Hostname, "process_cpu_seconds_total [0-9]+")
		findDifference(check, "Process CPU Seconds", "s", value, true, opts.Warning, opts.Critical)
	case "EtcdHelperStats":
		Hostname := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/metrics"
		cacheHits := findValue(check, Hostname, "etcd_helper_cache_hit_count [0-9]+")
		cacheHitsDifference := findDifference(check, "Etcd Helper Cache Hits", "", cacheHits, false, "", "")
		cacheMisses := findValue(check, Hostname, "etcd_helper_cache_miss_count [0-9]+")
		cacheMissesDifference := findDifference(check, "Etcd Helper Cache Hits", "", cacheMisses, false, "", "")
		outputCacheStats(check, cacheHitsDifference, cacheMissesDifference)
	default:
		check.ExitUnknown("Mode not found. Please check -m flag")
	}
}

func fetch(check *plugin.Plugin, URL string) []byte {

	var resp *http.Response
	var err error

	if opts.Scheme == "https" {
		client := sslSupport(check)
		resp, err = client.Get(URL)
		if err != nil {
			check.ExitUnknown("Error: Problem with URL: " + URL)
		}
	} else {
		resp, err = http.Get(URL)
		if err != nil {
			check.ExitUnknown("Error: Problem with URL: " + URL)
		}
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		check.ExitUnknown("Error: Can not connect to Kubernetes server API: " + URL)
	}
	return body
}

func sslSupport(check *plugin.Plugin) *http.Client {
	cert, err := tls.LoadX509KeyPair(opts.Certificate, opts.Key)
	if err != nil {
		check.ExitUnknown("Can not load certificate and client key. Error: %s ", err)
	}
	// Load CA cert

	caCert, err := ioutil.ReadFile(opts.Ca)
	if err != nil {
		check.ExitUnknown("Can not read CA. Error: %s", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// Setup HTTPS client

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	return client
}

func findValue(check *plugin.Plugin, url string, searchValue string) string {
	metrics := string(fetch(check, url))
	valueToFind := regexp.MustCompile(searchValue)
	foundValue := valueToFind.FindString(metrics)
	if foundValue == "" {
		check.ExitUnknown(searchValue + " value not found")
	}
	valueToFind = regexp.MustCompile("\\s[0-9]+")
	foundValue = valueToFind.FindString(foundValue)
	valueToFind = regexp.MustCompile("[0-9]+")
	foundValue = valueToFind.FindString(foundValue)

	return foundValue
}

func findDifference(check *plugin.Plugin, name string, UOM string, value string, output bool, warning string, critical string) int {
	previousValue := updateState(opts.Hostname, opts.Port, opts.Mode, value, check)
	foundInteger, err := strconv.Atoi(value)
	previousvalue, err := strconv.Atoi(previousValue)
	if err != nil {
		check.ExitUnknown("Error: Could not parse previous metric value. If this is your first run this error is expected, metrics will be recorded for subsequent checks", err)
	}
	currentValue := foundInteger - previousvalue
	if output == true {
		check.AddMetric(name, currentValue, UOM, warning, critical)
	}
	return currentValue
}

func findNodeMemoryUsage(check *plugin.Plugin, url string, node string) {
	var pluginResponse Items
	var totalMemory string
	var availableMemory string
	metrics := fetch(check, url)
	err := json.Unmarshal(metrics, &pluginResponse)
	if err != nil {
		check.ExitUnknown("Problem with unmarshaling json data = %s", err)
	}
	for i := range pluginResponse.Items {
		if pluginResponse.Items[i].Metadata.Name == node {
			totalMemory = pluginResponse.Items[i].Status.Capacity.Memory
			availableMemory = pluginResponse.Items[i].Status.Allocatable.Memory
		}
	}
	valueToFind := regexp.MustCompile("[0-9]+")
	totalMemory = valueToFind.FindString(totalMemory)
	availableMemory = valueToFind.FindString(availableMemory)

	totalMemory2, err := strconv.ParseFloat(totalMemory, 64)
	availableMemory2, err := strconv.ParseFloat(availableMemory, 64)

	memoryUtilisation := (totalMemory2 - availableMemory2) * 100.0 / totalMemory2

	totalMemory3, UOM := convertBytes(totalMemory2, "KB", 2)
	check.AddMetric("Memory Capacity", totalMemory3, UOM)

	availableMemory3, UOM := convertBytes(availableMemory2, "KB", 2)
	check.AddMetric("Available Memory", availableMemory3, UOM)

	memoryUtilisation2 := strconv.FormatFloat(memoryUtilisation, 'f', 2, 64)
	check.AddMetric("Memory Utilisation", memoryUtilisation2, "%", opts.Warning, opts.Critical)

}

func micro2milli(check *plugin.Plugin, micro string) string {
	micro2, err := strconv.ParseFloat(micro, 64)
	if err != nil {
		check.ExitUnknown("Failed to process metric. Error: %s", err)
	}
	milli := micro2 / float64(1000)
	milli2 := strconv.FormatFloat(milli, 'f', 2, 64)
	return milli2
}

func outputCacheStats(check *plugin.Plugin, cacheHits int, cacheMisses int) {
	totalHits := cacheHits + cacheMisses
	if totalHits == 0 {
		totalHits = 1
	}
	cacheHitPercentage := cacheHits / totalHits * 100
	check.AddMetric("Etcd Helper Cache Hit Percentage", cacheHitPercentage, "%", opts.Warning, opts.Critical)
	check.AddMetric("Etcd Helper Cache Hits", cacheHits, "")
	check.AddMetric("Etcd Helper Cache Misses", cacheMisses, "")
}

func findStatus(check *plugin.Plugin, url string, mode string, node string) {
	var pluginResponse Items
	metrics := fetch(check, url)
	err := json.Unmarshal(metrics, &pluginResponse)
	if err != nil {
		check.ExitUnknown("Problem with unmarshaling json data = %s", err)
	}
	for i := range pluginResponse.Items {
		for j := range pluginResponse.Items[i].Status.Conditions {
			if pluginResponse.Items[i].Status.Conditions[j].Type == mode && pluginResponse.Items[i].Metadata.Name == node {
				addFindStatus(check, pluginResponse.Items[i].Status.Conditions[j].Status, pluginResponse.Items[i].Metadata.Name)
			}
		}
	}
}

func identifyNode(check *plugin.Plugin, node string) string {
	var pluginResponse Items
	var address string
	url := opts.Scheme + "://" + opts.Hostname + ":" + opts.Port + "/api/v1/nodes"
	metrics := fetch(check, url)
	err := json.Unmarshal(metrics, &pluginResponse)
	if err != nil {
		check.ExitUnknown("Problem with unmarshaling json data = %s", err)
	}
	for i := range pluginResponse.Items {
		if pluginResponse.Items[i].Metadata.Name == node {
			address = pluginResponse.Items[i].Status.Addresses[0].Address
		}
	}
	return address
}

func findPerf(check *plugin.Plugin, url string, mode string, node string) {
	var pluginResponse Items
	done := false
	metrics := fetch(check, url)
	address := identifyNode(check, node)
	err := json.Unmarshal(metrics, &pluginResponse)
	if err != nil {
		check.ExitUnknown("Problem with unmarshaling json data = %s", err)
	}
	for i := range pluginResponse.Items {
		if mode == "PodStatus" && pluginResponse.Items[i].Status.HostIP == address {
			done = true
			addToPerf(check, pluginResponse.Items[i].Status.Phase, pluginResponse.Items[i].Metadata.Name)
		}
		for j := range pluginResponse.Items[i].Status.Conditions {
			if pluginResponse.Items[i].Status.Conditions[j].Type == mode && pluginResponse.Items[i].Metadata.Name == node {
				done = true
				addToPerfBool(check, pluginResponse.Items[i].Status.Conditions[j].Status, mode, pluginResponse.Items[i].Status.Conditions[j].Message)
			}
		}
	}
	if done == false {
		check.ExitUnknown("Metric not found")
	}
}

func addToPerf(check *plugin.Plugin, value string, name string) {
	if value == "Running" || value == "Succeeded" {
		check.AddMessage(name+" = %s", value)
	} else if value == "Pending" || value == "Unknown" {
		check.AddResult(plugin.WARNING, name+" = %s", value)
	} else if value == "Failed" {
		check.AddResult(plugin.CRITICAL, name+" = %s", value)
	} else {
		check.ExitUnknown("Can not identify state of pod")
	}
}

func addToPerfBool(check *plugin.Plugin, value string, valueName string, detail string) {
	if value == "False" {
		check.AddMessage(valueName+" = "+value+", %s", detail)
	} else if value == "True" {
		check.AddResult(plugin.CRITICAL, valueName+" = "+value+", %s", detail)
	} else {
		check.ExitCritical("Failed: %s", detail)
	}
}

func addFindStatus(check *plugin.Plugin, status string, node string) {
	if status == "True" {
		check.AddMessage("Node: " + node + " is healthy and ready to accept pods")
	} else if status == "False" {
		check.ExitCritical("Node: " + node + " is not healthy and is not accepting pods")
	} else if status == "Unknown" {
		check.ExitWarning("Node: " + node + " is unknown since the node controller has not heard from node in the last 40 seconds")
	} else {
		check.ExitUnknown("Unable to find status")
	}
}

func checkPlugin() *plugin.Plugin {
	check := plugin.New("check_kubernetes", "v0.9.0 BETA")

	check.Preamble = `Copyright (C) 2003-2018 Opsview Limited. All rights reserved.
This plugin tests the stats of a Kubernetes server.`

	check.Description = `Description
      Plugin supports the following run modes:
          OutOfDisk: Checks whether the node is out of diskspace
          MemoryPressure: Checks whether the node has memory pressure
          DiskPressure:	Checks whether the node has disk pressure
          NodeStatus: Provides the state of the node in the cluster as well as OutOfDisk, MemoryPressure and DiskPressure
          MemoryStats: Provides the node memory usage, memory capacity and memory utilisation
          PodStatus: The state of all pods
          FileDescriptors: Number of open file descriptors
          HttpRequests: Change in HTTP requests made
          HttpRequestsDuration: HTTP requests latency
          ProcessCpuSeconds: Change in process CPU seconds
          EtcdHelperStats: Contains Etcd Helper Cache Hits, Etcd Helper Cache Misses and Etcd Helper Cache Hit Percentage`
	return check
}

func updateState(HostAddress string, Port string, Mode string, records string, check *plugin.Plugin) string {
	// File is used to store temporary value for each metric to monitor changes between values
	// Everything that involves the file is run here
	// Opens the file a so it can be read, then writes a new file with the current records
	// Returns the value that was stored on the file

	path, err := checkFilePath(HostAddress, Port, Mode) // Provides a path for the file to be saved to
	if err != nil {
		check.ExitUnknown("Error finding temporary path: %s", err)
	}

	// Opens file in read and write mode, creates it if not already there and gives 600 permission levels
	file, err := os.OpenFile(path, syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil {
		// If there is an error opening/creating the file, exit unknown
		check.ExitUnknown("Error creating temporary file: " + path)
	}

	defer file.Close() // Closes the file after using it

	getLock(check, file, path) // Uses getLock() to prevent access to file while using it

	defer releaseLock(file) // Uses releaseLock() after using file to allow access again

	fileBytes, err := ioutil.ReadFile(path) // Reads the file contents at the given path
	if err != nil {
		// If there is an error reading the file, exit unknown
		check.ExitUnknown("Cannot read previous metrics from temporary file: "+path+" %s", err)
	}

	previousValues := string(fileBytes) // Saves the value after opening a previous value

	file.Truncate(0)

	w := bufio.NewWriter(file)
	_, err = w.WriteString(records)
	if err != nil {
		// If there is an error, exit unknown
		check.ExitUnknown("Error writing to temporary file: "+path+" %s", err)
	}

	w.Flush()

	return previousValues
}

// Set the flock on the file so no other processes can read or write to it
func getLock(check *plugin.Plugin, file *os.File, path string) {
	// Set the lock on the file so no other processes can read or write to it

	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX)

	if err != nil {
		// If there is an error, exit unknown
		check.ExitUnknown("Error locking temporary file: "+path+" %s", err)
	}
}

func releaseLock(file *os.File) {
	// Release file lock

	syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

func checkFilePath(HostAddress string, Port string, Mode string) (string, error) {
	// Tests the locations of the path to check the file can be written
	// Creates a file name using md5 to create a hash
	// Returns a string of the path for the file to be written to

	fileName := "kubernetes_"
	hash := HostAddress + "," + Port + "," + Mode

	digest := make([]byte, len(hash))
	copy(digest[:], hash)
	hash = fmt.Sprintf("%x", md5.Sum(digest))
	fileName = fileName + string(hash[:]) + ".tmp"

	env := os.Getenv("OPSVIEW_BASE")

	paths := []string{"/opt/opsview/monitoringscripts/tmp/",
		env + "/tmp/",
		"/tmp/"}

	var failedPaths string

	for _, path := range paths {
		// For all paths we can use for temp files

		if _, err := os.Stat(path); err == nil {
			// If temp path exists and user has permissions to read and write, return this path and filename
			return path + fileName, err
		} else {
			failedPaths += path + " or "
		}
	}

	// Return error if none of the paths available are valid
	err := errors.New("Unable to create temporary file in path(s): " + failedPaths[:len(failedPaths)-4])

	return "", err
}

func convertBytes(numberToConvert float64, startingUOM string, precision int) (string, string) {
	// Takes in a number that needs converting, the bytes UOM it is already in and requested precision of new value
	// Returns value and UOM, in form of lowest UOM needed

	startingUOM = strings.ToUpper(startingUOM)

	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}

	var startingPoint int = 0 // Assume number is in bytes to begin with

	for i, unit := range units {
		// For all bytes units, find the index of the one that the value is already in
		if unit == startingUOM {
			startingPoint = i
		}
	}

	for _, unit := range units[startingPoint:] {
		// Starting at the index of the UOM the value is already in
		// Iterate over each UOM and divide by 1024 each time if needed

		if numberToConvert >= 1024 {
			// If >= 1024 then it can be shown in a smaller UOM, so divide it
			numberToConvert = numberToConvert / 1024
		} else {
			// If < 1024, then lowest UOM needed is found, so break out of loop and return value + UOM
			newValue := strconv.FormatFloat(numberToConvert, 'f', precision, 64)
			return newValue, unit
		}
	}

	return "", "" // Should never happen
}
