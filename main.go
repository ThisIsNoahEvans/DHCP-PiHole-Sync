package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
//	"time"
)

// get a cookie from a header
func getCookie(header http.Header, key string) string {
	for _, values := range header {
		for _, v := range values {
			if strings.HasPrefix(v, key+"=") {
				cookieData := strings.TrimSpace(strings.TrimPrefix(v, key+"="))
				semicolonIndex := strings.Index(cookieData, ";")
				if semicolonIndex == -1 { // No semicolon found, return the whole string
					return cookieData
				}
				return cookieData[:semicolonIndex] // Return the substring before the first semicolon
			}
		}
	}
	return ""
}

// get the auth token
func getToken(PHPSESSID string, serverIP string) (string, string, error) {
	url := "http://" + serverIP + "/admin/index.php"
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Add("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Cookie", "PHPSESSID="+PHPSESSID)
	req.Header.Add("DNT", "1")
	req.Header.Add("Referer", "http://"+serverIP+"/admin/login.php")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	bodyStr := string(body)

	// Find the start index of the token div
	tokenStart := strings.Index(bodyStr, "<div id=\"token\" hidden>")
	if tokenStart == -1 {
		return "", "", errors.New("token not found in body")
	}

	// Correct the start index to the beginning of the actual token
	tokenStartCorrected := tokenStart + len("<div id=\"token\" hidden>")

	// Find the end index of the token div
	tokenEnd := strings.Index(bodyStr[tokenStartCorrected:], "</div>")
	if tokenEnd == -1 {
		return "", "", errors.New("token not found in body")
	}

	// Correct the token end index relative to the entire body
	tokenEndCorrected := tokenStartCorrected + tokenEnd

	// Extract the token
	token := bodyStr[tokenStartCorrected:tokenEndCorrected]

	// get the updated PHPSESSID cookie
	newPHPSESSID := getCookie(res.Header, "PHPSESSID")
	if newPHPSESSID == "" {
		return "", "", errors.New("PHPSESSID not found in response")
	}

	return token, newPHPSESSID, nil
}

func authenticate(serverIP string, password string) (string, string, error) {
	url := "http://" + serverIP + "/admin/login.php"
	method := "POST"

	payload := strings.NewReader("pw=" + password)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// don't follow redirects
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Add("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("DNT", "1")
	req.Header.Add("Origin", "http://"+serverIP)
	req.Header.Add("Referer", "http://"+serverIP+"/admin/login.php")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	defer res.Body.Close()

	// get the PHPSESSID cookie
	PHPSESSID := getCookie(res.Header, "PHPSESSID")
	if PHPSESSID == "" {
		return "", "", errors.New("PHPSESSID not found in response")
	}

	token, newPHPSESSID, err := getToken(PHPSESSID, serverIP)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}

	return newPHPSESSID, token, nil
}

func createClient(serverIP string, clientIP string, description string, PHPSESSID string, token string) error {
	url := "http://" + serverIP + "/admin/scripts/pi-hole/php/groups.php"
	method := "POST"

	// add the params using string interpolation
	payload := strings.NewReader(`action=add_client&ip=` + clientIP + `&comment=` + description + `&token=` + token)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return errors.New("failed to create request")
	}
	req.Header.Add("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Add("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("Cookie", "PHPSESSID="+PHPSESSID+"; PHPSESSID="+PHPSESSID)
	req.Header.Add("DNT", "1")
	req.Header.Add("Origin", "http://"+serverIP)
	req.Header.Add("Referer", "http://"+serverIP+"/admin/groups-clients.php")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return errors.New("failed to send request")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return errors.New("failed to read response")
	}

	// {"success":true,"message":null}

	// if response contains text Wrong token! Please re-login on the Pi-hole dashboard.
	if strings.Contains(string(body), "Wrong token! Please re-login on the Pi-hole dashboard.") {
		return errors.New("token error, try again")
	}

	// convert body to json
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		fmt.Println(err)
		return errors.New("failed to parse response")
	}

	success := jsonResponse["success"].(bool)
	if !success {
		fmt.Println("failed to add client")
		fmt.Println(jsonResponse["message"])
		return errors.New("failed to add client")
	}

	fmt.Println("client added!")

	return nil
}

func parseStaticHosts(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "host") && strings.HasSuffix(line, "}") {
			// Process the line containing host details
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue // Not enough information
			}

			hostname := strings.Trim(fields[1], "{ ")
			mac := ""
			ip := ""

			// Loop through fields to find MAC and IP
			for i := 0; i < len(fields); i++ {
				if fields[i] == "hardware" && i+2 < len(fields) {
					mac = strings.Trim(fields[i+2], ";")
				}
				if fields[i] == "fixed-address" && i+1 < len(fields) {
					ip = strings.Trim(fields[i+1], ";")
				}
			}

			if mac != "" && ip != "" {
				fmt.Printf("Host: %s, MAC: %s, IP: %s\n", hostname, mac, ip)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	return nil
}

func main() {

	filePath := "dhcpd.conf" // specify the path to your dhcpd.conf file
	if err := parseStaticHosts(filePath); err != nil {
		fmt.Println("Error:", err)
	}

	/*
		serverIP := "10.45.1.2"
		password := "f26WR9aDKy"

		PHPSESSID, token, err := authenticate(serverIP, password)
		if err != nil {
			fmt.Println(err)
			return
		}

		// add a client
		maxRetries := 5
		retryCount := 0

		for retryCount < maxRetries {
			err := createClient(serverIP, "10.69.69.69", "boop", PHPSESSID, token)
			if err != nil {
				if err.Error() == "token error, try again" {
					fmt.Println("Retry due to token error:", retryCount+1)
					retryCount++

					// wait for a second * retryCount
					time.Sleep(time.Duration(retryCount) * time.Second)
					// reauthenticate
					PHPSESSID, token, err = authenticate(serverIP, password)
					if err != nil {
						fmt.Println("Error:", err)
						break
					}

					continue
				} else {
					fmt.Println("Error:", err)
					break
				}
			}
			fmt.Println("Success on attempt", retryCount+1)
			break
		}

		if retryCount == maxRetries {
			fmt.Println("Failed after", maxRetries, "attempts")
		} */

}
