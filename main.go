package main

import (
	"errors"
	"fmt"

	"io/ioutil"

	"net/http"
	"strings"
)

// get the pihole status
// check we can connect to the pihole
func getSessonID(ip string, token string) (string, error) {
	url := "http://" + ip + "/admin/api.php?summaryRaw&auth=" + token
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer res.Body.Close()

	// check if the response status code is 200
	if res.StatusCode != 200 {
		return "", errors.New("Status code not 200")
	}

	// Retrieve the "Set-Cookie" header
	cookieHeader := res.Header.Get("Set-Cookie")

	// Check if the PHPSESSID cookie is included in the response
	if cookieHeader == "" {
		return "", errors.New("PHPSESSID cookie not set")
	}

	// Find the start of the PHPSESSID value
	startIndex := strings.Index(cookieHeader, "PHPSESSID=")
	if startIndex == -1 {
		return "", errors.New("PHPSESSID not found in cookie")
	}

	// Extract the substring starting from the PHPSESSID value
	cookieStart := startIndex + len("PHPSESSID=")
	cookieEnd := strings.Index(cookieHeader[cookieStart:], ";")
	if cookieEnd == -1 {
		// If there is no semicolon, the PHPSESSID is the rest of the string
		cookieEnd = len(cookieHeader)
	} else {
		// Otherwise, adjust cookieEnd to be the correct index within the full string
		cookieEnd += cookieStart
	}

	// Extract the PHPSESSID value
	phpsessidValue := cookieHeader[cookieStart:cookieEnd]

	if phpsessidValue == "" {
		return "", errors.New("PHPSESSID value not set")
	}

	// all good
	return phpsessidValue, nil
}

// get the auth token
func getAuthToken(ip string, sessid string) (string, error) {
	url := "http://" + ip + "/admin/index.php"
	method := "GET"
  
	client := &http.Client {
	}
	req, err := http.NewRequest(method, url, nil)
  
	if err != nil {
	  fmt.Println(err)
	  return "", err
	}
	req.Header.Add("Cookie", "PHPSESSID=jtbr63teb41t2dq8b4ou2268a2")
  
	res, err := client.Do(req)
	if err != nil {
	  fmt.Println(err)
	  return "", err
	}
	defer res.Body.Close()
  
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
	  fmt.Println(err)
	  return "", err
	}
	

	bodyStr := string(body)

	// Find the start index of the token div
	tokenStart := strings.Index(bodyStr, "<div id=\"token\" hidden>")
	if tokenStart == -1 {
		return "", errors.New("token not found")
	}

	// Correct the start index to the beginning of the actual token
	tokenStartCorrected := tokenStart + len("<div id=\"token\" hidden>")

	// Find the end index of the token div
	tokenEnd := strings.Index(bodyStr[tokenStartCorrected:], "</div>")
	if tokenEnd == -1 {
		return "", errors.New("token not found")
	}

	// Correct the token end index relative to the entire body
	tokenEndCorrected := tokenStartCorrected + tokenEnd

	// Extract the token
	token := bodyStr[tokenStartCorrected:tokenEndCorrected]

	return token, nil
}

func main() {
	sessid, err := getSessonID("10.45.1.2", "567959398aab9b9188341f95d8382b272124db58d4a92433121bf96e06b8f985")
	if err != nil {
		fmt.Println("Error getting Pi-hole status:", err)
	} else {
		fmt.Println("Got session ID:", sessid)
	}

	authToken, err := getAuthToken("10.45.1.2", sessid)
	if err != nil {
		fmt.Println("Error getting auth token:", err)
	} else {
		fmt.Println("Got auth token:", authToken)
	}
}
