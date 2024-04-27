package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

// Device represents a DHCP static lease with a hostname and an IP address.
type Device struct {
	Hostname string
	IP       string
}

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

func createClient(serverIP string, clientIP string, fileComment string, PHPSESSID string, token string) error {
	url := "http://" + serverIP + "/admin/scripts/pi-hole/php/groups.php"
	method := "POST"

	// add the params using string interpolation
	payload := strings.NewReader(`action=add_client&ip=` + clientIP + `&comment=` + fileComment + `&token=` + token)

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
		// if the message contains 'UNIQUE constraint failed: client.ip' then the client already exists
		if strings.Contains(string(body), "UNIQUE constraint failed: client.ip") {
			fmt.Println("Client already exists")

			///// TODO: RENAME things. This is a mess
			///// COMMENT is the one from pihole
			///// DESCRIPTION is the one from the file

			// ip is already added - check if the description (piholeComment) is the same with findClientID
			clientID, groups, piholeComment, err := findClientID(fileComment, clientIP, serverIP, PHPSESSID, token)
			if err != nil {
				fmt.Println(err)
				return err
			}

			if piholeComment != fileComment {
				// hostname/comment/description is different - update
				fmt.Println("Hostname/comment/description is different - updating client ID", clientID)
				err = updateClient(clientID, groups, fileComment, serverIP, PHPSESSID, token)
				if err != nil {
					fmt.Println(err)
					return err
				}

				// comment was updated - return success
				return nil
			} else {
				// hostname/comment/description is the same - return success
				return nil
			}

		}

		// unknown error
		fmt.Println("failed to add client")
		fmt.Println(jsonResponse["message"])
		return errors.New("failed to add client")
	}

	fmt.Println("client added!")

	return nil
}

// Edit a client - all values must be passed, even if they are the same
func updateClient(clientID string, groups []int, comment string, serverIP string, PHPSESSID string, token string) error {
	apiURL := "http://" + serverIP + "/admin/scripts/pi-hole/php/groups.php"
	method := "POST"

	var payload strings.Builder

	// Start by writing the initial part of the payload
	payload.WriteString(`action=edit_client&id=` + clientID + `&token=` + token + `&comment=` + comment)

	// For each group, add a &groups[]= parameter
	for _, group := range groups {
		payload.WriteString("&groups%5B%5D=" + strconv.Itoa(group))
	}

	finalPayload := payload.String()
	reader := strings.NewReader(finalPayload)

	// for each group, add a &groups[]= parameter
	for _, group := range groups {
		payload.WriteString("&groups%5B%5D=" + strconv.Itoa(group))
	}
	client := &http.Client{}
	req, err := http.NewRequest(method, apiURL, reader)

	if err != nil {
		fmt.Println(err)
		return err
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
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// body is json - check for success/error
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		fmt.Println(err)
		return err
	}

	success := jsonResponse["success"].(bool)
	if !success {
		fmt.Println("failed to update client")
		fmt.Println(jsonResponse["message"])
		return errors.New("failed to update client")
	}

	fmt.Println("client updated!")

	return nil
}

func parseStaticHosts(filePath string) ([]Device, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var devices []Device
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "host") && strings.HasSuffix(line, "}") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}

			hostname := strings.Trim(fields[1], "{ ")
			ip := ""

			for i := 0; i < len(fields); i++ {
				if fields[i] == "fixed-address" && i+1 < len(fields) {
					ip = strings.Trim(fields[i+1], ";")
					break
				}
			}

			if hostname != "" && ip != "" {
				devices = append(devices, Device{Hostname: hostname, IP: ip})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	return devices, nil
}

// returns the server IP, PHPSESSID, and token
func sync() (string, string, string, error) {

	serverIP := "10.45.1.2"
	password := "f26WR9aDKy"

	PHPSESSID, token, err := authenticate(serverIP, password)
	if err != nil {
		fmt.Println(err)
		return "", "", "", err
	}

	filePath := "dhcpd.conf"
	devices, err := parseStaticHosts(filePath)
	if err != nil {
		fmt.Println("Error:", err)
		return "", "", "", err
	}

	for _, device := range devices {
		fmt.Printf("Adding %s with IP %s\n", device.Hostname, device.IP)

		// add a client
		maxRetries := 5
		retryCount := 0

		for retryCount < maxRetries {
			err := createClient(serverIP, device.IP, device.Hostname, PHPSESSID, token)
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
		}
	}

	return serverIP, PHPSESSID, token, nil
}

// Find a Pi-hole client ID by hostname and IP address
func findClientID(hostname string, ip string, serverIP string, PHPSESSID string, token string) (string, []int, string, error) {
	url := "http://" + serverIP + "/admin/scripts/pi-hole/php/groups.php"
	method := "POST"

	payload := strings.NewReader(`action=get_clients&token=` + token)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return "", nil, "", err
	}
	req.Header.Add("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Add("Accept-Language", "en-GB,en-US;q=0.9,en;q=0.8")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Add("Cookie", "PHPSESSID="+PHPSESSID)
	req.Header.Add("DNT", "1")
	req.Header.Add("Origin", "http://"+serverIP)
	req.Header.Add("Referer", "http://"+serverIP+"/admin/groups-clients.php")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", nil, "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return "", nil, "", err
	}

	// body is json - clients under data
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		fmt.Println(err)
		return "", nil, "", errors.New("failed to parse response")
	}

	if data, ok := jsonResponse["data"].([]interface{}); ok {
		for _, client := range data {
			clientMap, ok := client.(map[string]interface{})
			if !ok {
				fmt.Println("Error parsing client data")
				continue
			}

			// Convert id to string safely
			clientID := fmt.Sprintf("%v", clientMap["id"]) // Using fmt.Sprintf to handle integer ID
			clientComment := ""
			if comment, ok := clientMap["comment"].(string); ok {
				clientComment = comment
			}
			clientIP := ""
			if ip, ok := clientMap["ip"].(string); ok {
				clientIP = ip
			}

			// get the groups the client is in
			groups := clientMap["groups"].([]interface{})
			var groupIDs []int
			for _, group := range groups {
				groupStr := fmt.Sprintf("%v", group)   // Convert group to string if not already
				groupID, err := strconv.Atoi(groupStr) // Convert string to int
				if err != nil {
					log.Printf("Error converting group ID to integer: %s", err)
					continue // Skip this group if conversion fails
				}
				groupIDs = append(groupIDs, groupID) // Append the converted integer
			}

			// find the client by hostname and IP address
			if hostname == clientComment && ip == clientIP {
				return clientID, groupIDs, clientComment, nil
			} // fallback - compare just the hostname
			if hostname == clientComment {
				return clientID, groupIDs, clientComment, nil
			} // fallback - compare just the IP address
			if ip == clientIP {
				return clientID, groupIDs, clientComment, nil
			}
		}
	} else {
		fmt.Println("Error: data field is not an array")
		return "", nil, "", errors.New("data field is not an array")
	}

	return "", nil, "", nil
}

func toggleBlock(hostname string, ip string, serverIP string, PHPSESSID string, token string) error {
	fmt.Println("!!!!!!! Toggling block for", hostname, ip)

	// find the client by hostname and IP address
	clientID, currentGroups, comment, err := findClientID(hostname, ip, serverIP, PHPSESSID, token)
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println("Found Client ID:", clientID)

	// Determine if the client is in group 0 or 1 and toggle accordingly
	var newGroups []int
	inGroup0 := false
	inGroup1 := false

	// Check if the client is in group 0 or 1 and prepare new list excluding 0 and 1
	for _, group := range currentGroups {
		if group == 0 {
			inGroup0 = true
		} else if group == 1 {
			inGroup1 = true
		} else {
			newGroups = append(newGroups, group)
		}
	}

	// Toggle the group
	if inGroup0 {
		fmt.Println("Switching from group 0 to group 1")
		newGroups = append(newGroups, 1)
	} else if inGroup1 {
		fmt.Println("Switching from group 1 to group 0")
		newGroups = append(newGroups, 0)
	}

	// If neither group 0 nor 1 was found, decide on the default behavior
	if !inGroup0 && !inGroup1 {
		fmt.Println("Client is not in group 0 or 1, adding to group 0 by default")
		newGroups = append(newGroups, 0)
	}

	fmt.Println("New groups:", newGroups)

	// Update the client with the new group settings
	return updateClient(clientID, newGroups, comment, serverIP, PHPSESSID, token)
}

func main() {

	serverIP, PHPSESSID, token, err := sync()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Get the bot token from a file
	tokenFile, err := os.Open("telegram-token.txt")
	if err != nil {
		log.Panic(err) // Proper error handling in case the file cannot be opened
	}
	defer tokenFile.Close() // Ensure that file.Close() is called at the end of the function

	tokenScanner := bufio.NewScanner(tokenFile)
	var botToken string
	if tokenScanner.Scan() {
		botToken = strings.TrimSpace(tokenScanner.Text())
	}

	if err := tokenScanner.Err(); err != nil {
		log.Panicf("Failed to read bot token: %v", err)
	}

	// Initialize the bot with the token
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Panic(err)
	}
	log.Printf("Authorized on account %s", bot.Self.UserName)

	// Open the file containing the authorized user's ID
	userFile, err := os.Open("authorised-user.txt")
	if err != nil {
		log.Panic(err) // Proper error handling in case the file cannot be opened
	}
	defer userFile.Close() // Ensure that file.Close() is called at the end of the function

	userScanner := bufio.NewScanner(userFile)
	var authorisedUser int
	if userScanner.Scan() {
		trimmedLine := strings.TrimSpace(userScanner.Text())
		authorisedUser, err = strconv.Atoi(trimmedLine) // Convert the trimmed string to an integer
		if err != nil {
			log.Panicf("Failed to convert user ID to integer: %v", err)
		}
	}

	if err := userScanner.Err(); err != nil {
		log.Panicf("Failed to read authorized user ID: %v", err)
	}

	// Use authorisedUser as needed in your program
	log.Printf("Authorized user ID: %d", authorisedUser)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Panic(err)
	}

	for update := range updates {
		fmt.Println("update:", update.CallbackQuery)

		if update.Message != nil && update.Message.From.ID != authorisedUser {
			log.Println("Unauthorized access attempted.")
			continue // Skip processing this update
		}

		if update.CallbackQuery != nil { // Check if there is a callback query
			callbackData := update.CallbackQuery.Data
			fmt.Println("callback data:", callbackData)

			// Extracting hostname and IP using string manipulation
			parts := strings.Split(callbackData, ", IP: ")
			if len(parts) != 2 {
				fmt.Println("Invalid callback data format")
				continue
			}

			hostnamePart := parts[0]
			ip := parts[1]
			hostname := strings.TrimPrefix(hostnamePart, "Hostname: ")

			fmt.Println("Sending toggleBlock request for hostname:", hostname, "ip:", ip)

			// Call your toggleBlock function
			err := toggleBlock(hostname, ip, serverIP, PHPSESSID, token)
			if err != nil {
				fmt.Println(err)
				// send error message
				msg := tgbotapi.NewMessage(update.CallbackQuery.Message.Chat.ID, fmt.Sprintf("Error toggling block: %v", err))
				bot.Send(msg)
				continue
			}

			devices, err := parseStaticHosts("dhcpd.conf")
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Error: %v", err))
				bot.Send(msg)
				continue
			}

			// Re-fetch devices or simply re-use if they are still valid
			var rows [][]tgbotapi.InlineKeyboardButton
			// sort devices by hostname
			sort.Slice(devices, func(i, j int) bool {
				return devices[i].Hostname < devices[j].Hostname
			})
			for _, device := range devices {
				status := getBlockStatus(device.Hostname, device.IP, serverIP, PHPSESSID, token)
				callbackData := fmt.Sprintf("Hostname: %s, IP: %s", device.Hostname, device.IP)
				buttonText := fmt.Sprintf("%s (%s) - %s", device.Hostname, device.IP, status)
				row := tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData(buttonText, callbackData),
				)
				rows = append(rows, row)
			}
			keyboard := tgbotapi.NewInlineKeyboardMarkup(rows...)

			// Update the message
			editMsg := tgbotapi.NewEditMessageText(update.CallbackQuery.Message.Chat.ID, update.CallbackQuery.Message.MessageID, "Select a client:")
			editMsg.ReplyMarkup = &keyboard
			bot.Send(editMsg)

			continue // skip further processing since we've handled the callback query
		}

		if update.Message == nil { // ignore any non-Message and non-CallbackQuery updates
			continue
		}

		// Handle commands
		if update.Message.IsCommand() {
			switch update.Message.Command() {
			case "getclients":
				devices, err := parseStaticHosts("dhcpd.conf") // Your device parsing logic
				if err != nil {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Error: %v", err))
					bot.Send(msg)
					continue
				}

				// Read and delete previous messages
				previousMessages, err := os.Open("previous-messages.txt")
				if err != nil {
					log.Println("Failed to open previous-messages.txt:", err)
					continue
				}
				scanner := bufio.NewScanner(previousMessages)
				var messageIDsToDelete []int
				for scanner.Scan() {
					id, convErr := strconv.Atoi(scanner.Text())
					if convErr != nil {
						log.Println("Error converting message ID to integer:", convErr)
						continue
					}
					messageIDsToDelete = append(messageIDsToDelete, id)
				}
				previousMessages.Close()

				// Delete previous messages
				for _, id := range messageIDsToDelete {
					deleteMsg := tgbotapi.DeleteMessageConfig{
						ChatID:    update.Message.Chat.ID,
						MessageID: id,
					}
					if _, err := bot.DeleteMessage(deleteMsg); err != nil {
						log.Printf("Failed to delete message %d: %v\n", id, err)
					}
				}

				// Prepare new keyboard
				var rows [][]tgbotapi.InlineKeyboardButton
				// sort devices by hostname
				sort.Slice(devices, func(i, j int) bool {
					return devices[i].Hostname < devices[j].Hostname
				})
				for _, device := range devices {
					blockStatus := getBlockStatus(device.Hostname, device.IP, serverIP, PHPSESSID, token)
					callbackData := fmt.Sprintf("Hostname: %s, IP: %s", device.Hostname, device.IP)
					buttonText := fmt.Sprintf("%s (%s) %s", device.Hostname, device.IP, blockStatus)
					row := tgbotapi.NewInlineKeyboardRow(
						tgbotapi.NewInlineKeyboardButtonData(buttonText, callbackData),
					)
					rows = append(rows, row)
				}
				keyboard := tgbotapi.NewInlineKeyboardMarkup(rows...)
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Select a client:")
				msg.ReplyMarkup = keyboard
				sentMsg, err := bot.Send(msg)
				if err != nil {
					log.Println("Failed to send message:", err)
					continue
				}

				// Store new message ID
				newMessagesFile, err := os.Create("previous-messages.txt")
				if err != nil {
					log.Println("Failed to create/open previous-messages.txt:", err)
					continue
				}
				defer newMessagesFile.Close()
				if _, err := newMessagesFile.WriteString(fmt.Sprintf("%d\n", sentMsg.MessageID)); err != nil {
					log.Println("Failed to write message ID to file:", err)
				}
			}
		}
	}

}

func getBlockStatus(hostname, ip, serverIP, PHPSESSID, token string) string {
	_, groups, _, err := findClientID(hostname, ip, serverIP, PHPSESSID, token)
	if err != nil {
		fmt.Printf("Error finding client ID: %v\n", err)
		return "⚠️" // Indicates an error
	}

	for _, groupID := range groups {
		if groupID == 0 {
			return "❌"
		} else if groupID == 1 {
			return "✅"
		}
	}
	return "🔍" // Default, in case no group matches
}
