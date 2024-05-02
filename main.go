package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

type IPAndMAC struct {
	IP  string
	MAC string
}
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

// dhcpd.conf categories for lease ranges
// returns an map of category name to [startIP, endIP]
func findDHCPCategories(filePath string) (map[string][2]int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open DHCP config file: %w", err)
	}
	defer file.Close()

	categories := make(map[string][2]int)
	scanner := bufio.NewScanner(file)
	digitRegex := regexp.MustCompile(`\d+`) // Regular expression to extract digits

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "##") && strings.Contains(line, "-") {
			line = strings.Trim(line, "# ")       // Trim spaces and # from both ends
			parts := strings.SplitN(line, ":", 2) // Split only into two parts
			if len(parts) == 2 {
				categoryName := strings.TrimSpace(parts[0])
				rangeStr := strings.TrimSpace(parts[1])
				rangeParts := strings.Fields(rangeStr) // Split by whitespace and get range
				if len(rangeParts) >= 2 {
					// Extract only digits from each part using regex
					startStr := digitRegex.FindString(rangeParts[0])
					endStr := digitRegex.FindString(rangeParts[len(rangeParts)-1])
					startIP, errStart := strconv.Atoi(startStr)
					endIP, errEnd := strconv.Atoi(endStr)
					if errStart == nil && errEnd == nil {
						categories[categoryName] = [2]int{startIP, endIP} // Add the category to the map
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read DHCP config file: %w", err)
	}

	return categories, nil
}

func createStaticHost(hostname, currentIP, dhcpdConfPath, leasesPath, category string) error {
	fmt.Println("Creating static host entry for", hostname, "with current IP", currentIP)

	categories, err := findDHCPCategories(dhcpdConfPath)
	if err != nil {
		return err
	}

	range_, exists := categories[category]
	if !exists {
		return fmt.Errorf("category '%s' not found", category)
	}

	nextIP, err := findNextAvailableIP(range_[0], range_[1], dhcpdConfPath)
	if err != nil {
		return err
	}

	fmt.Println("Next available IP for", category, ":", nextIP)

	// find the MAC address of device with current IP
	macAddress, err := findMacAddress(currentIP, leasesPath)
	if err != nil {
		return fmt.Errorf("failed to find MAC address: %v", err)
	}

	// check if the host or MAC address already exists in the DHCP config file
	exists, checkErr := checkIfHostExists(hostname, macAddress, dhcpdConfPath)
	if checkErr != nil {
		return fmt.Errorf("failed to check if host or MAC address exists: %v", err)
	}
	if exists {
		return fmt.Errorf("host or MAC address already exists in DHCP config file")
	}

	addErr := addHostToCategory(hostname, macAddress, nextIP, category, dhcpdConfPath)
	if addErr != nil {
		return addErr
	}

	// remove the lease
	removeErr := removeLease(macAddress, currentIP, leasesPath)
	if removeErr != nil {
		return removeErr
	}

	return nil
}

func removeLease(mac, ip, leasesPath string) error {
	fmt.Println("Removing lease for", mac, ip)

	// Open the original file for reading
	file, err := os.Open(leasesPath)
	if err != nil {
		return fmt.Errorf("failed to open leases file: %v", err)
	}
	defer file.Close()

	var buffer bytes.Buffer
	var leaseBuffer bytes.Buffer
	var inLeaseBlock bool

	scanner := bufio.NewScanner(file)
	// Scan each line in the file
	for scanner.Scan() {
		line := scanner.Text()

		// Detect start of a lease block
		if strings.HasPrefix(line, "lease") {
			inLeaseBlock = true
			leaseBuffer.WriteString(line + "\n")
			continue
		}

		if inLeaseBlock {
			leaseBuffer.WriteString(line + "\n") // Continue capturing the lease block
			// Check if the end of a lease block
			if strings.TrimSpace(line) == "}" {
				if strings.Contains(leaseBuffer.String(), mac) || strings.Contains(leaseBuffer.String(), ip) {
					fmt.Println("Found and deleting lease entry for", mac, ip)
					// Clear leaseBuffer to not write this block back, effectively deleting it
					leaseBuffer.Reset()
				} else {
					buffer.Write(leaseBuffer.Bytes()) // Write back non-matching lease block
				}
				inLeaseBlock = false // Reset the flag after processing a lease block
				leaseBuffer.Reset()  // Clear the lease buffer after processing it
			}
		} else {
			buffer.WriteString(line + "\n") // Write lines outside of lease blocks directly to the main buffer
		}
	}

	// Check for scanning errors
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading leases file: %v", err)
	}

	// Open the file for writing to overwrite with new data
	err = os.WriteFile(leasesPath, buffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("failed to write to leases file: %v", err)
	}

	return nil
}

// check if the host or MAC address already exists in the DHCP config file
func checkIfHostExists(hostname, macAddress, dhcpdConfPath string) (bool, error) {
	// Open the DHCP configuration file
	file, err := os.Open(dhcpdConfPath)
	if err != nil {
		return false, fmt.Errorf("failed to open DHCP config file: %v", err)
	}
	defer file.Close()

	// Create a scanner to read through the file line by line
	scanner := bufio.NewScanner(file)

	// Scan each line in the file
	for scanner.Scan() {
		line := scanner.Text()
		// Look for lines that start with "host" which indicate a host entry
		if strings.HasPrefix(line, "host") {
			// Check if the current line contains the hostname or MAC address
			if strings.Contains(line, hostname) || strings.Contains(line, macAddress) {
				return true, nil
			}
		}
	}

	// Check for scanning errors
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("error reading from DHCP config file: %v", err)
	}

	// If no match is found and no error occurred, return false
	return false, nil
}

// find where to add the new host entry
func addHostToCategory(hostname, macAddress string, nextIP int, category, filePath string) error {
	// Open the original file for reading
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open DHCP config file: %v", err)
	}
	defer file.Close()

	var buffer bytes.Buffer
	scanner := bufio.NewScanner(file)
	inCategory := false
	lastHostWritten := false
	appendHere := false

	// Iterate through the file to find the appropriate category
	for scanner.Scan() {
		line := scanner.Text()

		// Detect the start of the desired category
		if strings.Contains(line, fmt.Sprintf("## %s", category)) {
			inCategory = true
			buffer.WriteString(line + "\n")
			continue
		}

		// Detect the start of a new category while in the desired category
		if inCategory && strings.HasPrefix(line, "##") {
			appendHere = true // Mark that the new host should be appended just before this line
		}

		// If within the category and no new category has started
		if inCategory && !appendHere {
			buffer.WriteString(line + "\n")
			// If line starts with "host" keep track of it
			if strings.HasPrefix(line, "host") {
				lastHostWritten = true
			}
		} else if appendHere && lastHostWritten {
			// Insert new host entry here as we are at the end of the category
			newHostEntry := fmt.Sprintf("host %s { hardware ethernet %s; fixed-address 10.45.1.%d; }\n", hostname, macAddress, nextIP)
			buffer.WriteString(newHostEntry)
			buffer.WriteString(line + "\n")
			appendHere = false
			inCategory = false
			lastHostWritten = false // Reset after inserting
		} else {
			// Write other lines normally
			buffer.WriteString(line + "\n")
		}
	}

	// If the category is the last one and no new category was detected after, append the new host at the end
	if inCategory && lastHostWritten && !appendHere {
		newHostEntry := fmt.Sprintf("host %s { hardware ethernet %s; fixed-address 10.45.1.%d; }\n", hostname, macAddress, nextIP)
		buffer.WriteString(newHostEntry)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error while reading DHCP config file: %v", err)
	}

	// Write the updated content back to the file
	if err := os.WriteFile(filePath, buffer.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write updated DHCP config file: %v", err)
	}

	return nil
}

func findNextAvailableIP(startIP, endIP int, dhcpdConfPath string) (int, error) {
	usedIPs := make(map[int]bool)
	file, err := os.Open(dhcpdConfPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open DHCP config file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "host") {
			parts := strings.Fields(line)
			// Loop through parts to find the fixed-address entry
			for i, part := range parts {
				if part == "fixed-address" && i+1 < len(parts) {
					ipStr := strings.TrimSuffix(parts[i+1], ";")
					if ip, err := strconv.Atoi(strings.Split(ipStr, ".")[3]); err == nil {
						usedIPs[ip] = true
					}
				}
			}
		}
	}

	for ip := startIP; ip <= endIP; ip++ {
		if !usedIPs[ip] {
			return ip, nil
		}
	}

	return 0, fmt.Errorf("no available IPs in the range from %d to %d", startIP, endIP)
}

func findMacAddress(ip, leasesPath string) (string, error) {
	file, err := os.Open(leasesPath)
	if err != nil {
		return "", fmt.Errorf("failed to open leases file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var foundIP bool
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fmt.Sprintf("lease %s {", ip)) {
			foundIP = true
		}
		if foundIP && strings.Contains(line, "hardware ethernet") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return strings.Trim(parts[2], ";"), nil
			}
		}
		if foundIP && strings.Contains(line, "}") {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read leases file: %v", err)
	}

	return "", fmt.Errorf("MAC address not found for IP %s", ip)
}

func findAllIPsInLeasesFile(filePath string) ([]IPAndMAC, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open leases file: %v", err)
	}
	defer file.Close()

	var entries []IPAndMAC
	scanner := bufio.NewScanner(file)

	// Read file line by line
	for scanner.Scan() {
		line := scanner.Text()
		// Check if the line starts with 'lease' to identify the beginning of a lease block
		if strings.HasPrefix(line, "lease") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := fields[1] // The second element should be the IP address
				// Continue scanning until 'hardware ethernet' is found
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "  hardware ethernet") {
						fields = strings.Fields(line)
						if len(fields) >= 3 {
							mac := strings.TrimSuffix(fields[2], ";")
							entries = append(entries, IPAndMAC{IP: ip, MAC: mac})
							break
						}
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading leases file: %v", err)
	}

	// Sort the slice of IPAndMAC structs
	sort.Slice(entries, func(i, j int) bool {
		ipA, ipB := net.ParseIP(entries[i].IP), net.ParseIP(entries[j].IP)
		if ipA == nil || ipB == nil {
			return false // Handle parsing errors
		}
		ipA4, ipB4 := ipA.To4(), ipB.To4()
		if ipA4 != nil && ipB4 != nil {
			return bytes.Compare(ipA4, ipB4) < 0
		}
		return false // Handle non-IPv4 cases
	})

	return entries, nil
}

// returns the server IP, PHPSESSID, and token
// clientSync - just get auth, or sync with DHCP
func sync(dhcpdConfPath, serverIP string, clientSync bool) (string, string, string, error) {

	// Get the password from a file
	passwordFile, err := os.Open("pihole-password.txt")
	if err != nil {
		log.Panic(err) // Proper error handling in case the file cannot be opened
	}
	defer passwordFile.Close() // Ensure that file.Close() is called at the end of the function

	passwordScanner := bufio.NewScanner(passwordFile)
	var password string
	if passwordScanner.Scan() {
		password = strings.TrimSpace(passwordScanner.Text())
	}

	if err := passwordScanner.Err(); err != nil {
		log.Panicf("Failed to read password: %v", err)
	}

	PHPSESSID, token, err := authenticate(serverIP, password)
	if err != nil {
		fmt.Println(err)
		return "", "", "", err
	}

	if !clientSync {
		fmt.Println("not syncing with DHCP")
		return serverIP, PHPSESSID, token, nil
	}

	fmt.Println("syncing with DHCP")

	devices, err := parseStaticHosts(dhcpdConfPath)
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

// Toggle the groups of a client, blocking or unblocking
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

	dhcpdConfPath := "dhcpd.conf"
	dhcpdLeasesPath := "dhcpd.leases"
	var serverIP, PHPSESSID, token string
	var err error
	serverIP = "10.45.1.2"

	// sync once to get the initial values
	serverIP, _, _, err = sync(dhcpdConfPath, serverIP, true)
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

	log.Printf("Authorized user ID: %d", authorisedUser)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Panic(err)
	}

	var creatingNewClient bool
	//var newClientHostname string

	for update := range updates {

		var fromID int
		if update.CallbackQuery != nil {
			fromID = update.CallbackQuery.From.ID
		} else {
			fromID = update.Message.From.ID
		}

		if fromID != authorisedUser {
			log.Println("Unauthorized access attempted.")
			continue // Skip processing this update
		}

		if update.CallbackQuery != nil { // Check if there is a callback query

			// if it's a refresh button, send a new menu
			if update.CallbackQuery.Data == "refresh" {
				fmt.Println("Refresh button clicked")
				// send a refresh message
				msg := tgbotapi.NewMessage(int64(fromID), "Refreshing...")
				refreshMsg, err := bot.Send(msg)
				if err != nil {
					log.Println("Failed to send refresh message:", err)
					continue
				}

				serverIP, PHPSESSID, token, err = sync(dhcpdConfPath, serverIP, true) // refresh with DHCP
				if err != nil {
					fmt.Println(err)
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
					bot.Send(msg)
					return
				}

				devices, err := parseStaticHosts(dhcpdConfPath)
				if err != nil {
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
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

				// add a refresh button at the bottom
				refreshButton := tgbotapi.NewInlineKeyboardButtonData("Refresh", "refresh")
				rows = append(rows, tgbotapi.NewInlineKeyboardRow(refreshButton))

				// add a new button at the bottom
				newButton := tgbotapi.NewInlineKeyboardButtonData("New", "new")
				rows = append(rows, tgbotapi.NewInlineKeyboardRow(newButton))

				keyboard := tgbotapi.NewInlineKeyboardMarkup(rows...)

				// Update the message
				editMsg := tgbotapi.NewEditMessageText(int64(fromID), update.CallbackQuery.Message.MessageID, "Select a client:")
				editMsg.ReplyMarkup = &keyboard
				bot.Send(editMsg)

				// delete the refresh message
				deleteMsg := tgbotapi.DeleteMessageConfig{
					ChatID:    int64(fromID),
					MessageID: refreshMsg.MessageID,
				}
				if _, err := bot.DeleteMessage(deleteMsg); err != nil {
					log.Printf("Failed to delete refresh message %d: %v\n", refreshMsg.MessageID, err)
				}

				continue // skip further processing since we've handled the callback query

			}

			// if it's a toggle block (contains a hostname and IP)
			if strings.Contains(update.CallbackQuery.Data, "Hostname: ") && strings.Contains(update.CallbackQuery.Data, ", IP: ") {
				fmt.Println("got toggle block callback")
				callbackData := update.CallbackQuery.Data

				// send a loading message
				msg := tgbotapi.NewMessage(int64(fromID), "Processing...")
				loadingMsg, processErr := bot.Send(msg)
				if processErr != nil {
					log.Println("Failed to send loading message:", processErr)
					continue
				}

				// re-sync
				serverIP, PHPSESSID, token, err = sync(dhcpdConfPath, serverIP, false) // don't sync with DHCP, just re-auth
				if err != nil {
					fmt.Println(err)
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
					bot.Send(msg)
					return
				}

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
				blockErr := toggleBlock(hostname, ip, serverIP, PHPSESSID, token)
				if blockErr != nil {
					fmt.Println(blockErr)
					// send error message
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error toggling block: %v", blockErr))
					bot.Send(msg)
					continue
				}

				devices, err := parseStaticHosts(dhcpdConfPath)
				if err != nil {
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
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

				// add a refresh button at the bottom
				refreshButton := tgbotapi.NewInlineKeyboardButtonData("Refresh", "refresh")
				rows = append(rows, tgbotapi.NewInlineKeyboardRow(refreshButton))

				// add a new button at the bottom
				newButton := tgbotapi.NewInlineKeyboardButtonData("New", "new")
				rows = append(rows, tgbotapi.NewInlineKeyboardRow(newButton))

				keyboard := tgbotapi.NewInlineKeyboardMarkup(rows...)

				// Update the message
				editMsg := tgbotapi.NewEditMessageText(int64(fromID), update.CallbackQuery.Message.MessageID, "Select a client:")
				editMsg.ReplyMarkup = &keyboard
				bot.Send(editMsg)

				// delete the loading message
				deleteMsg := tgbotapi.DeleteMessageConfig{
					ChatID:    int64(fromID),
					MessageID: loadingMsg.MessageID,
				}
				if _, err := bot.DeleteMessage(deleteMsg); err != nil {
					log.Printf("Failed to delete loading message %d: %v\n", loadingMsg.MessageID, err)
				}

				continue // skip further processing since we've handled the callback query
			}

			// if it's a new client, get all the known IPs and send a menu
			if update.CallbackQuery.Data == "new" {
				fmt.Println("got new client callback")

				// send a loading message
				msg := tgbotapi.NewMessage(int64(fromID), "Loading clients...")
				loadingMsg, processErr := bot.Send(msg)
				if processErr != nil {
					log.Println("Failed to send loading message:", processErr)
					continue
				}

				// Get all the known IPs from the leases file
				ips, err := findAllIPsInLeasesFile(dhcpdLeasesPath)
				if err != nil {
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
					bot.Send(msg)
					continue
				}

				// Prepare new keyboard with all the IPs and MAC addresses
				var rows [][]tgbotapi.InlineKeyboardButton
				for _, entry := range ips {
					buttonText := fmt.Sprintf("New client for %s (%s)", entry.IP, entry.MAC)
					row := tgbotapi.NewInlineKeyboardRow(
						tgbotapi.NewInlineKeyboardButtonData(buttonText, "createNew"),
					)
					rows = append(rows, row)
				}

				keyboard := tgbotapi.NewInlineKeyboardMarkup(rows...)
				msg = tgbotapi.NewMessage(int64(fromID), "Select a client:")
				msg.ReplyMarkup = keyboard
				bot.Send(msg)

				// delete the loading message
				deleteMsg := tgbotapi.DeleteMessageConfig{
					ChatID:    int64(fromID),
					MessageID: loadingMsg.MessageID,
				}
				if _, err := bot.DeleteMessage(deleteMsg); err != nil {
					log.Printf("Failed to delete loading message %d: %v\n", loadingMsg.MessageID, err)
				}

				continue // skip further processing since we've handled the callback query
			}

			// if it's a createNew client, ask for a hostname
			if update.CallbackQuery.Data == "createNew" {
				fmt.Println("got createNew callback")

				// ask for a hostname
				msg := tgbotapi.NewMessage(int64(fromID), "Please enter a hostname for the new client:")
				bot.Send(msg)

				creatingNewClient = true
			}
		}

		if update.Message == nil { // ignore any non-Message and non-CallbackQuery updates
			// if we're creating a new client, this will be the hostname
			if creatingNewClient {
				//	newClientHostname = update.Message.Text

				// get all categories
				categories, err := findDHCPCategories(dhcpdConfPath)
				if err != nil {
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
					bot.Send(msg)
					continue
				}

				// send categories as a menu
				var rows [][]tgbotapi.InlineKeyboardButton
				// Print each category and its range
				for category, rangeArr := range categories {
					fmt.Printf("Category: %s, Range: %d - %d\n", category, rangeArr[0], rangeArr[1])
					buttonText := fmt.Sprintf("%s (%d - %d)", category, rangeArr[0], rangeArr[1])
					row := tgbotapi.NewInlineKeyboardRow(
						tgbotapi.NewInlineKeyboardButtonData(buttonText, fmt.Sprintf("category %s", category)),
					)
					rows = append(rows, row)
				}

				keyboard := tgbotapi.NewInlineKeyboardMarkup(rows...)
				msg := tgbotapi.NewMessage(int64(fromID), "Select a category:")
				msg.ReplyMarkup = keyboard
				bot.Send(msg)

				continue // skip further processing since we've handled the message
			}
		}

		// Handle commands
		if update.Message.IsCommand() {
			switch update.Message.Command() {
			case "getclients":

				// send a loading message
				loadMsg := tgbotapi.NewMessage(int64(fromID), "Loading clients...")
				loadingMsg, processErr := bot.Send(loadMsg)
				if processErr != nil {
					log.Println("Failed to send loading message:", processErr)
					continue
				}

				// re-sync
				serverIP, PHPSESSID, token, err = sync(dhcpdConfPath, serverIP, true) // sync with DHCP
				if err != nil {
					fmt.Println(err)
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
					bot.Send(msg)
					return
				}

				devices, err := parseStaticHosts(dhcpdConfPath)
				if err != nil {
					msg := tgbotapi.NewMessage(int64(fromID), fmt.Sprintf("Error: %v", err))
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
						ChatID:    int64(fromID),
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

				// add a refresh button at the bottom
				refreshButton := tgbotapi.NewInlineKeyboardButtonData("Refresh", "refresh")
				rows = append(rows, tgbotapi.NewInlineKeyboardRow(refreshButton))

				// add a new button at the bottom
				newButton := tgbotapi.NewInlineKeyboardButtonData("New", "new")
				rows = append(rows, tgbotapi.NewInlineKeyboardRow(newButton))

				keyboard := tgbotapi.NewInlineKeyboardMarkup(rows...)
				msg := tgbotapi.NewMessage(int64(fromID), "Select a client:")
				msg.ReplyMarkup = keyboard
				sentMsg, err := bot.Send(msg)
				if err != nil {
					log.Println("Failed to send message:", err)
					continue
				}

				// delete the loading message
				deleteMsg := tgbotapi.DeleteMessageConfig{
					ChatID:    int64(fromID),
					MessageID: loadingMsg.MessageID,
				}
				if _, err := bot.DeleteMessage(deleteMsg); err != nil {
					log.Printf("Failed to delete loading message %d: %v\n", loadingMsg.MessageID, err)
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
