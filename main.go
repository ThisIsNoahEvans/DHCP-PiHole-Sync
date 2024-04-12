package main

import (
	"errors"
	"fmt"
	"net/http"
)

// get the pihole status
// check we can connect to the pihole
func getPiholeStatus(ip string, token string) error {
	url := "http://" + ip + "/admin/api.php?summaryRaw&auth=" + token
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer res.Body.Close()

	// check if the response status code is 200
	if res.StatusCode != 200 {
		return errors.New("Status code not 200")
	}

	// all good - return nil
	return nil
}

func main() {
	err := getPiholeStatus("10.45.1.2", "567959398aab9b9188341f95d8382b272124db58d4a92433121bf96e06b8f985")
	if err != nil {
		fmt.Println("Error getting Pi-hole status:", err)
	} else {
		fmt.Println("Pi-hole status OK")
	}
}
