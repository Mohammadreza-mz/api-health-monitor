package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"time"
)

func sendAlert(username string, url string) {
	// TODO: insert an alert for given username and url in database

	list := users[username].Urls
	var index int
	for ind, x := range list {
		if x.Endpoint == url {
			index = ind
		}
	}

	curUser := users[username]
	curUser.AlertedURLs = append(curUser.AlertedURLs, users[username].Urls[index].Endpoint)
	users[username] = curUser
}
func updateDB(username string, url string, statusCode int) {
	// TODO: update successCount or failureCount in database
	// TODO: call sendAlert function if we have reached to the limit

	success := statusCode/100 == 2
	list := users[username].Urls

	var index int
	for ind, x := range list {
		if x.Endpoint == url {
			index = ind
		}
	}
	if success {
		users[username].Urls[index].SuccessCount++
	} else {
		users[username].Urls[index].FailureCount++
		if users[username].Urls[index].FailureCount == users[username].Urls[index].FailLimit {
			sendAlert(username, url)
		}
	}

	println(username, url, statusCode)
}

func sendGetReq(url string, username string) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalln(err)
	}

	updateDB(username, url, resp.StatusCode)
}

func doEveryDSecond(d int, url string, username string) {
	for {
		time.Sleep(time.Duration(d) * time.Second)
		go sendGetReq(url, username)
	}
}

func resetAtEndOfTheDay() {
	for {
		time.Sleep(24 * time.Hour)
		// TODO: reset successCount and failureCount and alerts in database
	}
}

type URL struct {
	Endpoint      string `json:"endpoint"`
	RequestPeriod int    `json:"request_period"`
	FailLimit     int    `json:"fail_limit"`
	SuccessCount  int    `json:"success_count"`
	FailureCount  int    `json:"failure_count"`
}

type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Urls         []URL    `json:"urls"`
	AlertedURLs  []string `json:"alerted_urls"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), 8)
	if _, ok := users[username]; ok {
		http.Error(w, "username is already taken", http.StatusForbidden)
	} else {
		users[username] = User{Username: username, PasswordHash: string(hashed), Urls: []URL{}, AlertedURLs: []string{}}
		// TODO: create user in database
		fmt.Fprintf(w, "register successfully")
	}
}

func checkPassword(username string, password string) bool {
	// TODO: read password hash from database
	res, ok := users[username]
	if !ok {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(res.PasswordHash), []byte(password))
	return err == nil
}

func askEndpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	if !checkPassword(username, password) {
		http.Error(w, "username or password is incorrect", http.StatusForbidden)
	} else {
		// TODO: read from database
		list, err := json.Marshal(users[username].Urls)
		if err != nil {
			fmt.Fprintf(w, "cannot convert data to JSON")
		} else {
			fmt.Fprintf(w, string(list))
		}
	}
}

func askEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	askedUrl := r.Header.Get("endpoint")
	if !checkPassword(username, password) {
		http.Error(w, "username or password is incorrect", http.StatusForbidden)
	} else {
		// TODO: read from database
		list := users[username].Urls
		for _, x := range list {
			if x.Endpoint == askedUrl {
				ans, err := json.Marshal(x)
				if err != nil {
					fmt.Fprintf(w, "cannot convert data to JSON")
				} else {
					fmt.Fprintf(w, string(ans))
				}
				return
			}
		}
		http.Error(w, "there is no such url in user's list", http.StatusNotFound)
	}
}

func addEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	if !checkPassword(username, password) {
		http.Error(w, "username or password is incorrect", http.StatusForbidden)
		return
	}
	if len(users[username].Urls) == 20 {
		http.Error(w, "you have reached to the 20 urls limit", http.StatusForbidden)
		return
	}

	/*_, ok := r.Header["fail_limit"]
	if !ok{
		http.Error(w, "fail_limit field cannot be empty", http.StatusForbidden)
	}

	_, ok = r.Header["request_period"]
	if !ok {
		http.Error(w, "request_period field cannot be empty", http.StatusForbidden)
		return
	}*/

	endpoint := r.Header.Get("endpoint")
	failLimit, ok1 := strconv.Atoi(r.Header.Get("fail_limit"))
	requestPeriod, ok2 := strconv.Atoi(r.Header.Get("request_period"))

	if ok1 != nil || ok2 != nil {
		http.Error(w, "fail_limit and request_period are required and must be integers", http.StatusForbidden)
	}

	if requestPeriod < 1 {
		http.Error(w, "request_period field cannot be less than 1", http.StatusForbidden)
		return
	}
	queryUrl := URL{Endpoint: endpoint, FailLimit: failLimit, FailureCount: 0, SuccessCount: 0, RequestPeriod: requestPeriod}
	// TODO: read from database
	list := users[username].Urls
	for _, x := range list {
		if x.Endpoint == endpoint {
			http.Error(w, "url is already in tracking list", http.StatusForbidden)
			return
		}
	}
	// TODO: insert to database
	curUser := users[username]
	curUser.Urls = append(curUser.Urls, queryUrl)
	users[username] = curUser

	go doEveryDSecond(requestPeriod, endpoint, username)
}

func alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	if !checkPassword(username, password) {
		http.Error(w, "username or password is incorrect", http.StatusForbidden)
		return
	}
	// TODO: read from database
	list, err := json.Marshal(users[username].AlertedURLs)
	if err != nil {
		fmt.Fprintf(w, "cannot convert data to JSON")
	} else {
		fmt.Fprintf(w, string(list))
	}
}

var users = map[string]User{}

func main() {
	//doEveryDSecond(1, "http://google.com/", "ali")

	http.HandleFunc("/signup", createUser)
	//http.HandleFunc("/login", login)
	http.HandleFunc("/urls", askEndpoints)
	http.HandleFunc("/url", askEndpoint)
	http.HandleFunc("/addurl", addEndpoint)
	http.HandleFunc("/alerts", alerts)
	go resetAtEndOfTheDay()
	log.Fatal(http.ListenAndServe(":8401", nil))
}
