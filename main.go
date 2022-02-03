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
	// TODO: insert alert in database
}
func updateDB(username string, url string, statusCode int) {
	// TODO: update successCount or failureCount in database
	// TODO: call sendAlert function if we have reached to limit

	//success := statusCode/100 == 2
	println(username, url, statusCode)
}

func sendGetReq(url string, username string)  {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalln(err)
	}

	updateDB(username, url, resp.StatusCode)
}

func doEveryDSecond(d int, url string, username string)  {
	for {
		time.Sleep(time.Duration(d) * time.Second)
		go sendGetReq(url, username)
	}
}

func resetAtEndOfTheDay(){
	for {
		time.Sleep(24 * time.Hour)
		// TODO: reset successCount and failureCount and alerts in database
	}
}

type URL struct {
	endpoint      string `json:"endpoint"`
	requestPeriod int    `json:"request_period"`
	failLimit     int    `json:"fail_limit"`
	successCount  int `json:"success_count"`
	failureCount  int    `json:"failure_count"`
}

type User struct {
	username     string `json:"username"`
	passwordHash string `json:"password_hash"`
	urls         []URL  `json:"urls"`
	alertedURLs  []URL  `json:"alerted_urls"`
}

func createUser(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost{
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), 8)
	if _, ok := users[username]; ok{
		http.Error(w, "username is already taken", http.StatusForbidden)
	} else{
		users[username] = User{username: username, passwordHash: string(hashed), urls: []URL{}, alertedURLs: []URL{}}
		// TODO: create user in database
		fmt.Fprintf(w, "register successfully")
	}
}

func checkPassword(username string, password string) bool{
	// TODO: read password hash from database
	res, ok := users[username]
	if !ok{
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(res.passwordHash), []byte(password))
	return err == nil
}

func askEndpoints(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodGet{
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	if !checkPassword(username, password){
		http.Error(w, "username or password is incorrect", http.StatusForbidden)
	} else{
		// TODO: read from database
		list, err := json.Marshal(users[username].urls)
		if err != nil{
			fmt.Fprintf(w, "cannot convert data to JSON")
		} else{
			fmt.Fprintf(w, string(list))
		}
	}
}

func askEndpoint(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodGet{
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	askedUrl := r.Header.Get("endpoint")
	if !checkPassword(username, password){
		http.Error(w, "username or password is incorrect", http.StatusForbidden)
	} else{
		// TODO: read from database
		list := users[username].urls
		for _,x:= range list{
			if x.endpoint == askedUrl{
				ans, err := json.Marshal(x)
				if err != nil{
					fmt.Fprintf(w, "cannot convert data to JSON")
				} else{
					fmt.Fprintf(w, string(ans))
				}
				return
			}
		}
		http.Error(w, "there is no such url in user's list", http.StatusNotFound)
	}
}

func addEndpoint(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost{
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	if !checkPassword(username, password){
		http.Error(w, "username or password is incorrect", http.StatusForbidden)
		return
	}
	if len(users[username].urls) == 20{
		http.Error(w, "you have reached to the 20 urls limit", http.StatusForbidden)
		return
	}

	endpoint := r.Header.Get("endpoint")
	//failLimit, _ := strconv.Atoi(r.Header.Get("fail_limit"))
	//failureCount, _ := strconv.Atoi(r.Header.Get("failure_count"))
	//successCount, _ := strconv.Atoi(r.Header.Get("success_count"))
	requestPeriod, _ := strconv.Atoi(r.Header.Get("request_period"))

	//queryUrl :=  URL {endpoint: endpoint, failLimit: failLimit, failureCount: failureCount, successCount: successCount, requestPeriod: requestPeriod}
	// TODO: read from database
	list := users[username].urls
	for _,x:= range list{
		if x.endpoint == endpoint{
			http.Error(w, "url is already in tracking list", http.StatusForbidden)
			return
		}
	}
	// TODO: insert to database
	//users[username].urls = append(users[username].urls, queryUrl)

	go doEveryDSecond(requestPeriod ,endpoint,username)
}

var users = map[string]User{}

func main() {
	//doEveryDSecond(1, "http://google.com/", "ali")

	http.HandleFunc("/signup", createUser)
	//http.HandleFunc("/login", login)
	http.HandleFunc("/urls", askEndpoints)
	http.HandleFunc("/url", askEndpoint)
	http.HandleFunc("/addurl", addEndpoint)
	//http.HandleFunc("/alerts", )
	go resetAtEndOfTheDay()
	log.Fatal(http.ListenAndServe(":8101", nil))
}
