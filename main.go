package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)


func sendAlert(username string, url string) {
	res, _ := GetUserByUsername(username)
	list := res.Urls
	var index int
	for ind, x := range list {
		if x.Endpoint == url {
			index = ind
		}
	}

	UpdateDBByUser(username, "alerted_urls", append(res.AlertedURLs, res.Urls[index].Endpoint))
}
func updateDB(username string, url string, statusCode int) {
	success := statusCode/100 == 2
	res, _ := GetUserByUsername(username)
	list := res.Urls

	var index int
	for ind, x := range list {
		if x.Endpoint == url {
			index = ind
		}
	}
	if success {
		res.Urls[index].SuccessCount++
		UpdateDBByUser(username, "urls", res.Urls)
	} else {
		res.Urls[index].FailureCount++
		UpdateDBByUser(username, "urls", res.Urls)
		if res.Urls[index].FailureCount == res.Urls[index].FailLimit {
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
		res, _ := GetAllUsers()
		for _,x := range res{
			x.AlertedURLs = []string{}
			for _,u:= range x.Urls{
				u.FailureCount =0
				u.SuccessCount =0
			}
			UpdateDBByUser(x.Username, "urls", x.Urls)
			UpdateDBByUser(x.Username, "alerted_urls", x.AlertedURLs)
		}
	}
}

type URL struct {
	Endpoint      string `json:"endpoint" bson:"endpoint"`
	RequestPeriod int    `json:"request_period" bson:"request_period"`
	FailLimit     int    `json:"fail_limit" bson:"fail_limit"`
	SuccessCount  int    `json:"success_count" bson:"success_count"`
	FailureCount  int    `json:"failure_count" bson:"failure_count"`
}

type User struct {
	Username     string   `json:"username" bson:"username"`
	PasswordHash string   `json:"password_hash" bson:"password_hash"`
	Urls         []URL    `json:"urls" bson:"urls"`
	AlertedURLs  []string `json:"alerted_urls" bson:"alerted_urls"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.Header.Get("username")
	password := r.Header.Get("password")
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), 8)
	if x,_ := GetUserByUsername(username); x.Username != "" {
		http.Error(w, "username is already taken", http.StatusForbidden)
	} else {
		CreateUserInDB(User{Username: username, PasswordHash: string(hashed), Urls: []URL{}, AlertedURLs: []string{}})
		fmt.Fprintf(w, "register successfully")
	}
}

func checkPassword(username string, password string) bool {
	res, _ := GetUserByUsername(username)
	if res.Username == ""{
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
		res, _ := GetUserByUsername(username)
		list, err := json.Marshal(res.Urls)
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
		res, _ := GetUserByUsername(username)
		list := res.Urls
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
	res, _ := GetUserByUsername(username)
	if len(res.Urls) == 20 {
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
		return
	}

	if requestPeriod < 1 {
		http.Error(w, "request_period field cannot be less than 1", http.StatusForbidden)
		return
	}
	queryUrl := URL{Endpoint: endpoint, FailLimit: failLimit, FailureCount: 0, SuccessCount: 0, RequestPeriod: requestPeriod}
	list := res.Urls
	for _, x := range list {
		if x.Endpoint == endpoint {
			http.Error(w, "url is already in tracking list", http.StatusForbidden)
			return
		}
	}
	UpdateDBByUser(username, "urls", append(res.Urls, queryUrl))
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

	res, _ := GetUserByUsername(username)
	list, err := json.Marshal(res.AlertedURLs)
	if err != nil {
		fmt.Fprintf(w, "cannot convert data to JSON")
	} else {
		fmt.Fprintf(w, string(list))
	}
}

func PrepareAPI() {
	res, _ := GetAllUsers()
	for _,x:= range res{
		for _,req:= range x.Urls{
			go doEveryDSecond(req.RequestPeriod, req.Endpoint, x.Username)
		}
	}
}

func main() {
	//doEveryDSecond(1, "http://google.com/", "ali")

	http.HandleFunc("/signup", createUser)
	//http.HandleFunc("/login", login)
	http.HandleFunc("/urls", askEndpoints)
	http.HandleFunc("/url", askEndpoint)
	http.HandleFunc("/addurl", addEndpoint)
	http.HandleFunc("/alerts", alerts)

	PrepareAPI()
	go resetAtEndOfTheDay()
	log.Fatal(http.ListenAndServe(":8405", nil))
}








/* Used to create a singleton object of MongoDB client.
Initialized and exposed through  GetMongoClient().*/
var clientInstance *mongo.Client
//Used during creation of singleton client object in GetMongoClient().
var clientInstanceError error
//Used to execute client creation procedure only once.
var mongoOnce sync.Once
//I have used below constants just to hold required database config's.
const (
	CONNECTIONSTRING = "mongodb://localhost:27017"
	DB               = "db_issue_manager"
	ISSUES           = "col_issues"
)

//GetMongoClient - Return mongodb connection to work with
func GetMongoClient() (*mongo.Client, error) {
	//Perform connection creation operation only once.
	mongoOnce.Do(func() {
		// Set client options
		clientOptions := options.Client().ApplyURI(CONNECTIONSTRING)
		// Connect to MongoDB
		client, err := mongo.Connect(context.TODO(), clientOptions)
		if err != nil {
			clientInstanceError = err
		}
		// Check the connection
		err = client.Ping(context.TODO(), nil)
		if err != nil {
			clientInstanceError = err
		}
		clientInstance = client
	})
	return clientInstance, clientInstanceError
}

//CreateUserInDB - Insert a new document in the collection.
func CreateUserInDB(task User) error {
	//Get MongoDB connection using connectionhelper.
	client, err := GetMongoClient()
	if err != nil {
		return err
	}
	//Create a handle to the respective collection in the database.
	collection := client.Database(DB).Collection(ISSUES)
	//Perform InsertOne operation & validate against the error.
	_, err = collection.InsertOne(context.TODO(), task)
	if err != nil {
		return err
	}
	//Return success without any error.
	return nil
}

//GetUserByUsername - Get All Users for collection
func GetUserByUsername(username string) (User, error) {
	result := User{}
	//Define filter query for fetching specific document from collection
	filter := bson.D{primitive.E{Key: "username", Value: username}}
	//Get MongoDB connection using connectionhelper.
	client, err := GetMongoClient()
	if err != nil {
		return result, err
	}
	//Create a handle to the respective collection in the database.
	collection := client.Database(DB).Collection(ISSUES)
	//Perform FindOne operation & validate against the error.
	err = collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		return result, err
	}
	//Return result without any error.
	return result, nil
}

//GetAllUsers - Get All Users for collection
func GetAllUsers() ([]User, error) {
	//Define filter query for fetching specific document from collection
	filter := bson.D{{}} //bson.D{{}} specifies 'all documents'
	issues := []User{}
	//Get MongoDB connection using connectionhelper.
	client, err := GetMongoClient()
	if err != nil {
		return issues, err
	}
	//Create a handle to the respective collection in the database.
	collection := client.Database(DB).Collection(ISSUES)
	//Perform Find operation & validate against the error.
	cur, findError := collection.Find(context.TODO(), filter)
	if findError != nil {
		return issues, findError
	}
	//Map result to slice
	for cur.Next(context.TODO()) {
		t := User{}
		err := cur.Decode(&t)
		if err != nil {
			return issues, err
		}
		issues = append(issues, t)
	}
	// once exhausted, close the cursor
	cur.Close(context.TODO())
	if len(issues) == 0 {
		return issues, mongo.ErrNoDocuments
	}
	return issues, nil
}

func UpdateDBByUser(username string, field string, updated interface{}) error {
	//Define filter query for fetching specific document from collection
	filter := bson.D{primitive.E{Key: "username", Value: username}}

	//Define updater for to specifiy change to be updated.
	updater := bson.D{primitive.E{Key: "$set", Value: bson.D{
		primitive.E{Key: field, Value: updated},
	}}}

	//Get MongoDB connection using connectionhelper.
	client, err := GetMongoClient()
	if err != nil {
		return err
	}
	collection := client.Database(DB).Collection(ISSUES)

	//Perform UpdateOne operation & validate against the error.
	_, err = collection.UpdateOne(context.TODO(), filter, updater)
	if err != nil {
		return err
	}
	//Return success without any error.
	return nil
}