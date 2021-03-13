package main

import (
	"go.mongodb.org/mongo-driver/bson"
	"fmt"
	pb "hotelReservation/services/user/proto"
	"golang.org/x/net/context"
	"github.com/golang/protobuf/proto"
	"hotelReservation/utils"
	"hotelReservation/libgo"
	"bytes"
	"net/http"
)

const name = "srv-user"
var users map[string]string 

func init() {
	users = loadUsers()
}

// CheckUser returns whether the username and password are correct.
func CheckUser(w http.ResponseWriter, r *http.Request) {
	res := new(pb.Result)
	req := &pb.Request{}
	var data []byte
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	data = buf.Bytes()
	err := proto.Unmarshal(data, req)
	if err != nil {
		fmt.Println("Unable to unmarshal User request", err)
	}

	pass := req.Password
	res.Correct = false
	if truePass, found := users[req.Username]; found {
	    res.Correct = pass == truePass
	}

	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Unable to marshal response : %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, string(response))
}

// loadUsers loads hotel users from mongodb.
func loadUsers() map[string]string {
	
	client, err := utils.MongoClient()
	if err != nil {
		fmt.Println("Error in loading user db", err)
	}
	defer client.Disconnect(context.Background())
	c := client.Database("user-db").Collection("user")

	var users []User
	
	cur, err := c.Find(context.Background(), bson.M{})
	if err != nil { 
		panic(err) 
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var result User
		err := cur.Decode(&result)
		if err != nil { 
			panic(err) 
		}
		users = append(users, result)
	}
	if err := cur.Err(); err != nil {
		fmt.Println("Failed get users data: ", err)
	}

	res := make(map[string]string)
	for _, user := range users {
		res[user.Username] = user.Password
	}
	fmt.Printf("loadUser: loaded %d users\n", len(users))
	return res
}

//User struct for user object in mongodb
type User struct {
	Username string `bson:"username"`
	Password string `bson:"password"`
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	CheckUser(w, r)
}

func main() {
	libgo.Serve(http.HandlerFunc(requestHandler))
}