package main

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"bytes"
	"net/http"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	pb "hotelReservation/services/profile/proto"
	"golang.org/x/net/context"
	"hotelReservation/utils"
	"hotelReservation/libgo"
)

const name = "srv-profile"

var c *mongo.Collection

// GetProfiles returns hotel profiles for requested IDs
func GetProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res := new(pb.Result)
	hotels := make([]*pb.Hotel, 0)
	req := &pb.Request{}
	var data []byte
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	data = buf.Bytes()
	err := proto.Unmarshal(data, req)
	if err != nil {
		fmt.Println("Unable to unmarshal Rate GetRate")
	}

	for _, i := range req.HotelIds {
		hotelProf := new(pb.Hotel)
		err := c.FindOne(ctx, bson.M{"id": i}).Decode(&hotelProf)

		if err != nil {
			fmt.Println("Failed get hotels data: ", err)
		}

		hotels = append(hotels, hotelProf)
	}

	res.Hotels = hotels
	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Unable to marshal response : %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, string(response))
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	GetProfiles(w, r)
}

func main() {
	client, err := utils.MongoClient()
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.Background())
	c = client.Database("profile-db").Collection("hotels")
	libgo.Serve(http.HandlerFunc(requestHandler))
}