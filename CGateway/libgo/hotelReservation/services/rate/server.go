package main

import (
	// "encoding/json"
	"fmt"
	"sort"
	"bytes"
	"net/http"
	// "time"
	// b64 "encoding/base64"	
	pb "hotelReservation/services/rate/proto"
	"golang.org/x/net/context"
	"hotelReservation/utils"
	"hotelReservation/libgo"
	"go.mongodb.org/mongo-driver/mongo"
	// "strings"
	"github.com/golang/protobuf/proto"
	"go.mongodb.org/mongo-driver/bson"

)

const name = "srv-rate"

var c *mongo.Collection

// GetRates gets rates for hotels for specific date range.
func GetRates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &pb.Request{}
	var data []byte
	// if r.IsBase64Encoded {
	// 	data, _ = b64.StdEncoding.DecodeString(r.Body)
	// } else {
	// 	data = []byte(r.Body)
	// }
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	data = buf.Bytes()

	err := proto.Unmarshal(data, req)
	if err != nil {
		fmt.Println("Unable to unmarshal Rate GetRate")
	}
	ratePlans := make(RatePlans, 0)

	if len(req.HotelIds) > 0 {
		cur, err := c.Find(ctx, bson.M{"hotelId": bson.M{"$in": req.HotelIds}})
		if err != nil { 
			panic(err) 
		}
		defer cur.Close(ctx)
		for cur.Next(ctx) {
			// tmpRatePlans := make(RatePlans, 0)
			tmpRatePlan := &pb.RatePlan{}
			err := cur.Decode(&tmpRatePlan)
			if err != nil { 
				panic(err) 
			}
			ratePlans = append(ratePlans, tmpRatePlan)
		}
		if err := cur.Err(); err != nil {
			fmt.Println("Failed get rate data: ", err)
		}
		sort.Sort(ratePlans)
	}
	res := &pb.Result{}
	res.RatePlans = ratePlans

	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Unable to marshal response : %v", err)
	}
	fmt.Printf("Sending %d ratePlans\n", len(ratePlans))
	// return events.APIGatewayProxyResponse{
	// 	StatusCode: 200,
	// 	Headers: map[string]string{"Content-Type": "application/octet-stream"},
	// 	// Body: string(response),
	// 	Body: b64.StdEncoding.EncodeToString(response),
	// 	IsBase64Encoded: true,
	// }, nil
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprint(w, string(response))
}

type RatePlans []*pb.RatePlan

func (r RatePlans) Len() int {
	return len(r)
}

func (r RatePlans) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r RatePlans) Less(i, j int) bool {
	return r[i].RoomType.TotalRate > r[j].RoomType.TotalRate
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	GetRates(w, r)
}

func main() {
	client, err := utils.MongoClient()
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.Background())
	c = client.Database("rate-db").Collection("inventory")
	libgo.Serve(http.HandlerFunc(requestHandler))
}