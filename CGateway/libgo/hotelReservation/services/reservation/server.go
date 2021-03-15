package main

import (
	// "encoding/json"
	"fmt"
	pb "hotelReservation/services/reservation/proto"
	"golang.org/x/net/context"
	// "io/ioutil"
	// "log"
	"bytes"
	"net/http"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"hotelReservation/libgo"
	"hotelReservation/utils"
	"github.com/golang/protobuf/proto"
	// "strconv"
)

const name = "srv-reservation"

var client *mongo.Client

// MakeReservation makes a reservation based on given information
func MakeReservation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res := new(pb.Result)
	res.HotelId = make([]string, 0)

	req := &pb.Request{}
	var data []byte
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	data = buf.Bytes()

	err := proto.Unmarshal(data, req)
	if err != nil {
		fmt.Println("Unable to unmarshal Reservation Make", err)
	}
	// client, err := utils.MongoClient()
	// if err != nil {
	// 	panic(err)
	// }
	// defer client.Disconnect(context.Background())
	c := client.Database("reservation-db").Collection("reservation")
	c1 := client.Database("reservation-db").Collection("number")
	
	inDate, _ := time.Parse(
		time.RFC3339,
		req.InDate + "T12:00:00+00:00")

	outDate, _ := time.Parse(
		time.RFC3339,
		req.OutDate + "T12:00:00+00:00")
	hotelId := req.HotelId[0]
	fmt.Printf("Received request make reservation with hotel id %s\n", hotelId)
	indate := inDate.String()[0:10]


	for inDate.Before(outDate) {
		// check reservations
		count := 0
		inDate = inDate.AddDate(0, 0, 1)
		outdate := inDate.String()[0:10]

		reserve := make([]reservation, 0)

		cur, err := c.Find(context.Background(), &bson.M{"hotelId": hotelId, "inDate": indate, "outDate": outdate})
		if err != nil { 
			panic(err) 
		}
		defer cur.Close(context.Background())
		for cur.Next(context.Background()) {
			// var result *point
			var result reservation
			err := cur.Decode(&result)
			if err != nil { 
				panic(err) 
			}
			reserve = append(reserve, result)
		}
		if err := cur.Err(); err != nil {
			fmt.Println("Failed get reservation (make) data: ", err)
		}

		
		for _, r := range reserve {
			count += r.Number
		}
		hotel_cap := 0
		var num number
		err = c1.FindOne(ctx, &bson.M{"hotelId": hotelId}).Decode(&num)
		if err != nil {
			panic(err)
		}
		hotel_cap = int(num.Number)

		if count + int(req.RoomNumber) > hotel_cap {
			// return res, nil
			return
			// return utils.LambdaResponse("Can't book so many rooms", http.StatusOK)
		}
		indate = outdate
	}

	inDate, _ = time.Parse(
		time.RFC3339,
		req.InDate + "T12:00:00+00:00")

	indate = inDate.String()[0:10]

	for inDate.Before(outDate) {
		inDate = inDate.AddDate(0, 0, 1)
		outdate := inDate.String()[0:10]
		_, err := c.InsertOne(ctx, &reservation{
			HotelId:      hotelId,
			CustomerName: req.CustomerName,
			InDate:       indate,
			OutDate:      outdate,
			Number:       int(req.RoomNumber),})
		if err != nil {
			panic(err)
		}
		indate = outdate
	}

	res.HotelId = append(res.HotelId, hotelId)

	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Unable to marshal response makeReservation %v", err)
	}
	// return events.APIGatewayProxyResponse{
	// 	StatusCode: 200,
	// 	Headers: map[string]string{"Content-Type": "application/octet-stream"},
	// 	// Body: string(response),
	// 	Body: b64.StdEncoding.EncodeToString(response),
	// 	IsBase64Encoded: true,
	// }, nil
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, string(response))
}

// CheckAvailability checks if given information is available
func CheckAvailability(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	res := new(pb.Result)
	res.HotelId = make([]string, 0)
	req := &pb.Request{}
	var data []byte
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	data = buf.Bytes()
	err := proto.Unmarshal(data, req)
	if err != nil {
		fmt.Println("Unable to unmarshal Reservation CheckAvail", err)
	}
	c := client.Database("reservation-db").Collection("reservation")
	c1 := client.Database("reservation-db").Collection("number")
	
	for _, hotelId := range req.HotelId {
		// fmt.Printf("reservation check hotel %s\n", hotelId)
		inDate, _ := time.Parse(
			time.RFC3339,
			req.InDate + "T12:00:00+00:00")

		outDate, _ := time.Parse(
			time.RFC3339,
			req.OutDate + "T12:00:00+00:00")

		indate := inDate.String()[0:10]

		for inDate.Before(outDate) {
			count := 0
			inDate = inDate.AddDate(0, 0, 1)
			// fmt.Printf("reservation check date %s\n", inDate.String()[0:10])
			outdate := inDate.String()[0:10]

			reserve := make([]reservation, 0)
			cur, err := c.Find(context.Background(), &bson.M{"hotelId": hotelId, "inDate": indate, "outDate": outdate})
			if err != nil { 
				panic(err) 
			}
			defer cur.Close(context.Background())
			for cur.Next(context.Background()) {
				var result reservation
				err := cur.Decode(&result)
				if err != nil { 
					panic(err) 
				}
				reserve = append(reserve, result)
			}
			if err := cur.Err(); err != nil {
				fmt.Println("Failed get reservation data: ", err)
			}
			// err := c.Find(&bson.M{"hotelId": hotelId, "inDate": indate, "outDate": outdate}).All(&reserve)
			// if err != nil {
			// 	panic(err)
			// }
			for _, r := range reserve {
				// fmt.Printf("reservation check reservation number = %d\n", hotelId)
				count += r.Number
			}

			hotel_cap := 0

			var num number
			err = c1.FindOne(ctx, &bson.M{"hotelId": hotelId}).Decode(&num)
			if err != nil {
				panic(err)
			}
			hotel_cap = int(num.Number)
	
			if count + int(req.RoomNumber) > hotel_cap {
				break
			}
			indate = outdate

			if inDate.Equal(outDate) {
				res.HotelId = append(res.HotelId, hotelId)
			}
		}
	}

	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Unable to marshal response checkAvail %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, string(response))
}

type reservation struct {
	HotelId      string `bson:"hotelId"`
	CustomerName string `bson:"customerName"`
	InDate       string `bson:"inDate"`
	OutDate      string `bson:"outDate"`
	Number       int    `bson:"number"`
}

type number struct {
	HotelId      string `bson:"hotelId"`
	Number       int    `bson:"numberOfRoom"`
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/cgi-hotel-reservation-api/reservation/checkAvailability":
		CheckAvailability(w, r)
		return
	case "/cgi-hotel-reservation-api/reservation/makeReservation":
		MakeReservation(w, r)
		return
	default:
		http.Error(w, fmt.Sprintf("The requested resource was not found. %s", r.URL.Path), http.StatusNotFound)
		return
	}
}

func main() {
	var err error
	client, err = utils.MongoClient()
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.Background())
	libgo.Serve(http.HandlerFunc(requestHandler))
}