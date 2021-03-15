package main

import (
	"go.mongodb.org/mongo-driver/bson"
	"fmt"
	"github.com/hailocab/go-geoindex"
	pb "hotelReservation/services/recommendation/proto"
	"golang.org/x/net/context"
	"hotelReservation/utils"
	"net/http"
	"bytes"
	"hotelReservation/libgo"
	"math"
	"github.com/golang/protobuf/proto"
)

const name = "srv-recommendation"

var hotels map[string]Hotel

func init() {
	hotels = loadRecommendations()
}
// GetRecommendations returns recommendations within a given requirement.
func GetRecommendations(w http.ResponseWriter, r *http.Request) {
	// ctx := r.Context()
	res := new(pb.Result)
	req := &pb.Request{}
	var data []byte
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	data = buf.Bytes()
	err := proto.Unmarshal(data, req)
	if err != nil {
		fmt.Println("Unable to unmarshal GetRecommendations", err)
	}
	require := req.Require
	if require == "dis" {
		p1 := &geoindex.GeoPoint{
			Pid:  "",
			Plat: req.Lat,
			Plon: req.Lon,
		}
		min := math.MaxFloat64
		for _, hotel := range hotels {
			tmp := float64(geoindex.Distance(p1, &geoindex.GeoPoint{
				Pid:  "",
				Plat: hotel.HLat,
				Plon: hotel.HLon,
			})) / 1000
			if tmp < min {
				min = tmp
			}
		}
		for _, hotel := range hotels {
			tmp := float64(geoindex.Distance(p1, &geoindex.GeoPoint{
				Pid:  "",
				Plat: hotel.HLat,
				Plon: hotel.HLon,
			})) / 1000
			if tmp == min {
				res.HotelIds = append(res.HotelIds, hotel.HId)
			}
		}
	} else if require == "rate" {
		max := 0.0
		for _, hotel := range hotels {
			if hotel.HRate > max {
				max = hotel.HRate
			}
		}
		for _, hotel := range hotels {
			if hotel.HRate == max {
				res.HotelIds = append(res.HotelIds, hotel.HId)
			}
		}
	} else if require == "price" {
		min := math.MaxFloat64
		for _, hotel := range hotels {
			if hotel.HPrice < min {
				min = hotel.HPrice
			}
		}
		for _, hotel := range hotels {
			if hotel.HPrice == min {
				res.HotelIds = append(res.HotelIds, hotel.HId)
			}
		}
	} else {
		fmt.Println("Wrong require parameter: ", require)
	}
	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Unable to marshal response GetRecommendations %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, string(response))
}

// loadRecommendations loads hotel recommendations from mongodb.
func loadRecommendations() map[string]Hotel {
	client, err := utils.MongoClient()
	if err != nil {
		fmt.Println("Failed to connect to mongoDB", err)
	}

	c := client.Database("recommendation-db").Collection("recommendation")
	defer client.Disconnect(context.Background())
	// unmarshal json profiles
	var hotels []Hotel

	cur, err := c.Find(context.Background(), bson.M{})
	if err != nil { 
		panic(err) 
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var result Hotel
		err := cur.Decode(&result)
		if err != nil { 
			panic(err) 
		}
		hotels = append(hotels, result)
	}
	if err := cur.Err(); err != nil {
		fmt.Println("Failed get recommendation data: ", err)
	}

	fmt.Printf("loadRecommendations: loaded %d hotels for recommendation\n", len(hotels))

	profiles := make(map[string]Hotel)
	for _, hotel := range hotels {
		profiles[hotel.HId] = hotel
	}

	return profiles
}

// Hotel struct for mongodb object
type Hotel struct {
	// ID     bson.ObjectId `bson:"_id"`
	HId    string        `bson:"hotelId"`
	HLat   float64       `bson:"lat"`
	HLon   float64       `bson:"lon"`
	HRate  float64       `bson:"rate"`
	HPrice float64       `bson:"price"`
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	GetRecommendations(w, r)
}

func main() {
	libgo.Serve(http.HandlerFunc(requestHandler))
}