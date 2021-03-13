package main

import (
	"fmt"
	"bytes"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
	"hotelReservation/libgo"
	"github.com/hailocab/go-geoindex"
	pb "hotelReservation/services/geo/proto"
	"golang.org/x/net/context"
	"github.com/golang/protobuf/proto"
	"hotelReservation/utils"
)

const (
	name             = "srv-geo"
	maxSearchRadius  = 10
	maxSearchResults = 5
)

var index *geoindex.ClusteringIndex

// Nearby returns all hotels within a given distance.
func Nearby(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req := &pb.Request{}
	var data []byte
	buf := new(bytes.Buffer)
    buf.ReadFrom(r.Body)
	data = buf.Bytes()
	err := proto.Unmarshal(data, req)
	fmt.Printf("Geo: received request: %s\n", req)
	if err != nil {
		fmt.Printf("Unable to unmarshal Geo Nearby %v\n", err)
		req = &pb.Request{
			Lat: 37.7834, 
			Lon: -122.4071,	
		}
	}
	var (
		points = getNearbyPoints(ctx, float64(req.Lat), float64(req.Lon))
		res    = &pb.Result{}
	)

	for _, p := range points {
		res.HotelIds = append(res.HotelIds, p.Id())
	}
	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Unable to marshal response : %v", err)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	// fmt.Fprintf(w, b64.StdEncoding.EncodeToString(response))
	fmt.Fprintf(w, string(response))
}

func getNearbyPoints(ctx context.Context, lat, lon float64) []geoindex.Point {
	center := &geoindex.GeoPoint{
		Pid:  "",
		Plat: lat,
		Plon: lon,
	}

	return index.KNearest(
		center,
		maxSearchResults,
		geoindex.Km(maxSearchRadius), func(p geoindex.Point) bool {
			return true
		},
	)
}

func init() {
	newGeoIndex()
}

// newGeoIndex returns a geo index with points loaded
func newGeoIndex() {

	client, err := utils.MongoClient()
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.Background())
	c := client.Database("geo-db").Collection("geo")

	var points []*point

	cur, err := c.Find(context.Background(), bson.M{})
	if err != nil { 
		panic(err) 
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var result *point
		err := cur.Decode(&result)
		if err != nil { 
			panic(err) 
		}
		points = append(points, result)
	}
	if err := cur.Err(); err != nil {
		fmt.Println("Failed get geo data: ", err)
	}

	fmt.Printf("newGeoIndex len(points) = %d\n", len(points))

	// // add points to index
	index = geoindex.NewClusteringIndex()
	for _, point := range points {
		index.Add(point)
	}
}

type point struct {
	Pid  string  `bson:"hotelId"`
	Plat float64 `bson:"lat"`
	Plon float64 `bson:"lon"`
}

// Implement Point interface
func (p *point) Lat() float64 { return p.Plat }
func (p *point) Lon() float64 { return p.Plon }
func (p *point) Id() string   { return p.Pid }


func requestHandler(w http.ResponseWriter, r *http.Request) {
	Nearby(w, r)
}

func main() {
	libgo.Serve(http.HandlerFunc(requestHandler))
}