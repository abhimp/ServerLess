package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"bytes"
	"log"

	"hotelReservation/libgo"
	"hotelReservation/utils"
	geo "hotelReservation/services/geo/proto"
	rate "hotelReservation/services/rate/proto"
	pb "hotelReservation/services/search/proto"
	"github.com/golang/protobuf/proto"
)

const name = "srv-search"

// Nearby returns ids of nearby hotels ordered by ranking algo
func Nearby(w http.ResponseWriter, r *http.Request) {
	reqProto := &pb.NearbyRequest{}
	buf := new(bytes.Buffer)
    buf.ReadFrom(r.Body)
	var data []byte
	// data, _ = b64.StdEncoding.DecodeString(buf.String())
	data = buf.Bytes()
	err := proto.Unmarshal(data, reqProto)
	if err != nil {
		fmt.Printf("Unmarshal error %v\n", err)
		reqProto = &pb.NearbyRequest{
			Lat: 37.7834, 
			Lon: -122.4071,
			InDate: "2015-04-09",
			OutDate: "2015-04-10",
		}
	}
	log.Printf("Received searchReqProto: %s\n", reqProto)

	////////////////////// make geo nearby request and get proto
	geoReq, err := proto.Marshal(&geo.Request{
		Lat: reqProto.Lat,
		Lon: reqProto.Lon,
	})
	if err != nil {
		fmt.Printf("Geo marshal error %v\n", err)
	}
	geoResp, err := http.Post(utils.APIURL + "geo/nearby", "application/octet-stream", bytes.NewReader(geoReq))
	if err != nil {
		fmt.Printf("Geo Request failed %v\n", err)
    }
    defer geoResp.Body.Close()
	geoRespBytes, err := ioutil.ReadAll(geoResp.Body)
	if err != nil {
		fmt.Printf("Geo Request read bytes failed %v\n", err)
	}
	geoRespProto := &geo.Result{}
	err = proto.Unmarshal(geoRespBytes, geoRespProto)
	fmt.Printf("Geo Response: %s\n", geoRespProto)
	if err != nil {
		fmt.Printf("Unmarshal geo response %v\n", err)
	}
	//////////////////////////////////////////////////////////////////

	
	////////////////////// make rate getRates request and get proto
	ratesReq, err := proto.Marshal(&rate.Request{
		HotelIds: geoRespProto.HotelIds,
		InDate:   reqProto.InDate,
		OutDate:  reqProto.OutDate,
	})	
	if err != nil {
		fmt.Printf("Rate marshal error %v\n", err)
	}
	rateResp, err := http.Post(utils.APIURL + "rate/getRates", "application/octet-stream", bytes.NewReader(ratesReq))
	if err != nil {
		fmt.Printf("Rate Request failed %v\n", err)
    }
    defer rateResp.Body.Close()
	rateRespBytes, err := ioutil.ReadAll(rateResp.Body)
	if err != nil {
		fmt.Printf("Rate Request read bytes failed %v\n", err)
	}
	rateRespProto := &rate.Result{}
	err = proto.Unmarshal(rateRespBytes, rateRespProto)
	// fmt.Printf("Rate Response: %s\n", rateRespProto)
	if err != nil {
		fmt.Printf("Unmarshal rate response %v\n", err)
	}
	//////////////////////////////////////////////////////////////////

	// build the response
	res := new(pb.SearchResult)
	for _, ratePlan := range rateRespProto.RatePlans {
		// fmt.Printf("get RatePlan HotelId = %s, Code = %s\n", ratePlan.HotelId, ratePlan.Code)
		res.HotelIds = append(res.HotelIds, ratePlan.HotelId)
	}
	response, err := proto.Marshal(res)
	if err != nil {
		fmt.Printf("Search result marshal error %v\n", err)
	}
	log.Printf("Sending search response %s\n", res)
	w.Header().Set("Content-Type", "application/octet-stream")
	// fmt.Fprint(w, b64.StdEncoding.EncodeToString(response))
	fmt.Fprintf(w, string(response))
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	Nearby(w, r)
	return
}

func main() {
	libgo.Serve(http.HandlerFunc(requestHandler))
}