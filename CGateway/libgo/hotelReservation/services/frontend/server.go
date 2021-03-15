package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"fmt"
	"io/ioutil"
	"bytes"
	"hotelReservation/utils"
	"hotelReservation/libgo"
	"hotelReservation/services/profile/proto"
	"hotelReservation/services/search/proto"
	"hotelReservation/services/recommendation/proto"
	"hotelReservation/services/reservation/proto"
	"hotelReservation/services/user/proto"
	"github.com/golang/protobuf/proto"
)

func searchHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// ctx := r.Context()

	// in/out dates from query params
	inDate, outDate := r.URL.Query().Get("inDate"), r.URL.Query().Get("outDate")
	if inDate == "" || outDate == "" {
		http.Error(w, "Please specify inDate/outDate params", http.StatusBadRequest)
		return
	}

	// lan/lon from query params
	sLat, sLon := r.URL.Query().Get("lat"), r.URL.Query().Get("lon")
	if sLat == "" || sLon == "" {
		http.Error(w, "Please specify location params", http.StatusBadRequest)
		return
	}


	Lat, _ := strconv.ParseFloat(sLat, 32)
	lat := float32(Lat)
	Lon, _ := strconv.ParseFloat(sLon, 32)
	lon := float32(Lon)


	// search for best hotels
	searchReq, err := proto.Marshal(&search.NearbyRequest{
		Lat:     lat,
		Lon:     lon,
		InDate:  inDate,
		OutDate: outDate,
	})
	// reqBase64 := b64.StdEncoding.EncodeToString(searchReq)
	if err!= nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("Sending search request: %s\n", inDate)
	////////////////////// make search nearby request and get proto
	httpClient := &http.Client{}
	httpReq, _ := http.NewRequest(http.MethodPost, utils.APIURL + "search/nearby", bytes.NewReader(searchReq)) 
	httpReq.Header.Add("Content-Type", "application/octet-stream")
	httpReq.Header.Add("Content-Length", strconv.Itoa(len(searchReq)))
	searchResp, err := httpClient.Do(httpReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    defer searchResp.Body.Close()
	searchRespBytes, err := ioutil.ReadAll(searchResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	searchRespProto := &search.SearchResult{}
	err = proto.Unmarshal(searchRespBytes, searchRespProto)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//////////////////////////////////////////////////////////////////

	locale := r.URL.Query().Get("locale")
	if locale == "" {
		locale = "en"
	}

	reservationReq, err := proto.Marshal(&reservation.Request{
		CustomerName: "Foo",
		HotelId:      searchRespProto.HotelIds,
		InDate:       inDate,
		OutDate:      outDate,
		RoomNumber:   1,
	})
	if err!= nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	/////////////////////////////////// make reservation request and get proto
	reservationResp, err := http.Post(utils.APIURL + "reservation/checkAvailability", "application/octet-stream", bytes.NewReader(reservationReq))
    if err!= nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    defer reservationResp.Body.Close()
	
	reservationRespBytes, err := ioutil.ReadAll(reservationResp.Body)
	if err!= nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reservationRespProto := &reservation.Result{}
	proto.Unmarshal(reservationRespBytes, reservationRespProto)

	// fmt.Printf("Check Avail Result: %s\n", reservationRespProto)
	/////////////////////////////////////////////////////////////////////

	profileReq, err := proto.Marshal(&profile.Request{
		HotelIds: reservationRespProto.HotelId,
		Locale:   locale,
	})
	if err!= nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//////////////////////////////// make profile request and get proto
	profileResp, err := http.Post(utils.APIURL + "profile/getProfiles", "application/octet-stream", bytes.NewReader(profileReq))
    if err!= nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    defer profileResp.Body.Close()
	profileRespBytes, err := ioutil.ReadAll(profileResp.Body)
	if err!= nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profileRespProto := &profile.Result{}
	proto.Unmarshal(profileRespBytes, profileRespProto)
	////////////////////////////////////////////////////////////////////////

	json.NewEncoder(w).Encode(geoJSONResponse(profileRespProto.Hotels))
}

func recommendHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	sLat, sLon := r.URL.Query().Get("lat"), r.URL.Query().Get("lon")
	if sLat == "" || sLon == "" {
		http.Error(w, "Please specify location params", http.StatusBadRequest)
		return
	}
	Lat, _ := strconv.ParseFloat(sLat, 64)
	lat := float64(Lat)
	Lon, _ := strconv.ParseFloat(sLon, 64)
	lon := float64(Lon)

	require := r.URL.Query().Get("require")
	if require != "dis" && require != "rate" && require != "price" {
		http.Error(w, "Please specify require params", http.StatusBadRequest)
		return
	}

	locale := r.URL.Query().Get("locale")
	if locale == "" {
		locale = "en"
	}
	
	recommendationReq, err := proto.Marshal(&recommendation.Request{
		Require: require,
		Lat:     float64(lat),
		Lon:     float64(lon),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	//////////////////////////////// make recommendation request and get proto
	recommendationResp, err := http.Post(utils.APIURL + "recommendation/getRecommendations", "application/octet-stream", bytes.NewReader(recommendationReq))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
    defer recommendationResp.Body.Close()
	recommendationRespBytes, err := ioutil.ReadAll(recommendationResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	recommendationRespProto := &recommendation.Result{}
	proto.Unmarshal(recommendationRespBytes, recommendationRespProto)
	////////////////////////////////////////////////////////////////////////

	profileReq, err := proto.Marshal(&profile.Request{
		HotelIds: recommendationRespProto.HotelIds,
		Locale:   locale,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//////////////////////////////// make profile request and get proto
	profileResp, err := http.Post(utils.APIURL + "profile/getProfiles", "application/octet-stream", bytes.NewReader(profileReq))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
    defer profileResp.Body.Close()
	profileRespBytes, err := ioutil.ReadAll(profileResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	profileRespProto := &profile.Result{}
	proto.Unmarshal(profileRespBytes, profileRespProto)
	////////////////////////////////////////////////////////////////////////

	json.NewEncoder(w).Encode(geoJSONResponse(profileRespProto.Hotels))
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	username, password := r.URL.Query().Get("username"), r.URL.Query().Get("password")
	if username == "" || password == "" {
		http.Error(w, "Please specify username and password", http.StatusBadRequest)
		return
	}
	userReq, err := proto.Marshal(&user.Request{
		Username: username,
		Password: password,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//////////////////////////////// make user request and get proto
	userResp, err := http.Post(utils.APIURL + "user/checkUser", "application/octet-stream", bytes.NewReader(userReq))
    if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    defer userResp.Body.Close()
	userRespBytes, err := ioutil.ReadAll(userResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userRespProto := &user.Result{}
	proto.Unmarshal(userRespBytes, userRespProto)
	////////////////////////////////////////////////////////////////////////


	str := "Login successfully!"
	if userRespProto.Correct == false {
		str = "Failed. Please check your username and password. "
	}

	res := map[string]interface{}{
		"message": str,
	}
	json.NewEncoder(w).Encode(res)
}

func reservationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// ctx := r.Context()

	inDate, outDate := r.URL.Query().Get("inDate"), r.URL.Query().Get("outDate")
	if inDate == "" || outDate == "" {
		http.Error(w, "Please specify inDate/outDate params", http.StatusBadRequest)
		return
	}

	if !checkDataFormat(inDate) || !checkDataFormat(outDate) {
		http.Error(w, "Please check inDate/outDate format (YYYY-MM-DD)", http.StatusBadRequest)
		return
	}

	hotelId := r.URL.Query().Get("hotelId")
	if hotelId == "" {
		http.Error(w, "Please specify hotelId params", http.StatusBadRequest)
		return
	}

	customerName := r.URL.Query().Get("customerName")
	if customerName == "" {
		http.Error(w, "Please specify customerName params", http.StatusBadRequest)
		return
	}

	username, password := r.URL.Query().Get("username"), r.URL.Query().Get("password")
	if username == "" || password == "" {
		http.Error(w, "Please specify username and password", http.StatusBadRequest)
		return
	}

	numberOfRoom := 0
	num := r.URL.Query().Get("number")
	if num != "" {
		numberOfRoom, _ = strconv.Atoi(num)
	}
	userReq, err := proto.Marshal(&user.Request{
		Username: username,
		Password: password,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//////////////////////////////// make user request and get proto
	userResp, err := http.Post(utils.APIURL + "user/checkUser", "application/octet-stream", bytes.NewReader(userReq))
    if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    defer userResp.Body.Close()
	userRespBytes, err := ioutil.ReadAll(userResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userRespProto := &user.Result{}
	proto.Unmarshal(userRespBytes, userRespProto)
	////////////////////////////////////////////////////////////////////////

	str := "Reserve successfully!"
	if userRespProto.Correct == false {
		str = "Failed. Please check your username and password. "
	}

	resReq, err := proto.Marshal(&reservation.Request{
		CustomerName: customerName,
		HotelId:      []string{hotelId},
		InDate:       inDate,
		OutDate:      outDate,
		RoomNumber:   int32(numberOfRoom),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//////////////////////////////// make user request and get proto
	resResp, err := http.Post(utils.APIURL + "reservation/makeReservation", "application/octet-stream", bytes.NewReader(resReq))
    if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    defer resResp.Body.Close()
	resRespBytes, err := ioutil.ReadAll(resResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resRespProto := &reservation.Result{}
	proto.Unmarshal(resRespBytes, resRespProto)
	////////////////////////////////////////////////////////////////////////

	if len(resRespProto.HotelId) == 0 {
		str = "Failed. Already reserved. "
	}

	res := map[string]interface{}{
		"message": str,
	}
	json.NewEncoder(w).Encode(res)
}

// return a geoJSON response that allows google map to plot points directly on map
// https://developers.google.com/maps/documentation/javascript/datalayer#sample_geojson
func geoJSONResponse(hs []*profile.Hotel) map[string]interface{} {
	fs := []interface{}{}

	for _, h := range hs {
		fs = append(fs, map[string]interface{}{
			"type": "Feature",
			"id":   h.Id,
			"properties": map[string]string{
				"name":         h.Name,
				"phone_number": h.PhoneNumber,
			},
			"geometry": map[string]interface{}{
				"type": "Point",
				"coordinates": []float32{
					h.Address.Lon,
					h.Address.Lat,
				},
			},
		})
	}

	return map[string]interface{}{
		"type":     "FeatureCollection",
		"features": fs,
	}
}

func checkDataFormat(date string) bool {
	if len(date) != 10 {
		return false
	}
	for i := 0; i < 10; i++ {
		if i == 4 || i == 7 {
			if date[i] != '-' {
				return false
			}
		} else {
			if date[i] < '0' || date[i] > '9' {
				return false
			}
		}
	}
	return true
}

func requestHandler(w http.ResponseWriter, r *http.Request) {

	// fmt.Printf("Resource %s\n", r.Resource)
	// fmt.Printf("Path %s\n", r.URL.Path)
	
	switch r.URL.Path {
	case "/cgi-hotel-reservation/frontend/index.html", "/cgi-hotel-reservation/frontend/":
		dat, err := ioutil.ReadFile("libgo/hotelReservation/services/frontend/static/index.html")
		// pwd, err := os.Getwd()	
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, string(dat))
		// w.Header().Set("Content-Type", "text/plain")
		// fmt.Fprint(w, pwd)
		return
	case "/cgi-hotel-reservation/frontend/hotels":
		searchHandler(w, r)
		return
	case "/cgi-hotel-reservation/frontend/recommendations":
		recommendHandler(w, r)
		return
	case "/cgi-hotel-reservation/frontend/reservation":
		reservationHandler(w, r)
		return
	case "/cgi-hotel-reservation/frontend/user":
		userHandler(w, r)
		return
	default:
		http.Error(w, fmt.Sprintf("The requested resource was not found. %s", r.URL.Path), http.StatusNotFound)
	}
}

func main() {
	libgo.Serve(http.HandlerFunc(requestHandler))
}
