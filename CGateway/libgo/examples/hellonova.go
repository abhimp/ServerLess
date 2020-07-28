package main

import (
	"fmt"
	"libgo"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func main() {
	libgo.Serve(http.HandlerFunc(handler))
	// fmt.Println("Inside lib")
}
