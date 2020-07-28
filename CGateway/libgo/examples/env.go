package main

import (
	"fmt"
	"libgo"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	for _, kv := range os.Environ() {
		fmt.Fprintf(w, "%s\n", kv)
	}
}

func main() {
	libgo.Serve(http.HandlerFunc(handler))
}
