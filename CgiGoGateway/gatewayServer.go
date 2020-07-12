package main

import (
	// "fmt"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	// "os/exec"
	"path/filepath"
)

//#include "nova_userland.h"
import "C"

func pagewriter(w http.ResponseWriter, r *http.Request) {

	var cgih cgi.Handler

	path := r.URL.Path
	path = filepath.FromSlash(path)
	root, _ := filepath.Abs(".")
	path = filepath.Join(root, path)

	finf, err := os.Stat(path)
	if err != nil {
		http.Error(w, "File Not Found", 404)
		return
	}

	fmod := finf.Mode()

	if !fmod.IsRegular() {
		http.Error(w, "Requires regular file", 403)
		return
	}

	if fmod.Perm()&0100 == 0 {
		http.Error(w, "Requires executable file", 403)
		return
	}

	cgih.Path = path
	cgih.Dir = root
	cgih.ServeHTTP(w, r)
}

func initKernel() {
	// fmt.Println("initializing kernel")
	_ = C.nova_disable()
	_ = C.nova_setpid(C.int(os.Getpid()))
	_ = C.nova_enable()
}

func main() {
	initKernel()
	// fmt.Println(os.Getpid())
	http.HandleFunc("/", pagewriter)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
