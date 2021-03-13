package libgo

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"errors"
)

var accepted = 0
func NcgimAccept(ncgiFd int) (int, error){
	// int ncgiFd = 4;
	msg, oob := make([]byte, 8192), make([]byte, 1024)
    recvFd := 0;
	// char retBuf[EIGHT_KB];
	if accepted >0 {
		nmsg := []byte("Hello")
		err := syscall.Sendmsg(ncgiFd, nmsg, nil, nil, 0);
		if err != nil {
			return -1, err
		}
		accepted = 0;
	}

	_, oobn, _, _, err := syscall.Recvmsg(ncgiFd, msg, oob, 0)
	if err != nil {
		return -21, err
	}

	cmsgs, err := syscall.ParseSocketControlMessage(oob[0:oobn])
	if err != nil {
		return -3, err
	} else if len(cmsgs) != 1 {
		return -4, errors.New("invalid number of cmsgs received")
	}

	fds, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil {
		return -5, err
	} else if len(fds) != 1 {
		return -6, errors.New("invalid number of fds received")
	}
	recvFd = fds[0]
	accepted = 1;
    return recvFd, nil;
}


//export go_callback_int
func go_callback_int() {
	fmt.Println("This is go")
}

type response struct {
	req        *http.Request
	header     http.Header
	bufw       *bufio.Writer
	headerSent bool
}

func (r *response) Flush() {
	r.bufw.Flush()
}

func (r *response) Header() http.Header {
	return r.header
}

func (r *response) Write(p []byte) (n int, err error) {
	if !r.headerSent {
		r.WriteHeader(http.StatusOK)
	}
	return r.bufw.Write(p)
}

func (r *response) WriteHeader(code int) {
	if r.headerSent {
		// Note: explicitly using Stderr, as Stdout is our HTTP output.
		fmt.Fprintf(os.Stderr, "CGI attempted to write header twice on request for %s", r.req.URL)
		return
	}
	r.headerSent = true
	fmt.Fprintf(r.bufw, "HTTP/1.0 %d %s\r\n", code, http.StatusText(code))
	// Set a default Content-Type
	if _, hasType := r.header["Content-Type"]; !hasType {
		r.header.Add("Content-Type", "text/html; charset=utf-8")
	}

	r.header.Write(r.bufw)
	r.bufw.WriteString("\r\n")
	r.bufw.Flush()
}

func serveRequest(f *os.File, handler http.Handler) {
	buf := bufio.NewReader(f)
	req, err := http.ReadRequest(buf)
	// req, err := Request()
	if err != nil {
		return
	}
	if handler == nil {
		handler = http.DefaultServeMux
	}
	rw := &response{
		req:    req,
		header: make(http.Header),
		bufw:   bufio.NewWriter(f),
	}
	handler.ServeHTTP(rw, req)
	rw.Write(nil) // make sure a response is sent
	if err = rw.bufw.Flush(); err != nil {
		return
	}
}

func Serve(handler http.Handler) {
	sharedFd := os.Getenv("NCGI_FD")
	if sharedFd == "" {
		return
	}
	nfd, err := strconv.Atoi(sharedFd)
	if err != nil {
		return
	}
	for {
		// fd := C.NcgimAccept(C.int(nfd))
		fd, err := NcgimAccept(nfd)
		// fmt.Println(err)
		if err != nil {
			fmt.Println("ERROR", err, fd)
			break
		}
		if fd < 0 {
			fmt.Println("PANIC ERROR")
			break;
		}
		f := os.NewFile(uintptr(fd), "socket")
		fmt.Println("Start Serving")
		serveRequest(f, handler)
		fmt.Println("Stop Served")
		f.Close()
	}
}

// func main() {
// 	Serve(nil)
// }
