package libgo

/*
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/uio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <assert.h>
extern void go_callback_int();

#define EIGHT_KB 8<<10

static inline int novaRecvFd(int unix_sock, int *recvfd, void *retBuf, size_t retBufCapa) {
#define MAXLINE EIGHT_KB //don't want loose a data due what ever the reason
#define CONTROL_LEN 1024
#define MIN(x, y) (x < y ? x : y)

    int             nr;
    char            buf[MAXLINE];
    char            contrl_buf[CONTROL_LEN];

    retBufCapa = retBuf ? retBufCapa : 0;
    if(!recvfd) return -1;

    struct iovec iov = {
                .iov_base = buf,
                .iov_len = MAXLINE
            };

    struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = contrl_buf,
                .msg_controllen = CONTROL_LEN
            };

    if ((nr = recvmsg(unix_sock, &msg, 0)) < 0) {
        perror("recvmsg");
        return -1;
    } else if (nr == 0) {
        fprintf(stderr, "connection closed by server\n");
        return 0;
    }

    if(retBuf || retBufCapa)
        memcpy(retBuf, iov.iov_base, MIN(iov.iov_len, retBufCapa));

    *recvfd = -1;
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(recvfd, CMSG_DATA(cmsg), sizeof(int));
            break;
        }
    }

    return MIN(iov.iov_len, retBufCapa);
#undef MAXLINE
#undef CONTROL_LEN
#undef MIN
}


static int accepted = 0; //needed only for first time
static inline int NcgimAccept(int ncgiFd) {
	// int ncgiFd = 4;
    int recvFd = 0;
	char retBuf[EIGHT_KB];
	if(accepted) {
		send(ncgiFd, "Hello", 5, 0);
		accepted = 0;
	}
    int ret = novaRecvFd(ncgiFd, &recvFd, retBuf, sizeof(retBuf));
    if (ret <= 0) {
        return -1;
    }
    // if(getpeername(recvFd, address, address_len) < 0) {
    //     close(recvFd);
    //     //TODO report back
    //     return -1;
	// }
	accepted = 1;
    return recvFd;
}

*/
import "C"
import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

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
		fd := C.NcgimAccept(C.int(nfd))
		if fd < 0 {
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
