#!/usr/bin/env python3.7

import socket, array
import socketserver

import os
# from builtins import int
import time

EIGHT_KB = 8192

class NCGIMHTTPServer(socketserver.BaseServer):

    def __init__(self, RequestHandlerClass):
        """Constructor.  May be extended, do not override."""
        NCGIFD = 4
        if "NCGI_FD" in os.environ:
            try:
                NCGIFD = int(os.environ["NCGI_FD"])
            except Exception:
                pass

        socketserver.BaseServer.__init__(self, "SERVER_FD_" + str(NCGIFD), RequestHandlerClass)
        self.socket = socket.socket(fileno=NCGIFD)

    def server_bind(self):
        """
        Useless in NCGI
        """
        pass

    def server_activate(self):
        """
        Useless in NCGI
        """
        pass

    def recvFds(self, msglen=EIGHT_KB, maxfds=1):
        fds = array.array("i")   # Array of ints
        msg, ancdata, flags, addr = self.socket.recvmsg(msglen, socket.CMSG_LEN(maxfds * fds.itemsize))
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                # Append data, ignoring any truncated integers at the end.
                fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        return msg, list(fds)

    def get_request(self):
        """Get the request and client address from the socket.
        May be overridden.
        """
        msg, fds = self.recvFds()
        sock = socket.socket(fileno=fds[0])
        return sock, sock.getpeername()

    def shutdown_request(self, request):
        """Called to shutdown and close an individual request."""
#         print("shutdown_request", request)
        try:
            #explicitly shutdown.  socket.close() merely releases
            #the socket and waits for GC to perform the actual close.
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass #some platforms may raise ENOTCONN here
        self.close_request(request)

    def close_request(self, request):
        """Called to clean up an individual request."""
        request.close()
#         time.sleep(5);
        self.socket.send(b"data");
#         print("Pid:  ->", os.getpid())
        
    def server_close(self):
        """Called to clean-up the server.
        May be overridden.
        """
        self.socket.close()

    def fileno(self):
        """Return socket file number.
        Interface required by selector.
        """
        return self.socket.fileno()


if __name__ == "__main__":
    from http.server import SimpleHTTPRequestHandler
    server = NCGIHTTPServer(SimpleHTTPRequestHandler)
    server.serve_forever()
    