


OBJECTS := \
	nova_userland.o \
	nova_gateway.o \
	nova_httpd.o \
	nova_http_request_handler.o \
	nova_httpd_util.o \
	picohttpparser.o

NCGI_LIBC_OBJ := \
	picohttpparser.o \
	nova_httpd_util.o \
	libc/libncgim.o \
	libc/example_m.o

all: nova_gateway libc/libc_example

libc/libc_example: $(NCGI_LIBC_OBJ)
	@gcc -Wall $(DEBUG) -o $@ $^

nova_gateway: $(OBJECTS)
	@gcc -Wall $(DEBUG) -o $@ $^

clean: clean-libc
	@rm -rf nova_gateway $(OBJECTS)
	
clean-libc:
	@rm -rf libc/libc_example $(NCGI_LIBC_OBJ)

%.o: %.c
	@echo "cc $<"
	@gcc -Wall $(DEBUG) -c -o $@ $<

