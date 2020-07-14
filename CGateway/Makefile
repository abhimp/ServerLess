


OBJECTS := \
	nova_userland.o \
	nova_gateway.o \
	nova_httpd.o \
	nova_http_request_handler.o \
	picohttpparser.o

all: $(OBJECTS)
	@gcc -Wall $(DEBUG) -o nova_gateway $(OBJECTS)

clean:
	@rm -rf nova_gateway $(OBJECTS)

%.o: %.c
	@echo "cc $<"
	@gcc -Wall $(DEBUG) -c -o $@ $<

