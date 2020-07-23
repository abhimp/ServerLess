


OBJECTS := \
	nova_userland.o \
	nova_gateway.o \
	nova_httpd.o \
	nova_http_request_handler.o \
	nova_http_ncgim_handler.o \
	nova_http_ncgis_handler.o \
	nova_httpd_util.o \
	picohttpparser.o

NCGI_LIBC_OBJ := \
	picohttpparser.o \
	nova_httpd_util.o

.PHONY: all clean libc clean-libc

all: nova_gateway libc

libc: $(NCGI_LIBC_OBJ)
	make -C libc NCGI_LIBC_OBJ="$(patsubst %,../%,$(NCGI_LIBC_OBJ))" DEBUG="$(DEBUG)" all

nova_gateway: $(OBJECTS)
	@echo "ld $@"
	@gcc -Wall $(DEBUG) -o $@ $^

clean: clean-libc
	@rm -rf nova_gateway $(OBJECTS)
	
clean-libc:
	@rm -rf $(NCGI_LIBC_OBJ)
	@make -C libc clean

%.o: %.c
	@echo "cc $@"
	@gcc -Wall $(DEBUG) -c -o $@ $<

