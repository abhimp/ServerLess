

.PHONY: all clean

EXES := $(patsubst %.go,%.fn,$(wildcard examples/*.go))
DEPENDS := src/libgo/libgo.go
GOPATH := $(shell pwd)

all: $(DEPENDS) $(EXES)

clean:
	@rm -f $(EXES) || true


%.fn: %.go $(DEPENDS)
	@echo "go $@"
	@GOPATH=$(GOPATH) go build -o $@ $<
