

.PHONY: all clean

OBJECTS := $(patsubst %.c,%.o,$(wildcard examples/*.c))
EXES := $(patsubst %.o,%.fn,$(OBJECTS))

DEP_OBJECTS := libncgim.o

all: $(DEP_OBJECTS) $(OBJECTS) $(EXES)
	@echo $(OBJECTS) $(EXES)

clean:
	@echo "clean"
	@rm -f  $(DEP_OBJECTS) $(EXES) $(OBJECTS)  || true
	@rm -f examples/*.o examples/*.fn || true
	
%.o: %.c
	@echo "cc $@"
	@gcc -Wall $(DEBUG) -c -o $@ $<

%.fn: %.o
	@echo "ld $@"
	@gcc -Wall $(DEBUG) -o $@ $< $(NCGI_LIBC_OBJ)  $(DEP_OBJECTS)