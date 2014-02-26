# Usage: make IDASDK=/path/to/IDA/sdk
NAME = patchdiff2

SOURCES = $(notdir $(wildcard *.cpp *.cc *.c))

COMMON_FLAGS = -D__IDP__ -D__PLUGIN__ -D__MAC__ -D__EA64__ -I$(IDAINC)
CFLAGS = $(COMMON_FLAGS)
CXXFLAGS = $(COMMON_FLAGS) -std=c++11
LDFLAGS = --shared -L$(IDALIB) -lida --no-undefined -Wl

IDASDK ?= $(HOME)/Software/ida/sdk+utilities/idasdk65
IDAINC  = $(IDASDK)/include

BaseNameSources := $(sort $(basename $(SOURCES)))
ObjectsO  := $(BaseNameSources:%=%.o)

.PHONY: all clean

all: $(NAME).pmc
$(NAME).pmc: $(ObjectsO)

clean:
	rm -f $(ObjectsO) $(OUTPUT)

# Debug targets, to print the vars
debug_%:
	@echo $($*)

