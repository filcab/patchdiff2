# Usage: make IDASDK=/path/to/IDA/sdk
NAME = patchdiff2

# By default assume we're not compiling on Windows with Makefiles
SOURCES = $(filter-out win_fct.cpp,$(notdir $(wildcard *.cpp *.cc *.c)))

COMMON_FLAGS = -D__IDP__ -D__PLUGIN__ -D__MAC__ -D__EA64__ "-I$(IDAINC)" -arch i386
CFLAGS = $(COMMON_FLAGS)
CXXFLAGS = $(COMMON_FLAGS) -std=c++11
# It had --shared, --no-undefined and -Wl
LDFLAGS = "-L$(IDALIB)" -lida64 -arch i386 -dylib

IDASDK ?= $(HOME)/Software/ida/sdk+utilities/idasdk65
IDAINC  = $(IDASDK)/include
IDAAPP ?= /Applications/IDA Pro 6.5/idaq.app
IDALIB  = $(IDAAPP)/Contents/MacOS
IDAPLUGINS = $(IDALIB)/plugins

BaseNameSources := $(sort $(basename $(SOURCES)))
ObjectsO  := $(BaseNameSources:%=%.o)

.PHONY: all install uninstall clean

OUTPUT = $(NAME).pmc
all: $(OUTPUT)

$(OUTPUT): $(ObjectsO)
	$(LD) $(LDFLAGS) -o $@

install: $(OUTPUT)
	cp $(OUTPUT) "$(IDAPLUGINS)"

uninstall:
	rm "$(IDAPLUGINS)/$(OUTPUT)"

clean:
	rm -f $(ObjectsO) $(OUTPUT)

# Debug targets, to print the vars
debug_%:
	@echo $($*)

