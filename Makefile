# Usage: make IDASDK=/path/to/IDA/sdk
NAME = patchdiff2

# By default assume we're not compiling on Windows with Makefiles
SOURCES = $(filter-out win_fct.cpp,$(notdir $(wildcard *.cpp *.cc *.c)))

# Use -isystem to not warn on the crappy IDA headers
COMMON_FLAGS = -D__PLUGIN__ -D__MAC__ -isystem "$(IDAINC)" -arch i386 $(EA64) -Werror -g
CFLAGS = $(COMMON_FLAGS)
CXXFLAGS = $(COMMON_FLAGS) -std=c++11
# It had --shared, --no-undefined and -Wl
LDFLAGS = "-L$(IDALIB)" -l$(LIBIDA) -arch i386 -dynamiclib
LD = $(CXX)

IDASDK ?= $(HOME)/Software/ida/sdk+utilities/idasdk65
IDAINC  = $(IDASDK)/include
IDAAPP ?= /Applications/IDA Pro 6.5/idaq.app
IDALIB  = $(IDAAPP)/Contents/MacOS
IDAPLUGINS = $(IDALIB)/plugins

OUTPUTS = $(NAME).pmc $(NAME).pmc64
all: $(OUTPUTS)

ifndef VERBOSE
  Verb := @
endif
Echo := @echo

BaseNameSources := $(sort $(basename $(SOURCES)))
Objects32  := $(BaseNameSources:%=%.32.o)
Objects64  := $(BaseNameSources:%=%.64.o)

.PHONY: all install uninstall clean

$(NAME).pmc: LIBIDA=ida
$(NAME).pmc: $(Objects32)
	$(Echo) Linking $@
	$(Verb) $(LD) $(LDFLAGS) -o $@ $+

$(NAME).pmc64: EA64=-D__EA64__
$(NAME).pmc64: LIBIDA=ida64
$(NAME).pmc64: $(Objects64)
	$(Echo) Linking $@
	$(Verb) $(LD) $(LDFLAGS) -o $@ $+

%.64.o: %.cpp
	$(Echo) Compiling $*.cpp for 64-bit build
	$(Verb) $(CXX) $(CXXFLAGS) -c -o $@ $^
%.32.o: %.cpp
	$(Echo) Compiling $*.cpp for 32-bit build
	$(Verb) $(CXX) $(CXXFLAGS) -c -o $@ $^

install: $(OUTPUTS)
	$(Echo) Installing $(OUTPUTS) to $(IDAPLUGINS)
	$(Verb) cp $(OUTPUTS) "$(IDAPLUGINS)"

uninstall:
	$(Echo) Removing "$(IDAPLUGINS)/$(OUTPUTS)"
	$(Verb) rm $(OUTPUTS:%="$(IDAPLUGINS)/%")

# Don't hide the clean command
clean:
	rm -f $(Objects32) $(Objects64) $(OUTPUTS)

# Debug targets, to print the vars
debug_%:
	@echo $($*)

