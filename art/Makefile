root := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# check if goat and svgcheck are installed
goat ?= $(shell command -v goat)
ifeq ($(strip $(goat)),)
$(error goat (ascii art to svg converter) not found. To install goat: 'go get github.com/blampe/goat')
endif

svgcheck ?= $(shell command -v svgcheck)
ifeq ($(strip $(svgcheck)),)
$(error svgcheck not found. To install svgcheck: 'pip install svgcheck')
endif

# ASCII -> SVG art
art_dir := $(root)
art_src := $(wildcard $(art_dir)*.ascii-art)
art_svg := $(art_src:.ascii-art=.svg)

all: $(art_svg)

%.svg: %.ascii-art ; @$(goat) $< | $(svgcheck) -r -o $@ 2>/dev/null || true

clean: ; $(RM) $(art_svg)
