all: init server build

init:
	git submodule update --recursive --remote

server: init
	nix-shell --run 'hugo server -D'

build: init
	nix-shell --run 'hugo -D'
