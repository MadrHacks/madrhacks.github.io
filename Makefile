all: init server build

init:
	git submodule update --recursive --remote

server: init
	hugo server -D

build: init
	hugo -D
