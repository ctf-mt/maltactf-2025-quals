
all: compile inject_relocs

inject_relocs:
	python3 inject_relocations.py

compile:
	g++ main.cpp vm.cpp -o tmp -std=c++23 -no-pie
	strip tmp
