# rev-chall

# Building

Required thingies:
* Clang 19
* libc++ 19
* CMake

## generating programs:

see [scripts/assemble.py](scripts/assemble.py) for details.

## dev

```commandline
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## production

on a linux machine, with clang 19 and libc++ 19:

```commandline
python3 scripts/assemble.py --ld-shuffler
```

each build gets tested whether it:
    * runs
    * accepts the expected input and prints `good`
    * rejects the unexpected random 16 bytes of input and prints `bad`

output is located in `out` folder
