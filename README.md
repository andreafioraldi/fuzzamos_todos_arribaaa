# fuzzamos todos arribaaaaaaa

## QSYM on docker

Some build tricks + new arguments for run_qsym_afl.

### why?

AFL and docker are not good friends, so with this scripts I can run QSYM on docker (ubuntu 16.04) and AFL on the host (ubuntu 18.04).

### diff

`run_qsym_afl.py` now takes -Q as argument for Qemu mode and you can set `AFL_PATH` to the directory in which is afl-tmin (by default it is qsym/afl).

### build

~~~~{.sh}
cd afl
make
cd qemu_mode
./build_qemu_support.sh
cd ../../
./qsym/build_z3.sh
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
docker build -t fuzzamos ./
~~~~

### usage

Terminal 1:

~~~~{.sh}
/path/to/fuzzamos/prepare_sys.sh
cd ~/directory/with/fuzzer/target/
mkdir -p test_input
mkdir -p test_output
/path/to/fuzzamos/afl-fuzz -M afl-master -i ./test_input -o ./test_output -- ./fuzz_target
~~~~

Terminal 2:

~~~~{.sh}
cd ~/directory/with/fuzzer/target/
/path/to/fuzzamos/afl-fuzz -S afl-slave -i ./test_input -o ./test_output -- ./fuzz_target
~~~~

Terminal 3:

~~~~{.sh}
docker run --cap-add=SYS_PTRACE -v "~/directory/with/fuzzer/target/:/fuzz_dir/" -it fuzzamos /bin/bash
cd /fuzz_dir
run_qsym_afl -a afl-slave -o ./test_output -n qsym -- ./fuzz_target
~~~~

For Qemu mode add -Q to the arguments of afl-fuzz and run_qsym_afl.

## initial test cases generators

Some custom generators for initial test cases, sometimes using angr, sometimes not.

Pwntools required on python 2, angr on python 3.

### concrete generator

[generators/concrete_generator.py](generators/concrete_generator.py) is a script (you must have pwntools installed) that you can use to generate testcases recording your input.

Simply type `generators/concrete_generator.py -i ./test_input ./fuzz_target` and interact with a spwaned process of the target binary.
At the end of the execution all the input that you have sent to the process is recorded in an input testcase.

### angr generator

[generators/angr_generator.py](generators/angr_generator.py) can be used to generate initial inputs using symbolic execution.

Simply type `generators/angr_generator.py -i ./test_input ./fuzz_target` and hit control-c when you are satisfied of the number of paths in the simulation manager.

### angrgdb generator

[generators/angrgdb_generator.py](generators/angrgdb_generator.py) can be used to generate initial inputs using symbolic execution from a concrete process (see [angrgdb](https://github.com/andreafioraldi/angrgdb)).

Start GDB with the fuzz_target and set a breakpoint in an interesting point before the input.
Then type `source /path/to/fuzzamos/generators/angrgdb_generator.py` and insert the path to test_input.
Hit control-c when you are satisfied of the number of paths in the simulation manager.

### angrgdb hybrid generator

[generators/angrgdb_hybrid_generator.py](generators/angrgdb_hybrid_generator.py) is the fusion of concrete_generator.py and angrgdb_generator.py.

`generators/angrgdb_hybrid_generator.py -i ./test_input -b breakpoint ./fuzz_target` to record the concrete input until breakpoint and after explore the paths with angr.

## AFL fork by @abiondo

Moar QEMU speed is better.

