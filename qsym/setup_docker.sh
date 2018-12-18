#!/bin/bash

# check ptrace_scope for PIN
if ! grep -qF "0" /proc/sys/kernel/yama/ptrace_scope; then
  echo "Please run 'echo 0|sudo tee /proc/sys/kernel/yama/ptrace_scope'"
  exit -1
fi

cd `dirname "$0"`

git submodule init
git submodule update

# install system deps
sudo apt-get update
sudo apt-get install -y libc6 libstdc++6 linux-libc-dev gcc-multilib \
  llvm-dev g++ g++-multilib python python-pip \
  lsb-release

# install z3
pushd ./third_party/z3

if [ -f build_32/libz3.so ]
then
    echo "Z3 already built"
else
    echo "building Z3..."
    pushd ../docker
    bash ./build_z3.sh
    popd
fi

pushd build

sudo mkdir -p /usr/bin
sudo mkdir -p /usr/include
sudo mkdir -p /usr/lib
sudo cp ../src/api/z3.h /usr/include/z3.h
sudo cp ../src/api/z3_v1.h /usr/include/z3_v1.h
sudo cp ../src/api/z3_macros.h /usr/include/z3_macros.h
sudo cp ../src/api/z3_api.h /usr/include/z3_api.h
sudo cp ../src/api/z3_ast_containers.h /usr/include/z3_ast_containers.h
sudo cp ../src/api/z3_algebraic.h /usr/include/z3_algebraic.h
sudo cp ../src/api/z3_polynomial.h /usr/include/z3_polynomial.h
sudo cp ../src/api/z3_rcf.h /usr/include/z3_rcf.h
sudo cp ../src/api/z3_fixedpoint.h /usr/include/z3_fixedpoint.h
sudo cp ../src/api/z3_optimization.h /usr/include/z3_optimization.h
sudo cp ../src/api/z3_interp.h /usr/include/z3_interp.h
sudo cp ../src/api/z3_fpa.h /usr/include/z3_fpa.h
sudo cp ../src/api/z3_spacer.h /usr/include/z3_spacer.h
sudo cp z3 /usr/bin/z3
sudo cp libz3.so /usr/lib/libz3.so
sudo cp ../src/api/c++/z3++.h /usr/include/z3++.h

popd

cd build_32
sudo cp libz3.so /usr/lib32/
popd

# build test directories
pushd tests
python build.py
popd

