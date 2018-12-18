#!/bin/bash

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

./configure --x86
pushd build
make -j$(nproc)
popd

mv build build_32

./configure
pushd build
make -j$(nproc)
popd


