#!/bin/bash

set -eux

pushd libcidr-git
  make
  make install
popd

release_path=$(pwd)/secureproxy-release-git-repo
export LUA_PATH="${LUA_PATH:-};${release_path}/src/lua-libcidr-ffi/lib/?.lua"
export LUA_PATH="${LUA_PATH:-};${release_path}/src/tic/?.lua"

pushd ${release_path}/src/tic
  LD_LIBRARY_PATH=/usr/local/lib prove t/tic.t
popd
