#!/bin/bash

set -eux

apt update
export PERL_MM_USE_DEFAULT=1
apt install -y build-essential libcidr-dev && cpan -T -i Test::Nginx

release_path=$(pwd)/secureproxy-release-git-repo
export LUA_PATH="${LUA_PATH:-};${release_path}/src/lua-libcidr-ffi/lib/?.lua"
export LUA_PATH="${LUA_PATH:-};${release_path}/src/tic/?.lua"

pushd ${release_path}/src/tic
  LD_LIBRARY_PATH=/usr/local/lib prove t/tic.t
popd
