# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

if [ ! -d "hyperscan-4.7.0" ]; then

apt-get -y install ragel

wget https://github.com/intel/hyperscan/archive/v4.7.0.tar.gz
tar -xf v4.7.0.tar.gz

wget https://dl.bintray.com/boostorg/release/1.67.0/source/boost_1_67_0.tar.gz
tar -xf boost_1_67_0.tar.gz
cp -r boost_1_67_0/boost hyperscan-4.7.0/include

cd hyperscan-4.7.0
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=true ..
make
make install

fi
