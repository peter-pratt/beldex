# Copyright (c) 2018, The Beldex Project
# Copyright (c) 2016-2018, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Nothing to do here: serialization code is completely header-only.
set(serialization_sources
 base.h
   binary_archive.h
   binary_utils.h
   boost_std_variant.h
   boost_std_optional.h
   container.h
   crypto.h
   deque.h
   list.h
   pair.h
   serialization.h
   set.h
   string.h
   unordered_set.h
   variant.h
   vector.h)

set(serialization_private_headers
json_archive.h
json_utils.h)

add_library(serialization INTERFACE
  ${serialization_sources}
  ${serialization_private_headers})
SET_TARGET_PROPERTIES(serialization PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(serialization
        INTERFACE
    cryptonote_basic
    cryptonote_core
    cryptonote_protocol
    epee
    ${Boost_CHRONO_LIBRARY}
    ${Boost_REGEX_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${EXTRA_LIBRARIES})
add_dependencies(serialization
  version)
