#
#  Copyright (c) 2020, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#

add_executable(ot-cli-mtd
    cli_uart.cpp
    main.c
)

target_include_directories(ot-cli-mtd PRIVATE ${COMMON_INCLUDES})

target_compile_definitions(ot-cli-mtd
    PRIVATE
        OPENTHREAD_FTD=0
        OPENTHREAD_MTD=1
        OPENTHREAD_RADIO=0
)

if(NOT DEFINED OT_PLATFORM_LIB_MTD)
    set(OT_PLATFORM_LIB_MTD ${OT_PLATFORM_LIB})
endif()

target_link_libraries(ot-cli-mtd PRIVATE
    openthread-cli-mtd
    ${OT_PLATFORM_LIB_MTD}
    openthread-mtd
    ${OT_PLATFORM_LIB_MTD}
    openthread-cli-mtd
    ${OT_MBEDTLS}
    ot-config-mtd
    ot-config
)

if(OT_LINKER_MAP)
    if("${CMAKE_CXX_COMPILER_ID}" MATCHES "AppleClang")
        target_link_libraries(ot-cli-mtd PRIVATE -Wl,-map,ot-cli-mtd.map)
    else()
        target_link_libraries(ot-cli-mtd PRIVATE -Wl,-Map=ot-cli-mtd.map)
    endif()
endif()

install(TARGETS ot-cli-mtd
    DESTINATION bin)
