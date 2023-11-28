find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories("../src")

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    link_libraries(CryptoPaillier
            ${GTEST_BOTH_LIBRARIES}
            /usr/local/lib
            pthread )
else()
    link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
endif()

add_executable(paillier-test paillier-test.cpp CTimer.cpp)
add_test(NAME paillier.slow-paillier-test COMMAND paillier-test)


