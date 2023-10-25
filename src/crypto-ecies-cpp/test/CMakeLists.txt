find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        ${GTEST_INCLUDE_DIRS}
        ../src
        /usr/local/include  # This directory is included default on linux but not on Mac os
)

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    find_package(CryptoBN REQUIRED)
    find_package(CryptoHash REQUIRED)
    find_package(CryptoEncode REQUIRED)
    find_package(CryptoCurve REQUIRED)

    include_directories(
            ${CryptoBN_INCLUDE_DIRS}
            ${CryptoHash_INCLUDE_DIRS}
            ${CryptoEncode_INCLUDE_DIRS}
            ${CryptoCurve_INCLUDE_DIRS}
    )

    # This directory is included default on linux but not on Mac os
    link_directories(/usr/local/lib)
    link_libraries(CryptoECIES
            ${PROTOBUF_LIBRARIES}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
else()
    link_libraries(${CMAKE_PROJECT_NAME}
            ${PROTOBUF_LIBRARIES}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
endif()


add_executable(auth-enc-test auth-enc-test.cpp)
add_test(NAME auth-enc-test COMMAND auth-enc-test)

add_executable(ecies-test ecies-test.cpp)
add_test(NAME ecies-test COMMAND ecies-test)

add_executable(curve-param-test curve-param-test.cpp)
add_test(NAME curve-param-test COMMAND curve-param-test)
