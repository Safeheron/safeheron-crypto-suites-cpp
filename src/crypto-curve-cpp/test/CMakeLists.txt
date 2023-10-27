find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        ${GTEST_INCLUDE_DIRS}
        "../src"
        /usr/local/include
        )

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
        link_directories(/usr/local/lib)
        link_libraries(CryptoCurve
                ${GTEST_BOTH_LIBRARIES}
                pthread )
else()
        link_libraries(${CMAKE_PROJECT_NAME}
                ${GTEST_BOTH_LIBRARIES}
                pthread )
endif()


add_executable(constructor-test constructor-test.cpp)
add_test(NAME constructor-test COMMAND constructor-test)

add_executable(comparison-test comparison-test.cpp)
add_test(NAME comparison-test COMMAND comparison-test)

add_executable(arithmetic-operation-test arithmetic-operation-test.cpp)
add_test(NAME arithmetic-operation-test COMMAND arithmetic-operation-test)

add_executable(encode-bytes-test encode-bytes-test.cpp)
add_test(NAME encode-bytes-test COMMAND encode-bytes-test)

add_executable(infinity-element-test infinity-element-test.cpp)
add_test(NAME infinity-element-test COMMAND infinity-element-test)

add_executable(serialization-base64-test serialization-base64-test.cpp)
add_test(NAME serialization-base64-test COMMAND serialization-base64-test)

add_executable(serialization-json-test serialization-json-test.cpp)
add_test(NAME serialization-json-test COMMAND serialization-json-test)

add_executable(ecdsa-test ecdsa-test.cpp)
add_test(NAME ecdsa-test COMMAND ecdsa-test)

add_executable(eddsa-test eddsa-test.cpp)
add_test(NAME eddsa-test COMMAND eddsa-test)

add_executable(stark-test stark-consistency-test.cpp)
add_test(NAME stark-test COMMAND stark-test)
