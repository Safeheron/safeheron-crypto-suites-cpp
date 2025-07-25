find_package(GTest REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        GTest::gtest
        pthread
)

add_executable(base64-test base64-test.cpp)
add_test(NAME encode.base64-test COMMAND base64-test)

add_executable(hex-test hex-test.cpp)
add_test(NAME encode.hex-test COMMAND hex-test)

add_executable(base58-test base58-test.cpp)
add_test(NAME encode.base58-test COMMAND base58-test)
