find_package(GTest REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        GTest::gtest
        pthread
)

add_executable(auth-enc-test auth-enc-test.cpp)
add_test(NAME ecies.auth-enc-test COMMAND auth-enc-test)

add_executable(ecies-test ecies-test.cpp)
add_test(NAME ecies.ecies-test COMMAND ecies-test)

add_executable(curve-param-test curve-param-test.cpp)
add_test(NAME ecies.curve-param-test COMMAND curve-param-test)
