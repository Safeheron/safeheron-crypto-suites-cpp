find_package(GTest REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        GTest::gtest
        pthread
)

add_executable(commitment-test commitment-test.cpp)
add_test(NAME commitment.commitment-test COMMAND commitment-test)


