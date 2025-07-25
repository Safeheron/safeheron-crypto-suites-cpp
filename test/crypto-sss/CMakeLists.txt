find_package(GTest REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        GTest::gtest
        pthread
)

add_executable(sss-test sss-test.cpp)
add_test(NAME sss.sss-test COMMAND sss-test)


