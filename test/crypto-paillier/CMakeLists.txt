find_package(GTest REQUIRED)
include_directories(${PROJECT_SOURCE_DIR}/src)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        GTest::gtest
        pthread
)

add_executable(paillier-test paillier-test.cpp CTimer.cpp)
add_test(NAME paillier.slow-paillier-test COMMAND paillier-test)


