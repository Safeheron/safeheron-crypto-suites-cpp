find_package(GTest REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        GTest::gtest
        pthread
)

add_executable(aes-gcm-test aes-gcm-test.cpp)
add_test(NAME aes-gcm-test COMMAND aes-gcm-test)

add_executable(aes-gcm-identical-test aes-gcm-identical-test.cpp)
add_test(NAME aes-gcm-identical-test COMMAND aes-gcm-identical-test)