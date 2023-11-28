find_package(GTest REQUIRED)

include_directories("../src"
        ${GTEST_INCLUDE_DIRS})

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    link_libraries(CryptoHash
            ${GTEST_BOTH_LIBRARIES}
            pthread )
else()
    link_libraries(${CMAKE_PROJECT_NAME}
            ${GTEST_BOTH_LIBRARIES}
            pthread )
endif()

add_executable(hash-test hash-test.cpp)
add_test(NAME hash.hash-test COMMAND hash-test)

add_executable(safe-hash256-test safe-hash256-test.cpp)
add_test(NAME hash.safe-hash256-test COMMAND safe-hash256-test)

add_executable(safe-hash512-test safe-hash512-test.cpp)
add_test(NAME hash.safe-hash512-test COMMAND safe-hash512-test)