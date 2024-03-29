find_package(GTest REQUIRED)

include_directories("../../src/crypto-suites")
link_libraries(${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread )

add_executable(bn-arithmetic-operation-test bn-arithmetic-operation-test.cpp)
add_test(NAME bn.bn-arithmetic-operation-test COMMAND bn-arithmetic-operation-test)

add_executable(bn-assignment-test bn-assignment-test.cpp)
add_test(NAME bn.bn-assignment-test COMMAND bn-assignment-test)

add_executable(bn-auxiliary-test bn-auxiliary-test.cpp)
add_test(NAME bn.bn-auxiliary-test COMMAND bn-auxiliary-test)

add_executable(bn-bit-operation-test bn-bit-operation-test.cpp)
add_test(NAME bn.bn-bit-operation-test COMMAND bn-bit-operation-test)

add_executable(bn-bytes-conversion-test bn-bytes-conversion-test.cpp)
add_test(NAME bn.bn-bytes-conversion-test COMMAND bn-bytes-conversion-test)

add_executable(bn-comparison-test bn-comparison-test.cpp)
add_test(NAME bn.bn-comparison-test COMMAND bn-comparison-test)

add_executable(bn-constructor-test bn-constructor-test.cpp)
add_test(NAME bn.bn-constructor-test COMMAND bn-constructor-test)

add_executable(bn-number-theory-func-test bn-number-theory-func-test.cpp)
add_test(NAME bn.bn-number-theory-func-test COMMAND bn-number-theory-func-test)

add_executable(bn-string-conversion-test bn-string-conversion-test.cpp)
add_test(NAME bn.bn-string-conversion-test COMMAND bn-string-conversion-test)

add_executable(rnd-test rnd-test.cpp)
add_test(NAME bn.rnd-test COMMAND rnd-test)

add_executable(bn-jacobi-test bn-jacobi-test.cpp)
add_test(NAME bn.bn-jacobi-test COMMAND bn-jacobi-test)

add_executable(bn-sqrt-test bn-sqrt-test.cpp)
add_test(NAME bn.bn-sqrt-test COMMAND bn-sqrt-test)


