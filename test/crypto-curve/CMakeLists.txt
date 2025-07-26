include_directories(${PROJECT_SOURCE_DIR}/src)

link_libraries(
        ${CMAKE_PROJECT_NAME}
        GTest::gtest
        pthread
)

add_executable(constructor-test constructor-test.cpp)
add_test(NAME curve.constructor-test COMMAND constructor-test)

add_executable(comparison-test comparison-test.cpp)
add_test(NAME curve.comparison-test COMMAND comparison-test)

add_executable(arithmetic-operation-test arithmetic-operation-test.cpp)
add_test(NAME curve.arithmetic-operation-test COMMAND arithmetic-operation-test)

add_executable(encode-bytes-test encode-bytes-test.cpp)
add_test(NAME curve.encode-bytes-test COMMAND encode-bytes-test)

add_executable(infinity-element-test infinity-element-test.cpp)
add_test(NAME curve.infinity-element-test COMMAND infinity-element-test)

add_executable(serialization-base64-test serialization-base64-test.cpp)
add_test(NAME curve.serialization-base64-test COMMAND serialization-base64-test)

add_executable(serialization-json-test serialization-json-test.cpp)
add_test(NAME curve.serialization-json-test COMMAND serialization-json-test)

add_executable(ecdsa-test ecdsa-test.cpp)
add_test(NAME curve.ecdsa-test COMMAND ecdsa-test)

add_executable(eddsa-test eddsa-test.cpp)
add_test(NAME curve.eddsa-test COMMAND eddsa-test)

add_executable(schnorr-bip340-test schnorr-bip340-test.cpp)
add_test(NAME curve.schnorr-bip340-test COMMAND schnorr-bip340-test)

add_executable(schnorr-legacy-test schnorr-legacy-test.cpp)
add_test(NAME curve.schnorr-legacy-test COMMAND schnorr-legacy-test)

if (${ENABLE_STARK})
        add_executable(stark-test stark-consistency-test.cpp)
        add_test(NAME curve.stark-test COMMAND stark-test)
endif()
