target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-bn/bn.cpp
        crypto-bn/rand.cpp
        )

# Refer to single internal library only if it's not assembled into a big library.
option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
    find_package(PkgConfig REQUIRED)
    #set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED)

    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
            ${OPENSSL_INCLUDE_DIR}
            )

    target_link_libraries(${CMAKE_PROJECT_NAME}
            OpenSSL::Crypto
            -ldl
            )
endif()
