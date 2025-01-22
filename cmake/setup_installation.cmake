include(CMakePackageConfigHelpers)

set(exported_targets_name "${PROJECT_NAME}Targets")
set(exported_targets_filename "${exported_targets_name}.cmake")
set(export_dirpath "lib/cmake/${PROJECT_NAME}")
set(config_basename "${PROJECT_NAME}Config")
set(config_filename "${config_basename}.cmake")
set(version_filename "${config_basename}Version.cmake")

write_basic_package_version_file(
        ${version_filename}
        COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
        "cmake/${config_filename}.in" "${config_filename}"
        INSTALL_DESTINATION "${export_dirpath}"
)

install(
        TARGETS ${PROJECT_NAME}
        EXPORT ${exported_targets_name}
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
)

install(
        EXPORT ${exported_targets_name}
        FILE ${exported_targets_filename}
        DESTINATION ${export_dirpath}
)

install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/${config_filename}"
            "${CMAKE_CURRENT_BINARY_DIR}/${version_filename}"
        DESTINATION
            ${export_dirpath}
)

## Install head files
install(
        DIRECTORY
            src/crypto-suites
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"

        # crypto-bip32-cpp
        PATTERN "ed25519_ex.h" EXCLUDE
        PATTERN "openssl_curve_wrapper.h" EXCLUDE
        PATTERN "util.h" EXCLUDE
        PATTERN "memzero.h" EXCLUDE
        PATTERN "bip32_ed25519.h" EXCLUDE
        PATTERN "bip32_ecdsa.h" EXCLUDE

        # crypto-curve-cpp
        PATTERN "ed25519_ex.h" EXCLUDE
        PATTERN "openssl_curve_wrapper.h" EXCLUDE

        # crypto-encode-cpp
        PATTERN "base64_imp.h" EXCLUDE
        PATTERN "hex_imp.h" EXCLUDE
        PATTERN "base58_imp.h" EXCLUDE

        # crypto-hash-cpp
        PATTERN "compat.h" EXCLUDE

        # crypto-ecies-cpp
        PATTERN "hmac.h" EXCLUDE
        PATTERN "kdf.h" EXCLUDE
        PATTERN "symm.h" EXCLUDE
)

## Install proto files
install(
        DIRECTORY
            proto/crypto-commitment/
            proto/crypto-curve/
            proto/crypto-paillier/
            proto/crypto-zkp/
        DESTINATION include/crypto-suites/proto
        FILES_MATCHING PATTERN "*.proto"
)
