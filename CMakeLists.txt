cmake_minimum_required(VERSION 3.31)
project(bastion_auth)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# Try to locate Crypto++ include directory.
find_path(CRYPTOPP_INCLUDE_DIR
        NAMES cryptopp/cryptlib.h
        PATHS /usr/include /usr/local/include
)

# Locate the Crypto++ library in /usr/lib64 (or the standard locations).
find_library(CRYPTOPP_LIBRARY
        NAMES cryptopp
        PATHS /usr/lib64 /usr/lib /usr/local/lib
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Could not find Crypto++ on your system.")
endif()

# Create an imported target for Crypto++.
add_library(CryptoPP::CryptoPP UNKNOWN IMPORTED)
set_target_properties(CryptoPP::CryptoPP PROPERTIES
        IMPORTED_LOCATION "${CRYPTOPP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${CRYPTOPP_INCLUDE_DIR}"
)


#refactor
add_library(bastion_data STATIC
        Implementations/conn_data_storage.cpp
        Implementations/conn_thread_pool.cpp
        Implementations/connection_data_queue.cpp
        Implementations/server_thread_work.cpp
        Cryptography/cryptography.cpp
        Database/database_comm.cpp
        Database/database_manager.cpp
        Implementations/conn_data_storage.cpp

)

# Specify include directories for the bastion_data library.
target_include_directories(bastion_data PUBLIC
        ${PROJECT_SOURCE_DIR}/Headers
        ${PROJECT_SOURCE_DIR}/Validation
        /usr/local/include
)

# Link external libraries with bastion_data.
target_link_libraries(bastion_data PUBLIC
        OpenSSL::Crypto
        ZLIB::ZLIB
        sqlite3
        CryptoPP::CryptoPP
)

add_executable(bastion_auth main.cpp
        Implementations/parse_message_json.cpp
        Headers/parse_message_json.h
        async_http/mobile_api_handler.cpp
        Headers/mobile_api_handler.h
        Validation/validation_work.h
        Headers/validation_work.h
        Headers/circular_queue.h
        Headers/thread_pool.h
        Implementations/global_thread_pool_tmp.cpp
        Headers/global_thread_pool_tmp.h
        Headers/idek_what_this_shits_for_anymore.h
        Implementations/validate_username.cpp
        Headers/validate_username.h
        User/UserCreation.cpp
        Headers/UserCreation.h
        Cryptography/SeedCipher.cpp
        Headers/SeedCipher.h
)


# Add include directories for the executable.
target_include_directories(bastion_auth PRIVATE
        ${PROJECT_SOURCE_DIR}/Headers
        ${PROJECT_SOURCE_DIR}/Validation
        /usr/local/include
        /usr/lib64
        /infinite/Projects/NoPass/SourceFiles/uWebSockets/src
        /infinite/Projects/NoPass/SourceFiles/uWebSockets/uSockets/src
)

# Link the static library and the uSockets static library.
target_link_libraries(bastion_auth PRIVATE
        bastion_data
        "/infinite/Projects/NoPass/SourceFiles/uWebSockets/uSockets/uSockets.a"
)
