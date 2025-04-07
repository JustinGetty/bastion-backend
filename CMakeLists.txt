cmake_minimum_required(VERSION 3.31)
project(bastion_auth)

set(CMAKE_CXX_STANDARD 20)

# Locate external dependencies.
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# Build a static library (bastion_data) from your source and implementation files.
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
        User/UserCreation.h
)


# Add include directories for the executable.
# Here we add both our project Headers and the uWebSockets include paths (as in your g++ command).
target_include_directories(bastion_auth PRIVATE
        ${PROJECT_SOURCE_DIR}/Headers
        ${PROJECT_SOURCE_DIR}/Validation
        /usr/local/include
        /infinite/Projects/NoPass/SourceFiles/uWebSockets/src
        /infinite/Projects/NoPass/SourceFiles/uWebSockets/uSockets/src
)

# Link the static library and the uSockets static library.
# The absolute path below should point to your uSockets.a file.
target_link_libraries(bastion_auth PRIVATE
        bastion_data
        "/infinite/Projects/NoPass/SourceFiles/uWebSockets/uSockets/uSockets.a"
)
