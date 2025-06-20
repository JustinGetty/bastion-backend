cmake_minimum_required(VERSION 3.31)
project(bastion_auth)

set(CMAKE_CXX_STANDARD 20)

find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL    REQUIRED)

list(APPEND CMAKE_PREFIX_PATH "/usr/local/lib64/cmake/AWSSDK")
find_package(AWSSDK REQUIRED COMPONENTS sesv2 lambda)

find_path(CRYPTOPP_INCLUDE_DIR
        NAMES cryptopp/cryptlib.h
        PATHS /usr/include /usr/local/include
)

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

        DatabaseV2/database_comm_v2.cpp
        DatabaseV2/DBService.cpp
        DatabaseV2/GenericStuff/Scheduler.cpp
        DatabaseV2/UserServices/UserDAO.cpp
        DatabaseV2/MobileDeviceServices/DeviceDAO.cpp
        DatabaseV2/EmailServices/EmailDAO.cpp
        DatabaseV2/SiteServices/SiteDAO.cpp

        AWS_SES_LAMBDA/AWS_manager.cpp
        AWS_SES_LAMBDA/EmailSys.cpp

        async_http/apiHandlerBoostPool.cpp
        async_http/handler_functionality.cpp

        SiteData/site_data_cache.cpp

)

# Specify include directories for the bastion_data library.
target_include_directories(bastion_data PUBLIC
        ${PROJECT_SOURCE_DIR}/Headers
        ${PROJECT_SOURCE_DIR}/Validation
        /usr/local/include
        ${PROJECT_SOURCE_DIR}/DatabaseV2
)

# Link external libraries with bastion_data.
target_link_libraries(bastion_data PUBLIC
        OpenSSL::Crypto
        ZLIB::ZLIB
        sqlite3
        CryptoPP::CryptoPP
        ${CURL_LIBRARIES}
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
        User/UserRecovery.cpp
        Headers/UserRecovery.h
        User/EmailRecovery.cpp
        Headers/EmailRecovery.h
        MainEventLoop/main_helpers.cpp
        Headers/main_helpers.h
        APNS/ios_notifications.cpp
        Headers/ios_notifications.h
        async_http/apiHandlerBoostPool.cpp
        Headers/apiHandlerBoostPool.h
        async_http/handler_functionality.cpp

)


find_path(JWT_INCLUDE_DIR
        NAMES jwt/jwt.hpp
        HINTS /usr/include /usr/local/include)

# Add include directories for the executable.
target_include_directories(bastion_auth PRIVATE
        ${PROJECT_SOURCE_DIR}/Headers
        ${PROJECT_SOURCE_DIR}/Validation
        /usr/local/include
        /usr/lib64
        /infinite/Projects/NoPass/SourceFiles/uWebSockets/src
        /infinite/Projects/NoPass/SourceFiles/uWebSockets/uSockets/src
        /usr/local/include/Crow/include
        ${JWT_INCLUDE_DIR}
)

# Link the static library and the uSockets static library.
target_link_libraries(bastion_auth PRIVATE
        bastion_data
        "/infinite/Projects/NoPass/SourceFiles/uWebSockets/uSockets/uSockets.a"
        ${AWSSDK_LINK_LIBRARIES}
)