cmake_minimum_required(VERSION 3.31)
project(bastion_auth)

set(CMAKE_CXX_STANDARD 20)
target_link_libraries(bastion_auth PRIVATE bastion_data)
add_executable(bastion_auth main.cpp
        Sources/database_comm.cpp)

target_include_directories(MyClient PRIVATE /usr/local/include)


link_directories(/usr/local/lib)

target_link_libraries(MyClient PRIVATE bastion_data)