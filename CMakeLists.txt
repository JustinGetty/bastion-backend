cmake_minimum_required(VERSION 3.31)
project(database_daemon)

set(CMAKE_CXX_STANDARD 20)

# Ensure SQLite3 is found
find_package(SQLite3 REQUIRED)

# Define the executable target
add_executable(database_daemon main.cpp sqldaemon.c)

# Now, link SQLite3 to the target (after defining it)
target_link_libraries(database_daemon PRIVATE SQLite::SQLite3)
