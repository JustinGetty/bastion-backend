#include <App.h>
#include <iostream>
#include "Headers/connection_data_queue.h"
#include "Headers/conn_data_storage.h"
#include "Headers/conn_thread_pool.h"
#include "Headers/custom_data.h"

#define EMPTY_USERNAME "NOTSET"

/*
 TODO

 - setup proxy to load balance event loop threads - single port delegates to other open ports
 - increase ulimit -n (file descriptor limit)
 - adjust net.core.somaxconn for maximum connections
 - set fs.file-max for max open files
 - thread pool to handle connections

 Avoid Threads Plan:
 - Client site to websocket connection, connection managed by uWebSockets
 - Websocket data stored, request to data daemon made and websock to phone made via uWebSocket
 - Keep both ws connections in data structure, note not signed in yet, unique id.
 - When user approves, update data structure to "ready to approve", send approval to client site
 - No threads


 To be figured out:
 - How to notify connection in structure that it's ready to be sent out?
    Connection sits in structure with websocket connections for both mobile and client site.
    When user approves on mobile, mobile conn manager daemon will need to update that connection.
    Possibly override/make new WebSocketBehavior for uWebSocket

    Solution:
    - Second queue that when the approval is finished, its added to a new queue that can be sent through
        event loop


    - nvm, API POST request to server after push notification to phone
New solution:
- ConnectionDataList stores connections while waiting for mobile verification. then mobile phone sends https POST request
    with the data and then the corresponding connection data is pulled from the list

 */

void main_thread_work()
{
    // grab connection here
}

struct WebSocketBehavior
{
    static void open(uWS::WebSocket<false, true, int> *ws)
    {
        // getUserData() returns empty memory space for particular conn data
        // fix cast here
        ConnectionData *connData = (ConnectionData *)ws->getUserData();
        connData->username = EMPTY_USERNAME;
        connData->connection_id = -1;
        std::cout << "Client connected!" << std::endl;
    }

    // for inbound message
    // first false is for ssl - false = no ssl
    static void message(uWS::WebSocket<false, true, int> *ws, std::string_view message, uWS::OpCode opCode)
    {
        std::cout << "Received: " << message << std::endl;
        ws->send(message, opCode);
        // if message recieved == sign in, add to threadpool queue
        /*
        threadPool.enqueueConnection(createConnectionData(i));
        std::cout << "Enqueued connection data " << i << std::endl;
        */
    }

    static void close(uWS::WebSocket<false, true, int> *ws, int code, std::string_view message)
    {
        std::cout << "Client disconnected!" << std::endl;
    }
};

int main()
{
    uWS::App app;

    /*
    create thread pool to do the work for each connection
    i.e get data, handle data, etc.
    */
    ConnThreadPool connection_work_thread_pool;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Attach WebSocket route
    // equivalant to app.open = XX, app.close = XX
    app.ws<int>("/*", {.open = &WebSocketBehavior::open,
                       .message = &WebSocketBehavior::message,
                       .close = &WebSocketBehavior::close});

    // lambda taking no parameters, token points to listening socket
    app.listen(8443, [](auto *token)
               {
        if (token) {
            std::cout << "Server is running on port 8443" << std::endl;
        } else {
            std::cerr << "Failed to start server" << std::endl;
        } });

    // event loop
    app.run();
    return 0;
}
