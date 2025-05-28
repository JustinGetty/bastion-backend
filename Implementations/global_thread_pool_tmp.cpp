//
// Created by root on 3/31/25.
//

#include "../Headers/circular_queue.h"
#include "../Validation/validation_work.h"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>

//rename to validation thread pool global or something TODO

CircularQueue<validation_work*> g_workQueue(10);
ConnectionDataStorage cds;
