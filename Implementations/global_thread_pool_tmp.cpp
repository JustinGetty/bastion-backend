//
// Created by root on 3/31/25.
//

#include "../Headers/circular_queue.h"
#include "../Validation/validation_work.h"

//rename to validation thread pool global or something TODO

CircularQueue<validation_work*> g_workQueue(10);