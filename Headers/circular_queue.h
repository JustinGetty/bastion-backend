#ifndef CIRCULAR_QUEUE_H
#define CIRCULAR_QUEUE_H

#include <vector>
#include <mutex>
#include <condition_variable>

template<typename T>
class CircularQueue {
public:
    explicit CircularQueue(size_t capacity)
        : capacity_(capacity), buffer_(capacity), head_(0), tail_(0), count_(0) {}

    void push(const T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this]() { return count_ < capacity_; });
        buffer_[tail_] = item;
        tail_ = (tail_ + 1) % capacity_;
        ++count_;
        lock.unlock();
        not_empty_.notify_one();
    }

    //non blocking pop
    bool try_pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (count_ == 0) {
            return false;
        }
        item = buffer_[head_];
        head_ = (head_ + 1) % capacity_;
        --count_;
        lock.unlock();
        not_full_.notify_one();
        return true;
    }

private:
    size_t capacity_;
    std::vector<T> buffer_;
    size_t head_;
    size_t tail_;
    size_t count_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
};

#endif // CIRCULAR_QUEUE_H
