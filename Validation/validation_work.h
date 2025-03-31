#ifndef MY_VALIDATION_WORK_H
#define MY_VALIDATION_WORK_H

#include <iostream>
#include <string>
#include <cstring>
#include "circular_queue.h"
#include "thread_pool.h"
#include "validation_work.h"
#include <bastion_data.h>
#include "../Headers/cryptography.h"
extern CircularQueue<validation_work*> g_workQueue;

class MyValidationWork : public validation_work {
public:
    MyValidationWork(
        int id,
        int user_id,
        //make references
        const std::string token_hash_encoded,
        const std::string sym_key_iv_encoded)
        : id_(id),
          user_id_(user_id),
          token_hash_encoded(token_hash_encoded),
          sym_key_iv_encoded(sym_key_iv_encoded)
    {
    }

    void execute() override {
        std::cout << "Executing validation work " << id_ << std::endl;

        token_hash auth_token_hash{};
        decode_fixed_length(token_hash_encoded, auth_token_hash, std::size(auth_token_hash));
        std::cout << "Auth token hash:" << std::endl;
        for (int i = 0; i < HASH_SIZE; i++) {
            printf("%02x", auth_token_hash[i]);
        }
        printf("\n");

        unsigned char key_iv[KEY_SIZE + IV_SIZE] = {0};
        decode_fixed_length(sym_key_iv_encoded, key_iv, KEY_SIZE + IV_SIZE);
        std::cout << "Sym key IV:" << std::endl;
        for (int i = 0; i < KEY_SIZE + IV_SIZE; i++) {
            printf("%02x", key_iv[i]);
        }
        printf("\n");

        unsigned char recovered_key[KEY_SIZE] = {0};
        unsigned char recovered_iv[IV_SIZE] = {0};
        std::memcpy(recovered_key, key_iv, KEY_SIZE);
        std::memcpy(recovered_iv, key_iv + KEY_SIZE, IV_SIZE);

    }

private:
    int id_;
    int user_id_;
    const std::string token_hash_encoded;
    const std::string sym_key_iv_encoded;
};

//currently unused, delete is deprecated
inline void setup_work_threads() {
    //add back global threadpool
    ThreadPool pool(4, g_workQueue);
}

#endif // MY_VALIDATION_WORK_H
