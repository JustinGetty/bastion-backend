#ifndef MY_VALIDATION_WORK_H
#define MY_VALIDATION_WORK_H

#include <iostream>
#include <string>
#include <cstring>
#include "circular_queue.h"
#include "thread_pool.h"
#include "validation_work.h"
#include <bastion_data.h>
#include "../Headers/conn_data_storage.h"

#include "databaseq.h"
#include "../Headers/cryptography.h"
extern CircularQueue<validation_work*> g_workQueue;
extern ConnectionDataStorage cds;

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
        std::cout << "Received sym key and iv encoded: \n" << sym_key_iv_encoded << std::endl;
        unsigned char decoded_key_iv[256];
        decode_fixed_length(sym_key_iv_encoded, decoded_key_iv, 256);
        printf("Decoded key iv:\n");
        print_hex(decoded_key_iv, 256);

        std::cout << "Received token hash: \n" << token_hash_encoded << std::endl;
        unsigned char decoded_token_hash[256];
        decode_fixed_length(token_hash_encoded, decoded_token_hash, 256);
        printf("Decoded token hash:\n");
        print_hex(decoded_token_hash, 256);

        /* SHOULD BE:
        Decoded token hash:
        44b42b3fe5b839e94e99376b60ca3d9916d30cdbc29a7c86e82c2a2b0610c4d3d90f541eefc2a1a06b899c95227d1fb623ec73a1f7113530128cfc448ab7ad5c70143fa1b67c6e2d2d547d0095b97f100ab2231745d53c1dc3081c2f0261f92d29d0a9e987699ec1df8fca36a70e5f979c948e94616cb43846ecd0bdfda2e90cdb27373b56d4571fe299a2ec8761175ee39d910a0e0f9c840043461d9fdcff2fe61545bba3cba3fe3e117b9e52710eb48bc1333f11bd1dfaa6d1ac477b1461f5b424b2e3bebcd5e207c3e243c23400086102c9dc4af99b8d188d2b1a94d0bdabc3220653827204abbfee7d8f2f3c9f628eb106504e3f13bf9fe77a81bc7e41c7
        Decoded key iv:
        195d74e1ab903a8f1496150397ba99890d5019fe477be2f909c611e405141203fbe4e267bf72e1817f32da9230c91ad1f1c906441990bee28b0a974bdd4f1dda7f4e9089ebcdfcc9e70295a99f7e0ce1e1a5761c72ea3945c30716afefe289fbf40cd004597c73c2e8eac61883a01b1c8d04a3866c6cdd5059e4d4c2c585c386a2d510d2c06157f42aeab30a2d1ea08d4a81b252bd76dff03d5c3d21435870feae5190151262e2d4ed30c9424c3050e4fdfc39c92867bdb1fa3958428bbcd355dee51826f1be719cd2bc794806eb67b0b6535787f874168e7bdcf969e5705b0e69f4400a716129665584c7aab87030c2341e6a4b8cd4953621fb8543bdcff81c
        */


        //TODO pass in connection id so this isnt hard coded
        ConnectionData *data_from_storage = cds.get_connection_data(1);
        std::cout << "Data pulled from storage with id: " << data_from_storage->connection_id << "\n";
        std::cout << "Username from storage: " << data_from_storage->username << "\n";

        //TODO PICKUP HERE - grab private key and decrypt and go nutty

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
