#include <iostream>
#include "../Headers/database_head.h"
#include <sqlite3.h>

task_queue_t queue;

void task_queue_init(task_queue_t *q) {
    q->front = 0;
    q->rear = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, nullptr);
    pthread_cond_init(&q->cond_not_empty, nullptr);
    pthread_cond_init(&q->cond_not_full, nullptr);
}

void task_queue_push(task_queue_t *q, query_data_struct* queryData) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == TASK_QUEUE_CAPACITY) {
        pthread_cond_wait(&q->cond_not_full, &q->mutex);
    }
    //fix
    q->task[q->rear].queryDataStruct = queryData;
    //add to end, wrap to 0 if needed - circle queue
    q->rear = (q->rear + 1) % TASK_QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->cond_not_empty);
    pthread_mutex_unlock(&q->mutex);
}

void add_to_queue(query_data_struct* queryData) {
    task_queue_push(&queue, queryData);
    std::cout << "[INFO] Pushed task to queue to be processed in database.\n";
}

query_data_struct* task_queue_pop(task_queue_t *q) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0) {
        pthread_cond_wait(&q->cond_not_empty, &q->mutex);
    }
    query_data_struct *queryData = q->task[q->front].queryDataStruct;
    //add to end, wrap to 100 if needed - circle queue
    q->front = (q->front + 1) % TASK_QUEUE_CAPACITY;
    q->count--;
    pthread_cond_signal(&q->cond_not_full);
    pthread_mutex_unlock(&q->mutex);
    return queryData;
}

//eventually this is going to need to switch between POST/GET, either send results or errmsg
void *worker_thread(void *arg) {
//going to have server_worker_thread push to the queue a QueryData or ConnectionData or something
sqlite3 *db;
if (sqlite3_open(DATABASE, &db) != SQLITE_OK) {
    fprintf(stderr, "[THREAD] ID %lu: Cannot open database: %s\n",
            pthread_self(), sqlite3_errmsg(db));
    pthread_exit(nullptr);
}

printf("[THREAD] ID %lu: Opening database %s\n", pthread_self(), DATABASE);
//lets get this closer to actual max query size
//also free this after use lmao???
query_data *inbound_data;

while (true) {
    restart:
    //what happens here when task_queue is full
    query_data_struct *inbound_data_struct = task_queue_pop(&queue);
    inbound_data = &inbound_data_struct->queryData;

    int temp_status = -2;

    // At this point, inbound_data is fully read.

    printf("[INFO] Thread %lu received query: %s\n", pthread_self(), inbound_data->query);

    sqlite3_stmt *stmt;
    const char *query = inbound_data->query;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        temp_status = -1;
        std::cerr << "[ERROR] Failed to prepare statement: " << sqlite3_errmsg(db) << "\n";

    }
    else {
        for (int i = 0; i < inbound_data->num_params; i++) {
            int index = i + 1;
            query_param param = inbound_data->params[i];
            switch (param.type) {
                case PARAM_INT:
                    if (sqlite3_bind_int(stmt, index, param.data.int_val) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_INT\n";
                        temp_status = -1;
                }
                break;

                case PARAM_FLOAT:
                    if (sqlite3_bind_double(stmt, index, param.data.float_val) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_FLOAT.\n";
                        temp_status = -1;
                }
                break;

                case PARAM_TEXT:
                    if (sqlite3_bind_text(stmt, index, param.data.text_val, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_TEXT.\n";
                        temp_status = -1;
                    }
                break;

                case PARAM_TOKEN_HASH:
                    for (int i = 0; i < HASH_SIZE; i++) {
                        printf("%02x", param.data.token_val_hash[i]);
                    }
                    printf("\n");
                    if (sqlite3_bind_blob(stmt, index, param.data.token_val_hash, HASH_SIZE, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_TOKEN_HASH.\n";
                        temp_status = -1;
                    }
                break;

                case PARAM_ASM_KEY:
                    for (int i = 0; i < param.data.priv_key_w_len.priv_key_len; i++) {
                        printf("%02x", param.data.priv_key_w_len.priv_key[i]);
                    }
                    printf("\n");

                    if (sqlite3_bind_blob(stmt, index, param.data.priv_key_w_len.priv_key, param.data.priv_key_w_len.priv_key_len, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_ASYM_KEY.\n";
                        temp_status = -1;
                    }
                break;

                case PARAM_SYM_KEY:
                    for (int i = 0; i < KEY_SIZE; i++) {
                        printf("%02x", param.data.sym_key_val[i]);
                    }

                    if (sqlite3_bind_blob(stmt, index, param.data.sym_key_val, KEY_SIZE, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_SYM_KEY.\n";
                        temp_status = -1;
                    }
                    break;

                case PARAM_SYM_IV:
                    if (sqlite3_bind_blob(stmt, index, param.data.sym_iv_val, IV_SIZE, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_SYM_IV.\n";
                        temp_status = -1;
                    }
                    break;

                case PARAM_USERNAME:
                    if (sqlite3_bind_text(stmt, index, param.data.text_val, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_USERNAME.\n";
                        temp_status = -1;
                    }
                    break;

                case PARAM_TOKEN_ENC:
                    if (sqlite3_bind_blob(stmt, index, param.data.encrypted_raw_token, 64, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_TOKEN_ENC.\n";
                        temp_status = -1;
                    }
                break;

                case PARAM_SEED_PHRASE_HASH:
                    if (sqlite3_bind_blob(stmt, index, param.data.seed_phrase_hash_, 32, SQLITE_TRANSIENT) != SQLITE_OK) {
                        std::cout << "[ERROR] Failed to bind blob of type PARAM_SEED_PHRASE_HASH.\n";
                        temp_status = -1;
                    }

                break;

                default:
                    //ahhhh more errors to fix
                        //#hope for good user input!
                            printf("Error\n");
                break;
            }
            if (temp_status == -1) {
                break;
            }
        }
        //get requests
        if (inbound_data->type == 'g') {
            switch (inbound_data->real_type) {


                case GET_FULL_USER_BY_ID: {
                    full_user_data user_data;
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                    //"SELECT user_id, username, CAST(strftime('%%s', timestamp) AS INTEGER), auth_token, asym_priv_key FROM user WHERE user_id = ?"
                    user_data.user_id = sqlite3_column_int(stmt, 0);
                    const unsigned char* raw_username = sqlite3_column_text(stmt, 1);
                    if (raw_username != NULL) {
                        /*
                        strncpy(user_data.username, (const char*)raw_username, 49);
                        user_data.username[49] = '\0';
                        */
                        strncpy(user_data.username, (const char*)raw_username, MAX_USERNAME_LENGTH - 1);
                        user_data.username[MAX_USERNAME_LENGTH - 1] = '\0';

                    } else {
                        user_data.username[0] = '\0';
                    }
                    user_data.user_creation_time = sqlite3_column_int(stmt, 2);
                    const unsigned char* raw_auth = (const unsigned char*)sqlite3_column_blob(stmt, 3);
                    if (raw_auth != NULL) {
                        memcpy(user_data.enc_auth_token, raw_auth, sizeof(user_data.enc_auth_token));
                    }
                    const unsigned char* raw_asym_key = (const unsigned char*)sqlite3_column_blob(stmt, 4);
                    if (raw_asym_key != NULL) {
                        memcpy(user_data.priv_key_w_len.priv_key, raw_asym_key, sizeof(user_data.priv_key_w_len.priv_key));
                    }
                    //add sym key here
                    if (temp_status == -1) {
                        user_data.user_status = DATABASE_FAILURE;
                    }
                    else {
                        user_data.user_status = SUCCESS;
                    }

                    //send(client_sock, &user_data, sizeof(full_user_data),0);

                    printf("Data retreived:\n");
                    printf("User ID: %d\n", user_data.user_id);
                    printf("Username: %s\n", user_data.username);
                    printf("User creation time: %d\n", user_data.user_creation_time);
                }
                break;
            }


                case GET_AUTH_TOKEN: {
                    hash_token_struct hash_token;
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const void* blob = sqlite3_column_blob(stmt, 0);
                        int blob_size = sqlite3_column_bytes(stmt, 0);
                        if (blob_size != HASH_SIZE || temp_status == -1) {
                            hash_token.status_ = DATABASE_FAILURE;
                        } else {
                            memcpy(hash_token.token_hash_, blob, HASH_SIZE);
                            hash_token.status_ = SUCCESS;
                        }
                    }
                    //send(client_sock, &hash_token, sizeof(hash_token),0);
                    if (hash_token.status_ = SUCCESS) {

                    }
                    printf("Query executed successfully\n");
                    break;
                }
                case GET_ASYM_PRIV_KEY:{
                    priv_key_struct priv_key;
                /*
                 *STORE LENGTH OF KEY TO COMPARE WHEN GRABBED
                 */
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const void* blob = sqlite3_column_blob(stmt, 0);
                        int blob_size = sqlite3_column_bytes(stmt, 0);
                        int priv_key_length = sqlite3_column_int(stmt, 1);
                        std::cout << "private key length: " << priv_key_length << std::endl;
                        if (priv_key_length <= 0){ temp_status = -1;}
                        //ensure correct size here !!!!!! somehow
                        if (temp_status == -1) {
                            priv_key.priv_key_status = DATABASE_FAILURE;
                        } else {
                            memcpy(priv_key.priv_key, blob, blob_size);
                            priv_key.priv_key_status = SUCCESS;
                            priv_key.priv_key_len = priv_key_length;
                        }
                    }
                    inbound_data_struct->status = priv_key.priv_key_status;
                    inbound_data_struct->processed_data.priv_key.priv_key_len = priv_key.priv_key_len;
                    memcpy(inbound_data_struct->processed_data.priv_key.priv_key, priv_key.priv_key, priv_key.priv_key_len);
                    inbound_data_struct->is_ready = true;
                    if (priv_key.priv_key_status == SUCCESS) {
                        printf("Query executed successfully\n");
                    } else {
                        printf("Query failed\n");
                    }
                break;
            }
                case GET_SYM_KEY:{
                    sym_key_full sym_key;
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const void* key = sqlite3_column_blob(stmt, 0);
                    int key_len = sqlite3_column_bytes(stmt, 0);
                    const void* iv = sqlite3_column_blob(stmt, 1);
                    int iv_len = sqlite3_column_bytes(stmt, 1);
                    if (temp_status == -1) {
                        sym_key.sym_key_status = DATABASE_FAILURE;
                    } else {
                        memcpy(sym_key.symmetric_key, key, key_len);
                        memcpy(sym_key.symmetric_iv, iv, iv_len);
                        sym_key.sym_key_status = SUCCESS;
                    }
                    }
                    //send(client_sock, &sym_key, sizeof(sym_key),0);
                    if (sym_key.sym_key_status == SUCCESS) {
                        printf("Query executed successfully\n");
                    } else {
                        printf("Query failed\n");
                    }
                break;
            }

                case GET_FULL_USER_BY_UNAME: {
                    full_user_data user_data;
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        user_data.user_id = sqlite3_column_int(stmt, 0);
                        const unsigned char* raw_username = sqlite3_column_text(stmt, 1);
                        if (raw_username != NULL) {
                            /*
                            strncpy(user_data.username, (const char*)raw_username, 49);
                            user_data.username[49] = '\0';
                            */
                            strncpy(user_data.username, (const char*)raw_username, MAX_USERNAME_LENGTH - 1);
                            user_data.username[MAX_USERNAME_LENGTH - 1] = '\0';
                        } else {
                            user_data.username[0] = '\0';
                        }
                        user_data.user_creation_time = sqlite3_column_int(stmt, 2);
                        const unsigned char* raw_auth = (const unsigned char*)sqlite3_column_blob(stmt, 3);
                        if (raw_auth != NULL) {
                            memcpy(user_data.enc_auth_token, raw_auth, sizeof(user_data.enc_auth_token));
                        }
                        const unsigned char* raw_asym_key = (const unsigned char*)sqlite3_column_blob(stmt, 4);
                        const int asym_key_len = sqlite3_column_int(stmt, 5);
                        if (raw_asym_key != NULL) {
                            memcpy(user_data.priv_key_w_len.priv_key, raw_asym_key, sizeof(user_data.priv_key_w_len.priv_key));
                            user_data.priv_key_w_len.priv_key_len = asym_key_len;
                        }
                        //add sym key here
                        if (temp_status == -1) {
                            user_data.user_status = DATABASE_FAILURE;
                        }
                        else {
                            user_data.user_status = SUCCESS;
                        }

                        //send(client_sock, &user_data, sizeof(full_user_data),0);
                        //this updates the data and marks it as ready
                        inbound_data_struct->processed_data.user_data = user_data;
                        inbound_data_struct->is_ready = true;



                        printf("[DEBUG] Data retrieved:\n");
                        printf("[DEBUG] User ID: %d\n", user_data.user_id);
                        printf("[DEBUG] Username: %s\n", user_data.username);
                        printf("[DEBUG] User creation time: %d\n", user_data.user_creation_time);
                    }

                    break;
                }

                case GET_USERNAME_EXISTS: {

                    bool exists_data;
                    int result = sqlite3_step(stmt);
                    exists_data = (result == SQLITE_ROW);
                    if (temp_status == -1) {
                        std::cout << "[ERROR] Failed to verify username in database.\n";
                        inbound_data_struct->status = DATABASE_FAILURE;
                    }
                    else {
                        inbound_data_struct->status = SUCCESS;
                    }
                    inbound_data_struct->processed_data.username_exists = exists_data;
                    inbound_data_struct->is_ready = true;
                break;
                }



                case GET_SEED_PHRASE_HASH: {
                    //TODO these while loops are bound to cause an error if index is not unique, FIXXX

                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const unsigned char* raw_seed_phrase_hash = (const unsigned char*)sqlite3_column_blob(stmt, 0);

                        if (temp_status == -1){
                            inbound_data_struct->status = DATABASE_FAILURE;
                        } else {

                            memcpy(inbound_data_struct->processed_data.hash_of_seed_phrase, raw_seed_phrase_hash, sizeof(inbound_data_struct->processed_data.hash_of_seed_phrase));
                            inbound_data_struct->status = SUCCESS;
                            std::cout << "[INFO] Successfully retrieved hashed seed phrase\n.";
                        }
                        inbound_data_struct->is_ready = true;
                    }
                break;
                }
                case GET_RAW_TOKEN_ENCRYPTED: {

                    const unsigned char* raw_token_enc{};
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        raw_token_enc = (const unsigned char*)sqlite3_column_blob(stmt, 0);
                    }
                    if (temp_status == -1){
                        inbound_data_struct->status = DATABASE_FAILURE;
                    } else {
                        memcpy(inbound_data_struct->processed_data.encrypted_raw_token, raw_token_enc, sizeof(inbound_data_struct->processed_data.encrypted_raw_token));
                        inbound_data_struct->status = SUCCESS;
                        std::cout << "[INFO] Successfully retrieved hashed seed phrase\n.";
                    }
                    inbound_data_struct->is_ready = true;

                break;
                }



                default:
                    std::cout << "[ERROR] Error in GET query.\n";
                break;
            }
        }
        if (inbound_data->type == 'p') {
            int step_result = sqlite3_step(stmt);
            STATUS update_status;

            if (step_result == SQLITE_DONE) {
                // Success path - query executed successfully
                if (temp_status == -1) {
                    // There was a binding error earlier
                    fprintf(stderr, "[ERROR] Binding failed: %s.\n", sqlite3_errmsg(db));
                    update_status = DATABASE_FAILURE;
                } else {
                    printf("[INFO] Update Successful.\n");
                    update_status = SUCCESS;
                }
            } else {
                // Failure path - query execution failed
                fprintf(stderr, "[ERROR] Execution failed: %s.\n", sqlite3_errmsg(db));
                update_status = DATABASE_FAILURE;
                //send(client_sock, &update_status, sizeof(STATUS), 0);
                printf("[ERROR] Failed due to execution error: %d.\n", step_result);
            }
            inbound_data_struct->status = update_status;
            inbound_data_struct->is_ready = true;
        }
    }
    sqlite3_finalize(stmt);
    //close(client_sock);
}

        //again this will prob never be hit
        sqlite3_close(db);
        return NULL;
}



// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.

void setup_threads() {
    task_queue_init(&queue);

    pthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&threads[i], nullptr, worker_thread, nullptr) != 0) {
            perror("[ERROR] pthread_create");
            exit(EXIT_FAILURE);
        }
    }
    printf("[INFO] Thread pool of %d worker threads created.\n", THREAD_POOL_SIZE);

    //task_queue_push(&queue, client_sock);
    return;
}