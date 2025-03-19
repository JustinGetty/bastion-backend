    #include <iostream>
    #include "sqldaemon.h"

    task_queue_t queue;
    //NEVER ADD POINTERS TO THIS


    void task_queue_init(task_queue_t *q) {
        q->front = 0;
        q->rear = 0;
        q->count = 0;
        pthread_mutex_init(&q->mutex, nullptr);
        pthread_cond_init(&q->cond_not_empty, nullptr);
        pthread_cond_init(&q->cond_not_full, nullptr);
    }

    void task_queue_push(task_queue_t *q, int client_sock) {
        pthread_mutex_lock(&q->mutex);
        while (q->count == TASK_QUEUE_CAPACITY) {
            pthread_cond_wait(&q->cond_not_full, &q->mutex);
        }
        q->task[q->rear].client_socket = client_sock;
	    //add to end, wrap to 0 if needed - circle queue
        q->rear = (q->rear + 1) % TASK_QUEUE_CAPACITY;
        q->count++;
        pthread_cond_signal(&q->cond_not_empty);
        pthread_mutex_unlock(&q->mutex);
    }

    int task_queue_pop(task_queue_t *q) {
        pthread_mutex_lock(&q->mutex);
        while (q->count == 0) {
            pthread_cond_wait(&q->cond_not_empty, &q->mutex);
        }
        int client_socket = q->task[q->front].client_socket;
	    //add to end, wrap to 100 if needed - circle queue
        q->front = (q->front + 1) % TASK_QUEUE_CAPACITY;
        q->count--;
        pthread_cond_signal(&q->cond_not_full);
        pthread_mutex_unlock(&q->mutex);
        return client_socket;
    }

    //eventually this is going to need to switch between POST/GET, either send results or errmsg
    void *worker_thread(void *arg) {
        sqlite3 *db;
        if (sqlite3_open(DATABASE, &db) != SQLITE_OK) {
            fprintf(stderr, "Thread %lu: Cannot open database: %s\n",
                    pthread_self(), sqlite3_errmsg(db));
            pthread_exit(nullptr);
        }

        printf("Thread %lu: Opening database %s\n", pthread_self(), DATABASE);
        //lets get this closer to actual max query size
        //also free this after use lmao???
        query_data inbound_data;

        while (true) {
            const int client_sock = task_queue_pop(&queue);
            int temp_status = -2;
            printf("Client sock in worker = %d\n", client_sock);
            memset(&inbound_data, 0, sizeof(query_data));

            ssize_t bytes_read = read(client_sock, &inbound_data, sizeof(query_data) - 1);
            if (bytes_read <= 0) {
                close(client_sock);
                continue;
            }
            printf("thread %lu received query: %s\n", pthread_self(), inbound_data.query);

            sqlite3_stmt *stmt;
            const char *query = inbound_data.query;
            if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {

                temp_status = -1;
            }
            else {
                for (int i = 0; i < inbound_data.num_params; i++) {
                    int index = i + 1;
                    query_param param = inbound_data.params[i];
                    switch (param.type) {
                        case PARAM_INT:
                            printf("Binding INT\n");
                        printf("Int to bind: %d\n", param.data.int_val);
                        if (sqlite3_bind_int(stmt, index, param.data.int_val) != SQLITE_OK) {
                            //FUCKKKK THERES AN ERROR AHHHHHHHHHH
                            printf("Int bind error");
                            temp_status = -1;
                        }
                        break;

                        case PARAM_FLOAT:
                            printf("Binding FLOAT\n");
                        printf("Float to bind: %f\n", param.data.float_val);
                        if (sqlite3_bind_double(stmt, index, param.data.float_val) != SQLITE_OK) {
                            temp_status = -1;
                        }
                        break;

                        case PARAM_TEXT:
                            printf("Binding TEXT\n");
                        printf("Text to bind: %s\n", param.data.text_val);
                        if (sqlite3_bind_text(stmt, index, param.data.text_val, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                            temp_status = -1;
                        }
                        break;

                        case PARAM_TOKEN_HASH:
                            printf("Binding TOKEN_HASH\n");
                        for (int i = 0; i < HASH_SIZE; i++) {
                            printf("%02x", param.data.token_val_hash[i]);
                        }
                        printf("\n");
                        if (sqlite3_bind_blob(stmt, index, param.data.token_val_hash, HASH_SIZE, SQLITE_TRANSIENT) != SQLITE_OK) {
                            temp_status = -1;
                        }
                        break;

                        case PARAM_ASM_KEY:
                            printf("Binding ASM_KEY\n");
                        printf("Private key: ");
                        for (int i = 0; i < param.data.priv_key_w_len.priv_key_len; i++) {
                            printf("%02x", param.data.priv_key_w_len.priv_key[i]);
                        }
                        printf("\n");

                        if (sqlite3_bind_blob(stmt, index, param.data.priv_key_w_len.priv_key, param.data.priv_key_w_len.priv_key_len, SQLITE_TRANSIENT) != SQLITE_OK) {
                            temp_status = -1;
                        }
                        break;

                        case PARAM_SYM_KEY:
                            printf("Binding SYM_KEY\n");
                            printf("Sym key: ");
                            for (int i = 0; i < KEY_SIZE; i++) {
                                printf("%02x", param.data.sym_key_val[i]);
                            }

                            if (sqlite3_bind_blob(stmt, index, param.data.sym_key_val, KEY_SIZE, SQLITE_TRANSIENT) != SQLITE_OK) {
                                temp_status = -1;
                            }
                            break;

                        case PARAM_SYM_IV:
                            printf("Binding SYM_IV\n");
                            printf("\nIV:\n");
                            for (int i = 0; i < IV_SIZE; i++) {
                                printf("%02x", param.data.sym_iv_val[i]);
                            }
                            printf("\n");
                            if (sqlite3_bind_blob(stmt, index, param.data.sym_iv_val, IV_SIZE, SQLITE_TRANSIENT) != SQLITE_OK) {
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
                if (inbound_data.type == 'g') {
                    switch (inbound_data.real_type) {
                        case GET_BASIC_USER_BY_ID: {
                            user_data_basic user = {0};
                            while (sqlite3_step(stmt) == SQLITE_ROW) {
                                user.user_id = sqlite3_column_int(stmt, 0);
                                const unsigned char* raw_username = sqlite3_column_text(stmt, 1);
                                if (raw_username != NULL) {
                                    strncpy(user.username, (const char*)raw_username, 49);
                                    user.username[49] = '\0';
                                } else {
                                    user.username[0] = '\0';
                                }
                                user.timestamp = sqlite3_column_int(stmt, 2);
                                if (temp_status == -2) {
                                    user.status = 0;
                                }
                                else {
                                    user.status = temp_status;
                                }
                                //error handle this as well
                                send(client_sock, &user, sizeof(user_data_basic),0);

                                printf("Query executed successfully\n");
                                printf("User ID: %d\n", user.user_id);
                                printf("Username: %s\n", user.username);
                                printf("Timestamp: %d\n", user.timestamp);
                            }
                            break;
                        }
                        case GET_FULL_USER_BY_ID:
                            full_user_data user_data;
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            //"SELECT user_id, username, CAST(strftime('%%s', timestamp) AS INTEGER), auth_token, asym_priv_key FROM user WHERE user_id = ?"
                            user_data.user_id = sqlite3_column_int(stmt, 0);
                            const unsigned char* raw_username = sqlite3_column_text(stmt, 1);
                            if (raw_username != NULL) {
                                strncpy(user_data.username, (const char*)raw_username, 49);
                                user_data.username[49] = '\0';
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
                            send(client_sock, &user_data, sizeof(full_user_data),0);
                            printf("Data retreived:\n");
                            printf("User ID: %d\n", user_data.user_id);
                            printf("Username: %s\n", user_data.username);
                            printf("User creation time: %d\n", user_data.user_creation_time);
                        }
                        break;

                        case GET_AUTH_TOKEN:
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
                        send(client_sock, &hash_token, sizeof(hash_token),0);
                        if (hash_token.status_ = SUCCESS) {

                        }
                        printf("Query executed successfully\n");
                        break;
                        case GET_ASYM_PRIV_KEY:
                            priv_key_struct priv_key;
                        /*
                         *STORE LENGTH OF KEY TO COMPARE WHEN GRABBED
                         */
                        while (sqlite3_step(stmt) == SQLITE_ROW) {
                            const void* blob = sqlite3_column_blob(stmt, 0);
                            int blob_size = sqlite3_column_bytes(stmt, 0);
                            //ensure correct size here !!!!!! somehow
                            if (temp_status == -1) {
                                priv_key.priv_key_status = DATABASE_FAILURE;
                            } else {
                                memcpy(priv_key.priv_key, blob, blob_size);
                                priv_key.priv_key_status = SUCCESS;
                            }
                        }
                        send(client_sock, &priv_key, sizeof(priv_key),0);
                        if (priv_key.priv_key_status == SUCCESS) {
                            printf("Query executed successfully\n");
                        } else {
                            printf("Query failed\n");
                        }
                        break;

                        case GET_SYM_KEY:
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
                        send(client_sock, &sym_key, sizeof(sym_key),0);
                        if (sym_key.sym_key_status == SUCCESS) {
                            printf("Query executed successfully\n");
                        } else {
                            printf("Query failed\n");
                        }
                        break;

                        default:
                            printf("Error\n");
                        break;
                    }
                }
                if (inbound_data.type == 'p') {
                    printf("Hit the post statement\n");
                    int step_result = sqlite3_step(stmt);

                    if (step_result == SQLITE_DONE) {
                        // Success path - query executed successfully
                        if (temp_status == -1) {
                            // There was a binding error earlier
                            fprintf(stderr, "Binding failed: %s\n", sqlite3_errmsg(db));
                            STATUS update_status = DATABASE_FAILURE;
                            send(client_sock, &update_status, sizeof(STATUS), 0);
                            printf("Failed due to binding error\n");
                        } else {
                            printf("Update Successful\n");
                            STATUS update_status = SUCCESS;
                            send(client_sock, &update_status, sizeof(STATUS), 0);
                        }
                    } else {
                        // Failure path - query execution failed
                        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
                        STATUS update_status = DATABASE_FAILURE;
                        send(client_sock, &update_status, sizeof(STATUS), 0);
                        printf("Failed due to execution error: %d\n", step_result);
                    }
                }
            }
            sqlite3_finalize(stmt);
            close(client_sock);
        }

            //again this will prob never be hit
            sqlite3_close(db);
            return NULL;
}



    // TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.

    int main() {
        task_queue_init(&queue);

        pthread_t threads[THREAD_POOL_SIZE];
        for (int i = 0; i < THREAD_POOL_SIZE; i++) {
            if (pthread_create(&threads[i], nullptr, worker_thread, nullptr) != 0) {
                perror("pthread_create");
                exit(EXIT_FAILURE);
            }
        }
        printf("Thread pool of %d worker threads created.\n", THREAD_POOL_SIZE);

        int server_fd, client_sock;
        struct sockaddr_un address;
        socklen_t addrlen = sizeof(address);

        if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }

        unlink(SQLITE_DAEMON_SOCKET_PATH);

        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strncpy(address.sun_path, SQLITE_DAEMON_SOCKET_PATH, sizeof(address.sun_path) - 1);

        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }

        //increase backlog with scale, can handle 64 conns in backlog rn
        if (listen(server_fd, 64) < 0) {
            perror("listen failed");
            exit(EXIT_FAILURE);
        }
        printf("SQLite daemon listening on UNIX socket %s...\n", SQLITE_DAEMON_SOCKET_PATH);

        while (1) {
            client_sock = accept(server_fd, (struct sockaddr *)&address, &addrlen);
            if (client_sock < 0) {
                perror("accept failed");
                continue;
            }
            printf("Client sock = %d\n", client_sock);
            task_queue_push(&queue, client_sock);
        }

        //theoretically never reached, should def make a more graceful closing lollll
        close(server_fd);
        unlink(SQLITE_DAEMON_SOCKET_PATH);
        return 0;
    }