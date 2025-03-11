#ifndef CUSTOM_DATA_H
#define CUSTOM_DATA_H

#include <App.h>

/* ----  DEFINITIONS ----------------------------------------*/
#define MAX_USERNAME_LENGTH 20
#define MAX_GET_QUERY 50

/*----- PATHS ----*/
#define GET_SOCKET_PATH "/tmp/sqlite_GET_daemon.sock"
#define POST_SOCKET_PATH "/tmp/sqlite_POST_daemon.sock"

/*----- STATUS ---*/

typedef enum STATUS
{
    SUCCESS,
    DATABASE_FAILURE,
    WEBSOCKET_FAILURE,
    HTTP_FAILURE,
    AFINET_FAILURE,
    BAD_DATA_LENGTH,
    BAD_DATA_TYPE,
    LOGIC_FAILURE,
    UNKNOWN_FAILURE
} STATUS;

/*----- Types ----*/
typedef unsigned char *blob;

typedef struct
{
    std::string username;
    int connection_id;
    uWS::WebSocket<false, true, int> *ws;
} ConnectionData;

/* ---  DATABASE --------------------------------------------*/

// depricated - remove
typedef struct
{
    char **rows;
    char **values;
} datastruct;

typedef struct
{
    int user_id;
    char username[MAX_USERNAME_LENGTH];
    time_t user_creation_time;
} user_data_struct;

typedef struct
{
    int user_id;
    char username[MAX_USERNAME_LENGTH];
    time_t user_creation_time;
    blob enc_auth_token;
    blob asym_priv_key;

} full_user_data_enc;

/* ----- TABLES --------------------------------------*/
/*
Table User
INFO:
- auth_token encrypted in user's sym key


SCHEMA:
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE user (
user_id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT NOT NULL,
auth_token BLOB,
asym_priv_key BLOB,
timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);




*/

#endif