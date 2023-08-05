#ifndef NFMASTER_H_INCLUDED
#define NFMASTER_H_INCLUDED

#include <stdint.h>
#include <pthread.h>
#include <sys/queue.h>
#include <netinet/in.h>

#define CLIENTS_COMM_POOL_SIZE 8

#define SECURE_KEY_CHALLENGE_SZ 6

enum gameserver_stage {
     GAMESERVER_STAGE_HEARTBEAT_REQ, /* server -> master */
     GAMESERVER_STAGE_VALIDATE_REQ, /* master -> server */
     GAMESERVER_STAGE_VALIDATE_RSP, /* server -> master */
     GAMESERVER_STAGE_STATUS_REQ, /* master -> server */
     GAMESERVER_STAGE_STATUS_RSP, /* server -> master */
     GAMESERVER_STAGE_INVALID
};

enum client_stage {
     CLIENT_STAGE_SECURE_REQ, /* master -> client */
     CLIENT_STAGE_SECURE_RSP, /* client -> master */
     CLIENT_STAGE_SERVER_LIST_REQ, /* client -> master */
     CLIENT_STAGE_SERVER_LIST_RSP, /* master -> client */
     CLIENT_STAGE_INVALID
};

struct ClientNF {
    uint16_t port;
    in_addr_t ip;
    int sock;
    char secure_key_challenge[SECURE_KEY_CHALLENGE_SZ + 1];
    enum client_stage conn_stage;
    STAILQ_ENTRY(ClientNF) entry;
};

struct GameServerNF {
    uint16_t port;
    in_addr_t ip;
    uint8_t statechanged;
    struct timespec time_last_comm;
    enum gameserver_stage conn_stage;
    STAILQ_ENTRY(GameServerNF) entry;
};

struct MasterServerNF {
    STAILQ_HEAD(gameserver_head, GameServerNF) gameservers;
    STAILQ_HEAD(clients_head, ClientNF) clients;
    pthread_mutex_t lock_gameservers;
    pthread_mutex_t lock_clients;
    pthread_cond_t cond_clients_comm;
    pthread_t serverlist_state_update;
    pthread_t gameservers_comm;
    pthread_t clients_comm_pool[CLIENTS_COMM_POOL_SIZE];
    int clients_sock;
    int gameservers_sock;
};

int32_t MasterSever_init(struct MasterServerNF **master);
int32_t MasterServer_start(struct MasterServerNF *master);
void MasterServer_free(struct MasterServerNF *master);

#endif // NFMASTER_H_INCLUDED
