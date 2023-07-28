#ifndef NFMASTER_H_INCLUDED
#define NFMASTER_H_INCLUDED

#include <stdint.h>
#include <pthread.h>
#include <sys/queue.h>
#include <netinet/in.h>

#define CLIENTS_COMM_POOL_SIZE 8

enum gameserver_stage {
     HEARTBEAT_REQ, /* server -> master */
     VALIDATE_REQ, /* master -> server */
     VALIDATE_RSP, /* server -> master */
     STATUS_REQ, /* master -> server */
     STATUS_RSP /* server -> master */
};

enum client_stage {
     SECURE_REQ, /* master -> client */
     SECURE_RSP, /* client -> master */
     SERVER_LIST_REQ, /* client -> master */
     SERVER_LIST_RSP /* master -> client */
};

struct ClientNF {
    uint16_t port;
    in_addr_t ip;
    int sock;
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
