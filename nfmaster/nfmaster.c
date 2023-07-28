/***************************************************************
 * Name:      nfmaster
 * Purpose:   Code for xxx
 * Author:    Luka Culic Viskota (luka.culic.viskota@gmail.com)
 * Created:   Friday 2022-10-21-13.55.02
 * Copyright: Luka Culic Viskota (https://microcafe.co)
 * License:
 **************************************************************/

 #include <time.h>
 #include <unistd.h>
 #include <stdlib.h>
 #include <stdio.h>
 #include <string.h>
 #include <syslog.h>
 #include <pthread.h>
 #include <regex.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <netinet/tcp.h>
 #include <errno.h>

 #include "nfmaster.h"

 #define MASTERSPY_TCP_PORT 28900
 #define MASTERSPY_UDP_PORT 27900

 #define MAX_UDP_BUFF_SIZE 2048
 #define MAX_CLIENT_BUFF_SIZE 1024

 #define SERVERLIST_CLEANUP_PERIOD_SEC 60 /* 60sec */
 #define CLIENT_TCP_CONN_TIMEOUT_MS 10000 /* 10sec */

  #define LOGGING_TYPE_PRINTF

 #ifdef LOGGING_TYPE_PRINTF
 #define INFO(...) printf(__VA_ARGS__)
 #define ERR(...) printf(__VA_ARGS__)
 #else
 #define INFO(...) syslog(LOG_INFO, __VA_ARGS__)
 #define ERR(...) syslog(LOG_ERR, __VA_ARGS__)
 #endif // LOGGING_TYPE_PRINTF

 /* server -> master */
 enum heartbeat_pkt {
     HEARTBEAT_PKT_PORT,
     HEARTBEAT_PKT_GAMENAME,
     HEARTBEAT_PKT_STATECHANGED,
     HEARTBEAT_PKT_MAX
 };
 /* server -> master */
 enum status_rsp_pkt {
     STATUS_RSP_PKT_GAMENAME,
     STATUS_RSP_PKT_GAMEVER,
     STATUS_RSP_PKT_DEDICATED,
     STATUS_RSP_PKT_GAMEMODE,
     STATUS_RSP_PKT_GAMETYPE,
     STATUS_RSP_PKT_HOSTPORT,
     STATUS_RSP_PKT_MAPNAME,
     STATUS_RSP_PKT_MAXPLAYERS,
     STATUS_RSP_PKT_HOSTNAME,
     STATUS_RSP_PKT_NUMPLAYERS,
     STATUS_RSP_PKT_PASSWORD,
     STATUS_RSP_PKT_TIMELIMIT,
     STATUS_RSP_PKT_FRAGLIMIT,
     STATUS_RSP_PKT_CTFLIMIT,
     STATUS_RSP_PKT_TEAMPLAY,
     STATUS_RSP_PKT_FRIENDLYFIRE,
     STATUS_RSP_PKT_WEAPONSTAY,
     STATUS_RSP_PKT_BOTSMODE,
     STATUS_RSP_PKT_FINAL,
     STATUS_RSP_PKT_QUERYID,
     STATUS_RSP_PKT_MAX
 };
 /* master -> client */
 enum client_secure {
     CLIENT_SECURE_PKT_BASIC,
     CLIENT_SECURE_PKT_SECURE,
     CLIENT_SECURE_PKT_MAX
 };

 /* client -> master */
 enum client_validate {
     CLIENT_VALIDATE_PKT_GAMENAME,
     CLIENT_VALIDATE_PKT_GAMEVER,
     CLIENT_VALIDATE_PKT_LOCATION,
     CLIENT_VALIDATE_PKT_VALIDATE,
     CLIENT_VALIDATE_PKT_ENCTYPE,
     CLIENT_VALIDATE_PKT_FINAL,
     CLIENT_VALIDATE_PKT_QUERYID,
     CLIENT_VALIDATE_PKT_MAX
 };

 /* client -> master */
 enum client_list {
     CLIENT_LIST_PKT_LIST,
     CLIENT_LIST_PKT_GAMENAME,
     CLIENT_LIST_PKT_FINAL,
     CLIENT_LIST_PKT_MAX
 };

 static inline void dbg_print_gameserver_stage(enum gameserver_stage stage)
 {
     switch (stage) {
     case HEARTBEAT_REQ:
        INFO("HEARTBEAT_REQ");
        break;
     case VALIDATE_REQ:
        INFO("VALIDATE_REQ");
        break;
     case VALIDATE_RSP:
        INFO("VALIDATE_RSP");
        break;
     case STATUS_REQ:
        INFO("STATUS_REQ");
        break;
     case STATUS_RSP:
        INFO("STATUS_RSP");
        break;
     default:
        INFO("UNKNOWN");
        break;
     }
 }

 static inline void dbg_print_client_stage(enum client_stage stage)
 {
     switch (stage) {
     case SECURE_REQ:
        INFO("SECURE_REQ");
        break;
     case SECURE_RSP:
        INFO("SECURE_RSP");
        break;
     case SERVER_LIST_REQ:
        INFO("SERVER_LIST_REQ");
        break;
     case SERVER_LIST_RSP:
        INFO("SERVER_LIST_RSP");
        break;
     default:
        INFO("UNKNOWN");
        break;
     }
 }

 static void *serverlist_state_update(void *arg)
 {
     struct MasterServerNF *master = NULL;
     struct GameServerNF *gameserver = NULL;
     struct timespec poll_period = {
         .tv_sec = SERVERLIST_CLEANUP_PERIOD_SEC,
         .tv_nsec = 0,
     };

     if (!arg)
        return NULL;

    master = (struct MasterServerNF *)arg;

    while (1) {
        INFO("Serverlist cleanup: started");
        STAILQ_FOREACH(gameserver, &master->gameservers, entry) {
        /* poll */
        }
        INFO("Serverlist cleanup: completed");
        nanosleep(&poll_period, NULL);
    }

    return NULL;
 }

 static int32_t process_heartbeat(uint8_t *packet, ssize_t size)
 {
     int32_t ret = 0;
     char *tok = strtok((char *)packet, "\\");
     uint32_t statechanged = 0;
     struct GameServerNF *gameserver = NULL;
     uint8_t *heartbeat_pkt[HEARTBEAT_PKT_MAX];
     if (!tok)
        return -EINVAL;

    gameserver = malloc(sizeof(*gameserver));
    if (!gameserver)
        return -ENOMEM;

     do {
        if (!strncmp(tok, "heartbeat", strlen(tok))) {
            tok = strtok(NULL, "\\");
            if (!tok) {
               INFO("Heartbeat: bad packet -> missing port param");
               return -EINVAL;
            }
            heartbeat_pkt[HEARTBEAT_PKT_PORT] = tok;
        }
        else if (!strncmp(tok, "gamename", strlen(tok))) {
            tok = strtok(NULL, "\\");
            if (!tok) {
                INFO("Heartbeat: bad packet -> empty gamename param\n");
                return -EINVAL;
            }
            heartbeat_pkt[HEARTBEAT_PKT_GAMENAME] = tok;
        }
        else if (!strncmp(tok, "statechanged", strlen(tok))) {
            tok = strtok(tok, "\\");
            if (!tok) {
                INFO("Heartbeat: empty 'statechanged', accepting anyway...\n");
                gameserver->statechanged = 0;
            }
            else {
                ret = sscanf(tok, "%u", &statechanged);
                if (ret != 1) {
                    INFO("Heartbeat: invalid 'statechanged't, accepting anyway...\n");
                    gameserver->statechanged = 0;
                }
                else
                    gameserver->statechanged = statechanged;
            }
        }
        else {
            return -EINVAL;
        }

        tok = strtok(NULL, "\\");
     } while (tok);

     gameserver->conn_stage = HEARTBEAT_REQ;
     return 0;
 }

 static int32_t process_gameserver_packet(uint8_t *packet, ssize_t size)
 {
     if (!packet)
        return -EINVAL;
     if (!size)
        return 0;

     if (!strncmp(packet, "\\heartbeat\\", size - 1))
        return process_heartbeat(packet, size);
     else if (!strncmp(packet, "\\gamename\\", size - 1))
        return process_status(packet, size);
     else {
        INFO("Received invalid packet type on UDP sock");
        return -EINVAL;
     }

 }

 static void *gameservers_handler(void *arg)
 {
     int32_t ret = 0;
     struct MasterServerNF *master = NULL;
     struct sockaddr_in gameserver_addr = {0};
     socklen_t gameserver_addr_len = 0;
     uint8_t buff[MAX_UDP_BUFF_SIZE + 1] = {0};

     if (!arg)
        return NULL;

     master = (struct MasterServerNF *)arg;

     while (1) {
        ret = recvfrom(master->gameservers_sock, buff, MAX_UDP_BUFF_SIZE, 0,
                  (struct sockaddr *)&gameserver_addr, &gameserver_addr_len);
        if (ret > 0) {
            process_gameserver_packet(buff, ret); /* TODO: custom retcodes for API? */
        }
     }
 }

 int32_t MasterSever_init(struct MasterServerNF **master)
 {
     int32_t ret = 0;
     struct sockaddr_in addr = {0};

     if (!master)
        return -EINVAL;

     *master = malloc(sizeof(**master));
     if (!*master)
        return -ENOMEM;

    ret = pthread_mutex_init(&(*master)->lock_gameservers, NULL);
    if (ret) {
        ERR("Failed to init the gameservers mutex: %d\n", ret);
        return ret;
    }

    ret = pthread_mutex_init(&(*master)->lock_clients, NULL);
    if (ret) {
        ERR("Failed to init the clients mutex: %d\n", ret);
        return ret;
    }

    ret = pthread_cond_init(&(*master)->cond_clients_comm, NULL);
    if (ret) {
        ERR("Failed to init cond for clients comm: %d", ret);
        return ret;
    }

    STAILQ_INIT(&(*master)->gameservers);
    STAILQ_INIT(&(*master)->clients);

    (*master)->clients_sock = socket(AF_INET, SOCK_STREAM, 0);
    if ((*master)->clients_sock == -1) {
        ERR("Failed to open TCP sock: %d", -errno);
        return -EFAULT;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(MASTERSPY_TCP_PORT);

    ret = bind((*master)->clients_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        ERR("Failed to bind to port %d: %d\n", MASTERSPY_TCP_PORT, -errno);
        return -EFAULT;
    }

    ret = listen((*master)->clients_sock, CLIENTS_COMM_POOL_SIZE);
    if (ret == -1) {
        ERR("Failed to set listening on sock: %d\n", -errno);
        return -EFAULT;
    }

    (*master)->gameservers_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if ((*master)->gameservers_sock == -1) {
        ERR("Failed to open UDP gameservers sock: %d\n", -errno);
        return -EFAULT;
    }

    addr.sin_port = htons(MASTERSPY_UDP_PORT);

    ret = bind((*master)->gameservers_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        ERR("Failed to bind to port %d: %d\n", MASTERSPY_UDP_PORT, -errno);
        return -EFAULT;
    }

    return 0;
 }

 void *client_handler(void *arg)
 {
     struct MasterServerNF *master = NULL;
     struct ClientNF *client = NULL;
     uint8_t buff[MAX_CLIENT_BUFF_SIZE + 1] = {0};

     if (!arg)
        return NULL;

     master = (struct MasterServerNF *)arg;

     while (1) {
         pthread_mutex_lock(&master->lock_clients);
         while (STAILQ_EMPTY(&master->clients))
            pthread_cond_wait(&master->cond_clients_comm, &master->lock_clients);

         client = STAILQ_FIRST(&master->clients);
         STAILQ_REMOVE_HEAD(&master->clients, entry);
         pthread_mutex_unlock(&master->lock_clients);
         /* validate client and go through the list-fetch procedure */

         close(client->sock);
         free(client);
     }
     return NULL;
 }

 int32_t MasterServer_start(struct MasterServerNF *master)
 {
    int32_t ret = 0;
    struct ClientNF *gameclient = NULL;
    struct sockaddr_in client_addr = {0};
    socklen_t client_addr_len = 0;
    uint32_t client_timeout = CLIENT_TCP_CONN_TIMEOUT_MS;

    if (!master)
        return -EINVAL;

    ret = pthread_create(&master->serverlist_state_update, NULL, serverlist_state_update, master);
    if (ret)
        return -EFAULT;

    ret = pthread_create(&master->gameservers_comm, NULL, gameservers_handler, master);
    if (ret)
        return -EFAULT;

    for (uint16_t i = 0; i < CLIENTS_COMM_POOL_SIZE; i++) {
        ret = pthread_create(&master->clients_comm_pool[i], NULL, client_handler, master);
        if (ret) {
            ERR("Failed to start thread %u for clients comm handling: %d", i, ret);
            /* TODO: what? */
        }
    }
    while (1) {
            ret = accept(master->clients_sock, (struct sockaddr *)&client_addr, &client_addr_len);
            if (ret == -1) {
                INFO("Client: error processing req -> failed to open sock: %d", -errno);
                continue;
            }
            gameclient = malloc(sizeof(*gameclient));
            if (!gameclient)
                return -ENOMEM;

            gameclient->port = ntohs(client_addr.sin_port);
            gameclient->ip = ntohl(client_addr.sin_addr.s_addr);
            gameclient->sock = ret;
            ret = setsockopt(gameclient->sock, SOL_TCP, TCP_USER_TIMEOUT,
                             (uint8_t *)&client_timeout, sizeof(client_timeout));
            if (ret == -1)
                INFO("Failed to set client TCP sock timeout: %d", -errno); /* TODO: ignore it? */

            /* insert into the client comm queue */
            pthread_mutex_lock(&master->lock_clients);
            STAILQ_INSERT_TAIL(&master->clients, gameclient, entry);
            pthread_mutex_unlock(&master->lock_clients);
            pthread_cond_signal(&master->cond_clients_comm);
    }

     return 0;
 }

 void MasterServer_free(struct MasterServerNF *master)
 {
     struct ClientNF *client = NULL;

     if (!master)
        return;

    pthread_cancel(master->serverlist_state_update);
    pthread_join(master->serverlist_state_update, NULL);
    pthread_cancel(master->gameservers_comm);
    pthread_join(master->gameservers_comm, NULL);

    for (uint16_t i = 0; i < CLIENTS_COMM_POOL_SIZE; i++) {
        pthread_cancel(master->clients_comm_pool[i]);
        pthread_join(master->clients_comm_pool[i], NULL);
    }

    if (master->clients_sock > 0)
        close(master->clients_sock);

    if (master->gameservers_comm > 0)
        close(master->gameservers_comm);

    STAILQ_FOREACH(client, &master->clients, entry) {
        if (client->sock > 0)
            close(client->sock);
    }

    pthread_cond_destroy(&master->cond_clients_comm);
    pthread_mutex_destroy(&master->lock_gameservers);
    pthread_mutex_destroy(&master->lock_clients);

    free(master);
 }
