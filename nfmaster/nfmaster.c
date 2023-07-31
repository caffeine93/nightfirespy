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

 #define MAX_PKT_SZ      1024
 #define MAX_PKT_KEY_LEN 32
 #define MAX_PKT_VAL_LEN 64
 #define PKT_INVALID_KEY -1
 #define SECURE_KEY_SZ    6

 struct pkt_key {
     uint8_t key;
     char str[MAX_PKT_KEY_LEN];
 };

 /* server -> master */
 enum heartbeat_pkt {
     GAMESERVER_HEARTBEAT_PKT_PORT,
     GAMESERVER_HEARTBEAT_PKT_GAMENAME,
     GAMESERVER_HEARTBEAT_PKT_STATECHANGED,
     GAMESERVER_HEARTBEAT_PKT_MAX
 };

 static struct pkt_key pkt_gameserver_heartbeat_keys[] = {
     {GAMESERVER_HEARTBEAT_PKT_PORT, "heartbeat"},
     {GAMESERVER_HEARTBEAT_PKT_GAMENAME, "gamename"},
     {GAMESERVER_HEARTBEAT_PKT_STATECHANGED, "statechanged"},
     {PKT_INVALID_KEY, ""}
 };

 /* server -> master */
 enum status_rsp_pkt {
     GAMESERVER_STATUS_RSP_PKT_GAMENAME,
     GAMESERVER_STATUS_RSP_PKT_GAMEVER,
     GAMESERVER_STATUS_RSP_PKT_DEDICATED,
     GAMESERVER_STATUS_RSP_PKT_GAMEMODE,
     GAMESERVER_STATUS_RSP_PKT_GAMETYPE,
     GAMESERVER_STATUS_RSP_PKT_HOSTPORT,
     GAMESERVER_STATUS_RSP_PKT_MAPNAME,
     GAMESERVER_STATUS_RSP_PKT_MAXPLAYERS,
     GAMESERVER_STATUS_RSP_PKT_HOSTNAME,
     GAMESERVER_STATUS_RSP_PKT_NUMPLAYERS,
     GAMESERVER_STATUS_RSP_PKT_PASSWORD,
     GAMESERVER_STATUS_RSP_PKT_TIMELIMIT,
     GAMESERVER_STATUS_RSP_PKT_FRAGLIMIT,
     GAMESERVER_STATUS_RSP_PKT_CTFLIMIT,
     GAMESERVER_STATUS_RSP_PKT_TEAMPLAY,
     GAMESERVER_STATUS_RSP_PKT_FRIENDLYFIRE,
     GAMESERVER_STATUS_RSP_PKT_WEAPONSTAY,
     GAMESERVER_STATUS_RSP_PKT_BOTSMODE,
     GAMESERVER_STATUS_RSP_PKT_FINAL,
     GAMESERVER_STATUS_RSP_PKT_QUERYID,
     GAMESERVER_STATUS_RSP_PKT_MAX
 };
 /* master -> client */
 enum client_secure {
     CLIENT_SECURE_PKT_BASIC,
     CLIENT_SECURE_PKT_SECURE,
     CLIENT_SECURE_PKT_MAX
 };

 static struct pkt_key pkt_client_secure_keys[] = {
     {CLIENT_SECURE_PKT_BASIC, "basic"},
     {CLIENT_SECURE_PKT_SECURE, "secure"},
     {PKT_INVALID_KEY, ""}
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

 static struct pkt_key pkt_client_validate_keys[] = {
     {CLIENT_VALIDATE_PKT_GAMENAME, "gamename"},
     {CLIENT_VALIDATE_PKT_GAMEVER, "gamever"},
     {CLIENT_VALIDATE_PKT_LOCATION, "location"},
     {CLIENT_VALIDATE_PKT_VALIDATE, "validate"},
     {CLIENT_VALIDATE_PKT_ENCTYPE, "enctype"},
     {CLIENT_VALIDATE_PKT_FINAL, "final"},
     {CLIENT_VALIDATE_PKT_QUERYID, "queryid"},
     {PKT_INVALID_KEY, ""}
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
     case GAMESERVER_STAGE_HEARTBEAT_REQ:
        INFO("HEARTBEAT_REQ");
        break;
     case GAMESERVER_STAGE_VALIDATE_REQ:
        INFO("VALIDATE_REQ");
        break;
     case GAMESERVER_STAGE_VALIDATE_RSP:
        INFO("VALIDATE_RSP");
        break;
     case GAMESERVER_STAGE_STATUS_REQ:
        INFO("STATUS_REQ");
        break;
     case GAMESERVER_STAGE_STATUS_RSP:
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
     case CLIENT_STAGE_SECURE_REQ:
        INFO("SECURE_REQ");
        break;
     case CLIENT_STAGE_SECURE_RSP:
        INFO("SECURE_RSP");
        break;
     case CLIENT_STAGE_SERVER_LIST_REQ:
        INFO("SERVER_LIST_REQ");
        break;
     case CLIENT_STAGE_SERVER_LIST_RSP:
        INFO("SERVER_LIST_RSP");
        break;
     default:
        INFO("UNKNOWN");
        break;
     }
 }

 static inline uint8_t* pkt_put_key_value(struct pkt_key *pkt_key, uint8_t key, char *val, uint8_t *pkt)
 {
     uint8_t *curr_pkt = pkt;

     while (pkt_key->key != PKT_INVALID_KEY) {
        if (pkt_key->key == key) {
            *curr_pkt = '\\';
            (*curr_pkt)++;
            strncpy(curr_pkt, pkt_key->str, MAX_PKT_KEY_LEN);
            /* key/value strings are NOT null-terminted in packages */
            curr_pkt += strlen(pkt_key->str);
            *curr_pkt = '\\';
            (*curr_pkt)++;
            strncpy(curr_pkt, val, MAX_PKT_VAL_LEN);
            curr_pkt += strlen(val);
            return curr_pkt;
        }
        pkt_key++;
     }

     return NULL;
 }

 static char *pkt_get_value(struct pkt_key *pkt_key, uint8_t key, uint8_t *pkt)
 {
     uint8_t *curr_pkt = pkt;
     char *key_str = NULL;

     while (pkt_key->key != PKT_INVALID_KEY) {
        if (pkt_key->key == key) {
            key_str = pkt_key->str;
            break;
        }
     }

     if (!key_str)
        return NULL;

     while (*pkt != '\0') {
        /* extract key */
        if (*pkt == '\\') {
            pkt++;
            /* invalid packet, key can't be empty */
            if ((*pkt == '\0') || (*pkt == '\\'))
                return 1;

            /* found the desired key */
            if (!strncmp(pkt, key_str, strlen(key_str))) {
                pkt += strlen(key_str);
                /* missing delimiter after key */
                if ((*pkt == '\0') || (*pkt != '\\'))
                    return 1;

                pkt++;

                /* find the end of the value */
                curr_pkt = pkt;
                while ((curr_pkt != '\0') && (curr_pkt != '\\'))
                    curr_pkt++;

                return strndup(pkt, curr_pkt - pkt);
            }
        }
     }

     return NULL;
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
     char *str_val = NULL;
     uint32_t statechanged = 0;
     struct GameServerNF *gameserver = NULL;

     gameserver = malloc(sizeof(*gameserver));
     if (!gameserver)
         return -ENOMEM;

     str_val = pkt_get_value(pkt_gameserver_heartbeat_keys, GAMESERVER_HEARTBEAT_PKT_PORT, packet);
     if (!str_val) {
         INFO("Heartbeat: bad packet -> missing port param");
         ret = -EINVAL;
         goto out;
     }
     free(str_val);

     str_val = pkt_get_value(pkt_gameserver_heartbeat_keys, GAMESERVER_HEARTBEAT_PKT_GAMENAME, packet);
     if (!str_val) {
         INFO("Heartbeat: bad packet -> empty gamename param\n");
         ret = -EINVAL;
         goto out;
     }
     free(str_val);

     str_val = pkt_get_value(pkt_gameserver_heartbeat_keys, GAMESERVER_HEARTBEAT_PKT_STATECHANGED, packet);
     if (!str_val) {
         INFO("Heartbeat: empty 'statechanged', accepting anyway...\n");
         gameserver->statechanged = 0;
     }
     else {
         ret = sscanf(str_val, "%u", &statechanged);
         if (ret < 0) {
             INFO("Heartbeat: invalid 'statechanged't, accepting anyway...\n");
             gameserver->statechanged = 0;
          }
         else
             gameserver->statechanged = statechanged;
     }

     gameserver->conn_stage = GAMESERVER_STAGE_HEARTBEAT_REQ;

out:
     free(str_val);
     return ret;
 }

 static int32_t process_status(uint8_t *packet, ssize_t size)
 {
     (void)packet;
     (void)size;

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

  static enum client_stage client_send_secure_req(struct ClientNF *client)
 {
     uint8_t pkt[MAX_PKT_SZ] = {'\0'};
     char secure_key[SECURE_KEY_SZ];
     time_t time_seed;
     uint8_t *pkt_bldr = NULL;

     srand((unsigned) time(&time_seed));

     for (uint8_t i = 0; i < SECURE_KEY_SZ; i++)
            secure_key[i] = rand() % 0xff;

     pkt_bldr = pkt_put_key_value(pkt_client_secure_keys, CLIENT_SECURE_PKT_BASIC, "", pkt);
     if (!pkt_bldr)
        return CLIENT_STAGE_INVALID;

     pkt_bldr = pkt_put_key_value(pkt_client_secure_keys, CLIENT_SECURE_PKT_SECURE, secure_key, pkt_bldr);
     if (!pkt_bldr)
        return CLIENT_STAGE_INVALID;

     send(client->sock, pkt, pkt_bldr - pkt + 1, 0);

     return CLIENT_STAGE_SECURE_RSP;
 }

 static enum client_stage client_parse_secure_rsp(struct ClientNF *client)
 {
     uint8_t pkt[MAX_PKT_SZ] = {'\0'};
     char *str_val = NULL;
     enum client_stage ret = CLIENT_STAGE_SERVER_LIST_REQ;

     recv(client->sock, pkt, MAX_PKT_SZ, 0);

     str_val = pkt_get_value(pkt_client_validate_keys, CLIENT_VALIDATE_PKT_GAMENAME, pkt);
     if (!str_val)
        return CLIENT_STAGE_INVALID;

     if (strncmp(str_val, "jbnightfire", strlen(str_val)))
         ret = CLIENT_STAGE_INVALID;
         free(str_val);

     return ret;
 }

 static enum client_stage client_parse_server_list_req(struct ClientNF *client)
 {
     return CLIENT_STAGE_SERVER_LIST_RSP;
 }

 static enum client_stage client_send_server_list_rsp(struct ClientNF *client)
 {
     return CLIENT_STAGE_INVALID;
 }

 static enum client_stage process_client(struct ClientNF *client)
 {
     enum client_stage ret;

     if (!client)
        return CLIENT_STAGE_INVALID;

     switch(client->conn_stage) {
        case CLIENT_STAGE_SECURE_REQ:
            ret = client_send_secure_req(client);
            break;
        case CLIENT_STAGE_SECURE_RSP:
            ret = client_parse_secure_rsp(client);
            break;
        case CLIENT_STAGE_SERVER_LIST_REQ:
            ret = client_parse_server_list_req(client);
            break;
        case CLIENT_STAGE_SERVER_LIST_RSP:
            ret = client_send_server_list_rsp(client);
            break;
        default:
            return CLIENT_STAGE_INVALID;
     }

     return ret;
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
         client->conn_stage = CLIENT_STAGE_SECURE_REQ;
         while((client->conn_stage = process_client(client)) != CLIENT_STAGE_INVALID);

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
