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
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <netinet/tcp.h>
 #include <errno.h>

 #include "nfmaster.h"
 #include "gsmsalg.h"

 #define MASTERSPY_TCP_PORT 28900
 #define MASTERSPY_UDP_PORT 27900

 #define MAX_UDP_BUFF_SIZE 2048
 #define MAX_CLIENT_BUFF_SIZE 1024

 #define SERVERLIST_CLEANUP_PERIOD_SEC 5 /* 5sec */
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

 #define NIGHTFIRE_GAMENAME "jbnightfire"
 #define NIGHTFIRE_GAMEKEY "S9j3L2"
 #define NIGHTFIRE_ENCTYPE_VER 2


 #define GAMESERVER_HEARTBEAT_INTERVAL 30 /* 30s */
 #define GAMESERVER_HEARTBEAT_INTERVAL_MARGIN 10 /* 10s */
 #define GAMESERVER_HEARTBEAT_INTERVAL_MAX  (GAMESERVER_HEARTBEAT_INTERVAL + GAMESERVER_HEARTBEAT_INTERVAL_MARGIN)

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

 static struct pkt_key pkt_client_list_keys[] = {
     {CLIENT_LIST_PKT_LIST, "list"},
     {CLIENT_LIST_PKT_GAMENAME, "gamename"},
     {CLIENT_LIST_PKT_FINAL, "final"},
     {PKT_INVALID_KEY, ""}
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

 static struct GameServerNF *get_gameserver_by_addr(struct MasterServerNF *master, struct sockaddr_in *addr)
 {
     struct GameServerNF *gameserver = NULL;

     STAILQ_FOREACH(gameserver, &master->gameservers, entry) {
         if ((gameserver->ip == addr->sin_addr.s_addr) && (gameserver->port == ntohs(addr->sin_port)))
            return gameserver;
     }

     return NULL;
 }

 static inline void add_gameserver(struct MasterServerNF *master, struct GameServerNF *gameserver)
 {
     pthread_mutex_lock(&master->lock_gameservers);
     STAILQ_INSERT_TAIL(&master->gameservers, gameserver, entry);
     pthread_mutex_unlock(&master->lock_gameservers);
 }

 static inline void update_gameserver_lastcomm_time(struct GameServerNF *gameserver)
 {
     clock_gettime(CLOCK_REALTIME, &gameserver->time_last_comm);
 }

 static void *serverlist_state_update(void *arg)
 {
     struct MasterServerNF *master = NULL;
     struct GameServerNF *gameserver = NULL;
     struct timespec poll_period = {
         .tv_sec = SERVERLIST_CLEANUP_PERIOD_SEC,
         .tv_nsec = 0,
     };
     struct timespec now_time = {0};

     if (!arg)
        return NULL;

    master = (struct MasterServerNF *)arg;

    clock_gettime(CLOCK_REALTIME, &now_time);

    while (!master->cancel_threads) {
        INFO("Serverlist cleanup: started\n");
        STAILQ_FOREACH(gameserver, &master->gameservers, entry) {
            if (now_time.tv_sec - gameserver->time_last_comm.tv_sec > GAMESERVER_HEARTBEAT_INTERVAL_MAX) {
                    STAILQ_REMOVE(&master->gameservers, gameserver, GameServerNF, entry);
                    free(gameserver);
            }
        }
        INFO("Serverlist cleanup: completed\n");
        nanosleep(&poll_period, NULL);
    }

    return NULL;
 }

 static int32_t process_heartbeat(struct MasterServerNF *master, struct sockaddr_in *addr, uint8_t *packet, ssize_t size)
 {
     int32_t ret = 0;
     char *str_val = NULL;
     uint32_t statechanged = 0;
     struct GameServerNF *gameserver = NULL;
     uint8_t new_server = 0;
     char *port_end = NULL;

     gameserver = get_gameserver_by_addr(master, addr);
     if (!gameserver) {
         new_server = 1;
         gameserver = malloc(sizeof(*gameserver));
         if (!gameserver)
            return -ENOMEM;
     }

     gameserver->ip = addr->sin_addr.s_addr;

     str_val = pkt_get_value(pkt_gameserver_heartbeat_keys, GAMESERVER_HEARTBEAT_PKT_PORT, packet);
     if (!str_val) {
         INFO("Heartbeat: bad packet -> missing port param\n");
         ret = -EINVAL;
         goto out;
     }
     gameserver->port = strtoul(str_val, &port_end, 10);
     if (str_val != '\0' && port_end == '\0') {
        /* if server reports a different query port than from what it has sent the
         * heartbeat from, it's probably spoofing, thus reject the heartbeat */
        if (gameserver->port != ntohs(addr->sin_port)) {
            INFO("Heartbeat: bad packet -> stated query port doesn't match packet's originating port\n");
            ret = -EINVAL;
            goto out;
        }
     }
     else {
        INFO("Heartbeat: bad packet -> missing or invalid port param\n");
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
             INFO("Heartbeat: invalid 'statechanged', accepting anyway...\n");
             gameserver->statechanged = 0;
          }
         else
             gameserver->statechanged = statechanged;
     }

     update_gameserver_lastcomm_time(gameserver);
     gameserver->conn_stage = GAMESERVER_STAGE_HEARTBEAT_REQ;

out:
     free(str_val);
     if (new_server) {
        if (!ret)
            add_gameserver(master, gameserver);
        else
            free(gameserver);
     }

     return ret;
 }

 static int32_t process_status(struct MasterServerNF *master, struct sockaddr_in *addr, uint8_t *packet, ssize_t size)
 {
     (void)master;
     (void)addr;
     (void)packet;
     (void)size;

     /* TODO: implement status parsing + filtering based on server params in client reqs */

     return 0;
 }

 static int32_t process_gameserver_packet(struct MasterServerNF *master, struct sockaddr_in *addr, uint8_t *packet, ssize_t size)
 {
     if (!packet)
        return -EINVAL;
     if (!size)
        return 0;

     if (!strncmp(packet, "\\heartbeat\\", size - 1))
        return process_heartbeat(master, addr, packet, size);
     else if (!strncmp(packet, "\\gamename\\", size - 1))
        return process_status(master, addr, packet, size);
     else {
        INFO("Received invalid packet type on UDP sock\n");
        return -EINVAL;
     }

 }

 static void *gameservers_handler(void *arg)
 {
     int32_t ret = 0;
     struct MasterServerNF *master = NULL;
     struct sockaddr_in gameserver_addr = {0};
     socklen_t gameserver_addr_len = sizeof(gameserver_addr);
     uint8_t buff[MAX_UDP_BUFF_SIZE + 1] = {0};

     if (!arg)
        return NULL;

     master = (struct MasterServerNF *)arg;

     while (!master->cancel_threads) {
        ret = recvfrom(master->gameservers_sock, buff, MAX_UDP_BUFF_SIZE, 0,
                  (struct sockaddr *)&gameserver_addr, &gameserver_addr_len);
        if (ret > 0) {
            process_gameserver_packet(master, &gameserver_addr, buff, ret);
        }
     }
 }

 static inline void get_clienthandler_addr(struct sockaddr_in *addr)
 {
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
    addr->sin_port = htons(MASTERSPY_TCP_PORT);
 }

 static inline void get_gameserver_addr(struct sockaddr_in *addr)
 {
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
    addr->sin_port = htons(MASTERSPY_UDP_PORT);
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
        ERR("Failed to init cond for clients comm: %d\n", ret);
        return ret;
    }

    STAILQ_INIT(&(*master)->gameservers);
    STAILQ_INIT(&(*master)->clients);

    (*master)->clients_sock = socket(AF_INET, SOCK_STREAM, 0);
    if ((*master)->clients_sock == -1) {
        ERR("Failed to open TCP sock: %d\n", -errno);
        return -EFAULT;
    }

    get_clienthandler_addr(&addr);

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

    get_gameserver_addr(&addr);

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
     time_t time_seed;
     uint8_t *pkt_bldr = NULL;

     srand((unsigned) time(&time_seed));

     for (uint8_t i = 0; i < SECURE_KEY_CHALLENGE_SZ; i++)
            client->secure_key_challenge[i] = rand() % 0xff;

     client->secure_key_challenge[SECURE_KEY_CHALLENGE_SZ] = '\0';

     pkt_bldr = pkt_put_key_value(pkt_client_secure_keys, CLIENT_SECURE_PKT_BASIC, "", pkt);
     if (!pkt_bldr)
        return CLIENT_STAGE_INVALID;

     pkt_bldr = pkt_put_key_value(pkt_client_secure_keys, CLIENT_SECURE_PKT_SECURE, client->secure_key_challenge, pkt_bldr);
     if (!pkt_bldr)
        return CLIENT_STAGE_INVALID;

     send(client->sock, pkt, pkt_bldr - pkt + 1, 0);

     return CLIENT_STAGE_SECURE_RSP;
 }

 static enum client_stage client_parse_secure_rsp(struct ClientNF *client)
 {
     uint8_t pkt[MAX_PKT_SZ] = {'\0'};
     char *str_val = NULL;
     char *expected_validate = NULL;
     uint32_t enctype_ver = 0;
     enum client_stage ret = CLIENT_STAGE_SERVER_LIST_REQ;

     recv(client->sock, pkt, MAX_PKT_SZ, 0);

     str_val = pkt_get_value(pkt_client_validate_keys, CLIENT_VALIDATE_PKT_GAMENAME, pkt);
     if (!str_val)
        return CLIENT_STAGE_INVALID;

     if (strncmp(str_val, NIGHTFIRE_GAMENAME, strlen(str_val))) {
         ret = CLIENT_STAGE_INVALID;
         free(str_val);
         goto out;
     }
     free(str_val);

     str_val = pkt_get_value(pkt_client_validate_keys, CLIENT_VALIDATE_PKT_ENCTYPE, pkt);
     if (!str_val)
        return CLIENT_STAGE_INVALID;

     if (!isdigit(str_val[0]) || (atoi(str_val[0]) != NIGHTFIRE_ENCTYPE_VER)) {
         ret = CLIENT_STAGE_INVALID;
         free(str_val);
         goto out;
     }
     free(str_val);

     str_val = pkt_get_value(pkt_client_validate_keys, CLIENT_VALIDATE_PKT_VALIDATE, pkt);
     if (!str_val)
        return CLIENT_STAGE_INVALID;

     expected_validate = gsseckey(NULL, client->secure_key_challenge, NIGHTFIRE_GAMEKEY, NIGHTFIRE_ENCTYPE_VER);
     if (strncmp(str_val, expected_validate, strlen(expected_validate)))
        ret = CLIENT_STAGE_INVALID;

     free(str_val);
     free(expected_validate);

out:
     return ret;
 }

 static enum client_stage client_parse_server_list_req(struct ClientNF *client)
 {
     uint8_t pkt[MAX_PKT_SZ] = {'\0'};
     char *str_val = NULL;
     char *expected_validate = NULL;
     uint32_t enctype_ver = 0;
     enum client_stage ret = CLIENT_STAGE_SERVER_LIST_RSP;

     recv(client->sock, pkt, MAX_PKT_SZ, 0);

     str_val = pkt_get_value(pkt_client_list_keys, CLIENT_LIST_PKT_LIST, pkt);
     if (!str_val)
        return CLIENT_STAGE_INVALID;
     /* TODO: cmp list send? need to investigate more, ignore param for now */

     str_val = pkt_get_value(pkt_client_list_keys, CLIENT_LIST_PKT_GAMENAME, pkt);
     if (!str_val)
        return CLIENT_STAGE_INVALID;

     if (strncmp(str_val, NIGHTFIRE_GAMENAME, strlen(str_val))) {
         ret = CLIENT_STAGE_INVALID;
         free(str_val);
         goto out;
     }
     free(str_val);

     str_val = pkt_get_value(pkt_client_list_keys, CLIENT_LIST_PKT_FINAL, pkt);
     if (!str_val)
         ret = CLIENT_STAGE_INVALID;

     free(str_val);

out:
     return ret;
 }

 static enum client_stage client_send_server_list_rsp(struct MasterServerNF *master, struct ClientNF *client)
 {
     uint8_t pkt[MAX_PKT_SZ] = {'\0'};
     char ip_addr_str[INET_ADDRSTRLEN];
     char port_str[10];
     uint16_t pkt_free_space = MAX_PKT_SZ - 1;
     uint16_t encrypted_pkt_sz = 0;
     struct GameServerNF *gameserver = NULL;

     STAILQ_FOREACH(gameserver, &master->gameservers, entry) {
         if (inet_ntop(AF_INET, gameserver->ip, ip_addr_str, INET_ADDRSTRLEN))
            continue;

         snprintf(port_str, sizeof(port_str), "%u", gameserver->port);

         if (strlen(ip_addr_str) + 1 + strlen(port_str) + 1 > pkt_free_space)
            break;

         strncat(pkt, "\\", pkt_free_space);
         pkt_free_space--;
         strncat(pkt, ip_addr_str, pkt_free_space);
         pkt_free_space -= strlen(ip_addr_str);
         strncat(pkt, ":", pkt_free_space);
         pkt_free_space--;
         strncat(pkt, port_str, pkt_free_space);
         pkt_free_space -= strlen(port_str);
     }

     /* empty list only contains delimiters, TODO: check */
     if (!strlen(pkt))
        strncat(pkt, "\\\\", pkt_free_space);

     encrypted_pkt_sz = enctype2_encoder(NIGHTFIRE_GAMEKEY, pkt, strlen(pkt) + 1);
     send(client->sock, pkt, encrypted_pkt_sz, 0);

     /* this is the final stage and client can be invalidated now, this will in turn
      * close the connection and free the client resources in the handler thread */
     return CLIENT_STAGE_INVALID;
 }

 static enum client_stage process_client(struct MasterServerNF *master, struct ClientNF *client)
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
            ret = client_send_server_list_rsp(master, client);
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
         while (STAILQ_EMPTY(&master->clients) && !master->cancel_threads)
            pthread_cond_wait(&master->cond_clients_comm, &master->lock_clients);

         if (master->cancel_threads) {
            pthread_mutex_unlock(&master->lock_clients);
            goto out;
         }

         client = STAILQ_FIRST(&master->clients);
         STAILQ_REMOVE_HEAD(&master->clients, entry);
         pthread_mutex_unlock(&master->lock_clients);

         /* validate client and go through the list-fetch procedure */
         client->conn_stage = CLIENT_STAGE_SECURE_REQ;
         while((client->conn_stage = process_client(master, client)) != CLIENT_STAGE_INVALID);

         close(client->sock);
         free(client);
     }
out:
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

    master->cancel_threads = 0;

    ret = pthread_create(&master->serverlist_state_update, NULL, serverlist_state_update, master);
    if (ret)
        return -EFAULT;

    pthread_setname_np(master->serverlist_state_update, "nightfirespy_srvlst");

    ret = pthread_create(&master->gameservers_comm, NULL, gameservers_handler, master);
    if (ret)
        return -EFAULT;

    pthread_setname_np(master->serverlist_state_update, "nightfirespy_gamesrv");

    for (uint16_t i = 0; i < CLIENTS_COMM_POOL_SIZE; i++) {
        ret = pthread_create(&master->clients_comm_pool[i], NULL, client_handler, master);
        if (ret) {
            ERR("Failed to start thread %u for clients comm handling: %d\n", i, ret);
            /* TODO: what? */
        }
    }
    while (1) {
            ret = accept(master->clients_sock, (struct sockaddr *)&client_addr, &client_addr_len);
            if (ret == -1) {
                INFO("Client: error processing req -> failed to open sock: %d\n", -errno);
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
                INFO("Failed to set client TCP sock timeout: %d\n", -errno); /* TODO: ignore it? */

            /* insert into the client comm queue */
            pthread_mutex_lock(&master->lock_clients);
            STAILQ_INSERT_TAIL(&master->clients, gameclient, entry);
            pthread_mutex_unlock(&master->lock_clients);
            pthread_cond_signal(&master->cond_clients_comm);
    }

     return 0;
 }

 static inline void unblock_gameserver_handler(void)
 {
     struct sockaddr_in gameserver_addr;
     int dummy_sock = -1;

     get_gameserver_addr(&gameserver_addr);
     dummy_sock = socket(AF_INET, SOCK_DGRAM, 0);
     if (dummy_sock > 0) {
            sendto(dummy_sock, "cancel", strlen("cancel") + 1, 0, &gameserver_addr, sizeof(gameserver_addr));
            close(dummy_sock);
     }
 }
 void MasterServer_free(struct MasterServerNF *master)
 {
     struct ClientNF *client = NULL;

     if (!master)
        return;

    master->cancel_threads = 1;

    pthread_join(master->serverlist_state_update, NULL);
    /* gameservers_comm thread is blocked in recvfrom,
     * send dummy data to unblock and exit grecefully */
    unblock_gameserver_handler();
    pthread_join(master->gameservers_comm, NULL);

    pthread_cond_broadcast(&master->cond_clients_comm);
    for (uint16_t i = 0; i < CLIENTS_COMM_POOL_SIZE; i++)
        pthread_join(master->clients_comm_pool[i], NULL);

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
