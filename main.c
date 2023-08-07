/***************************************************************
 * Name:      main
 * Purpose:   Code for main application utilizing the master API
 * Author:    Luka Culic Viskota (luka.culic.viskota@gmail.com)
 * Created:   Tuesday 2022-10-18-17.24.13
 * Copyright: Luka Culic Viskota (https://microcafe.co)
 * License:   GNU General Public License v2.0
 **************************************************************/

 #include <stdlib.h>
 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <unistd.h>
 #include <signal.h>
 #include <errno.h>

 #include "nfmaster/nfmaster.h"

 static struct MasterServerNF *master = NULL;

 static void sigint_handler(int signum)
 {
     printf("Master server shutdown initiated due to signal: %d\n", signum);
     MasterServer_free(master);
     printf("Master server shutdown completed\n");
     exit(0);
 }

 int main(void)
 {
     int32_t ret = 0;

     /* install signal handler */
     if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        printf("Failed to install signal handler: %d\n", -errno);
        return -1;
     }

     ret = MasterSever_init(&master);
     if (ret) {
        printf("Failed to init master server: %d\n", ret);
        return ret;
     }

     ret = MasterServer_start(master);
     if (ret)
        printf("Master server failed with: %d\n", ret);

     MasterServer_free(master);
     return 0;
 }
