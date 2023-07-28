/***************************************************************
 * Name:      main
 * Purpose:   Code for xxx
 * Author:    Luka Culic Viskota (luka.culic.viskota@gmail.com)
 * Created:   Tuesday 2022-10-18-17.24.13
 * Copyright: Luka Culic Viskota (https://microcafe.co)
 * License:
 **************************************************************/

 #include <stdlib.h>
 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <sys/queue.h>

 #include "nfmaster/nfmaster.h"

 int main(void)
 {
     struct MasterServerNF *master = NULL;
     int32_t ret = 0;

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
