/**
 * AES67 Framework
 * Copyright (C) 2021  Philip Tschiemer, https://github.com/tschiemer/aes67
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "aes67/utils/sapsrv.h"

#include "aes67/sap.h"

#include <stdlib.h>
#include <signal.h>
//#include <stdlib.h>

static volatile bool keep_running;

void sapsrv_callback(aes67_sapsrv_t sapserver, aes67_sapsrv_session_t sapsession, enum aes67_sap_event event, const struct aes67_sdp_originator * origin, u8_t * payload, u16_t payloadlen, void * user_data)
{
    printf("sapsrv callback: %d\n", event);
}

void sig_int(int sig)
{
    keep_running = false;
}

 int main(int argc, char * argv[]){

     aes67_time_init_system();
     aes67_timer_init_system();

     struct aes67_net_addr listen_addr = {
             .ipver = aes67_net_ipver_4,
             .addr = AES67_SAP_IPv4,
             .port = AES67_SAP_PORT
     };
     struct aes67_net_addr iface_addr = {
             .ipver = aes67_net_ipver_4,
             .addr = {192,168,2,138},
             .port = 0
     };
     aes67_sapsrv_t * sapsrv = aes67_sapsrv_start(&listen_addr, NULL, sapsrv_callback, NULL);

     if (sapsrv == NULL){
         printf("err\n");
         return EXIT_FAILURE;
     }

     aes67_sapsrv_setblocking(sapsrv, false);

     signal(SIGINT, sig_int);
     keep_running = true;
     while(keep_running){

         aes67_sapsrv_process(sapsrv);
     }

     aes67_sapsrv_stop(sapsrv);

     aes67_timer_deinit_system();
     aes67_time_deinit_system();

     return EXIT_SUCCESS;
 }