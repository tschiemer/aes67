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

#include "aes67/utils/rtsp.h"

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static char * argv0;

static void help(FILE * fd)
{
    fprintf( fd,
             "Usage: %s\n"
            , argv0);
}


int main(int argc, char * argv[])
{
    argv0 = argv[0];

    u8_t sdp[1500];

    u8_t rtsp[] = "rtsp://192.168.2.199/by-foo";

    aes67_rtsp_describe_url(rtsp, sdp, sizeof(sdp));

    return EXIT_SUCCESS;
}