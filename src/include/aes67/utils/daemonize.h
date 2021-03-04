/**
 * @file daemonize.h
 * Helper to quickly daemonize the current process.
 *
 *
 * References:
 * Thanks to Pascal Werkl https://stackoverflow.com/a/17955149/1982142
 */

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

#ifndef AES67_UTILS_DAEMONIZE_H
#define AES67_UTILS_DAEMONIZE_H

#ifdef __cplusplus
extern "C" {
#endif

int aes67_daemonize();

#ifdef __cplusplus
}
#endif

#endif //AES67_UTILS_DAEMONIZE_H
