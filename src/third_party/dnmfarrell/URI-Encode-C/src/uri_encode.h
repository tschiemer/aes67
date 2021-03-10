/**
 * The original source was slightly modified, primarily introduced the fourth uri_encode
 * argument to designating the maximum allowed dst-len (which originally can be 3*len)
 * - For AES67 Framework
 */

#include <stdlib.h>
#include <inttypes.h>


ssize_t uri_encode (const char *src, const size_t len, char *dst, const size_t count);
size_t uri_decode (const char *src, const size_t len, char *dst);
