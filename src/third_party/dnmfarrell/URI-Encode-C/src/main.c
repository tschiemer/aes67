#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "minunit.h"
#include "uri_encode.h"

int tests_run = 0;

static char * test_uri_encode(const char *uri, const char *expected) {
  const size_t len = strlen(uri);
  char buffer[ len * 3 + 1 ];
  buffer[0] = '\0';
  uri_encode(uri, len,  buffer);
  const size_t match = strcmp(expected, buffer);
  printf("uri_encode() got: \"%s\" expected: \"%s\"\n", buffer, expected);
  mu_assert("Strings don't match", match == 0);
  return 0;
}

static char * test_uri_encode_len(const char *uri, const size_t len, const char *expected) {
  char buffer[ len * 3 + 1 ];
  buffer[0] = '\0';
  uri_encode(uri, len,  buffer);
  const size_t match = strcmp(expected, buffer);
  printf("uri_encode() got: \"%s\" expected: \"%s\"\n", buffer, expected);
  mu_assert("Strings don't match", match == 0);
  return 0;
}

static char * test_uri_decode(const char *uri, const char *expected) {
  const size_t len = strlen(uri);
  char buffer[ len + 1 ];
  buffer[0] = '\0';
  uri_decode(uri, len, buffer);
  const size_t match = strcmp(expected, buffer);
  printf("uri_decode() got: \"%s\" expected: \"%s\"\n", buffer, expected);
  mu_assert("Strings don't match", match == 0);
  return 0;
}

static char * test_uri_decode_len(const char *uri, const size_t len, const char *expected) {
  char buffer[ len + 1 ];
  buffer[0] = '\0';
  uri_decode(uri, len, buffer);
  const size_t match = strcmp(expected, buffer);
  printf("uri_decode() got: \"%s\" expected: \"%s\"\n", buffer, expected);
  mu_assert("Strings don't match", match == 0);
  return 0;
}

/* tests for encode_uri */
static char * test_encode_empty() {
  char * msg = test_uri_encode("","");
  return msg ? msg : 0;
}
static char * test_encode_something() {
  char * msg = test_uri_encode("something","something");
  return msg ? msg : 0;
}
static char * test_encode_space() {
  char * msg = test_uri_encode(" ","%20");
  return msg ? msg : 0;
}
static char * test_encode_percent() {
  char * msg = test_uri_encode("%%20","%25%2520");
  return msg ? msg : 0;
}
static char * test_encode_latin1() {
  char * msg = test_uri_encode("|abcå", "%7Cabc%C3%A5");
  return msg ? msg : 0;
}
static char * test_encode_symbols() {
  char * msg = test_uri_encode("~*'()", "~%2A%27%28%29");
  return msg ? msg : 0;
}
static char * test_encode_angles() {
  char * msg = test_uri_encode("<\">", "%3C%22%3E");
  return msg ? msg : 0;
}
static char * test_encode_middle_null() {
  char * msg = test_uri_encode("ABC\0DEF", "ABC");
  return msg ? msg : 0;
}
static char * test_encode_middle_null_len() {
  char * msg = test_uri_encode_len("ABC\0DEF", 7, "ABC%00DEF");
  return msg ? msg : 0;
}
static char * test_encode_latin1_utf8() {
  char * msg = test_uri_encode("åäö", "%C3%A5%C3%A4%C3%B6");
  return msg ? msg : 0;
}
static char * test_encode_utf8() {
  char * msg = test_uri_encode("❤","%E2%9D%A4");
  return msg ? msg : 0;
}

/* tests for decode_uri */
static char * test_decode_empty() {
  char * msg = test_uri_decode("","");
  return msg ? msg : 0;
}
static char * test_decode_something() {
  char * msg = test_uri_decode("something","something");
  return msg ? msg : 0;
}
static char * test_decode_something_percent() {
  char * msg = test_uri_decode("something%", "something%");
  return msg ? msg : 0;
}
static char * test_decode_something_percenta() {
  char * msg = test_uri_decode("something%a", "something%a");
  return msg ? msg : 0;
}
static char * test_decode_something_zslash() {
  char * msg = test_uri_decode("something%Z/", "something%Z/");
  return msg ? msg : 0;
}
static char * test_decode_space() {
  char * msg = test_uri_decode("%20", " ");
  return msg ? msg : 0;
}
static char * test_decode_percents() {
  char * msg = test_uri_decode("%25%2520", "%%20");
  return msg ? msg : 0;
}
static char * test_decode_latin1() {
  char * msg = test_uri_decode("%7Cabc%C3%A5", "|abcå");
  return msg ? msg : 0;
}
static char * test_decode_symbols() {
  char * msg = test_uri_decode("~%2A%27%28%29", "~*'()");
  return msg ? msg : 0;
}
static char * test_decode_angles() {
  char * msg = test_uri_decode("%3C%22%3E", "<\">");
  return msg ? msg : 0;
}
static char * test_decode_middle_null() {
  char * msg = test_uri_decode("ABC%00DEF", "ABC\0");
  return msg ? msg : 0;
}
static char * test_decode_middle_null_len() {
  char * msg = test_uri_decode_len("ABC%00DEF", 9, "ABC\0DEF");
  return msg ? msg : 0;
}

static char * all_tests() {
  mu_run_test(test_encode_empty);
  mu_run_test(test_encode_something);
  mu_run_test(test_encode_percent);
  mu_run_test(test_encode_space);
  mu_run_test(test_encode_empty);
  mu_run_test(test_encode_latin1);
  mu_run_test(test_encode_symbols);
  mu_run_test(test_encode_angles);
  mu_run_test(test_encode_middle_null);
  mu_run_test(test_encode_middle_null_len);
  mu_run_test(test_encode_latin1_utf8);
  mu_run_test(test_encode_utf8);
  mu_run_test(test_decode_empty);
  mu_run_test(test_decode_something);
  mu_run_test(test_decode_something_percent);
  mu_run_test(test_decode_something_percenta);
  mu_run_test(test_decode_something_zslash);
  mu_run_test(test_decode_space);
  mu_run_test(test_decode_percents);
  mu_run_test(test_decode_latin1);
  mu_run_test(test_decode_symbols);
  mu_run_test(test_decode_angles);
  mu_run_test(test_decode_middle_null);
  mu_run_test(test_decode_middle_null_len);
  return 0;
}

int main(int argc, char **argv) {
   char *result = all_tests();
   if (result != 0) {
       printf("%s\n", result);
   }
   else {
       printf("ALL TESTS PASSED\n");
   }
   printf("Tests run: %d\n", tests_run);

   return result != 0;
}
