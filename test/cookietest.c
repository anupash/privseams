/*

export MALLOC_TRACE=malloctrace-crtest;rm -f $MALLOC_TRACE;gcc -g -O3 -Wall -Wno-unused -o crtest crtest.c ../tools/crypto.c ../tools/debug.c -lcrypto && ./crtest;mtrace crtest malloctrace-crtest

*/

#include <string.h>
#include <netinet/in.h>
#include <limits.h>
#include <mcheck.h>
#include "../tools/crypto.h"

int main(int argc,char **argv) {

  int err = 0;

  struct hip_birthday_cookie testcookie;
  struct hip_birthday_cookie savedcookie;

  /* Enable malloc debugging. When the mtrace function is called it looks for
     an environment variable named MALLOC_TRACE.  This variable is
     supposed to contain a valid file name. */
  mtrace();

  memset(&savedcookie, 0, sizeof(struct hip_birthday_cookie));
  memset(&testcookie,  0, sizeof(struct hip_birthday_cookie));

  // generate responder cookie

  // .. generate values I and J and select K ..
  // initialize cookie and calculate hash_target (challenge)
  /* err = init_cookie(&savedcookie,
		       HIP_R1_COOKIE, // type
		       0xaabbccdd00112233ULL, // i
		       0x33445566ddaaccffULL, //j
		       13ULL, //k
		       0x55665566aaffaaffULL);
*/
  err = init_cookie(&savedcookie,
		       HIP_R1_COOKIE, // type
		       0ULL, // i
		       0ULL, //j
		       64ULL, //k
		       0ULL);
  if (err) {
    HIP_INFO("fail: init_cookie err=%d\n", err);
    exit(1);
  }
 
  // .. send cookie R1 ..

  // received gets values from R1
  testcookie.random_i = savedcookie.random_i;
  testcookie.random_j_k = savedcookie.random_j_k;
  testcookie.hash_target = savedcookie.hash_target;
  testcookie.type = htons(HIP_I2_COOKIE);
  testcookie.length = htons(36);
  testcookie.reserved = 0;
  // onko tämä tarpeen ? : testcookie.birthday = savedcookie.birthday;
  // pois: testcookie.random_j_k = 0; // initiator calculates this 

  err = solve_puzzle(&testcookie);
  if (err) {
    HIP_INFO("fail: solve_puzzle err=%d\n", err);
    exit(1);
  } else {
    //    fprintf(stderr, "challenge-response:%llx\n", testcookie.);
    fprintf(stderr, "ret j_k:0x%llx=%llu\n", testcookie.random_j_k, testcookie.random_j_k);
    fprintf(stderr, "ret hash_target:0x%llx\n", testcookie.hash_target);
  }

  // .. send cookie I2 ..

  // responder validates received cookie
  err = validate_cookie(&savedcookie, &testcookie);
  if (err) {
    HIP_INFO("fail: validate_cookie err=%d\n", err);
    exit(1);
  } else {
    fprintf(stderr, "validate ok\n");
  }

  muntrace();

 out_err:
  HIP_INFO("exit=%d\n", err);
  return(0);
}
