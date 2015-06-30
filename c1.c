/* Fundamentals of Cryptography Problem Set 6
 * Cryptography System #1
 */

/* security parameter in bits */
#define N 80

#include "ext.h"
#include <stdlib.h>
#include <time.h>

unsigned char* gen_random(size_t num_bytes) {
  unsigned char *stream = malloc(num_bytes);
  size_t i;
  for (i = 0; i < num_bytes; i++) {
    stream[i] = rand();
  }
  return stream;
}

void print_bytes(unsigned char* bytes, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02X ", *bytes++);
  }
  printf("\n");
} 

int main(void) {
  int n_in_B = N / 8; /* security parameter in bytes */
  int crude_len = n_in_B;
  for (int n = n_in_B; n; n >>= 1) {
    crude_len *= n_in_B; 
  }
  int ext_len = n_in_B; 
  unsigned char* crude_rand = gen_random(crude_len);
  print_bytes(crude_rand, crude_len); 
  unsigned char* ext_rand = ext(crude_rand, crude_len, ext_len);
  print_bytes(ext_rand, ext_len); 
  return 0; 
} 
