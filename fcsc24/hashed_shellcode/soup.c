#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void sha256_string(char *string, char *output) /* from https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c */
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(output, &sha256);
}

const char alphabet [79] = "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
const char target [4] = {0x52, 0x5e, 0x0f, 0x5};

int main() {
  char target [4] = {0x52, 0x5e, 0x0f, 0x5}; // push rdx; pop rsi; syscall
  char test[33];
  test[0] = 'F';
  test[1] = 'C';
  test[2] = 'S';
  test[3] = 'C';
  test[4] = '_';
  test[32] = 0;
  unsigned char idx[32];
  char hash[SHA256_DIGEST_LENGTH];
  int fd = open("/dev/urandom",O_RDONLY); // fastest way to read random indices that I figured out
  size_t l = strlen(alphabet);
  for(;;) {
    read(fd,&idx,32);
    for(int i = 5 ; i < 32 ; ++i) {
      test[i] = alphabet[idx[i]%l];
      sha256_string(test,hash);
    }
    //printf("%s\n",test);
    if(!strncmp(target,hash,4)) {
      printf("OK: %s\n",test);
      exit(1337);
    }
  }
}
