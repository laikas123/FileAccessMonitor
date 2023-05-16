struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
   char path2[16];
   unsigned int fd;
};


struct openat_dat_t {
   int pid;
   int uid;
   int dirfd;
   char filename[50];
};

struct exit_openat_dat_t {
   int pid;
   int uid;
   int fd;
   char command[16];
};


struct exit_read_dat_t {
   int pid;
   int uid;
   long bytes_read;
   char command[16];
};

struct msg_t {
   char message[12];
};
