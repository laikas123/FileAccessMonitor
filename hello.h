struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
   char path2[16];
   unsigned int fd;
};

struct msg_t {
   char message[12];
};
