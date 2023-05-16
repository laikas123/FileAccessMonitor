struct read_data_t {
   int pid;
   int uid;
   int fd;
   uint64_t inode;
   char command[30];
};




struct msg_t {
   char message[12];
};
