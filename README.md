# Monitoring File Access with eBPF

When reading a file on your computer, the following diagram is roughly what happens:

```mermaid
flowchart TD
   
    users(["Users \n[root, logan, ...]"])
    os(((Operating\nSystem)))
    disk[(Files on \nDisk)]
    syscall("execute\nread(fd)")
    style syscall fill:#bbf,stroke:#f66,stroke-width:2px,color:#fff,stroke-dasharray: 5 5
    users -->|"cat secret.txt"| os
    os -->|"{data}"| users
    disk --> |"{data}"|os
    os --> |fd|syscall
    syscall --> disk


    
    us(Userspace)---ks
    ks(Kernel Space)----hw(Hardware)
    linkStyle 5 stroke:#fff,stroke-width:4px,color:red;
    linkStyle 6 stroke:#fff,stroke-width:4px,color:red;
    linkStyle 6 stroke:#fff,stroke-width:4px,color:red;
    style us fill:#fff,stroke:#fff,stroke-width:2px,color:#00FF00,stroke-dasharray: 5 5    
    style ks fill:#fff,stroke:#fff,stroke-width:2px,color:#0000FF,stroke-dasharray: 5 5    
    style hw fill:#fff,stroke:#fff,stroke-width:2px,color:#FF0000,stroke-dasharray: 5 5    
    
    
```


Obviously there are more steps than this such as first using the open system call to get a file descriptor, checking the cache for the file before checking disk, etc.

But for all practical purposes the above model will do. In writing the process is:

1) Some userspace process is executed by some user. This program asks the operating system to read a file based on its current file descriptors.
2) The operating system will execute the read system call with the provided file descriptor e.g. read(fd).
3) The file data is returned by disk and passed all the way back up to the user.


