//#include "pch.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <sys/stat.h>
#include <signal.h>
#include <poll.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include "queue.h"
#include "../aesd-char-driver/aesd_ioctl.h"


typedef struct slist_data_s slist_data_t;
struct slist_data_s {
    int new_fd;
    const char * filename;
    pthread_mutex_t* fd_mutex;
    struct sockaddr_storage their_addr;
    bool terminated;
    pthread_t thrd;
    SLIST_ENTRY(slist_data_s) entries;
};


void syslogaddrAccept(struct sockaddr* sockaddr)
{
    struct sockaddr_in* addr = (struct sockaddr_in*)sockaddr;
    struct sockaddr_in6* addripv6= (struct sockaddr_in6*)sockaddr;

    switch (sockaddr->sa_family)
    {
        case AF_INET:
            printf("Accepted connection from %u.%u.%u.%u\n", (addr->sin_addr.s_addr >> 0) & 0xFF, (addr->sin_addr.s_addr >> 8) & 0xFF, (addr->sin_addr.s_addr >> 16) & 0xFF, (addr->sin_addr.s_addr >> 24) & 0xFF);
            syslog(LOG_INFO, "Accepted connection from %u.%u.%u.%u", (addr->sin_addr.s_addr >> 0) & 0xFF, (addr->sin_addr.s_addr >> 8) & 0xFF, (addr->sin_addr.s_addr >> 16) & 0xFF, (addr->sin_addr.s_addr >> 24) & 0xFF);
            break;

        case AF_INET6:
            printf( "Accepted connection from %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
                addripv6->sin6_addr.__in6_u.__u6_addr16[0] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[1] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[2] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[3] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[4] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[5] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[6] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[7] & 0xFFFF
            );
            syslog(LOG_INFO, "Accepted connection from %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", 
                addripv6->sin6_addr.__in6_u.__u6_addr16[0] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[1] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[2] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[3] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[4] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[5] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[6] & 0xFFFF,
                addripv6->sin6_addr.__in6_u.__u6_addr16[7] & 0xFFFF
            );
            break;

    }

}

void syslogaddrClose(struct sockaddr* sockaddr)
{
    struct sockaddr_in* addr = (struct sockaddr_in*)sockaddr;
    struct sockaddr_in6* addripv6 = (struct sockaddr_in6*)sockaddr;

    switch (sockaddr->sa_family)
    {
    case AF_INET:
        printf("Closed connection from %u.%u.%u.%u\n", (addr->sin_addr.s_addr >> 0) & 0xFF, (addr->sin_addr.s_addr >> 8) & 0xFF, (addr->sin_addr.s_addr >> 16) & 0xFF, (addr->sin_addr.s_addr >> 24) & 0xFF);
        syslog(LOG_INFO, "Closed connection from %u.%u.%u.%u", (addr->sin_addr.s_addr >> 0) & 0xFF, (addr->sin_addr.s_addr >> 8) & 0xFF, (addr->sin_addr.s_addr >> 16) & 0xFF, (addr->sin_addr.s_addr >> 24) & 0xFF);
        break;

    case AF_INET6:
        printf("Closed connection from %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
            addripv6->sin6_addr.__in6_u.__u6_addr16[0] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[1] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[2] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[3] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[4] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[5] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[6] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[7] & 0xFFFF
        );
        syslog(LOG_INFO, "Closed connection from %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
            addripv6->sin6_addr.__in6_u.__u6_addr16[0] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[1] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[2] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[3] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[4] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[5] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[6] & 0xFFFF,
            addripv6->sin6_addr.__in6_u.__u6_addr16[7] & 0xFFFF
        );
        break;

    }

}

int open_r(slist_data_t* datap)
{
    int fd = open(datap->filename, O_RDONLY); //clear file
    if (fd == -1)
    {
        syslog(LOG_ERR, "Open file %s error: %d", datap->filename, errno);
    }
    return fd;
}

int open_w(slist_data_t* datap)
{
    int fd = open(datap->filename, O_WRONLY | O_APPEND); //clear file
    if (fd == -1)
    {
        syslog(LOG_ERR, "Open file %s error: %d", datap->filename, errno);
    }
    return fd;
}


volatile bool Ctrl_C_Event = false;
void signal_callback_handler(int signum)
{
    switch (signum)
    {
    case SIGTERM:
    case SIGINT:
        //TRACE_LEV(TRACE_INFO, _T("\nSIGINT\n")); 
        Ctrl_C_Event = true;
        break;
    case SIGPIPE: //socket send() in certe situazioni genera questo segnale, vedi write() EPIPE error
        //TRACE_LEV(TRACE_INFO, _T("SIGPIPE\n")); 
        break;
    }
}
bool mywrite(slist_data_t* datap, void* lpBuf, size_t nCount)
{
    int fd = open_w(datap);

    ssize_t nwr;
    char* ptr = (char*)lpBuf;
    size_t size = nCount;

    if (fd == -1)
    {
        return false;
    }

    
    while (size)
    {
        nwr = write(fd, ptr, size);
        if (nwr == -1)
        {
            close(fd);
            return false;
        }
        size -= nwr;
        ptr += nwr;
    }
    close(fd);
    return true;
}

int myselect(int fd, int to)
{
    if (fd < 0)
        return false;


    struct pollfd fdset;
    memset(&fdset, 0, sizeof(fdset));
    fdset.events = POLLPRI | POLLIN | POLLHUP | POLLNVAL | POLLERR;
    fdset.fd = fd;
    //printf("poll\n");
    int res = poll(&fdset, 1, to);
    //printf("revents%d=%X %d\n",to, fdset.revents,res);
    if (res == 0) //timeout
    {
        if (Ctrl_C_Event)
        {
            syslog(LOG_INFO, "-Signal exiting-\n");
            return -1;
        }
        return 0;
    }

    if (res == 1 && fdset.revents & POLLIN)
        return 1;
    
    return -1;
}

bool copy(slist_data_t* datap, int dfd, int cmd, int ofs)
{
    int sfd = open_r(datap);
    char buf[4096];
    int nrd;
    int nwr;

    if(cmd>=0)
    {
        struct aesd_seekto skt;
        skt.write_cmd=cmd;
        skt.write_cmd_offset=ofs;
        int err=ioctl(sfd,AESDCHAR_IOCSEEKTO,&skt);
        printf( "ioctl error:%d %d\n",err,errno);
    }

    do
    {
        nrd = read(sfd, buf, sizeof(buf));
        if (nrd < 0)
        {
            close(sfd);
            return false;
        }

        if(nrd>0)
        {
            nwr = write(dfd, buf, nrd);
            if (nwr < 0)
            {
                close(sfd);
                return false;
            }
        }

 
    } while (nrd>0);

 
    close(sfd);
    return true;
}

#define BUFFSIZE 4096
ssize_t rxframe(int fd, char** pbuff, ssize_t* psz)
{
    //printf("rxframe\n");
    char* tmp = NULL;
    ssize_t idx = 0;
    int nrd;
    int sel;
    while (!Ctrl_C_Event)
    {
        if (*psz <= idx)
        {
            tmp = (char*)realloc(*pbuff, *psz + BUFFSIZE);
            if (tmp != NULL)
            {
                *psz += BUFFSIZE;
                *pbuff = tmp;
            }
            else
            {
                printf( "realloc error:\n");
                syslog(LOG_ERR, "realloc error:");
                return -1;
            }
        }

        sel = myselect(fd, 100);
        if (sel ==1)
        {
            nrd = read(fd, &(*pbuff)[idx], *psz - idx);
            if (nrd == 0)
            {
                printf("EOF\n");
                return 0;
            }
            //printf("rx=%d %d\n", nrd, errno);
            while (nrd > 0)
            {
                if ((*pbuff)[idx] == '\n')
                {         
                    return idx + 1;
                }
                ++idx;
                --nrd;
            }
            

            if(nrd<0)
                return -1;
        }
        else if (sel == 0)
        {

        }
        else
            return -1;
    }
    return 0;
}



void* ClientApp(void *data)
{
    slist_data_t* datap = (slist_data_t*)data;

    int nrd;
    char* buff = NULL;
    ssize_t sz = 0;
     

    while (!Ctrl_C_Event)
    {
        nrd = rxframe(datap->new_fd, &buff, &sz);
        if (nrd > 0)
        {
            pthread_mutex_lock(datap->fd_mutex);
            buff[nrd]=0;
            if(strncmp(buff,"AESDCHAR_IOCSEEKTO:",19)==0)
            {
                printf("-> %s\n", buff);
                int i=19;
                while(buff[i]!=0)
                {
                    if(buff[i]==',')
                    {
                        buff[i]=0;
                        ++i;
                        break;
                    }
                    ++i;
                }
                
                int ofs=atoi(&buff[i]);
                int cmd=atoi(&buff[19]);
                printf("AESDCHAR_IOCSEEKTO: %d %d -> %s\n", cmd, ofs,buff);
                
                if (!copy(datap, datap->new_fd,cmd,ofs))
                {
                    printf("copy error: %d\n", errno);
                    syslog(LOG_ERR, "Write file error: %d", errno);
                    pthread_mutex_unlock(datap->fd_mutex);
                    break;
                }
            }
            else
            {
                if (!mywrite(datap, buff, nrd))
                {
                    printf("Write file error: %d\n", errno);
                    syslog(LOG_ERR, "Write file error: %d", errno);
                    pthread_mutex_unlock(datap->fd_mutex);
                    break;
                }
                else if (!copy(datap, datap->new_fd,-1,0))
                {
                    printf("copy error: %d\n", errno);
                    syslog(LOG_ERR, "Write file error: %d", errno);
                    pthread_mutex_unlock(datap->fd_mutex);
                    break;
                }
            }

            pthread_mutex_unlock(datap->fd_mutex);

        }
        else if (nrd == 0)
        {
            shutdown(datap->new_fd, SHUT_RDWR);
            //close(new_fd);
            //new_fd = -1;
            //syslogaddrClose((struct sockaddr*)&their_addr);
            break;
        }
        else
        {
            if (datap->new_fd != -1)
            {
                shutdown(datap->new_fd, SHUT_RDWR);
                //close(new_fd);
                break;
            }
            break;
        }

    }

    syslogaddrClose((struct sockaddr*)&datap->their_addr);

    if (buff != NULL)
    {
        free(buff);
        buff = NULL;
    }
    datap->terminated = true;
    //printf("terminated\n");
    return (void *)0;
}

unsigned int getclock_ms(void)
{
    struct timespec t;
    int rc;
    unsigned int time = 0;

    rc = clock_gettime(CLOCK_MONOTONIC, &t);
    if (rc == 0)
    {
        time = t.tv_sec * 1000;
        time += t.tv_nsec / 1000000;
    }
    return time;
}


void* timerapp(void* data)
{
    slist_data_t* datap = (slist_data_t*)data;
    //printf("timerapp\n");
    unsigned int dt;
    unsigned int t0 = getclock_ms();
    char buff[256];


    while (!Ctrl_C_Event)
    {
        usleep(100);
        dt = getclock_ms() - t0;
        if(dt>10000)
        {
            t0 = getclock_ms();
            pthread_mutex_lock(datap->fd_mutex);
            
            struct timeval tv;
            struct tm time;
            gettimeofday(&tv, NULL);
            localtime_r(&tv.tv_sec, &time);
            strftime(buff, sizeof(buff)-1, "timestamp:%Y/%m/%d %H:%M:%S\n", &time);
            printf("%s",buff);
            
            int fd = open_w(datap);
            if(fd>=0)
            {
                write(fd, buff, strlen(buff));
            }
            close(fd);
            
            pthread_mutex_unlock(datap->fd_mutex);
        }
    }
    datap->terminated = true;
    //printf("timerapp terminated\n");
    return NULL;
}

int main(int argc, const char* argv[])
{
    int status;
    struct addrinfo hints;
    struct addrinfo* servinfo;  // will point to the results
    int sockfd = -1;
    pthread_mutex_t file_mutex;
    pthread_mutex_init(&file_mutex, NULL);
    
    signal(SIGINT, signal_callback_handler);
    signal(SIGTERM, signal_callback_handler);
    signal(SIGPIPE, signal_callback_handler);

    openlog(NULL, 0, LOG_USER);

    printf("startapp\n");

 

   
    

    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    if ((status = getaddrinfo(NULL, "9000", &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(-1);
    }

    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sockfd == -1)
    {
        fprintf(stderr, "socket error: %d\n", errno);
        exit(-1);
    }
    int blen = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&blen, sizeof(blen)) != 0)
    {
        fprintf(stderr, "setsockopt error: %d\n", errno);
        exit(-1);
    }

    if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) != 0)
    {
        fprintf(stderr, "bind error: %d\n", errno);
        freeaddrinfo(servinfo); // free the linked-list
        if (sockfd != -1)
            close(sockfd);
        exit(-1);
    }
    freeaddrinfo(servinfo); // free the linked-list

    if (argc > 1 && strcmp(argv[1], "-d") == 0)
    {
        if (daemon(0, 0))
        {
            perror("daemon");
            if (sockfd != -1)
                close(sockfd);
            exit(-1);
        }
    }

    
#ifndef USE_AESD_CHAR_DEVICE
    int fd = open("/var/tmp/aesdsocketdata", O_CREAT | O_RDWR | O_TRUNC, 0644); //clear file
    if (fd == -1)
    {
        syslog(LOG_ERR, "Open file %s error: %d", "/var/tmp/aesdsocketdata", errno);
        if (sockfd != -1)
            close(sockfd);
        exit(-1);
    }
    close(fd);
#endif

    if (listen(sockfd, 5) != 0)
    {
        fprintf(stderr, "listen error: %d\n", errno);
        syslog(LOG_ERR, "listen error: %d", errno);
        if (sockfd != -1)
            close(sockfd);
        exit(-1);
    }


    slist_data_t* datap = NULL;
    slist_data_t* tmp = NULL;
    SLIST_HEAD(slisthead, slist_data_s) head;
    SLIST_INIT(&head);

    

#ifndef USE_AESD_CHAR_DEVICE
    datap = malloc(sizeof(slist_data_t));
    datap->new_fd = -1;
    datap->fd_mutex = &file_mutex;
    datap->terminated = false;
    datap->filename = "/var/tmp/aesdsocketdata";
    if (pthread_create(&datap->thrd, NULL, timerapp, datap)) {
        perror("ERROR creating thread.");
        free(datap);
    }
    else
    {
        SLIST_INSERT_HEAD(&head, datap, entries);
    }
#endif // !USE_AESD_CHAR_DEVICE
    
    
    

    

    struct sockaddr_storage their_addr;
    int new_fd = -1;
    socklen_t addr_size;
    
    int sel;
    while(!Ctrl_C_Event)
    {
        sel = myselect(sockfd, 100);
        if(sel==1)
        {
            SLIST_FOREACH_SAFE(datap, &head, entries, tmp)
            {
                if(datap->terminated)
                {
                    void** __thread_return=NULL;
                    pthread_join(datap->thrd, __thread_return);
                    if(datap->new_fd>0)
                        close(datap->new_fd);
                    SLIST_REMOVE(&head, datap, slist_data_s, entries);
                    free(datap);
                }
            }


            addr_size = sizeof their_addr;
            new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &addr_size);
            //printf("accept %d\n", new_fd);
            
            if (new_fd != -1)
            {
                syslogaddrAccept((struct sockaddr*)&their_addr);
                datap = malloc(sizeof(slist_data_t));
                datap->new_fd = new_fd;
#ifndef USE_AESD_CHAR_DEVICE
                datap->filename = "/var/tmp/aesdsocketdata";
                printf("use %s\n", datap->filename);
#else
                
                datap->filename = "/dev/aesdchar";
                printf("use %s\n", datap->filename);
#endif // !USE_AESD_CHAR_DEVICE
                datap->fd_mutex = &file_mutex;
                datap->their_addr = their_addr;
                datap->terminated = false;
                if (pthread_create(&datap->thrd, NULL, ClientApp, datap)) {
                    perror("ERROR creating thread.");
                    free(datap);
                }
                else
                {
                    SLIST_INSERT_HEAD(&head, datap, entries);
                }
                
                
            }
            else
            {
                fprintf(stderr, "accept error: %d\n", errno);
                syslog(LOG_ERR, "accept error: %d", errno);
                break;
            }
        }
        else if (sel == 0)
        {

        }
        else
        {
            break;
        }
    }

    if (Ctrl_C_Event)
    {
        syslog(LOG_INFO, "Signal exiting\n");
        fprintf(stderr, "Signal exiting\n");
    }

    Ctrl_C_Event = true;
    while (!SLIST_EMPTY(&head))
    {
        datap = SLIST_FIRST(&head);
        if (!datap->terminated)
        {
      
            if (datap->new_fd > 0)
            {
                shutdown(datap->new_fd, SHUT_RDWR);
                close(datap->new_fd);
            }
        }
        void** __thread_return=NULL;
        pthread_join(datap->thrd, __thread_return);
        SLIST_REMOVE_HEAD(&head, entries);
        free(datap);
    }

 
    

    if (sockfd != -1)
        close(sockfd);

   
    pthread_mutex_destroy(&file_mutex);
    return 0;
}