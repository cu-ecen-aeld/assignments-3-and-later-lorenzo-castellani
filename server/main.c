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
bool mywrite(int fd, void* lpBuf, size_t nCount)
{
    ssize_t nwr;
    char* ptr = (char*)lpBuf;
    size_t size = nCount;

    if (fd == -1)
        return false;

    
    while (size)
    {
        nwr = write(fd, ptr, size);
        if (nwr == -1)
            return false;
        size -= nwr;
        ptr += nwr;
    }
    return true;
}

bool myselect(int fd)
{
    struct pollfd fdset;
    memset(&fdset, 0, sizeof(fdset));
    fdset.events = POLLIN;
    fdset.fd = fd;
    //printf("poll\n");
    int res = poll(&fdset, 1, -1);
    //printf("res=%d\n", res);
    if (res == 1 && fdset.revents & POLLIN)
        return true;
    
    return false;
}

bool copy(int sfd, int dfd)
{
    char buf[4096];
    int nrd;
    int nwr;
    off_t pos = lseek(sfd, 0, SEEK_CUR);
    if (pos < 0)
        return false;
    lseek(sfd, 0, SEEK_SET);
    off_t cp = 0;
    do
    {
        nrd = read(sfd, buf, sizeof(buf));
        if (nrd < 0)
            return false;

        nwr = write(dfd, buf, nrd);
        if (nwr < 0)
            return false;

        cp += nwr;
    } while (cp<pos);

    lseek(sfd, pos, SEEK_SET);
    return true;
}

#define BUFFSIZE 200000
ssize_t rxframe(int fd, char** pbuff, ssize_t* psz)
{
    
    char* tmp = NULL;
    ssize_t idx = 0;
    int nrd;
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

        if (myselect(fd))
        {
            nrd = read(fd, &(*pbuff)[idx], *psz - idx - 1);
            //printf("rx=%d %d\n", nrd, errno);
            if (nrd > 0)
            {
                (*pbuff)[idx + nrd] = 0;
                while ((*pbuff)[idx] != 0)
                {
                    if ((*pbuff)[idx] == '\n')
                        return idx + 1;
                    ++idx;
                }
            }

            else
                return -1;
        }
        else
            return -1;
    }
    return 0;
}

int main(int argc, const char* argv[])
{
    int status;
    struct addrinfo hints;
    struct addrinfo* servinfo;  // will point to the results
    int sockfd = -1;
    
    signal(SIGINT, signal_callback_handler);
    signal(SIGTERM, signal_callback_handler);
    signal(SIGPIPE, signal_callback_handler);

    openlog(NULL, 0, LOG_USER);
    

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

    int fd = open("/var/tmp/aesdsocketdata", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd == -1)
    {
        syslog(LOG_ERR, "Open file %s error: %d", "/var/tmp/aesdsocketdata", errno);
        if (sockfd != -1)
            close(sockfd);
        exit(-1);
    }

    if (listen(sockfd, 5) != 0)
    {
        fprintf(stderr, "listen error: %d\n", errno);
        syslog(LOG_ERR, "listen error: %d", errno);
        if (sockfd != -1)
            close(sockfd);
        exit(-1);
    }

    struct sockaddr_storage their_addr;
    int new_fd = -1;
    socklen_t addr_size;
    int nrd;
    char* buff = NULL;
    ssize_t sz = 0;
   
    while(!Ctrl_C_Event)
    {
        if(myselect(sockfd))
        {
            addr_size = sizeof their_addr;
            new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &addr_size);
            //printf("accept %d\n", new_fd);
            
            if (new_fd != -1)
            {
                syslogaddrAccept((struct sockaddr*)&their_addr);
                
                while (!Ctrl_C_Event)
                {
                    nrd=rxframe(new_fd, &buff, &sz);
                    if (nrd > 0)
                    {
                        if (!mywrite(fd, buff, nrd))
                        {
                            printf("Write file error: %d", errno);
                            syslog(LOG_ERR, "Write file error: %d", errno);
                            break;
                        }
                        else if (!copy(fd, new_fd))
                        {
                            printf("copy error: %d\n", errno);
                            syslog(LOG_ERR, "Write file error: %d", errno);
                            break;
                        }
                    }
                    else
                    {
                        if (new_fd != -1)
                        {
                            shutdown(new_fd, SHUT_RDWR);
                            close(new_fd);
                            syslogaddrClose((struct sockaddr*)&their_addr);
                        }
                        break;
                    }

                }
                
            }
            else
            {
                fprintf(stderr, "accept error: %d\n", errno);
                syslog(LOG_ERR, "accept error: %d", errno);
                break;
            }
        }
        else
        {
            break;
        }
    }

    if (new_fd != -1)
    {
        shutdown(new_fd, SHUT_RDWR);
        close(new_fd);
        syslogaddrClose((struct sockaddr*)&their_addr);
    }

    

    if (sockfd != -1)
        close(sockfd);

    if (fd != -1)
        close(fd);

    if (buff != NULL)
    {
        free(buff);
        buff = NULL;
    }

    if(Ctrl_C_Event)
        fprintf(stderr, "Signal exiting\n");

    
    
    

    return 0;
}
