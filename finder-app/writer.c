
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h> 

int main(int argc, const char** argv)
{
	openlog (NULL,0,LOG_USER);
	if(argc<3)
	{
		syslog(LOG_ERR,"%s", "invalid Number of arguments");
		syslog(LOG_ERR,"%s", "use writer <filepath> <string>");
		closelog();
		return 1;
	}
	
	syslog(LOG_DEBUG,"Writing %s to %s",argv[2],argv[1]);
	int fd= open(argv[1],O_CREAT | O_WRONLY | O_TRUNC,0644);
	if(fd==-1)
	{
		syslog(LOG_ERR,"Open file %s error: %d",argv[1],errno);
		closelog();
		return 1;
	}
	
	ssize_t nw=write(fd,argv[2],strlen(argv[2]));
	if(nw==-1)
	{
		syslog(LOG_ERR,"Write file %s error: %d",argv[1],errno);
		close(fd);
		closelog();
		return 1;
	}
	close(fd);
	closelog();
	return 0;
}
