#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct init_request {
    int     magic;
    int     cmd;
    int     runlevel;
    int     sleeptime;
    char    data[368];
};

int main(int argc, char *argv[])
{
	int fd, ret;
	struct init_request request;

	fd = open("/dev/initctl", O_WRONLY);
	if (fd < 0) {
		perror("open initctl");
		return fd;
	}

	request.magic = 0x03091969; 
	request.cmd = 1;
	request.runlevel = '0';
	if (argc == 2 && !strcmp(argv[1], "-r"))
		request.runlevel = '6';
	ret = write(fd, &request, sizeof(request));
	printf("write %d\n", ret);
	return 0;
}
