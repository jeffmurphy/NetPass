#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <stdio.h>

int main (int argc, char **argv) {

	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *s;

	ifap = (struct ifaddrs *)malloc(sizeof(struct ifaddrs));

	if (argc != 2) {
		printf("Usage: %s <ip address>\n", argv[0]);
		exit (1);
	}

	if (getifaddrs(&ifap) != 0) {
		perror("Unable to retrieve interfaces\n");
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET) {
			s  = (struct sockaddr_in *)ifa->ifa_addr;
			if (strcmp((char *)(inet_ntoa(s->sin_addr)), argv[1]) == 0) {
				printf("%s\n", ifa->ifa_name);
				break;
			}
		}
	}

	exit (0);
}
