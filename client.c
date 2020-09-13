#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

// #define PORT_NO 54321 /* PORT Number */
#define MAX_BUFFER_SIZE 4096

int main(int argc, char *argv[])
{
    int sockfd, numbytes;
    struct hostent *he;
    struct sockaddr_in their_addr; /* connector's address information */

    if (argc < 3)
    {
        fprintf(stderr, "usage: client_hostname\n");
        exit(1);
    }

    int PORT_NO = atoi(argv[2]);

    if ((he = gethostbyname(argv[1])) == NULL)
    { /* get the host info */
        herror("gethostbyname");
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }

    // Argument contains the program the client wishes to run
    char *program = argv[3];

    char args[MAX_BUFFER_SIZE];

    // Get all of the arguments for the program
    for (int i = 4; i < argc; i++)
    {
        strncat(args, argv[i], sizeof(argv[i]));
        strncat(args, " ", 1);
    }

    // Open file stream test and passing it to Overseer (this is how we can write to a log file)
    // FILE *fp;
    // fp = fopen("test123.txt", "w+");

    /* clear address struct */
    memset(&their_addr, 0, sizeof(their_addr));

    their_addr.sin_family = AF_INET;      /* host byte order */
    their_addr.sin_port = htons(PORT_NO); /* short, network byte order */
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);

    if (connect(sockfd, (struct sockaddr *)&their_addr,
                sizeof(struct sockaddr)) == -1)
    {
        // Write error message to log file
        fprintf(stderr, "Could not connect to Overseer %s:%d\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
        perror("connect");
        exit(1);
    }
    else
    {
        fprintf(stdout, "Made successful connection to Overseer %s:%d\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));

        // Send the program and args separately. For consistency!

        //uint16_t programSize = htons(sizeof(program));
        // send(sockfd, &programSize, sizeof(program), 0);
        // fflush(stdout);

        send(sockfd, program, MAX_BUFFER_SIZE, 0);
        fflush(stdout);

        send(sockfd, args, MAX_BUFFER_SIZE, 0);
        fflush(stdout);
    }

    close(sockfd);

    return 0;
}
