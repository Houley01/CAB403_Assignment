#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXDATASIZE 100 /* max number of bytes we can get at once */

#define ARRAY_SIZE 30

int *Receive_Array_Int_Data(int socket_identifier, int size)
{
    uint16_t buffer;
    int *results = malloc(sizeof(int) * size);
    for (int i = 0; i < ARRAY_SIZE; ++i)
    {
        recv(socket_identifier, &buffer, sizeof(uint16_t), 0);
        results[i] = ntohs(buffer);
        printf("%d\n", results[i]);
    }

    return results;
}

// #define PORT_NO 54321 /* PORT Number */

int main(int argc, char *argv[])
{
    int sockfd, numbytes, i = 0;
    char buf[MAXDATASIZE];
    struct hostent *he;
    struct sockaddr_in their_addr; /* connector's address information */

    if (argc != 3)
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

    /* clear address struct */
    memset(&their_addr, 0, sizeof(their_addr));

    their_addr.sin_family = AF_INET;      /* host byte order */
    their_addr.sin_port = htons(PORT_NO); /* short, network byte order */
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);

    if (connect(sockfd, (struct sockaddr *)&their_addr,
                sizeof(struct sockaddr)) == -1)
    {
        perror("connect");
        exit(1);
    }

    int *results = Receive_Array_Int_Data(sockfd, ARRAY_SIZE);

    if (send(sockfd, "All of array data received by client\n", 40, 0) == -1)
        perror("send");
    close(sockfd);

    return 0;
}
