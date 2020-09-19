#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

// #define PORT_NO 54321 /* PORT Number */
#define MAX_BUFFER_SIZE 4096
#define HELP_TEXT "\
Usage: controller <address> <port> {[-o out_file] \
[-log log_file][-t seconds] <file> [arg...] | mem \
[pid] | memkill <percent>}\n"

void stderr_help_text_exit1() {
    fprintf(stderr, HELP_TEXT);
    exit(1);
} 

int main(int argc, char *argv[])
{
    int sockfd, numbytes;
    bool argument_safe = true;
    int PORT_NO;
    // int OUTPUT_ARG_NUM = 0;
    // int LOG_ARG_NUM = 0;
    int program_arg = 3;
    struct hostent *he;
    struct sockaddr_in their_addr; /* connector's address information */

    if(argv[1] != NULL) // Need to check if the first arg is null before strcmp
    {
        if(strcmp(argv[1], "--help") == 0)
        {
            printf(HELP_TEXT);
            exit(1);
        }
    } else if (argv[1] == NULL) // else if == to null
    {
        // printf("NULL\n");
        stderr_help_text_exit1();
    } 

    // Quit if args are less then 3
    if (argc < 3)
    {
        printf("Less then 3\n");
        stderr_help_text_exit1();
    }

    // Hostname Checking
    if ((he = gethostbyname(argv[1])) == NULL)
    { /* get the host info */
        herror("gethostbyname");
        stderr_help_text_exit1();
    }

    // Port Number Checking
    for (int i = 0; argv[2][i] != '\0'; i++) {
        if (isdigit(argv[2][i]) == 0) {
            argument_safe = false;
            break; 
        }
    } 
    if (argument_safe == false) {
        stderr_help_text_exit1();
    } else {
        PORT_NO = atoi(argv[2]);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }

    char *optionalArgs[3];
    // Check for -o out_file and -log log_file flags
    for (int i = 2; i < argc; i++) {
        if (strcmp("-o", argv[i]) == 0) {
            // OUTPUT_ARG_NUM = i;
            optionalArgs[0] = argv[i+1];
            // printf("found -o Arg : %s\n", optionalArgs[0]);
            if (program_arg < i+2) 
            {
                program_arg = i+2;
            }
        }
        else if (strcmp("-log", argv[i]) == 0)
        {
            // LOG_ARG_NUM = i;
            optionalArgs[1] = argv[i + 1];
            // printf("found -log Arg : %s\n", optionalArgs[1]);
            if (program_arg < i + 2)
            {
                program_arg = i + 2;
            }
        }
        // else if (strcmp("-t", argv[i]) == 0)
        // {
        //     /* code */
        // }
        
    }



    // Argument contains the program the client wishes to run
    char *program = argv[program_arg];

    char args[MAX_BUFFER_SIZE];

    //     0       1       2      3   4    5    6
    // localhost 12345 test_prog one two three four

    // Get all of the arguments for the program
    for (int i = program_arg; i < argc; i++)
    {
        strncat(args, argv[i], sizeof(argv[i]));
        printf("%d:%s\n", i,argv[i]);
        printf("---------------\n");
        strncat(args, " ", argc); // Doesn't actually matter what int value we put here (1 causes a warning though)=
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
        // if (optionalArgs[0] != NULL || optionalArgs[3] != NULL || optionalArgs[3] != NULL){
            printf("%s \n", optionalArgs);
        send(sockfd, optionalArgs, MAX_BUFFER_SIZE, 0);
        fflush(stdout);

        send(sockfd, program, MAX_BUFFER_SIZE, 0);
        fflush(stdout);

        send(sockfd, args, MAX_BUFFER_SIZE, 0);
        fflush(stdout);
    }

    close(sockfd);

    return 0;
}
