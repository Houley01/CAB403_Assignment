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
#define MINIMUM_ARGS 3

void stderr_help_text_exit1()
{
    fprintf(stderr, HELP_TEXT);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sockfd;
    bool argument_safe = true;
    int PORT_NO;
    // int OUTPUT_ARG_NUM = 0;
    // int LOG_ARG_NUM = 0;
    int program_arg = MINIMUM_ARGS;
    struct hostent *he;
    struct sockaddr_in their_addr; /* connector's address information */

    if (argv[1] != NULL) // Need to check if the first arg is null before strcmp
    {
        if (strcmp(argv[1], "--help") == 0)
        {
            printf(HELP_TEXT);
            exit(1);
        }
    }
    // Quit if args are less then MINIMUM number of arguments
    else if (argc < MINIMUM_ARGS)
    {
        stderr_help_text_exit1();
    }

    // Hostname Checking
    if ((he = gethostbyname(argv[1])) == NULL)
    { /* get the host info */
        herror("gethostbyname");
        stderr_help_text_exit1();
    }

    // Port Number Checking
    for (int i = 0; argv[2][i] != '\0'; i++)
    {
        if (isdigit(argv[2][i]) == 0)
        {
            argument_safe = false;
            break;
        }
    }
    if (argument_safe == false)
    {
        stderr_help_text_exit1();
    }
    else
    {
        PORT_NO = atoi(argv[2]);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }

    char argsOutFile[MAX_BUFFER_SIZE];
    memset(&argsOutFile, 0, sizeof(argsOutFile));

    char argsLogFile[MAX_BUFFER_SIZE];
    memset(&argsLogFile, 0, sizeof(argsLogFile));

    // char argsTimeFile[MAX_BUFFER_SIZE];
    // memset(&argsTimeFile, 0, sizeof(argsTimeFile));
    // Loop through the arguments to find optional Arguments
    // This include '-o' '-log' '-t' 'mem' 'memkill' Arguments

    int log_arg_location = __INT_MAX__, out_arg_location = __INT_MAX__;
    for (int i = 2; i < argc; i++)
    {
        if (strcmp("-o", argv[i]) == 0)
        {
            if (program_arg < i + 2)
            {
                out_arg_location = i;
                program_arg = i + 2;
            }
            strcat(argsOutFile, argv[i]);
            strcat(argsOutFile, " ");
            strcat(argsOutFile, argv[i + 1]);
        }
        else if (strcmp("-log", argv[i]) == 0)
        {
            strcat(argsLogFile, argv[i]);
            strcat(argsLogFile, " ");
            strcat(argsLogFile, argv[i + 1]);
            if (program_arg < i + 2)
            {
                log_arg_location = i;
                program_arg = i + 2;
            }
        }
        // else if (strcmp("-t", argv[i]) == 0)
        // {
        //     strcat(argsTimeFile, argv[i]);
        //     strcat(argsTimeFile, " ");
        //     strcat(argsTimeFile, argv[i + 1]);
        //     strcat(argsTimeFile, " ");
        // }
    }

    // If Outfile arg location is != MAX INT
    if (out_arg_location != __INT_MAX__)
    {
        // If Outfile arg location is greater than Logfile Arg Location
        // Send Error Help Text and exit
        if (out_arg_location > log_arg_location)
        {
            // Log is less then out
            stderr_help_text_exit1();
        }
    }

    // Argument contains the program the client wishes to run
    char *program = argv[program_arg];

    char args[MAX_BUFFER_SIZE];
    args[0] = 0;
    // Get all of the arguments for the program
    for (int i = program_arg + 1; i < argc; i++)
    {
        strncat(args, argv[i], sizeof(argv[i]));
        printf("%d:%s\n", i, argv[i]);
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

        // send(sockfd, argsTimeFile, MAX_BUFFER_SIZE, 0);
        // fflush(stdout);

        if (strcmp(program, "mem") == 0)
        {
            send(sockfd, program, MAX_BUFFER_SIZE, 0);
            fflush(stdout);
            sleep(0.3);

            uint16_t isPidHistory;
            if (strlen(args) > 0)
            {
                isPidHistory = htons(1);
                send(sockfd, &isPidHistory, sizeof(uint16_t), 0);
                send(sockfd, &args, MAX_BUFFER_SIZE, 0);
            }
            else
            {
                isPidHistory = htons(0);
                send(sockfd, &isPidHistory, sizeof(uint16_t), 0);
            }

            sleep(1);

            uint16_t buffer;

            if (recv(sockfd, &buffer, sizeof(uint16_t), 0) == -1)
            {
                perror("recv");
                exit(1);
            }
            int numOfHistoryItems = ntohs(buffer);

            //printf("%s\n", test);
            printf("Expecting %d memory history items\n", numOfHistoryItems);

            while (numOfHistoryItems > 0)
            {
                char buffybuffbuff[MAX_BUFFER_SIZE];
                sleep(0.3);
                if (recv(sockfd, &buffybuffbuff, MAX_BUFFER_SIZE, 0) == -1)
                {
                    perror("recv");
                    exit(1);
                }
                printf("%s", buffybuffbuff);
                numOfHistoryItems--;
            }
        }
        else
        {
            send(sockfd, program, MAX_BUFFER_SIZE, 0);
            fflush(stdout);

            send(sockfd, args, MAX_BUFFER_SIZE, 0);
            fflush(stdout);

            // Output file sending data
            send(sockfd, argsOutFile, MAX_BUFFER_SIZE, 0);
            fflush(stdout);

            // Log file sending data
            send(sockfd, argsLogFile, MAX_BUFFER_SIZE, 0);
            fflush(stdout);

            // Sleep so the Overseer gets a chance to recive the icoming string.
            sleep(1);
        }
    }

    close(sockfd);

    return 0;
}