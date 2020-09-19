#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "helpers.h"

#define NUM_HANDLER_THREADS 5
#define NUM_OF_REQUESTS 10
#define MAX_BUFFER_SIZE 4096

#define TERMINATE_TIMEOUT 10

pthread_mutex_t request_mutex;
pthread_cond_t got_request;
int num_requests = 0;

struct request
{
    int number;
    int fd;
    char *program;
    char **args;
    struct request *next;
};

struct request *requests = NULL;
struct request *last_request = NULL;

void add_request(int request_num,
                 int fd,
                 char *program,
                 char **args,
                 pthread_mutex_t *p_mutex,
                 pthread_cond_t *p_cond_var)
{
    struct request *a_request;

    a_request = (struct request *)malloc(sizeof(struct request));
    if (!a_request)
    {
        fprintf(stderr, "add_request: out of memory\n");
        exit(1);
    }
    a_request->fd = fd;
    a_request->number = request_num;
    a_request->program = program;
    a_request->args = args;
    a_request->next = NULL;

    pthread_mutex_lock(p_mutex);

    if (num_requests == 0)
    {
        requests = a_request;
        last_request = a_request;
    }
    else
    {
        last_request->next = a_request;
        last_request = a_request;
    }

    num_requests++;

    pthread_mutex_unlock(p_mutex);

    pthread_cond_signal(p_cond_var);
}

struct request *get_request()
{
    struct request *a_request;

    if (num_requests > 0)
    {
        a_request = requests;
        requests = a_request->next;
        if (requests == NULL)
        {
            last_request = NULL;
        }

        num_requests--;
    }
    else
    {
        a_request = NULL;
    }

    return a_request;
}

void sig_process(pid_t pid)
{
    int timeout = 0, kill_loop,wait = 0, sig_loop = 1, term;
    int count = TERMINATE_TIMEOUT; // Need to update once part B is done
    while(sig_loop)
    {
        // printf("Loop: %d %d\n", timeout, sig_loop);
        timeout++;
        sleep(1);

        if(timeout >= count)
        {
            if(timeout == count)        // Once we reach the threshold
            {
                // Ask nicely to close the program
                term = kill(pid, SIGTERM);
                printf("%s - sent SIGTERM to %d\n", timestamp(), pid);
            }
            // Term handling, term returns 0 on success, -1 on failure or an ERRNO
            switch(term)
            {
                case 0: // Program terminated successfully.
                    printf("%s - %d has been terminated with status code %d\n", timestamp(), pid, WEXITSTATUS(SIGTERM));
                    sig_loop = 0;
                break;
                // If for some reason we cannot terminate the program by asking nicely.
                case -1:
                    kill_loop = 1;
                    while(kill_loop)
                    {
                        if(wait == 5)
                        {
                            printf("%s - sent SIGKILL to %d\n", timestamp(), pid);
                            term = kill(pid, SIGKILL);
                            kill_loop = 0;  // Exit this loop
                            sig_loop = 0;    // Exit main loop
                        }
                        sleep(1);
                        wait++;
                    }
                break;
                // Error handling
                case EPERM:
                    perror("User not priviliged?...\n");
                break;
                case EINVAL:
                    printf("Sig <%d>\n", SIGTERM); // Doubt we will ever encounter this error.
                    perror("Invalid SIG value when attempting to terminate.\n");
                break;
                case ESRCH:
                    printf("Pid <%d>\n", getpid());
                    perror("Could not find PID of child process.\n");
                break;
            }
        }
    }
}

int handle_request(struct request *a_request, int thread_id)
{
    // Debug
    printf("Thread %d handled request %d\n", thread_id, a_request->number);

    fprintf(stdout, "%s - Attempting to execute '%s'...\n", timestamp(), a_request->program);

    // retVal will contain the return value '-1' if execlp couldn't execute the program
    int retVal;
    int status;

    // Create a fork before calling execlp so we don't replace the overseer with the program the client wishes to run!
    pid_t pid = fork();

    // Fork was successfully executed!
    if (pid >= 0)
    {
        // Fork returns 0 for the child process
        if (pid == 0)
        {
            // Run the program and check if execlp will return '-1' which will let the parent know if it failed
            retVal = execvp(a_request->program, a_request->args);
        }
        else
        {
            // PART D
            sig_process(pid);
        }
        
        // Waiting on the child!
        wait(&status);

        // Todo
        // Implement some code that calls back to 
        // sig_process and kills the loop if program executed.
        // - Attempted double pointers (in this func and out)
        // - Alarm (Just won't work since we can't parse the pid)
        // - wait doesn't work (kind of obvious since pointers dont)
        // Need to find a solution that allows both the pid and the callback to modify the sig_loop variable to stop the loop.

        // If the value returned was '-1', we know that the program had failed to execute! Otherwise, program executed successfully

        // Waiting on the child!
        wait(&status);

        // If the value returned was '-1', we know that the program had failed to execute! Otherwise, program executed successfully
        if (retVal == -1)
        {
            fprintf(stdout, "%s - Could not execute '%s'\n", timestamp(), a_request->program);
        }
        else
        {
            fprintf(stdout, "%s - '%s' has been executed with PID %d\n", timestamp(), a_request->program, pid);
            fprintf(stdout, "%s - PID %d has terminated with status code %d\n", timestamp(), pid, WEXITSTATUS(status));
        }
    }
    // If a fork could not be created, log to stderr
    else
    {
        fprintf(stderr, "Could not create a fork.\n");
    }

    // Let the Overseer know that the job has finished
    close(a_request->fd);
    return 1;
}

void *handle_requests_loop(void *data)
{
    struct request *a_request;
    int thread_id = *((int *)data);
    // Debug info
    printf("Thread ID: %d running...\n", thread_id);
    pthread_mutex_lock(&request_mutex);

    while (1)
    {
        // sleep(1);
        if (num_requests > 0)
        {
            // Debug info
            printf("Thread ID: %d - Requests in list: %d\n", thread_id, num_requests);
            a_request = get_request();
            if (a_request)
            {
                pthread_mutex_unlock(&request_mutex);
                handle_request(a_request, thread_id);
                free(a_request);
                pthread_mutex_lock(&request_mutex);
            }
        }
        else
        {
            // Debug info
            printf("Thread ID: %d - No requests\n", thread_id);
            pthread_cond_wait(&got_request, &request_mutex);
        }
    }
}

int main(int argc, char *argv[])
{
    // Setting up distributed system server
    if (argc != 2)
    {
        perror("No port number supplied.");
        exit(1);
    }

    int port = atoi(argv[1]);

    /* generate the socket */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("Socked returned error");
        exit(1);
    }

    /* Enable address/port reuse, useful for server development */
    int opt_enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt_enable, sizeof(opt_enable));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt_enable, sizeof(opt_enable));

    struct sockaddr_in my_addr;
    memset(&my_addr, 0, sizeof(my_addr));

    // Generating the end point

    // Host byte order
    my_addr.sin_family = AF_INET;
    // Network byte order: short
    my_addr.sin_port = htons(port);
    // auto fill IP
    my_addr.sin_addr.s_addr = INADDR_ANY;

    /* bind the socket to the end point */
    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("Bind returned error");
        exit(1);
    }

    /* start listening */
    if (listen(sockfd, NUM_OF_REQUESTS) == -1)
    {
        perror("Listen returned error");
        exit(1);
    }

    struct sockaddr_in their_addr;
    socklen_t sin_size;
    int new_fd;

    printf("Server successfully setup\n");
    printf("Now listening for requests...\n\n");

    // Setting up thread pool
    int thr_id[NUM_HANDLER_THREADS];
    pthread_t p_threads[NUM_HANDLER_THREADS];

    pthread_mutex_init(&request_mutex, NULL);
    pthread_cond_init(&got_request, NULL);

    // PART C
    for (int i = 0; i < NUM_HANDLER_THREADS; i++)
    {
        pthread_create(&p_threads[i], NULL, handle_requests_loop, &i);
    }

    int request_counter = 0;

    while (1)
    {
        sleep(1);
        sin_size = sizeof(struct sockaddr_in);
        if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
                             &sin_size)) == -1)
        {
            perror("accept");
            continue;
        }
        else
        {
            // Connection from a client was successfully made to the overseer!
            fprintf(stdout, "%s - Connection received from %s\n", timestamp(), inet_ntoa(their_addr.sin_addr));

            // Code below for getting the number of bytes being sent to know how many bytes to expect to receive
            // Doesn't really work for some reason though on the 2nd recv, further testing needed!

            // uint16_t buffer;

            // if (recv(new_fd, &buffer, sizeof(uint16_t), 0) == -1)
            // {
            //     perror("recv");
            //     exit(1);
            // }
            // int programBytes = ntohs(buffer);
            
            // Output file or Log File or Other optional Arguments
            char optionalArgs[MAX_BUFFER_SIZE];
            if (recv(new_fd, &optionalArgs, MAX_BUFFER_SIZE, 0) == -1)
            {
                perror("recv");
                exit(1);
            }
            // printf("Optional Args: %s\n");

                char programBuffer[MAX_BUFFER_SIZE];

                if (recv(new_fd, &programBuffer, MAX_BUFFER_SIZE, 0) == -1)
                {
                    perror("recv");
                    exit(1);
            }

            programBuffer[MAX_BUFFER_SIZE] = '\0';

            char argsBuffer[MAX_BUFFER_SIZE];
            if (recv(new_fd, &argsBuffer, MAX_BUFFER_SIZE, 0) == -1)
            {
                perror("recv");
                exit(1);
            }

            argsBuffer[MAX_BUFFER_SIZE] = '\0';

            // Below splits argsBuffer into substrings from it's original string (args come from client as one string)
            char **args = NULL;
            char *p = strtok(argsBuffer, " ");
            int spaces = 0;

            while (p)
            {
                spaces++;
                args = realloc(args, sizeof(char *) * spaces);
                if (args == NULL)
                {
                    // Break out if realloc fails. Probably will need to set the args list to NULL to send zero args for the sake of it I guess
                    break;
                }
                args[spaces - 1] = p;
                p = strtok(NULL, " ");
            }

            // Add space for NULL char in args list
            args = realloc(args, sizeof(char *) * (spaces + 1));
            args[spaces] = 0;

            add_request(request_counter, new_fd, programBuffer, args, &request_mutex, &got_request);
            request_counter++;
        }
    }

    return 0;
}