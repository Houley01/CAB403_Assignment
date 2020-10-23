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
#include <stdbool.h>
#include <fcntl.h>
#include "helpers.h"

#define NUM_HANDLER_THREADS 5
#define NUM_OF_REQUESTS 10
#define MAX_BUFFER_SIZE 4096

#define TERMINATE_TIMEOUT 10

int sockfd;

pthread_mutex_t request_mutex;
pthread_cond_t got_request;
int num_requests = 0;

pthread_mutex_t file_mutex;
pthread_cond_t got_file;
bool file_mutex_activated = false;
char new_connection_buffer[MAX_BUFFER_SIZE];

pthread_mutex_t memory_mutex;
pthread_cond_t got_memory;
bool memory_mutex_activated = false;

struct request
{
    int number;
    int fd;
    char *program;
    char **args;
    char **outfile;
    char **logfile;
    struct request *next;
};

struct request *requests = NULL;
struct request *last_request = NULL;

struct pidMemoryInfo
{
    int pid;
    char *timestamp;
    int memory;
    bool active;
    struct pidMemoryInfo *next;
};

struct pidMemoryInfo *add_memory_start = NULL;
struct pidMemoryInfo *add_memory_last = NULL;

// Manage memory info to the memory linked list of running processes
// Memory will either be the memory of the current running process, or -1
// If -1, it has been indicated that the process is no longer running
void manage_memory_info(int pid, int memory)
{
    pthread_mutex_trylock(&memory_mutex);
    struct pidMemoryInfo *read_memory = add_memory_start;
    bool pid_does_exist = false;

    while (read_memory != NULL)
    {
        if (read_memory->pid == pid)
        {
            pid_does_exist = true;
            break;
        }
        else
        {
            read_memory = read_memory->next;
        }
    }

    if (pid_does_exist && read_memory != NULL)
    {
        read_memory->timestamp = timestamp();
        if (memory != -1)
        {
            read_memory->memory = memory;
            read_memory->active = true;
        }
        else
        {
            read_memory->active = false;
        }
    }
    else
    {
        struct pidMemoryInfo *new_memory_info;

        new_memory_info = (struct pidMemoryInfo *)malloc(sizeof(struct pidMemoryInfo));
        if (!new_memory_info)
        {
            fprintf(stderr, "Adding new memory info: out of memory\n");
            exit(1);
        }

        new_memory_info->pid = pid;
        new_memory_info->timestamp = timestamp();
        new_memory_info->memory = memory;
        new_memory_info->active = true;

        if (add_memory_start == NULL)
        {
            add_memory_start = new_memory_info;
            add_memory_last = new_memory_info;
        }
        else
        {
            add_memory_last->next = new_memory_info;
            add_memory_last = new_memory_info;
        }
    }

    pthread_mutex_unlock(&memory_mutex);

    pthread_cond_signal(&got_memory);
}

void add_request(int request_num,
                 int fd,
                 char *program,
                 char **args,
                 char **outfile,
                 char **logfile,
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
    a_request->outfile = outfile;
    a_request->logfile = logfile;
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

void exit_handler(int SIG)
{
    // TODO
    // - Kill all children process here
    // https://stackoverflow.com/questions/10619952/how-to-completely-destroy-a-socket-connection-in-c
    // Apperently doesn't completely destroy the socket (os cleans it up anyways)
    close(sockfd);

    pid_t parent = getppid();
    // kill(-parent, SIGKILL);



    printf("%s - Exiting overseer due to: CTRL^C\n", timestamp());
    exit(0);
}

int handle_request(struct request *a_request, int thread_id)
{
    // Debug
    printf("Thread %d handled request %d\n", thread_id, a_request->number);
    // retVal will contain the return value '-1' if execlp couldn't execute the program
    int retVal = 0;
    int status;
    int logFile = 0;
    int logFileFd = 0;
    int stdoutFd = 0;
    int stderrFd = 0;
    int outFile = 0;
    int outFileFd = 0;
    int outFileFdErr = 0;
    // Contains the filename of the log file. For some reason, this buffer is a workaround for a memory bug?..
    char logBuffer[MAX_BUFFER_SIZE];
    if (a_request->logfile != NULL)
    {
        snprintf(logBuffer, sizeof(logBuffer), "%s", a_request->logfile[1]);
    }
    char outBuffer[MAX_BUFFER_SIZE];
    if (a_request->outfile != NULL)
    {
        snprintf(outBuffer, sizeof(outBuffer), "%s", a_request->outfile[1]);
    }
    // Debug memory
    // printf("%p\n", &a_request->logfile);
    // printf("request number: %d\n", a_request->number);

    while (file_mutex_activated)
    {
        printf("Thread %d waiting...\n", thread_id);
        pthread_cond_wait(&got_file, &file_mutex);
        printf("Thread %d finished waiting\n", thread_id);
    }

    if (a_request->logfile != NULL)
    {
        file_mutex_activated = true;
        pthread_mutex_trylock(&file_mutex);
        //int test = pthread_mutex_trylock(&file_mutex);
        //printf("%d\n", test);
        printf("Thread %d locked\n", thread_id);
        sleep(2);
        //printf("%p\n", a_request->logfile);
        // Duplicate stdout fd to be used for restoring stdout to the screen
        stdoutFd = dup(STDOUT_FILENO);

        //debug
        // printf("Thread id: %d\n", thread_id);
        // printf("Buffer name: %s\n", logBuffer);
        // printf("Log file name below:\n");
        // printf("%s\n", a_request->logfile[1]);
        // printf("request number: %d\n", a_request->number);

        // Open the logfile with write only and append flags
        logFile = open(logBuffer, O_WRONLY | O_APPEND | O_CREAT, 0777);
        if (logFile < 0)
        {
            printf("%s\n", a_request->logfile[1]);
            perror("Cannot open log file.");
            exit(1);
        }

        // Redirect stdout to write or append to the logfile provided by the user
        logFileFd = dup2(logFile, STDOUT_FILENO);

        if (logFileFd < 0)
        {
            perror("Cannot duplicate file descriptor.");
            exit(1);
        }
    }

    fprintf(stdout, "%s - Attempting to execute '%s'...\n", timestamp(), a_request->program);

    if (a_request->logfile != NULL)
    {
        // Close the log file fd and return stdout to the screen
        close(logFile);
        close(logFileFd);
        dup2(stdoutFd, STDOUT_FILENO);
        close(stdoutFd);
        pthread_mutex_unlock(&file_mutex);
        pthread_cond_signal(&got_file);
        // printf("Thread %d unlocked\n", thread_id);
        file_mutex_activated = false;
    }

    // Create a fork before calling execlp so we don't replace the overseer with the program the client wishes to run!
    pid_t pid = fork();
    // Fork was successfully executed!
    if (pid >= 0)
    {
        // Fork returns 0 for the child process
        if (pid == 0)
        {
            while (file_mutex_activated)
            {
                // printf("Thread %d waiting...\n", thread_id);
                pthread_cond_wait(&got_file, &file_mutex);
                // printf("Thread %d finished waiting\n", thread_id);
            }
            if (a_request->outfile != NULL)
            {
                file_mutex_activated = true;
                pthread_mutex_trylock(&file_mutex);

                // printf("Thread %d locked\n", thread_id);
                sleep(2);

                stdoutFd = dup(STDOUT_FILENO);
                stderrFd = dup(STDERR_FILENO);
                // Open the outfile with write only and append flags
                outFile = open(outBuffer, O_WRONLY | O_APPEND | O_CREAT, 0777);
                if (outFile < 0)
                {
                    printf("%s\n", a_request->outfile[1]);
                    perror("Cannot open out file.");
                    exit(1);
                }

                // Redirect stdout to write or append to the outfile provided by the user
                outFileFd = dup2(outFile, STDOUT_FILENO);
                outFileFdErr = dup2(outFile, STDERR_FILENO);
                // outFileFd = dup2(outFile, STDOUT_FILENO);
                if (outFileFd < 0)
                {
                    perror("Cannot duplicate file descriptor.");
                    exit(1);
                }
                if (outFileFdErr < 0)
                {
                    perror("Cannot duplicate file descriptor. Err");
                    exit(1);
                }
            }
            // Run the program and check if execlp will return '-1' which will let the parent know if it failed
            // retVal = execvp(a_request->program, a_request->args);
            retVal = execvp(a_request->program, a_request->args);

            // Close the Out file fd and return stdout to the screen
            if (a_request->outfile != NULL)
            {
                close(outFile);
                close(outFileFd);
                close(outFileFdErr);
                dup2(stdoutFd, STDOUT_FILENO);
                dup2(stderrFd, STDERR_FILENO);
                close(stdoutFd);
                close(stderrFd);
                pthread_mutex_unlock(&file_mutex);
                pthread_cond_signal(&got_file);
                // printf("Thread %d unlocked\n", thread_id);
                file_mutex_activated = false;
            }
        }
        else
        {
            char memoryRead[MAX_BUFFER_SIZE];
            snprintf(memoryRead, sizeof(memoryRead), "/proc/%d/maps", pid);

            // While the process is running, update it's memory every 1 second!!!
            while (waitpid(pid, &status, WNOHANG) == 0)
            {
                while (memory_mutex_activated)
                {
                    pthread_cond_wait(&got_memory, &memory_mutex);
                }
                memory_mutex_activated = true;
                manage_memory_info(pid, getProcMemoryInfo(pid, memoryRead));
                memory_mutex_activated = false;
                sleep(1);
            }
            pid_t ws = waitpid(pid, &status, WNOHANG); // Current status of child (0 is running)

            // Let it be known that the process has finished running
            while (memory_mutex_activated)
            {
                pthread_cond_wait(&got_memory, &memory_mutex);
            }
            memory_mutex_activated = true;
            manage_memory_info(pid, -1);
            memory_mutex_activated = false;

            while (file_mutex_activated)
            {
                // printf("Thread %d waiting...\n", thread_id);
                pthread_cond_wait(&got_file, &file_mutex);
                // printf("Thread %d finished waiting\n", thread_id);
            }

            if (a_request->logfile != NULL)
            {
                file_mutex_activated = true;
                pthread_mutex_trylock(&file_mutex);
                // int test = pthread_mutex_trylock(&file_mutex);
                // printf("%d\n", test);
                // printf("Thread %d locked\n", thread_id);
                sleep(2);
                //printf("%p\n", a_request->logfile);
                // Duplicate stdout fd to be used for restoring stdout to the screen
                stdoutFd = dup(STDOUT_FILENO);

                //debug
                // printf("Thread id: %d\n", thread_id);
                // printf("Log file name below:\n");
                // printf("%s\n", a_request->logfile[1]);
                // printf("request number: %d\n", a_request->number);

                // Open the logfile with write only and append flags
                logFile = open(logBuffer, O_WRONLY | O_APPEND | O_CREAT, 0777);
                if (logFile < 0)
                {
                    printf("%s\n", a_request->logfile[1]);
                    perror("Cannot open log file.");
                    exit(1);
                }

                // Redirect stdout to write or append to the logfile provided by the user
                logFileFd = dup2(logFile, STDOUT_FILENO);

                if (logFileFd < 0)
                {
                    perror("Cannot duplicate file descriptor.");
                    exit(1);
                }
            }

            int count = 0, term;
            int timeout = TERMINATE_TIMEOUT; // Need to update once part B is done
            // PART D
            while (!(ws = waitpid(pid, &status, WNOHANG)))
            {
                if (count >= timeout)
                {
                    if (count == timeout) // Once we reach the threshold
                    {
                        // Ask nicely to close the program
                        term = kill(pid, SIGTERM);
                        printf("%s - sent SIGTERM to %d\n", timestamp(), pid);
                    }
                    switch (term)
                    {
                    case 0: // Program terminated successfully.
                        printf("%s - %d has been terminated with status code %d\n", timestamp(), pid, WEXITSTATUS(SIGTERM));
                        break;
                    case -1: // If for some reason we cannot terminate the program by asking nicely.
                        sleep(5);
                        printf("%s - sent SIGKILL to %d\n", timestamp(), pid);
                        term = kill(pid, SIGKILL);
                        break;
                    // Error handling
                    case EPERM:
                        perror("Not root or super-user. (Please run under sudo).\n");
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
                count++;
                sleep(1);
            }

            // Logging

            // Need to check signal to check WTERMSIG (best practice)
            if (!WIFEXITED(status) && WIFSIGNALED(status))
            {
                // Making sure we somehow didn't mess up.
                if (WTERMSIG(status) != SIGTERM && WTERMSIG(status) != SIGKILL)
                {
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
            }
            // WIFEXITED returns true for exit(<1)
            // (programmed executed sucessfully)
            else
            {
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
        }
    }
    // If a fork could not be created, log to stderr
    else
    {
        fprintf(stderr, "Could not create a fork.\n");
    }

    // Close the log file fd and return stdout to the screen
    if (a_request->logfile != NULL)
    {
        // Close the log file fd and return stdout to the screen
        close(logFileFd);
        dup2(stdoutFd, STDOUT_FILENO);
        close(stdoutFd);
        pthread_mutex_unlock(&file_mutex);
        pthread_cond_signal(&got_file);
        printf("Thread %d unlocked\n", thread_id);
        file_mutex_activated = false;
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
            //printf("Thread ID: %d - Requests in list: %d\n", thread_id, num_requests);
            a_request = get_request();
            if (a_request)
            {
                pthread_mutex_unlock(&request_mutex);
                handle_request(a_request, thread_id);
                free(a_request);
                //pthread_mutex_lock(&request_mutex);
            }
        }
        else
        {
            // Debug info
            if (thread_id == 0)
            {
                struct pidMemoryInfo *memtest = add_memory_start;

                while (memtest != NULL)
                {
                    printf("%s | PID: %d | Memory: %d | Active: %d\n", memtest->timestamp, memtest->pid, memtest->memory, memtest->active);
                    memtest = memtest->next;
                }

                memtest = add_memory_start;
            }
            printf("Thread ID: %d - No requests\n", thread_id);
            pthread_cond_wait(&got_request, &request_mutex);
        }
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, exit_handler); // PART D (Do not remove)
    // threading cleanup (man prctl)
    // prctl(PR_SET_PDEATHSIG, SIGHUP);z
    // Setting up distributed system server
    if (argc != 2)
    {
        perror("No port number supplied.\n");
        exit(1);
    }

    int port = atoi(argv[1]);

    /* generate the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
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
    pthread_t p_threads[NUM_HANDLER_THREADS];

    pthread_mutex_init(&request_mutex, NULL);
    pthread_cond_init(&got_request, NULL);

    pthread_mutex_init(&file_mutex, NULL);
    pthread_cond_init(&got_file, NULL);

    pthread_mutex_init(&memory_mutex, NULL);
    pthread_cond_init(&got_memory, NULL);

    // PART C
    for (int i = 0; i < NUM_HANDLER_THREADS; i++)
    {
        pthread_create(&p_threads[i], NULL, handle_requests_loop, &i);
        // For some reason, the value will not be accurate without a micro sleep
        // This is okay though because it's not busy-waiting
        sleep(0.1);
    }

    int request_counter = 0;

    while (1)
    {
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
            if (file_mutex_activated)
            {
                snprintf(new_connection_buffer, sizeof(new_connection_buffer), "%s - Connection received from %s\n", timestamp(), inet_ntoa(their_addr.sin_addr));
            }
            else
            {
                fprintf(stdout, "%s - Connection received from %s\n", timestamp(), inet_ntoa(their_addr.sin_addr));
            }

            char **outfileArg = NULL;
            char **logfileArg = NULL;

            int index = 0;
            char temp[MAX_BUFFER_SIZE];
            if (recv(new_fd, &temp, MAX_BUFFER_SIZE, 0) == -1)
            {
                perror("recv");
                exit(1);
            }
            temp[MAX_BUFFER_SIZE - 1] = 0;

            if (temp[0] != '\0')
            {
                char *token = strtok(temp, " ");
                while (token != NULL)
                {
                    outfileArg = realloc(outfileArg, sizeof(char *) * index);
                    outfileArg[index] = token;
                    token = strtok(NULL, " ");
                    index++;
                }
                outfileArg = realloc(outfileArg, sizeof(char *) * (index + 1));
                outfileArg[index] = 0;
            }

            // Log FILE
            int indexLog = 0;
            char tempLog[MAX_BUFFER_SIZE];
            tempLog[0] = '\0';

            if (recv(new_fd, &tempLog, MAX_BUFFER_SIZE, 0) == -1)
            {
                perror("recv");
                exit(1);
            }
            tempLog[MAX_BUFFER_SIZE] = 0;

            if (tempLog[0] != '\0')
            {
                // Take the first char to SPACE, then place the string into a char[]
                char *tokenLog = strtok(tempLog, " ");
                while (tokenLog != NULL)
                {
                    logfileArg = realloc(logfileArg, sizeof(char *) * indexLog);
                    logfileArg[indexLog] = tokenLog;
                    tokenLog = strtok(NULL, " ");
                    indexLog++;
                }
                logfileArg = realloc(logfileArg, sizeof(char *) * (indexLog + 1));
                logfileArg[indexLog] = 0;
            }

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

            while (p != NULL)
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

            // Debug memory
            //printf("%p\n", &logfileArg);

            add_request(request_counter, new_fd, programBuffer, args, outfileArg, logfileArg, &request_mutex, &got_request);
            request_counter++;
        }
    }

    return 0;
}