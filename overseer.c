#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
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
#define NUM_OF_BUFFERED_REQUESTS 30
#define TERMINATE_TIMEOUT 10
#define CONNECT_MSG_BUFFER_SIZE 60

int sockfd;
int new_fd;

// Holds the buffered messages of new connections received whilst stdout/err are being
// redirected to a log/outfile.
char *connectionMsgBuffer[NUM_OF_BUFFERED_REQUESTS];

// Points to the index of a message that is stored in the buffer
int msgBufferPointer = 0;

// Amount of messages stored in the buffer
int msgBufferCounter = 0;

// Setting up thread pool
pthread_t p_threads[NUM_HANDLER_THREADS];

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
    int numOfArgs;
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
    bool active;
    int historyCounter;
    char *program;
    char *args;
    struct pidHistory *history_start;
    struct pidHistory *history_end;
    struct request *request;
    struct pidMemoryInfo *next;
};

// For all memory
uint16_t pidCount = 0;

struct pidHistory
{
    char *timestamp;
    int memory;
    struct pidHistory *next;
};

struct pidMemoryInfo *add_memory_start = NULL;
struct pidMemoryInfo *add_memory_last = NULL;

// Sends the entire memory history of a PID to the controller
void send_pid_memory_info(int fd, char **pid)
{
    pthread_mutex_trylock(&memory_mutex);
    memory_mutex_activated = true;
    struct pidMemoryInfo *temp = add_memory_start;

    sleep(0.3);
    if (temp != NULL)
    {
        uint16_t pidCountBuffer = htons(temp->historyCounter);
        send(fd, &pidCountBuffer, sizeof(uint16_t), 0);
        while (temp != NULL)
        {
            // Below is suited for getting info from specific pid since we need to know all the history
            //struct pidHistory *history = add_memory_start->history_start;
            char sendTime[20];
            int sendMemory = 0;
            char memoryInfo[MAX_BUFFER_SIZE];
            int pidArg = atoi(pid[0]);

            // Logging to linked list

            while (temp->history_start != NULL && pidArg)
            {
                strcpy(sendTime, temp->history_start->timestamp);
                sendMemory = temp->history_start->memory;
                snprintf(memoryInfo, sizeof(memoryInfo), "%s %d\n", sendTime, sendMemory);
                send(fd, &memoryInfo, MAX_BUFFER_SIZE, 0);
                temp->history_start = temp->history_start->next;
            }
            temp = temp->next;
        }
    }

    pthread_mutex_unlock(&memory_mutex);
    pthread_cond_signal(&got_memory);
    memory_mutex_activated = false;
}

// Send all memory information to the controller for PIDs that are currently active
void send_memory_info(int fd)
{
    pthread_mutex_trylock(&memory_mutex);
    memory_mutex_activated = true;
    struct pidMemoryInfo *temp = add_memory_start;

    sleep(0.3);
    uint16_t pidCountBuffer = htons(pidCount);
    send(fd, &pidCountBuffer, sizeof(uint16_t), 0);
    while (temp != NULL)
    {
        if (temp->active == true)
        {
            char memoryInfo[MAX_BUFFER_SIZE];
            snprintf(memoryInfo, sizeof(memoryInfo), "%d %d %s %s\n", temp->pid, temp->history_end->memory, temp->program, temp->args);
            send(fd, &memoryInfo, MAX_BUFFER_SIZE, 0);
        }
        temp = temp->next;
    }

    pthread_mutex_unlock(&memory_mutex);
    pthread_cond_signal(&got_memory);
    memory_mutex_activated = false;
}

// When the client requests to kill any process
// using x% of total system memory
void mem_kill(char **amount)
{
    struct sysinfo sys_info;
    if (sysinfo(&sys_info) != 0)
        perror("sysinfo");

    int percentage = atoi(amount[0]);

    struct pidMemoryInfo *temp = add_memory_start;
    while (temp != NULL)
    {
        if (temp->active)
        {
            while (temp->history_start != NULL && temp->active)
            {
                unsigned long process_mem = temp->history_end->memory;
                unsigned long ram = sys_info.totalram;
                double memory_percent = ((double)process_mem / (double)ram * 100);

                if ((double)percentage <= memory_percent + 10)
                {
                    kill(temp->pid, SIGKILL);
                    char *timePointer = timestamp();
                    fprintf(stdout, "%s - Sent SIGKILL to pid: %d for using up %d percent of total memory\n", timePointer, temp->pid, (int)memory_percent);
                    free(timePointer);
                    break;
                }

                temp->history_start = temp->history_start->next;
            }
        }
        temp = temp->next;
    }
    free(temp);
}

// If a request is performing redirection to an out/log file, once it has finished,
// it will then call this function to check if there were any connections made during
// the mutex being locked. This function will print to stdout all of those buffered
// messages to stdout and unlock the mutex.
void connection_msg_buffer_check()
{
    if (msgBufferCounter > 0)
    {
        msgBufferPointer = 0;
        while (msgBufferCounter > 0)
        {
            fprintf(stdout, "%s", connectionMsgBuffer[msgBufferPointer]);
            free(connectionMsgBuffer[msgBufferPointer]);
            msgBufferPointer++;
            msgBufferCounter--;
        }
        if (msgBufferCounter == 0)
        {
            msgBufferPointer = 0;
        }
    }

    pthread_mutex_unlock(&file_mutex);
    pthread_cond_signal(&got_file);
    file_mutex_activated = false;
}

// Manage history info to the history linked list of memory linked list.
// History is the chain of information for a process timestamping what
// it's current memory use is at the point in time.
void manage_history_info(struct pidMemoryInfo *memoryData, int memory)
{
    struct pidHistory *history;

    history = malloc(sizeof(struct pidHistory));

    if (!history)
    {
        fprintf(stderr, "Adding new memory info: out of memory\n");
        exit(1);
    }

    history->memory = memory;
    history->timestamp = timestamp();

    if (memoryData->history_start == NULL)
    {
        memoryData->history_start = history;
        memoryData->history_end = history;
        memoryData->historyCounter = 1;
    }
    else
    {
        memoryData->history_end->next = history;
        memoryData->history_end = history;
        memoryData->historyCounter++;
    }
}

// Manage memory info to the memory linked list of running processes
// Memory will either be the memory of the current running process, or -1
// If -1, it has been indicated that the process is no longer running
void manage_memory_info(int pid, int memory, char *program, int numOfArgs, char **args)
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
        if (memory != -1)
        {
            read_memory->active = true;
            manage_history_info(read_memory, memory);
        }
        else
        {
            read_memory->active = false;
            pidCount--;
        }
    }
    else
    {
        struct pidMemoryInfo *new_memory_info;

        new_memory_info = malloc(sizeof(struct pidMemoryInfo));

        if (!new_memory_info)
        {
            fprintf(stderr, "Adding new memory info: out of memory\n");
            exit(1);
        }

        new_memory_info->pid = pid;
        new_memory_info->active = true;
        new_memory_info->program = malloc(sizeof(program) * sizeof(char));
        strcpy(new_memory_info->program, program);
        new_memory_info->args = malloc(sizeof(args) * sizeof(char));
        for (int i = 0; i < numOfArgs; i++)
        {
            strcat(new_memory_info->args, args[i]);
            strcat(new_memory_info->args, " ");
        }

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
        pidCount++;
        manage_history_info(new_memory_info, memory);
    }

    pthread_mutex_unlock(&memory_mutex);

    pthread_cond_signal(&got_memory);
}

// When a connection is received by the overseer, add_request will
// add a job request for one of the threads to handle
void add_request(int request_num,
                 int fd,
                 char *program,
                 int numOfArgs,
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
    a_request->numOfArgs = numOfArgs;
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

// get_request returns an available job request if num_requests
// is not 0 to an available thread
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

// exit_handler closes the open socket, tells the threads to
// immediately stop what they're doing and cancel then join,
// and any malloc'd areas of memory are cleaned up
void exit_handler(int SIG)
{
    // Close socket connection
    close(sockfd);

    for (int i = 0; i < 5; i++)
    {
        pthread_cancel(p_threads[i]);
        pthread_mutex_unlock(&request_mutex);
        pthread_join(p_threads[i], NULL);
    }

    char *timePointer = NULL;

    while (add_memory_start != NULL)
    {
        struct pidMemoryInfo *temp = add_memory_start;
        if (add_memory_start->active)
        {
            kill(add_memory_start->pid, SIGKILL);
            time_t t = time(&t);
            timePointer = timestamp();
            fprintf(stdout, "%s - SIGKILL sent to pid %d\n", timePointer, add_memory_start->pid);
            free(timePointer);
        }
        add_memory_start = add_memory_start->next;
        free(temp);
    }

    timePointer = timestamp();
    fprintf(stdout, "%s - Exiting overseer due to: CTRL^C\n", timePointer);
    free(timePointer);
    exit(0);
}

int handle_request(struct request *a_request, int thread_id)
{
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
    char *time = NULL;
    // Contains the filename of the log file. For some reason, this buffer is a workaround for a memory bug?..
    char logBuffer[MAX_BUFFER_SIZE];
    if (strcmp(a_request->program, "mem") == 0)
    {
        while (memory_mutex_activated)
        {
            pthread_cond_wait(&got_memory, &memory_mutex);
        }
        if (a_request->args != NULL)
        {
            send_pid_memory_info(a_request->fd, a_request->args);
        }
        else
        {
            send_memory_info(a_request->fd);
        }

        // Let the Overseer know that the job has finished
        close(a_request->fd);
        return 1;
    }
    else if (strcmp(a_request->program, "memkill") == 0)
    {
        mem_kill(a_request->args);
        // Let the Overseer know that the job has finished
        close(a_request->fd);
        return 1;
    }
    else
    {
        if (a_request->logfile != NULL)
        {
            snprintf(logBuffer, sizeof(logBuffer), "%s", a_request->logfile[1]);
        }
        char outBuffer[MAX_BUFFER_SIZE];
        if (a_request->outfile != NULL)
        {
            snprintf(outBuffer, sizeof(outBuffer), "%s", a_request->outfile[1]);
        }

        while (file_mutex_activated)
        {
            pthread_cond_wait(&got_file, &file_mutex);
        }

        if (a_request->logfile != NULL)
        {
            file_mutex_activated = true;
            pthread_mutex_trylock(&file_mutex);
            // Duplicate stdout fd to be used for restoring stdout to the screen
            stdoutFd = dup(STDOUT_FILENO);

            // Open the logfile with write only and append flags
            logFile = open(logBuffer, O_WRONLY | O_APPEND | O_CREAT, 0777);
            if (logFile < 0)
            {
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

        time = timestamp();
        fprintf(stdout, "%s - Attempting to execute '%s'...\n", time, a_request->program);
        free(time);
        if (a_request->logfile != NULL)
        {
            // Close the log file fd and return stdout to the screen
            close(logFile);
            close(logFileFd);
            dup2(stdoutFd, STDOUT_FILENO);
            close(stdoutFd);
            connection_msg_buffer_check();
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
                    pthread_cond_wait(&got_file, &file_mutex);
                }
                if (a_request->outfile != NULL)
                {
                    file_mutex_activated = true;
                    pthread_mutex_trylock(&file_mutex);

                    sleep(2);

                    stdoutFd = dup(STDOUT_FILENO);
                    stderrFd = dup(STDERR_FILENO);
                    // Open the outfile with write only and append flags
                    outFile = open(outBuffer, O_WRONLY | O_APPEND | O_CREAT, 0777);
                    if (outFile < 0)
                    {
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
                    connection_msg_buffer_check();
                }
            }
            else
            {
                char memoryRead[MAX_BUFFER_SIZE];
                snprintf(memoryRead, sizeof(memoryRead), "/proc/%d/maps", pid);

                int count = 0, term;
                int timeout = TERMINATE_TIMEOUT;
                // While the process is running, update it's memory every 1 second!!!
                while (waitpid(pid, &status, WNOHANG) == 0)
                {
                    while (memory_mutex_activated)
                    {
                        pthread_cond_wait(&got_memory, &memory_mutex);
                    }
                    memory_mutex_activated = true;
                    sleep(0.2);
                    manage_memory_info(pid, getProcMemoryInfo(pid, memoryRead), a_request->program, a_request->numOfArgs, a_request->args);
                    memory_mutex_activated = false;

                    if (count >= timeout)
                    {
                        if (count == timeout) // Once we reach the threshold
                        {
                            // Ask nicely to close the program
                            term = kill(pid, SIGTERM);
                            fprintf(stdout, "%s - sent SIGTERM to %d\n", timestamp(), pid);
                        }
                        switch (term)
                        {
                        case 0: // Program terminated successfully.
                            time = timestamp();
                            fprintf(stdout, "%s - %d has been terminated with status code %d\n", time, pid, WEXITSTATUS(SIGTERM));
                            free(time);
                            break;
                        case -1: // If for some reason we cannot terminate the program by asking nicely.
                            sleep(5);
                            time = timestamp();
                            fprintf(stdout, "%s - sent SIGKILL to %d\n", time, pid);
                            free(time);
                            term = kill(pid, SIGKILL);
                            break;
                        // Error handling
                        case EPERM:
                            perror("Not root or super-user. (Please run under sudo).\n");
                            break;
                        case EINVAL:
                            fprintf(stdout, "Sig <%d>\n", SIGTERM); // Doubt we will ever encounter this error.
                            perror("Invalid SIG value when attempting to terminate.\n");
                            break;
                        case ESRCH:
                            fprintf(stdout, "Pid <%d>\n", getpid());
                            perror("Could not find PID of child process.\n");
                            break;
                        }
                    }
                    count++;
                    sleep(1);
                }
                pid_t ws = waitpid(pid, &status, WNOHANG); // Current status of child (0 is running)

                // Let it be known that the process has finished running
                while (memory_mutex_activated)
                {
                    pthread_cond_wait(&got_memory, &memory_mutex);
                }
                memory_mutex_activated = true;
                manage_memory_info(pid, -1, a_request->program, a_request->numOfArgs, a_request->args);
                memory_mutex_activated = false;

                while (file_mutex_activated)
                {
                    pthread_cond_wait(&got_file, &file_mutex);
                }

                if (a_request->logfile != NULL)
                {
                    file_mutex_activated = true;
                    pthread_mutex_trylock(&file_mutex);
                    // Duplicate stdout fd to be used for restoring stdout to the screen
                    stdoutFd = dup(STDOUT_FILENO);

                    // Open the logfile with write only and append flags
                    logFile = open(logBuffer, O_WRONLY | O_APPEND | O_CREAT, 0777);
                    if (logFile < 0)
                    {
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

                // Need to check signal to check WTERMSIG (best practice)
                if (!WIFEXITED(status) && WIFSIGNALED(status))
                {
                    // Making sure we somehow didn't mess up.
                    if (WTERMSIG(status) != SIGTERM && WTERMSIG(status) != SIGKILL)
                    {
                        if (retVal == -1)
                        {
                            time = timestamp();
                            fprintf(stdout, "%s - Could not execute '%s'\n", time, a_request->program);
                            free(time);
                        }
                        else
                        {
                            time = timestamp();
                            fprintf(stdout, "%s - '%s' has been executed with PID %d\n", time, a_request->program, pid);
                            fprintf(stdout, "%s - PID %d has terminated with status code %d\n", time, pid, WEXITSTATUS(status));
                            free(time);
                        }
                    }
                }
                // WIFEXITED returns true for exit(<1)
                // (programmed executed sucessfully)
                else
                {
                    if (retVal == -1)
                    {
                        time = timestamp();
                        fprintf(stdout, "%s - Could not execute '%s'\n", time, a_request->program);
                        free(time);
                    }
                    else
                    {
                        time = timestamp();
                        fprintf(stdout, "%s - '%s' has been executed with PID %d\n", time, a_request->program, pid);
                        fprintf(stdout, "%s - PID %d has terminated with status code %d\n", time, pid, WEXITSTATUS(status));
                        free(time);
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
            connection_msg_buffer_check();
        }
    }
    // Let the Overseer know that the job has finished
    close(a_request->fd);
    return 1;
}

// handle_requests_loop is the main area of the thread pool. When a
// thread is created, it will endlessly run waiting on any new
// job requests that have came in, otherwise the threads will
// be on standby.
void *handle_requests_loop(void *data)
{
    // When the CTRL+C signal carried out, need to ensure that all threads will cancel and join once they are finished their job
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    struct request *a_request;
    int thread_id = *((int *)data);

    pthread_mutex_lock(&request_mutex);

    while (1)
    {
        if (num_requests > 0)
        {
            a_request = get_request();
            if (a_request)
            {
                pthread_mutex_unlock(&request_mutex);
                handle_request(a_request, thread_id);
                free(a_request->outfile);
                free(a_request->args);
                free(a_request->logfile);
                free(a_request);
            }
        }
        else
        {
            pthread_cond_wait(&got_request, &request_mutex);
        }
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, exit_handler);
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
    char *time = NULL;
    while (1)
    {
        sin_size = sizeof(struct sockaddr_in);
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
                        &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }
        else
        {
            // Connection from a client was successfully made to the overseer!
            // If a thread is currently re-directing stdout, connection messages will get stored in a buffer
            // then printed out to stdout once the logging to the thread's out/log file is finished.
            // Otherwise, it will log to stdout!
            if (file_mutex_activated == true)
            {
                char msg[CONNECT_MSG_BUFFER_SIZE];
                time = timestamp();
                snprintf(msg, sizeof(msg), "%s - Connection received from %s\n", time, inet_ntoa(their_addr.sin_addr));
                free(time);
                connectionMsgBuffer[msgBufferCounter] = malloc(CONNECT_MSG_BUFFER_SIZE * sizeof(char));
                strcpy(connectionMsgBuffer[msgBufferCounter], msg);
                msgBufferCounter++;
                msgBufferPointer++;
            }
            else
            {
                time = timestamp();
                fprintf(stdout, "%s - Connection received from %s\n", time, inet_ntoa(their_addr.sin_addr));
                free(time);
            }

            char programBuffer[MAX_BUFFER_SIZE];
            if (recv(new_fd, &programBuffer, MAX_BUFFER_SIZE, 0) == -1)
            {
                perror("recv");
                exit(1);
            }
            programBuffer[MAX_BUFFER_SIZE] = '\0';

            if (strcmp(programBuffer, "mem") == 0)
            {
                uint16_t test;

                if (recv(new_fd, &test, sizeof(uint16_t), 0) == -1)
                {
                    perror("recv");
                    exit(1);
                }
                test = ntohs(test);

                if (test == 0)
                {
                    add_request(request_counter, new_fd, programBuffer, 0, NULL, NULL, NULL, &request_mutex, &got_request);
                    request_counter++;
                }
                else
                {
                    char **args = NULL;
                    char argsBuffer[MAX_BUFFER_SIZE];
                    if (recv(new_fd, &argsBuffer, MAX_BUFFER_SIZE, 0) == -1)
                    {
                        perror("recv");
                        exit(1);
                    }
                    argsBuffer[MAX_BUFFER_SIZE] = '\0';
                    //args[0] = malloc(sizeof(argsBuffer) * sizeof(char));
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
                    add_request(request_counter, new_fd, programBuffer, 1, args, NULL, NULL, &request_mutex, &got_request);
                    request_counter++;
                }
            }
            else
            {
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

                add_request(request_counter, new_fd, programBuffer, spaces, args, outfileArg, logfileArg, &request_mutex, &got_request);
                request_counter++;
            }
        }
    }

    return 0;
}