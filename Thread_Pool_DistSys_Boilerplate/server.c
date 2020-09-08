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
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define NUM_HANDLER_THREADS 4
#define NUM_OF_REQUESTS 10
#define ARRAY_SIZE 30

pthread_mutex_t request_mutex;
pthread_cond_t got_request;
int num_requests = 0;

struct request
{
    int number;
    int fd;
    struct request *next;
};

struct request *requests = NULL;
struct request *last_request = NULL;

void add_request(int request_num,
                 int fd,
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

int handle_request(struct request *a_request, int thread_id)
{
    printf("Thread %d handled request %d\n", thread_id, a_request->number);

    int i = 0;
    uint16_t nbos;
    char buf[100];

    int arr[ARRAY_SIZE] = {0};
    for (i = 0; i < ARRAY_SIZE; i++)
    {
        arr[i] = i * i;
    }

    for (i = 0; i < ARRAY_SIZE; i++)
    {
        nbos = htons(arr[i]);
        send(a_request->fd, &nbos, sizeof(uint16_t), 0);
    }
    fflush(stdout);

    int numbytes;

    if ((numbytes = recv(a_request->fd, buf, 100, 0)) == -1)
    {
        perror("recv");
        exit(1);
    }

    buf[numbytes] = '\0';

    printf("Received: %s", buf);

    close(a_request->fd);

    return 1;
}

// To implement!
// void check_for_requests(sin_size, new_fd, sockfd, their_addr)
// {
//     sin_size = sizeof(struct sockaddr_in);
//     if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
//                          &sin_size)) == -1)
//     {
//         perror("accept");
//         continue;
//     }
//     printf("server: got connection from %s\n",
//            inet_ntoa(their_addr.sin_addr));
// }

void *handle_requests_loop(void *data)
{
    struct request *a_request;
    int thread_id = *((int *)data);
    printf("Thread ID: %d running...\n", thread_id);
    pthread_mutex_lock(&request_mutex);

    while (1)
    {
        sleep(1);
        if (num_requests > 0)
        {
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
    printf("Now listening for requests...\n");

    // Setting up thread pool
    int thr_id[NUM_HANDLER_THREADS];
    pthread_t p_threads[NUM_HANDLER_THREADS];

    pthread_mutex_init(&request_mutex, NULL);
    pthread_cond_init(&got_request, NULL);

    for (int i = 0; i < NUM_HANDLER_THREADS; i++)
    {
        pthread_create(&p_threads[i], NULL, handle_requests_loop, &i);
    }

    // Hold a condition to exit maybe?
    int request_counter = 0;
    while (1)
    {
        sleep(3);
        sin_size = sizeof(struct sockaddr_in);
        if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
                             &sin_size)) == -1)
        {
            perror("accept");
            continue;
        }
        else
        {
            printf("Server: Got connection from %s\n",
                   inet_ntoa(their_addr.sin_addr));
            add_request(request_counter, new_fd, &request_mutex, &got_request);
            request_counter++;
        }
    }

    return 0;
}