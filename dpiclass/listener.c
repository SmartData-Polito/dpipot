#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "classifier.h"

#include <syslog.h>

#define MAX_SIZE        9000
#define LISTEN_BACKLOG  16000
#define SOCK_PATH       "/tmp/dpisocket"

int socket_desc;

void sighandler() {
    shutdown(socket_desc, SHUT_RD);
    close(socket_desc);
    exit(0);
}

/*
 * This will handle connection for each client
 *
 */
void *connection_handler(void *desc) {
    int socket_desc = *(int*)desc;
    int64_t size;
    char client_message[MAX_SIZE];
    char default_answer[] = "unknown";

    struct nDPI_workflow *workflow = init_workflow();
    struct pcap_pkthdr header;

    // Receive a message from client
    while ((size = recv(socket_desc, client_message, MAX_SIZE, 0)) > 0) {
        char *server_answer;
        gettimeofday(&header.ts, 0);
        header.len = (uint32_t)size;
        header.caplen = MAX_SIZE;
        server_answer = ndpi_process_packet(workflow, &header, (uint8_t*)&client_message);
        if (server_answer)
           size = write(socket_desc, server_answer, strlen(server_answer));
        else
           size = write(socket_desc, default_answer, strlen(default_answer));

    }
    free_workflow(&workflow);
    return 0;
}

int main() {
    struct sockaddr_un addr;

    struct timeval ts;
    gettimeofday(&ts, 0);
    int64_t time_ms = ((int64_t)ts.tv_sec) * TICK_RESOLUTION + ts.tv_usec / (1000000 / TICK_RESOLUTION);

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    //Create socket
    socket_desc = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (socket_desc == -1) {
        fprintf(stderr, "%lu Could not create socket\n", time_ms);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCK_PATH);

    //Bind
    if (bind(socket_desc, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("socket");
        fprintf(stderr, "%lu bind error\n", time_ms);
        exit(-1);
    }

    fprintf(stderr, "%lu Starting DPI service\n", time_ms);

    //Listen
    listen(socket_desc, LISTEN_BACKLOG);

    while (1) {
        // incoming connection
        int new_socket;
        if ((new_socket = accept(socket_desc, NULL, NULL)) == -1) {
            fprintf(stderr, "%lu Server shutdown!\n", time_ms);
            return 1;
        }
        gettimeofday(&ts, 0);
        time_ms = ((int64_t)ts.tv_sec) * TICK_RESOLUTION + ts.tv_usec / (1000000 / TICK_RESOLUTION);

        pthread_t sniffer_thread;
        if (pthread_create(&sniffer_thread, NULL, connection_handler, &new_socket) < 0) {
            fprintf(stderr, "%lu Could not create the thread\n", time_ms);
            return 1;
        }
    }
    return 0;
}
