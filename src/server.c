/**
 * @file server.c
 * @brief Server application for chat server
 * 
 * This program is a simple chat server that allows multiple clients to connect and communicate with each other.
 * 
 * @authors
 * Bartlomiej Kisielewski
 * Jakub Wozniak
 * Ryszard Mleczko
 * 
 * @date January 2025
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <time.h>

#define USERS_FILE "users.txt"
#define CHAT_HISTORY_FILE "chat_history.txt"
#define MAX_MESSAGE_LENGTH 512
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define MAX_USERNAME 32
#define MAX_PASSWORD 32
#define MULTICAST_ADDR "224.0.0.1"
#define MULTICAST_PORT 8889
#define SERVER_PORT 8888

/**
 * @brief Structure representing a chat message
 */
typedef struct {
    char timestamp[26];
    char sender[MAX_USERNAME];
    char recipient[MAX_USERNAME];
    char content[MAX_MESSAGE_LENGTH];
} ChatMessage;

/**
 * @brief Structure representing a client
 */
typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    int socket;
    int is_logged_in;
} Client;

/**
 * @brief Structure representing a user
 */
typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
} User;


Client clients[MAX_CLIENTS];
User users[100];
int user_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Save users to file
 */
void save_users_to_file();

/**
 * @brief Load users from file
 */
void load_users_from_file();

/**
 * @brief Save chat message to file
 * 
 * @param sender Sender of the message
 * @param recipient Recipient of the message
 * @param message Message content
 */
void save_chat_message(const char* sender, const char* recipient, const char* message);

/**
 * @brief Send chat history to client
 * 
 * @param client_socket Client socket
 * @param username Username of the client
 */
void send_chat_history(int client_socket, const char* username);

/**
 * @brief Resolve hostname to IP address
 * 
 * @param hostname Hostname to resolve
 * @return IP address
 */
char* resolve_hostname(const char* hostname);

/**
 * @brief Initialize clients
 */
void init_clients();

/**
 * @brief Find a free slot in the clients array
 * 
 * @return Index of the free slot
 */
int find_free_slot();

/**
 * @brief Find a user by username
 * 
 * @param username Username to search for
 * @return Index of the user
 */
int find_user_by_name(const char* username);

/**
 * @brief Register a new user
 * 
 * @param username Username
 * @param password Password
 * @return 1 on success, 0 on failure
 */
int register_user(char* username, char* password);

/**
 * @brief Authenticate a user
 * 
 * @param username Username
 * @param password Password
 * @return 1 on success, 0 on failure
 */
int authenticate_user(char* username, char* password);

/**
 * @brief Send the list of users to a client
 * 
 * @param client_socket Client socket
 */
void send_user_list(int client_socket);

/**
 * @brief Handle client connection
 * 
 * @param arg Client socket
 * @return NULL
 */
void* handle_client(void* arg);

/**
 * @brief Handle discovery
 * 
 * @param arg Unused
 * @return NULL
 */
void* handle_discovery(void* arg);


void save_users_to_file() {
    FILE *file = fopen(USERS_FILE, "w");
    if (file == NULL) {
        perror("Error opening users file");
        return;
    }

    for (int i = 0; i < user_count; i++) {
        fprintf(file, "%s %s\n", users[i].username, users[i].password);
    }

    fclose(file);
}

void load_users_from_file() {
    FILE *file = fopen(USERS_FILE, "r");
    if (file == NULL) {
        return; 
    }

    while (!feof(file) && user_count < 100) {
        char username[MAX_USERNAME];
        char password[MAX_PASSWORD];
        if (fscanf(file, "%s %s", username, password) == 2) {
            strcpy(users[user_count].username, username);
            strcpy(users[user_count].password, password);
            user_count++;
        }
    }

    fclose(file);
}

void save_chat_message(const char* sender, const char* recipient, const char* message) {
    FILE *file = fopen(CHAT_HISTORY_FILE, "a");
    if (file == NULL) {
        perror("Error opening chat history file");
        return;
    }

    time_t now;
    time(&now);
    char timestamp[26];
    ctime_r(&now, timestamp);
    timestamp[24] = '\0';

    fprintf(file, "[%s] %s -> %s: %s\n", timestamp, sender, recipient, message);
    fclose(file);
}

void send_chat_history(int client_socket, const char* username) {
    FILE *file = fopen(CHAT_HISTORY_FILE, "r");
    if (file == NULL) {
        return;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        
        if (strstr(line, username)) {
            char buffer[BUFFER_SIZE];
            snprintf(buffer, sizeof(buffer), "HISTORY %s", line);
            send(client_socket, buffer, strlen(buffer), 0);
        
            usleep(10000); 
        }
    }

    fclose(file);
}

char* resolve_hostname(const char* hostname) {
    struct hostent *he;
    struct in_addr **addr_list;
    static char ip[100];
    
    if ((he = gethostbyname(hostname)) == NULL) {
        herror("gethostbyname");
        return NULL;
    }
    
    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] != NULL) {
        strcpy(ip, inet_ntoa(*addr_list[0]));
        return ip;
    }
    
    return NULL;
}
void init_clients() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
        clients[i].is_logged_in = 0;
    }
}

int find_free_slot() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) return i;
    }
    return -1;
}

int find_user_by_name(const char* username) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1 && clients[i].is_logged_in && 
            strcmp(clients[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

int register_user(char* username, char* password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return 0; 
        }
    }
    
    strcpy(users[user_count].username, username);
    strcpy(users[user_count].password, password);
    user_count++;
    return 1;
}

int authenticate_user(char* username, char* password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return 1;
        }
    }
    return 0;
}

void send_user_list(int client_socket) {
    char buffer[BUFFER_SIZE] = "USERS ";
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1 && clients[i].is_logged_in) {
            strcat(buffer, clients[i].username);
            strcat(buffer, " ");
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    send(client_socket, buffer, strlen(buffer), 0);
}

void* handle_client(void* arg) {
    int client_socket = *((int*)arg);
    free(arg);
    char buffer[BUFFER_SIZE];
    int client_index = -1;
    
    pthread_mutex_lock(&clients_mutex);
    client_index = find_free_slot();
    if (client_index != -1) {
        clients[client_index].socket = client_socket;
    }
    pthread_mutex_unlock(&clients_mutex);
    
    if (client_index == -1) {
        close(client_socket);
        return NULL;
    }
    
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) break;
        
        char command[32], arg1[MAX_USERNAME], arg2[MAX_PASSWORD], message[BUFFER_SIZE];
        sscanf(buffer, "%s %s %s", command, arg1, arg2);
        
        if (strcmp(command, "REGISTER") == 0) {
            int result = register_user(arg1, arg2);
            if (result) save_users_to_file();
            send(client_socket, result ? "Registration successful" : "Registration failed", 
                 result ? 22 : 19, 0);
        }
        else if (strcmp(command, "LOGIN") == 0) {
            if (authenticate_user(arg1, arg2)) {
                strcpy(clients[client_index].username, arg1);
                clients[client_index].is_logged_in = 1;
                send(client_socket, "Login successful", 16, 0);
                send_chat_history(client_socket, arg1);  
                send_user_list(client_socket);           
                
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].socket != -1 && clients[i].is_logged_in) {
                        send_user_list(clients[i].socket);
                    }
                }
            } else {
                send(client_socket, "Login failed", 12, 0);
            }
        }
        else if (strcmp(command, "MSG") == 0) {
            if (!clients[client_index].is_logged_in) continue;
            
            char* recipient = arg1;
            char* msg_start = strstr(buffer + 4, " ") + 1;
            int recipient_index = find_user_by_name(recipient);
            
            if (recipient_index != -1) {
                char full_message[BUFFER_SIZE];
                snprintf(full_message, sizeof(full_message), "MSG %s: %s", 
                        clients[client_index].username, msg_start);
                send(clients[recipient_index].socket, full_message, strlen(full_message), 0);
                save_chat_message(clients[client_index].username, recipient, msg_start);
            }
        }
        else if (strcmp(command, "LIST") == 0) {
            if (clients[client_index].is_logged_in) {
                send_user_list(client_socket);
                
                send_chat_history(client_socket, clients[client_index].username);
            }
        }
    }
    
    pthread_mutex_lock(&clients_mutex);
    clients[client_index].socket = -1;
    clients[client_index].is_logged_in = 0;
    pthread_mutex_unlock(&clients_mutex);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1 && clients[i].is_logged_in) {
            send_user_list(clients[i].socket);
        }
    }
    
    close(client_socket);
    return NULL;
}

void* handle_discovery(void* arg) {
    int discovery_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (discovery_socket < 0) {
        perror("Discovery socket creation failed");
        return NULL;
    }
    
    int reuse = 1;
    if (setsockopt(discovery_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("Failed to set SO_REUSEADDR");
        close(discovery_socket);
        return NULL;
    }
    
    struct sockaddr_in multi_addr;
    memset(&multi_addr, 0, sizeof(multi_addr));
    multi_addr.sin_family = AF_INET;
    multi_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    multi_addr.sin_port = htons(MULTICAST_PORT);
    
    if (bind(discovery_socket, (struct sockaddr*)&multi_addr, sizeof(multi_addr)) < 0) {
        perror("Discovery bind failed");
        close(discovery_socket);
        return NULL;
    }
    
    unsigned char ttl = 1;
    if (setsockopt(discovery_socket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("Failed to set multicast TTL");
        close(discovery_socket);
        return NULL;
    }
    
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    
    if (setsockopt(discovery_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("Multicast join failed");
        close(discovery_socket);
        return NULL;
    }

    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    struct sockaddr_in temp_addr;
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr("8.8.8.8");  
    temp_addr.sin_port = htons(53);  
    connect(temp_sock, (struct sockaddr*)&temp_addr, sizeof(temp_addr));
    getsockname(temp_sock, (struct sockaddr*)&server_addr, &addr_len);
    close(temp_sock);
    
    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        recvfrom(discovery_socket, buffer, BUFFER_SIZE, 0, 
                 (struct sockaddr*)&client_addr, &client_len);
        
        if (strcmp(buffer, "DISCOVER") == 0) {
            char response[BUFFER_SIZE];
            char host_ip[16];
            inet_ntop(AF_INET, &server_addr.sin_addr, host_ip, sizeof(host_ip));
            
            snprintf(response, sizeof(response), "SERVER %s %d", host_ip, SERVER_PORT);
            printf("Sending discovery response: %s\n", response);
            sendto(discovery_socket, response, strlen(response), 0,
                   (struct sockaddr*)&client_addr, client_len);
        }
    }
}


int main() {
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8"); 
    addr.sin_port = htons(53); 
    connect(temp_sock, (struct sockaddr*)&addr, sizeof(addr));
    getsockname(temp_sock, (struct sockaddr*)&addr, &addr_len);
    char host_ip[16];
    inet_ntop(AF_INET, &addr.sin_addr, host_ip, sizeof(host_ip));
    printf("Server IP address: %s\n", host_ip);
    close(temp_sock);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    load_users_from_file();
    init_clients();
    
    pthread_t discovery_thread;
    pthread_create(&discovery_thread, NULL, handle_discovery, NULL);
    
    printf("Server started on port %d\n", SERVER_PORT);
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int* client_socket = malloc(sizeof(int));
        *client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (*client_socket < 0) {
            perror("Accept failed");
            free(client_socket);
            continue;
        }
        
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, (void*)client_socket) < 0) {
            perror("Could not create thread");
            free(client_socket);
            continue;
        }
        pthread_detach(thread);
    }
    
    close(server_socket);
    return 0;
}
