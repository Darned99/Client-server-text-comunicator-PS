/**
 * @file client.c
 * @brief Client application for chat server
 * 
 * This program is a simple chat client that connects to a chat server and allows users to register, login, and send messages to other users.
 * 
 * @authors     
 * Bartlomiej Kisielewski
 * Jakub Wozniak
 * Ryszard Mleczko         
 * 
 * @date January 2025
 * 
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
#include <errno.h>

#define BUFFER_SIZE 1024
#define MAX_USERNAME 32
#define MAX_PASSWORD 32
#define MULTICAST_ADDR "224.0.0.1"
#define MULTICAST_PORT 8889
#define DISCOVER_TIMEOUT 5

int sock = 0;
char username[MAX_USERNAME];
int is_logged_in = 0;
char* available_users[MAX_USERNAME];
int user_count = 0;
char stored_history[10000] = ""; 
char current_recipient[MAX_USERNAME] = ""; 

/**
 * @brief Clear the terminal screen
 */
void clear_screen();

/**
 * @brief Print a divider line
 */
void print_divider();

/**
 * @brief Print a header with a title
 * 
 * @param title Title of the header
 */
void print_header(const char* title);

/**
 * @brief Print a status message
 * 
 * @param message Status message
 */
void print_status(const char* message);

/**
 * @brief Print an error message
 * 
 * @param message Error message
 */
void print_error(const char* message);

/**
 * @brief Print a success message
 * 
 * @param message Success message
 */
void print_success(const char* message);

/**
 * @brief Print the main menu
 */
void print_menu();

/**
 * @brief Display chat history
 * 
 * @param message Chat history message
 */
void display_chat_history(const char* message);

/**
 * @brief Clear the list of available users
 */
void clear_users();

/**
 * @brief Update the list of available users
 * 
 * @param user_list List of users
 */
void update_users(char* user_list);

/**
 * @brief Register a new user
 */
void register_user();

/**
 * @brief Login to an existing account
 */
void login();

/**
 * @brief Send a message to another user
 */
void send_message();

/**
 * @brief Resolve a hostname to an IP address
 * 
 * @param hostname Hostname to resolve
 * @return Resolved IP address
 */
char* resolve_hostname(const char* hostname);

/**
 * @brief Discover the chat server
 * 
 * @param server_ip Server IP address
 * @param server_port Server port
 * @return 0 on success, -1 on failure
 */
int discover_server(char* server_ip, int* server_port);


void clear_screen() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}


void print_divider() {
    printf("\n----------------------------------------\n");
}

void print_header(const char* title) {
    clear_screen();
    printf("\n=== %s ===\n", title);
}

void print_status(const char* message) {
    printf("\n[STATUS] %s\n", message);
}

void print_error(const char* message) {
    printf("\n[ERROR] %s\n", message);
}

void print_success(const char* message) {
    printf("\n[SUCCESS] %s\n", message);
}

void print_menu() {
    print_header("CHAT APPLICATION");
    printf("\nMain Menu:\n");
    print_divider();
    printf("1. Register new account\n");
    printf("2. Login to existing account\n");
    printf("3. Send message\n");
    printf("4. Exit\n");
    print_divider();
}

void display_chat_history(const char* message) {
    
    printf("%s", message + 8);
}

void clear_users() {
    for (int i = 0; i < user_count; i++) {
        free(available_users[i]);
    }
    user_count = 0;
}

void update_users(char* user_list) {
    clear_users();
    
    char* token = strtok(user_list + 6, " "); 
    while (token != NULL) {
        
        if (strcmp(token, username) != 0) {
            available_users[user_count] = strdup(token);
            user_count++;
        }
        token = strtok(NULL, " ");
    }
}


void* receive_messages(void* arg) {
    char buffer[BUFFER_SIZE];
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            print_error("Disconnected from server");
            exit(1);
        }
        
        if (strncmp(buffer, "USERS ", 6) == 0) {
            update_users(buffer);
        } 
        else if (strncmp(buffer, "HISTORY ", 8) == 0) {
            
            strcat(stored_history, buffer + 8);
        }
        else if (strstr(buffer, "MSG ") == buffer) {
            printf("\n[MESSAGE] %s\n", buffer + 4);
        }
        else {
            if (strstr(buffer, "successful")) {
                print_success(buffer);
                if (strstr(buffer, "Login successful")) {
                    is_logged_in = 1;
                }
            } else if (strstr(buffer, "failed")) {
                print_error(buffer);
                if (strstr(buffer, "Login failed")) {
                    is_logged_in = 0;
                }
            } else {
                printf("\n[SYSTEM] %s\n", buffer);
            }
        }
    }
    return NULL;
}

void* refresh_users_list(void* arg) {
    while (1) {
        sleep(10); 
    }
    return NULL;
}

void register_user() {
    print_header("USER REGISTRATION");
    
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char buffer[BUFFER_SIZE];
    
    printf("\nEnter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);
    
    snprintf(buffer, sizeof(buffer), "REGISTER %s %s", username, password);
    send(sock, buffer, strlen(buffer), 0);
    
    print_status("Processing registration...");
    sleep(1); 
}

void login() {
    print_header("LOGIN");
    
    char password[MAX_PASSWORD];
    char buffer[BUFFER_SIZE];
    
    printf("\nEnter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);
    
    is_logged_in = 0;  
    
    snprintf(buffer, sizeof(buffer), "LOGIN %s %s", username, password);
    send(sock, buffer, strlen(buffer), 0);
    
    print_status("Processing login...");
    sleep(1); 

    char list_request[BUFFER_SIZE] = "LIST";
    send(sock, list_request, strlen(list_request), 0);
}

void send_message() {
    if (!is_logged_in) {
        print_error("You must login first");
        sleep(2);
        return;
    }

    clear_screen();
    print_header("SEND MESSAGE");

    char list_request[BUFFER_SIZE] = "LIST";
    send(sock, list_request, strlen(list_request), 0);
    sleep(1); 
    
    if (user_count == 0) {
        print_error("No other users are online");
        sleep(2);
        return;
    }

    printf("\nAvailable Users:\n");
    print_divider();
    for (int i = 0; i < user_count; i++) {
        printf("%d. %s\n", i + 1, available_users[i]);
    }
    print_divider();
    
    printf("\nSelect user number (0 to cancel): ");
    int choice;
    scanf("%d", &choice);
    
    if (choice == 0) {
        return;
    }
    
    if (choice < 1 || choice > user_count) {
        print_error("Invalid user number");
        sleep(2);
        return;
    }

   clear_screen();
    print_header("Chat with ");
    printf("%s\n", available_users[choice-1]);
    print_divider();

    char* history_ptr = stored_history;
    char* line;
    while ((line = strtok_r(history_ptr, "\n", &history_ptr))) {
        if (strstr(line, available_users[choice-1]) || 
            strstr(line, username)) {
            printf("%s\n", line);
        }
    }
    print_divider();
    
    printf("\nEnter your message: ");
    char message[BUFFER_SIZE];
    getchar(); 
    fgets(message, BUFFER_SIZE, stdin);
    message[strcspn(message, "\n")] = 0; 
    
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "MSG %s %s", available_users[choice-1], message);
    send(sock, buffer, strlen(buffer), 0);
    
    print_success("Message sent");
    sleep(1);
}

char* resolve_hostname(const char* hostname) {
    struct hostent *he;
    struct in_addr **addr_list;
    static char ip[100];
    
    struct in_addr addr;
    if (inet_aton(hostname, &addr) != 0) {
        return (char*)hostname;
    }
    
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

int discover_server(char* server_ip, int* server_port) {
    int discover_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (discover_socket < 0) {
        perror("Discovery socket creation failed");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = DISCOVER_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(discover_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Failed to set timeout");
        close(discover_socket);
        return -1;
    }

    int reuse = 1;
    if (setsockopt(discover_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("Failed to set SO_REUSEADDR");
        close(discover_socket);
        return -1;
    }

    unsigned char ttl = 1;
    if (setsockopt(discover_socket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("Failed to set multicast TTL");
        close(discover_socket);
        return -1;
    }

    struct sockaddr_in multi_addr;
    memset(&multi_addr, 0, sizeof(multi_addr));
    multi_addr.sin_family = AF_INET;
    multi_addr.sin_addr.s_addr = inet_addr(MULTICAST_ADDR);
    multi_addr.sin_port = htons(MULTICAST_PORT);

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(discover_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("Failed to join multicast group");
        close(discover_socket);
        return -1;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(0);  
    
    if (bind(discover_socket, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("Bind failed");
        close(discover_socket);
        return -1;
    }

    printf("Sending discovery message...\n");
    const char* discover_msg = "DISCOVER";
    if (sendto(discover_socket, discover_msg, strlen(discover_msg), 0,
               (struct sockaddr*)&multi_addr, sizeof(multi_addr)) < 0) {
        perror("Failed to send discovery message");
        close(discover_socket);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    
    printf("Waiting for server response (timeout: %d seconds)...\n", DISCOVER_TIMEOUT);
    int received = recvfrom(discover_socket, buffer, BUFFER_SIZE, 0,
                           (struct sockaddr*)&server_addr, &server_len);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Discovery timeout - no server found\n");
        } else {
            perror("Error receiving server response");
        }
        close(discover_socket);
        return -1;
    }

    buffer[received] = '\0';
    printf("Received response: %s\n", buffer);
    
    if (strncmp(buffer, "SERVER ", 7) == 0) {
        char server_host[64];
        if (sscanf(buffer + 7, "%s %d", server_host, server_port) == 2) {
        
            char* resolved_ip = resolve_hostname(server_host);
            if (resolved_ip == NULL) {
                printf("Failed to resolve hostname: %s\n", server_host);
                close(discover_socket);
                return -1;
            }
            
            strcpy(server_ip, resolved_ip);
            printf("Successfully discovered server at %s:%d\n", server_ip, *server_port);
            close(discover_socket);
            return 0;
        }
    }

    printf("Invalid server response format\n");
    close(discover_socket);
    return -1;
}


int main() {
    print_status("Discovering chat server...");
    
    char server_ip[16];
    int server_port;
    
    if (discover_server(server_ip, &server_port) < 0) {
        print_error("Could not find server. Make sure it's running.");
        return -1;
    }
    
    print_success("Found server.");
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        print_error("Socket creation error");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);
    
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        print_error("Invalid address");
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        print_error("Connection failed");
        return -1;
    }
    
    print_success("Connected to server");
    
    pthread_t receive_thread, refresh_thread;
    pthread_create(&receive_thread, NULL, receive_messages, NULL);
    pthread_create(&refresh_thread, NULL, refresh_users_list, NULL);
    
    while (1) {
        
        print_menu();
        printf("\nEnter your choice: ");
        int choice;
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                register_user();
                break;
            case 2:
                login();
                break;
            case 3:
                if (is_logged_in) {
                    send_message();
                } else {
                    print_error("You must login first");
                    sleep(2);
                }
                break;
            case 4:
                clear_screen();
                print_success("Thank you for using the chat application!");
                close(sock);
                sleep(1);
                return 0;
            default:
                print_error("Invalid choice");
                sleep(2);
        }
    }
    
    return 0;
}
