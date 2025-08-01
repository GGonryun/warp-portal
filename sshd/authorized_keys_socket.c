#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <json-c/json.h>

#define SOCKET_PATH "/run/p0_agent.sock"
#define MAX_BUFFER_SIZE 4096
#define MAX_RESPONSE_SIZE 8192

static int connect_to_daemon(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        fprintf(stderr, "Error: Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Error: Failed to connect to daemon socket: %s\n", strerror(errno));
        close(sock_fd);
        return -1;
    }
    
    return sock_fd;
}

static char* send_request(const char* request) {
    int sock_fd = connect_to_daemon();
    if (sock_fd == -1) {
        return NULL;
    }
    
    size_t request_len = strlen(request);
    if (send(sock_fd, request, request_len, 0) != (ssize_t)request_len) {
        fprintf(stderr, "Error: Failed to send request to daemon: %s\n", strerror(errno));
        close(sock_fd);
        return NULL;
    }
    
    char *response = malloc(MAX_RESPONSE_SIZE);
    if (!response) {
        fprintf(stderr, "Error: Failed to allocate memory for response\n");
        close(sock_fd);
        return NULL;
    }
    
    ssize_t received = recv(sock_fd, response, MAX_RESPONSE_SIZE - 1, 0);
    close(sock_fd);
    
    if (received <= 0) {
        fprintf(stderr, "Error: Failed to receive response from daemon: %s\n", strerror(errno));
        free(response);
        return NULL;
    }
    
    response[received] = '\0';
    return response;
}

static int parse_key_response(const char* response) {
    json_object *root = json_tokener_parse(response);
    if (!root) {
        fprintf(stderr, "Error: Failed to parse JSON response\n");
        return 1;
    }
    
    json_object *status_obj;
    if (!json_object_object_get_ex(root, "status", &status_obj)) {
        fprintf(stderr, "Error: No status field in response\n");
        json_object_put(root);
        return 1;
    }
    
    const char *status = json_object_get_string(status_obj);
    if (strcmp(status, "success") != 0) {
        json_object *error_obj;
        if (json_object_object_get_ex(root, "error", &error_obj)) {
            fprintf(stderr, "Error: %s\n", json_object_get_string(error_obj));
        }
        json_object_put(root);
        return 1;
    }
    
    json_object *keys_obj;
    if (!json_object_object_get_ex(root, "keys", &keys_obj)) {
        fprintf(stderr, "Error: No keys field in response\n");
        json_object_put(root);
        return 1;
    }
    
    if (json_object_get_type(keys_obj) == json_type_array) {
        size_t keys_count = json_object_array_length(keys_obj);
        if (keys_count == 0) {
            fprintf(stderr, "Error: No keys found in response array\n");
            json_object_put(root);
            return 1;
        }
        
        for (size_t i = 0; i < keys_count; i++) {
            json_object *key_obj = json_object_array_get_idx(keys_obj, i);
            if (!key_obj) {
                fprintf(stderr, "Warning: Null key object at index %zu\n", i);
                continue;
            }
            
            const char *key = json_object_get_string(key_obj);
            if (key && strlen(key) > 0) {
                printf("%s\n", key);
                fflush(stdout);
            } else {
                fprintf(stderr, "Warning: Empty or null key at index %zu\n", i);
            }
        }
    } else if (json_object_get_type(keys_obj) == json_type_string) {
        const char *key = json_object_get_string(keys_obj);
        if (key && strlen(key) > 0) {
            printf("%s\n", key);
            fflush(stdout);
        } else {
            fprintf(stderr, "Error: Empty key in response\n");
            json_object_put(root);
            return 1;
        }
    } else {
        fprintf(stderr, "Error: Keys field is neither array nor string\n");
        json_object_put(root);
        return 1;
    }
    
    json_object_put(root);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <key_type> <key_fingerprint> <username>\n", argv[0]);
        fprintf(stderr, "This program is intended to be called by sshd via AuthorizedKeysCommand\n");
        return 1;
    }
    
    const char *key_type = argv[1];
    const char *key_fingerprint = argv[2];
    const char *username = argv[3];
    
    json_object *request = json_object_new_object();
    json_object *op = json_object_new_string("getkeys");
    json_object *user_obj = json_object_new_string(username);
    json_object *type_obj = json_object_new_string(key_type);
    json_object *fingerprint_obj = json_object_new_string(key_fingerprint);
    
    json_object_object_add(request, "op", op);
    json_object_object_add(request, "username", user_obj);
    json_object_object_add(request, "key_type", type_obj);
    json_object_object_add(request, "key_fingerprint", fingerprint_obj);
    
    const char *request_str = json_object_to_json_string(request);
    char *response = send_request(request_str);
    
    json_object_put(request);
    
    if (!response) {
        fprintf(stderr, "Error: Failed to get response from daemon\n");
        return 1;
    }
    
    int result = parse_key_response(response);
    free(response);
    
    return result;
}