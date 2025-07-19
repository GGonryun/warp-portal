#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <json-c/json.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SOCKET_PATH "/run/warp_portal.sock"
#define LOG_FILE "/var/log/nss_socket.log"
#define MAX_BUFFER_SIZE 4096
#define MAX_RESPONSE_SIZE 8192

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t enum_mutex = PTHREAD_MUTEX_INITIALIZER;
static int enum_index = 0;
static int enum_active = 0;

static void log_message(const char *level, const char *message) {
    pthread_mutex_lock(&log_mutex);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        if (time_str) {
            time_str[strlen(time_str) - 1] = '\0';
        }
        fprintf(log_file, "[%s] %s: %s\n", time_str ? time_str : "unknown", level, message);
        fclose(log_file);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

static int connect_to_daemon(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        log_message("ERROR", "Failed to create socket");
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        log_message("ERROR", "Failed to connect to daemon socket");
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
        log_message("ERROR", "Failed to send request to daemon");
        close(sock_fd);
        return NULL;
    }
    
    char *response = malloc(MAX_RESPONSE_SIZE);
    if (!response) {
        log_message("ERROR", "Failed to allocate memory for response");
        close(sock_fd);
        return NULL;
    }
    
    ssize_t received = recv(sock_fd, response, MAX_RESPONSE_SIZE - 1, 0);
    close(sock_fd);
    
    if (received <= 0) {
        log_message("ERROR", "Failed to receive response from daemon");
        free(response);
        return NULL;
    }
    
    response[received] = '\0';
    return response;
}

static enum nss_status parse_passwd_response(const char* response, struct passwd *pwd, char *buffer, size_t buflen, int *errnop) {
    json_object *root = json_tokener_parse(response);
    if (!root) {
        log_message("ERROR", "Failed to parse JSON response");
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    json_object *status_obj;
    if (!json_object_object_get_ex(root, "status", &status_obj)) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    const char *status = json_object_get_string(status_obj);
    if (strcmp(status, "success") != 0) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    json_object *user_obj;
    if (!json_object_object_get_ex(root, "user", &user_obj)) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    json_object *name_obj, *uid_obj, *gid_obj, *gecos_obj, *dir_obj, *shell_obj;
    if (!json_object_object_get_ex(user_obj, "name", &name_obj) ||
        !json_object_object_get_ex(user_obj, "uid", &uid_obj) ||
        !json_object_object_get_ex(user_obj, "gid", &gid_obj) ||
        !json_object_object_get_ex(user_obj, "gecos", &gecos_obj) ||
        !json_object_object_get_ex(user_obj, "dir", &dir_obj) ||
        !json_object_object_get_ex(user_obj, "shell", &shell_obj)) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    const char *name = json_object_get_string(name_obj);
    const char *gecos = json_object_get_string(gecos_obj);
    const char *dir = json_object_get_string(dir_obj);
    const char *shell = json_object_get_string(shell_obj);
    uid_t uid = json_object_get_int(uid_obj);
    gid_t gid = json_object_get_int(gid_obj);
    
    size_t total_len = strlen(name) + strlen(gecos) + strlen(dir) + strlen(shell) + 5;
    if (total_len > buflen) {
        json_object_put(root);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    
    char *ptr = buffer;
    pwd->pw_name = ptr;
    strcpy(ptr, name);
    ptr += strlen(name) + 1;
    
    pwd->pw_passwd = ptr;
    strcpy(ptr, "x");
    ptr += 2;
    
    pwd->pw_uid = uid;
    pwd->pw_gid = gid;
    
    pwd->pw_gecos = ptr;
    strcpy(ptr, gecos);
    ptr += strlen(gecos) + 1;
    
    pwd->pw_dir = ptr;
    strcpy(ptr, dir);
    ptr += strlen(dir) + 1;
    
    pwd->pw_shell = ptr;
    strcpy(ptr, shell);
    
    json_object_put(root);
    return NSS_STATUS_SUCCESS;
}

static enum nss_status parse_group_response(const char* response, struct group *grp, char *buffer, size_t buflen, int *errnop) {
    json_object *root = json_tokener_parse(response);
    if (!root) {
        log_message("ERROR", "Failed to parse JSON response");
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    json_object *status_obj;
    if (!json_object_object_get_ex(root, "status", &status_obj)) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    const char *status = json_object_get_string(status_obj);
    if (strcmp(status, "success") != 0) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    json_object *group_obj;
    if (!json_object_object_get_ex(root, "group", &group_obj)) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    json_object *name_obj, *gid_obj, *members_obj;
    if (!json_object_object_get_ex(group_obj, "name", &name_obj) ||
        !json_object_object_get_ex(group_obj, "gid", &gid_obj) ||
        !json_object_object_get_ex(group_obj, "members", &members_obj)) {
        json_object_put(root);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    const char *name = json_object_get_string(name_obj);
    gid_t gid = json_object_get_int(gid_obj);
    
    size_t name_len = strlen(name);
    size_t members_count = json_object_array_length(members_obj);
    
    size_t total_len = name_len + 3 + (members_count + 1) * sizeof(char*);
    for (size_t i = 0; i < members_count; i++) {
        json_object *member_obj = json_object_array_get_idx(members_obj, i);
        total_len += strlen(json_object_get_string(member_obj)) + 1;
    }
    
    if (total_len > buflen) {
        json_object_put(root);
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    
    char *ptr = buffer;
    grp->gr_name = ptr;
    strcpy(ptr, name);
    ptr += name_len + 1;
    
    grp->gr_passwd = ptr;
    strcpy(ptr, "x");
    ptr += 2;
    
    grp->gr_gid = gid;
    
    char **members = (char**)ptr;
    ptr += (members_count + 1) * sizeof(char*);
    
    for (size_t i = 0; i < members_count; i++) {
        json_object *member_obj = json_object_array_get_idx(members_obj, i);
        const char *member_name = json_object_get_string(member_obj);
        members[i] = ptr;
        strcpy(ptr, member_name);
        ptr += strlen(member_name) + 1;
    }
    members[members_count] = NULL;
    
    grp->gr_mem = members;
    
    json_object_put(root);
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_socket_getpwnam_r(const char *name, struct passwd *pwd, char *buffer, size_t buflen, int *errnop) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "getpwnam_r called for user: %s", name);
    log_message("INFO", log_msg);
    
    json_object *request = json_object_new_object();
    json_object *op = json_object_new_string("getpwnam");
    json_object *username = json_object_new_string(name);
    
    json_object_object_add(request, "op", op);
    json_object_object_add(request, "username", username);
    
    const char *request_str = json_object_to_json_string(request);
    char *response = send_request(request_str);
    
    json_object_put(request);
    
    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    enum nss_status result = parse_passwd_response(response, pwd, buffer, buflen, errnop);
    free(response);
    
    if (result == NSS_STATUS_SUCCESS) {
        log_message("INFO", "getpwnam_r succeeded");
    } else {
        log_message("INFO", "getpwnam_r failed");
    }
    
    return result;
}

enum nss_status _nss_socket_getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t buflen, int *errnop) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "getpwuid_r called for uid: %d", uid);
    log_message("INFO", log_msg);
    
    json_object *request = json_object_new_object();
    json_object *op = json_object_new_string("getpwuid");
    json_object *uid_obj = json_object_new_int(uid);
    
    json_object_object_add(request, "op", op);
    json_object_object_add(request, "uid", uid_obj);
    
    const char *request_str = json_object_to_json_string(request);
    char *response = send_request(request_str);
    
    json_object_put(request);
    
    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    enum nss_status result = parse_passwd_response(response, pwd, buffer, buflen, errnop);
    free(response);
    
    if (result == NSS_STATUS_SUCCESS) {
        log_message("INFO", "getpwuid_r succeeded");
    } else {
        log_message("INFO", "getpwuid_r failed");
    }
    
    return result;
}

enum nss_status _nss_socket_setpwent(void) {
    log_message("INFO", "setpwent called - initializing enumeration");
    
    pthread_mutex_lock(&enum_mutex);
    enum_index = 0;
    enum_active = 1;
    pthread_mutex_unlock(&enum_mutex);
    
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_socket_endpwent(void) {
    log_message("INFO", "endpwent called - ending enumeration");
    
    pthread_mutex_lock(&enum_mutex);
    enum_active = 0;
    enum_index = 0;
    pthread_mutex_unlock(&enum_mutex);
    
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_socket_getpwent_r(struct passwd *pwd, 
                                       char *buffer, 
                                       size_t buflen, 
                                       int *errnop) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "getpwent_r called with index: %d", enum_index);
    log_message("INFO", log_msg);
    
    pthread_mutex_lock(&enum_mutex);
    if (!enum_active) {
        pthread_mutex_unlock(&enum_mutex);
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    int current_index = enum_index++;
    pthread_mutex_unlock(&enum_mutex);
    
    json_object *request = json_object_new_object();
    json_object *op = json_object_new_string("getpwent");
    json_object *index_obj = json_object_new_int(current_index);
    
    json_object_object_add(request, "op", op);
    json_object_object_add(request, "index", index_obj);
    
    const char *request_str = json_object_to_json_string(request);
    char *response = send_request(request_str);
    
    json_object_put(request);
    
    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    enum nss_status result = parse_passwd_response(response, pwd, buffer, buflen, errnop);
    free(response);
    
    if (result == NSS_STATUS_SUCCESS) {
        log_message("INFO", "getpwent_r succeeded");
    } else {
        log_message("INFO", "getpwent_r failed - end of enumeration");
    }
    
    return result;
}

enum nss_status _nss_socket_getgrnam_r(const char *name, struct group *grp, char *buffer, size_t buflen, int *errnop) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "getgrnam_r called for group: %s", name);
    log_message("INFO", log_msg);
    
    json_object *request = json_object_new_object();
    json_object *op = json_object_new_string("getgrnam");
    json_object *groupname = json_object_new_string(name);
    
    json_object_object_add(request, "op", op);
    json_object_object_add(request, "groupname", groupname);
    
    const char *request_str = json_object_to_json_string(request);
    char *response = send_request(request_str);
    
    json_object_put(request);
    
    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    enum nss_status result = parse_group_response(response, grp, buffer, buflen, errnop);
    free(response);
    
    if (result == NSS_STATUS_SUCCESS) {
        log_message("INFO", "getgrnam_r succeeded");
    } else {
        log_message("INFO", "getgrnam_r failed");
    }
    
    return result;
}

enum nss_status _nss_socket_getgrgid_r(gid_t gid, struct group *grp, char *buffer, size_t buflen, int *errnop) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "getgrgid_r called for gid: %d", gid);
    log_message("INFO", log_msg);
    
    json_object *request = json_object_new_object();
    json_object *op = json_object_new_string("getgrgid");
    json_object *gid_obj = json_object_new_int(gid);
    
    json_object_object_add(request, "op", op);
    json_object_object_add(request, "gid", gid_obj);
    
    const char *request_str = json_object_to_json_string(request);
    char *response = send_request(request_str);
    
    json_object_put(request);
    
    if (!response) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    enum nss_status result = parse_group_response(response, grp, buffer, buflen, errnop);
    free(response);
    
    if (result == NSS_STATUS_SUCCESS) {
        log_message("INFO", "getgrgid_r succeeded");
    } else {
        log_message("INFO", "getgrgid_r failed");
    }
    
    return result;
}

enum nss_status _nss_socket_setgrent(void) {
    log_message("INFO", "setgrent called (no-op)");
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_socket_endgrent(void) {
    log_message("INFO", "endgrent called (no-op)");
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_socket_getgrent_r(struct group *grp __attribute__((unused)), 
                                       char *buffer __attribute__((unused)), 
                                       size_t buflen __attribute__((unused)), 
                                       int *errnop) {
    log_message("INFO", "getgrent_r called (not supported)");
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}