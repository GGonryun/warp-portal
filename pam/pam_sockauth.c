#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define SOCKET_PATH "/run/warp_portal.sock"
#define LOG_FILE "/var/log/pam_sockauth.log"
#define MAX_BUFFER_SIZE 4096

static void log_message(const char *level, const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        if (time_str) {
            time_str[strlen(time_str) - 1] = '\0'; // Remove newline
        }
        fprintf(log_file, "[%s] %s: %s\n", time_str ? time_str : "unknown", level, message);
        fclose(log_file);
    }
    
    // Also log to syslog for system administrators
    syslog(LOG_AUTHPRIV | LOG_INFO, "pam_sockauth: %s", message);
}

static int connect_to_daemon(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to create socket: %s", strerror(errno));
        log_message("ERROR", error_msg);
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to connect to daemon socket: %s", strerror(errno));
        log_message("ERROR", error_msg);
        close(sock_fd);
        return -1;
    }
    
    return sock_fd;
}

static int check_sudo_auth(const char *username) {
    int sock_fd = connect_to_daemon();
    if (sock_fd == -1) {
        return 0; // Deny access if socket unavailable
    }
    
    // Send request to daemon
    char request[256];
    snprintf(request, sizeof(request), "{\"op\":\"checksudo\",\"username\":\"%s\"}", username);
    
    size_t request_len = strlen(request);
    if (send(sock_fd, request, request_len, 0) != (ssize_t)request_len) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to send request for user %s: %s", username, strerror(errno));
        log_message("ERROR", error_msg);
        close(sock_fd);
        return 0;
    }
    
    // Receive response
    char response[MAX_BUFFER_SIZE];
    ssize_t received = recv(sock_fd, response, sizeof(response) - 1, 0);
    close(sock_fd);
    
    if (received <= 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Failed to receive response for user %s: %s", username, strerror(errno));
        log_message("ERROR", error_msg);
        return 0;
    }
    
    response[received] = '\0';
    
    // Check response
    if (strncmp(response, "ALLOW", 5) == 0) {
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), "Authentication successful for user: %s", username);
        log_message("INFO", success_msg);
        return 1;
    } else {
        char deny_msg[256];
        snprintf(deny_msg, sizeof(deny_msg), "Authentication denied for user: %s (response: %s)", username, response);
        log_message("WARN", deny_msg);
        return 0;
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags __attribute__((unused)), 
                                   int argc __attribute__((unused)), 
                                   const char **argv __attribute__((unused))) {
    const char *username;
    int retval;
    
    // Get username
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || username == NULL) {
        log_message("ERROR", "Failed to get username from PAM");
        return PAM_AUTH_ERR;
    }
    
    char info_msg[256];
    snprintf(info_msg, sizeof(info_msg), "Authentication attempt for user: %s", username);
    log_message("INFO", info_msg);
    
    // Check if user is allowed sudo access
    if (check_sudo_auth(username)) {
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), "PAM authentication granted for user: %s", username);
        log_message("INFO", success_msg);
        return PAM_SUCCESS;
    } else {
        char deny_msg[256];
        snprintf(deny_msg, sizeof(deny_msg), "PAM authentication denied for user: %s", username);
        log_message("WARN", deny_msg);
        return PAM_AUTH_ERR;
    }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh __attribute__((unused)), 
                              int flags __attribute__((unused)), 
                              int argc __attribute__((unused)), 
                              const char **argv __attribute__((unused))) {
    // No credentials to set for this module
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh __attribute__((unused)), 
                                int flags __attribute__((unused)), 
                                int argc __attribute__((unused)), 
                                const char **argv __attribute__((unused))) {
    // Account management - just allow if authentication passed
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh __attribute__((unused)), 
                                   int flags __attribute__((unused)), 
                                   int argc __attribute__((unused)), 
                                   const char **argv __attribute__((unused))) {
    // No session management needed
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh __attribute__((unused)), 
                                    int flags __attribute__((unused)), 
                                    int argc __attribute__((unused)), 
                                    const char **argv __attribute__((unused))) {
    // No session management needed
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh __attribute__((unused)), 
                                int flags __attribute__((unused)), 
                                int argc __attribute__((unused)), 
                                const char **argv __attribute__((unused))) {
    // Password changing not supported
    return PAM_AUTHTOK_ERR;
}