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
#include <json-c/json.h>
#include <stdarg.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define SOCKET_PATH "/run/warp_portal.sock"
#define LOG_FILE "/var/log/pam_sockauth.log"
#define MAX_BUFFER_SIZE 4096

static void log_message(const char *level, const char *format, ...) {
    FILE *log_file;
    time_t now;
    char *time_str;
    va_list args;
    char msg_buf[1024];
    
    /* Format the message */
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);
    
    /* Log to file */
    log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        now = time(NULL);
        time_str = ctime(&now);
        if (time_str) {
            time_str[strlen(time_str) - 1] = '\0'; /* Remove newline */
        }
        
        fprintf(log_file, "[%s] %s: %s\n", time_str ? time_str : "unknown", level, msg_buf);
        fclose(log_file);
    }
    
    /* Also log to syslog */
    syslog(LOG_AUTHPRIV | LOG_INFO, "pam_sockauth: %s", msg_buf);
}

static int connect_to_daemon(void) {
    log_message("DEBUG", "Attempting to connect to daemon");
    
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        log_message("ERROR", "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        log_message("ERROR", "Failed to connect to daemon socket: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }
    
    log_message("DEBUG", "Successfully connected to daemon");
    return sock_fd;
}

static int check_sudo_auth(const char *username) {
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "Starting sudo authorization check for user: %s", username);
    log_message("DEBUG", log_msg);
    
    int sock_fd = connect_to_daemon();
    if (sock_fd == -1) {
        log_message("ERROR", "Cannot connect to daemon for sudo check");
        return 0; // Deny access if socket unavailable
    }
    
    // Create JSON request object
    json_object *request_obj = json_object_new_object();
    json_object *op_obj = json_object_new_string("checksudo");
    json_object *username_obj = json_object_new_string(username);
    
    if (!request_obj || !op_obj || !username_obj) {
        log_message("ERROR", "Failed to create JSON objects for request");
        if (request_obj) json_object_put(request_obj);
        if (op_obj) json_object_put(op_obj);
        if (username_obj) json_object_put(username_obj);
        close(sock_fd);
        return 0;
    }
    
    json_object_object_add(request_obj, "op", op_obj);
    json_object_object_add(request_obj, "username", username_obj);
    
    const char *request_str = json_object_to_json_string(request_obj);
    if (!request_str) {
        log_message("ERROR", "Failed to serialize JSON request");
        json_object_put(request_obj);
        close(sock_fd);
        return 0;
    }
    
    snprintf(log_msg, sizeof(log_msg), "Sending JSON request: %s", request_str);
    log_message("DEBUG", log_msg);
    
    size_t request_len = strlen(request_str);
    if (send(sock_fd, request_str, request_len, 0) != (ssize_t)request_len) {
        snprintf(log_msg, sizeof(log_msg), "Failed to send request for user %s: %s", username, strerror(errno));
        log_message("ERROR", log_msg);
        json_object_put(request_obj);
        close(sock_fd);
        return 0;
    }
    
    json_object_put(request_obj);
    
    // Receive response
    char response[MAX_BUFFER_SIZE];
    ssize_t received = recv(sock_fd, response, sizeof(response) - 1, 0);
    close(sock_fd);
    
    if (received <= 0) {
        snprintf(log_msg, sizeof(log_msg), "Failed to receive response for user %s: %s", username, strerror(errno));
        log_message("ERROR", log_msg);
        return 0;
    }
    
    response[received] = '\0';
    snprintf(log_msg, sizeof(log_msg), "Received response: %s", response);
    log_message("DEBUG", log_msg);
    
    // Parse JSON response (if it's JSON) or handle plain text response
    json_object *response_obj = json_tokener_parse(response);
    if (response_obj) {
        // Handle JSON response
        json_object *status_obj;
        if (json_object_object_get_ex(response_obj, "status", &status_obj)) {
            const char *status = json_object_get_string(status_obj);
            json_object *allowed_obj;
            int allowed = 0;
            
            if (strcmp(status, "success") == 0 && 
                json_object_object_get_ex(response_obj, "allowed", &allowed_obj)) {
                allowed = json_object_get_boolean(allowed_obj);
            }
            
            json_object_put(response_obj);
            
            if (allowed) {
                snprintf(log_msg, sizeof(log_msg), "JSON response: Authentication successful for user: %s", username);
                log_message("INFO", log_msg);
                return 1;
            } else {
                snprintf(log_msg, sizeof(log_msg), "JSON response: Authentication denied for user: %s (status: %s)", username, status);
                log_message("WARN", log_msg);
                return 0;
            }
        }
        json_object_put(response_obj);
    }
    
    // Fallback: Handle plain text response (backward compatibility)
    if (strncmp(response, "ALLOW", 5) == 0) {
        snprintf(log_msg, sizeof(log_msg), "Plain text response: Authentication successful for user: %s", username);
        log_message("INFO", log_msg);
        return 1;
    } else {
        snprintf(log_msg, sizeof(log_msg), "Plain text response: Authentication denied for user: %s (response: %s)", username, response);
        log_message("WARN", log_msg);
        return 0;
    }
}

static int send_session_request(const char *pam_type, const char *username, const char *rhost) {
    log_message("DEBUG", "Preparing session request: type=%s, user=%s, rhost=%s", 
               pam_type, username ? username : "unknown", rhost ? rhost : "unknown");
    
    int sock_fd = connect_to_daemon();
    if (sock_fd == -1) {
        log_message("ERROR", "Cannot connect to daemon for session request");
        return -1;
    }
    
    /* Create JSON request object */
    json_object *request_obj = json_object_new_object();
    json_object *op_obj = json_object_new_string(pam_type);
    json_object *username_obj = json_object_new_string(username ? username : "unknown");
    
    if (!request_obj || !op_obj || !username_obj) {
        log_message("ERROR", "Failed to create JSON objects for session request");
        if (request_obj) json_object_put(request_obj);
        if (op_obj) json_object_put(op_obj);
        if (username_obj) json_object_put(username_obj);
        close(sock_fd);
        return -1;
    }
    
    json_object_object_add(request_obj, "op", op_obj);
    json_object_object_add(request_obj, "username", username_obj);
    
    /* Add remote host if available */
    if (rhost && strlen(rhost) > 0) {
        json_object *rhost_obj = json_object_new_string(rhost);
        if (rhost_obj) {
            json_object_object_add(request_obj, "rhost", rhost_obj);
        }
    }
    
    /* Add timestamp */
    time_t now = time(NULL);
    json_object *timestamp_obj = json_object_new_int64((int64_t)now);
    if (timestamp_obj) {
        json_object_object_add(request_obj, "timestamp", timestamp_obj);
    }
    
    const char *request_str = json_object_to_json_string(request_obj);
    if (!request_str) {
        log_message("ERROR", "Failed to serialize JSON request");
        json_object_put(request_obj);
        close(sock_fd);
        return -1;
    }
    
    log_message("DEBUG", "Sending session request: %s", request_str);
    
    size_t request_len = strlen(request_str);
    if (send(sock_fd, request_str, request_len, 0) != (ssize_t)request_len) {
        log_message("ERROR", "Failed to send session request: %s", strerror(errno));
        json_object_put(request_obj);
        close(sock_fd);
        return -1;
    }
    
    /* Receive response */
    char response[MAX_BUFFER_SIZE];
    ssize_t received = recv(sock_fd, response, sizeof(response) - 1, 0);
    close(sock_fd);
    
    if (received <= 0) {
        log_message("ERROR", "Failed to receive response from daemon: %s", 
                   received < 0 ? strerror(errno) : "connection closed");
        json_object_put(request_obj);
        return -1;
    }
    
    response[received] = '\0';
    log_message("DEBUG", "Received session response: %s", response);
    
    /* Parse response */
    json_object *response_obj = json_tokener_parse(response);
    int success = 0;
    
    if (response_obj) {
        json_object *status_obj;
        if (json_object_object_get_ex(response_obj, "status", &status_obj)) {
            const char *status = json_object_get_string(status_obj);
            success = (strcmp(status, "success") == 0);
            log_message("DEBUG", "Session request status: %s", status);
        }
        json_object_put(response_obj);
    } else {
        /* Fallback: check for plain text response */
        success = (strncmp(response, "SUCCESS", 7) == 0 || strncmp(response, "OK", 2) == 0);
        log_message("DEBUG", "Plain text session response: %s", response);
    }
    
    json_object_put(request_obj);
    
    log_message("INFO", "Session %s request for user %s %s", 
               pam_type, username ? username : "unknown", 
               success ? "completed successfully" : "failed");
    
    return success ? 0 : -1;
}

static const char* get_pam_env_var(pam_handle_t *pamh, const char *name) {
    const char *value = pam_getenv(pamh, name);
    if (!value) {
        /* Try system environment as fallback */
        value = getenv(name);
    }
    return value;
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
    
    char info_msg[512];
    snprintf(info_msg, sizeof(info_msg), "PAM authentication attempt for user: %s", username);
    log_message("INFO", info_msg);
    
    // Check if user is allowed sudo access
    if (check_sudo_auth(username)) {
        char success_msg[512];
        snprintf(success_msg, sizeof(success_msg), "PAM authentication granted for user: %s", username);
        log_message("INFO", success_msg);
        return PAM_SUCCESS;
    } else {
        char deny_msg[512];
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

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, 
                                int flags __attribute__((unused)), 
                                int argc __attribute__((unused)), 
                                const char **argv __attribute__((unused))) {
    const char *username;
    int retval;
    
    log_message("DEBUG", "pam_sm_acct_mgmt called");
    
    /* Get username */
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || !username) {
        log_message("ERROR", "Failed to get username from PAM for account management");
        return PAM_USER_UNKNOWN;
    }
    
    log_message("INFO", "Account management check for user: %s", username);
    
    /* For now, just allow all users that we can identify */
    /* In the future, this could check with daemon for account status */
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags __attribute__((unused)), 
                                   int argc __attribute__((unused)), 
                                   const char **argv __attribute__((unused))) {
    const char *username;
    const char *rhost;
    int retval;
    
    log_message("DEBUG", "pam_sm_open_session called");
    
    /* Get username */
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || !username) {
        log_message("ERROR", "Failed to get username from PAM");
        return PAM_SESSION_ERR;
    }
    
    /* Get remote host */
    rhost = get_pam_env_var(pamh, "PAM_RHOST");
    if (!rhost) {
        rhost = pam_getenv(pamh, "SSH_CLIENT");
        if (rhost) {
            /* Extract IP from "IP port localport" format */
            static char rhost_ip[64];
            strncpy(rhost_ip, rhost, sizeof(rhost_ip) - 1);
            rhost_ip[sizeof(rhost_ip) - 1] = '\0';
            char *space = strchr(rhost_ip, ' ');
            if (space) *space = '\0';
            rhost = rhost_ip;
        }
    }
    
    log_message("INFO", "Opening session for user: %s from %s", 
               username, rhost ? rhost : "local");
    
    /* Send session open request to daemon */
    if (send_session_request("open_session", username, rhost) != 0) {
        log_message("WARN", "Session open request failed, but allowing session to proceed");
        /* Don't fail the session if daemon is unavailable */
    }
    
    log_message("INFO", "Session opened for user: %s", username);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags __attribute__((unused)), 
                                    int argc __attribute__((unused)), 
                                    const char **argv __attribute__((unused))) {
    const char *username;
    const char *rhost;
    int retval;
    
    log_message("DEBUG", "pam_sm_close_session called");
    
    /* Get username */
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || !username) {
        log_message("ERROR", "Failed to get username from PAM during session close");
        /* Don't fail session close due to username lookup failure */
        username = "unknown";
    }
    
    /* Get remote host */
    rhost = get_pam_env_var(pamh, "PAM_RHOST");
    if (!rhost) {
        rhost = pam_getenv(pamh, "SSH_CLIENT");
        if (rhost) {
            /* Extract IP from "IP port localport" format */
            static char rhost_ip[64];
            strncpy(rhost_ip, rhost, sizeof(rhost_ip) - 1);
            rhost_ip[sizeof(rhost_ip) - 1] = '\0';
            char *space = strchr(rhost_ip, ' ');
            if (space) *space = '\0';
            rhost = rhost_ip;
        }
    }
    
    log_message("INFO", "Closing session for user: %s from %s", 
               username, rhost ? rhost : "local");
    
    /* Send session close request to daemon */
    if (send_session_request("close_session", username, rhost) != 0) {
        log_message("WARN", "Session close request failed, but allowing session close to proceed");
        /* Don't fail the session close if daemon is unavailable */
    }
    
    log_message("INFO", "Session closed for user: %s", username);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh __attribute__((unused)), 
                                int flags __attribute__((unused)), 
                                int argc __attribute__((unused)), 
                                const char **argv __attribute__((unused))) {
    // Password changing not supported
    return PAM_AUTHTOK_ERR;
}