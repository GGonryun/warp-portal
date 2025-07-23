#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <stdarg.h>

#include <sudo_plugin.h>

#define PLUGIN_VERSION SUDO_API_VERSION_MAJOR, SUDO_API_VERSION_MINOR
#define SOCKET_PATH "/run/warp_portal.sock"
#define LOG_FILE "/var/log/warp_portal_sudo.log"
#define MAX_BUFFER_SIZE 4096

/* Plugin function prototypes */
static int policy_open(unsigned int version, sudo_conv_t conversation,
                      sudo_printf_t plugin_printf, char * const settings[],
                      char * const user_info[], char * const user_env[],
                      char * const plugin_options[], const char **errstr);
static void policy_close(int exit_status, int error);
static int policy_show_version(int verbose);
static int policy_check_policy(int argc, char * const argv[],
                              char *env_add[], char **command_info[],
                              char **argv_out[], char **user_env_out[],
                              const char **errstr);
static int policy_list(int argc, char * const argv[], int verbose,
                      const char *list_user, const char **errstr);
static int policy_validate(const char **errstr);
static void policy_invalidate(int remove);

/* Global variables */
static sudo_conv_t sudo_conv;
static sudo_printf_t sudo_log;

/* Plugin structure */
struct policy_plugin policy = {
    SUDO_POLICY_PLUGIN,
    PLUGIN_VERSION,
    policy_open,
    policy_close,
    policy_show_version,
    policy_check_policy,
    policy_list,
    policy_validate,
    policy_invalidate,
    NULL, /* init_session */
    NULL, /* register_hooks */
    NULL, /* deregister_hooks */
    NULL  /* event_alloc */
};

/* Logging function */
static void log_message(const char *level, const char *format, ...) {
    FILE *log_file;
    time_t now;
    char *time_str;
    va_list args;
    
    /* Log to file */
    log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        now = time(NULL);
        time_str = ctime(&now);
        if (time_str) {
            time_str[strlen(time_str) - 1] = '\0'; /* Remove newline */
        }
        
        fprintf(log_file, "[%s] %s: ", time_str ? time_str : "unknown", level);
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fprintf(log_file, "\n");
        fclose(log_file);
    }
    
    /* Also log to syslog */
    va_start(args, format);
    char msg_buf[1024];
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);
    syslog(LOG_AUTHPRIV | LOG_INFO, "warp_portal_sudo: %s", msg_buf);
}

/* Connect to warp portal daemon */
static int connect_to_daemon(void) {
    int sock_fd;
    struct sockaddr_un addr;
    
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        log_message("ERROR", "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        log_message("ERROR", "Failed to connect to daemon socket: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }
    
    log_message("DEBUG", "Successfully connected to daemon socket");
    return sock_fd;
}

/* Check sudo authorization with daemon */
static int check_sudo_authorization(const char *username, const char *target_user, const char *command) {
    int sock_fd;
    char request[512];
    char response[MAX_BUFFER_SIZE];
    ssize_t sent, received;
    
    sock_fd = connect_to_daemon();
    if (sock_fd == -1) {
        log_message("ERROR", "Cannot connect to daemon for user %s", username);
        return 0; /* Deny access if daemon unavailable */
    }
    
    /* Build JSON request with command context */
    snprintf(request, sizeof(request), 
             "{\"op\":\"checksudo\",\"username\":\"%s\",\"target_user\":\"%s\",\"command\":\"%s\"}", 
             username, target_user ? target_user : "root", command ? command : "unknown");
    
    log_message("DEBUG", "Sending request: %s", request);
    
    sent = send(sock_fd, request, strlen(request), 0);
    if (sent != (ssize_t)strlen(request)) {
        log_message("ERROR", "Failed to send request for user %s: %s", username, strerror(errno));
        close(sock_fd);
        return 0;
    }
    
    /* Receive response */
    received = recv(sock_fd, response, sizeof(response) - 1, 0);
    close(sock_fd);
    
    if (received <= 0) {
        log_message("ERROR", "Failed to receive response for user %s: %s", username, strerror(errno));
        return 0;
    }
    
    response[received] = '\0';
    log_message("DEBUG", "Received response: %s", response);
    
    /* Check response */
    if (strncmp(response, "ALLOW", 5) == 0) {
        log_message("INFO", "Authorization granted for user %s to run %s as %s", 
                   username, command ? command : "command", target_user ? target_user : "root");
        return 1;
    } else {
        log_message("WARN", "Authorization denied for user %s to run %s as %s (response: %s)", 
                   username, command ? command : "command", target_user ? target_user : "root", response);
        return 0;
    }
}

/* Plugin initialization */
static int policy_open(unsigned int version, sudo_conv_t conversation,
                      sudo_printf_t plugin_printf, char * const settings[] __attribute__((unused)),
                      char * const user_info[] __attribute__((unused)), char * const user_env[] __attribute__((unused)),
                      char * const plugin_options[] __attribute__((unused)), const char **errstr) {
    
    sudo_conv = conversation;
    sudo_log = plugin_printf;
    
    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        *errstr = "Incompatible plugin API version";
        log_message("ERROR", "Plugin API version mismatch. Expected %d, got %d", 
                   SUDO_API_VERSION_MAJOR, SUDO_API_VERSION_GET_MAJOR(version));
        return -1;
    }
    
    log_message("INFO", "Warp Portal sudo plugin initialized (version %d.%d)", 
               SUDO_API_VERSION_GET_MAJOR(version), SUDO_API_VERSION_GET_MINOR(version));
    
    /* Test daemon connectivity */
    int sock_fd = connect_to_daemon();
    if (sock_fd == -1) {
        log_message("WARN", "Cannot connect to warp portal daemon during initialization");
        /* Don't fail initialization - daemon might start later */
    } else {
        close(sock_fd);
        log_message("INFO", "Daemon connectivity verified during initialization");
    }
    
    return 1; /* Success */
}

/* Plugin cleanup */
static void policy_close(int exit_status, int error) {
    log_message("INFO", "Plugin closing (exit_status=%d, error=%d)", exit_status, error);
}

/* Show plugin version */
static int policy_show_version(int verbose) {
    sudo_log(SUDO_CONV_INFO_MSG, "Warp Portal sudo plugin version 1.0\n");
    if (verbose) {
        sudo_log(SUDO_CONV_INFO_MSG, "Socket path: %s\n", SOCKET_PATH);
        sudo_log(SUDO_CONV_INFO_MSG, "Log file: %s\n", LOG_FILE);
    }
    return 1;
}

/* Main policy check function */
static int policy_check_policy(int argc, char * const argv[],
                              char *env_add[] __attribute__((unused)), char **command_info[],
                              char **argv_out[], char **user_env_out[],
                              const char **errstr) {
    
    const char *username = getenv("SUDO_USER");
    const char *target_user = getenv("SUDO_COMMAND");
    char *command = NULL;
    
    if (!username) {
        struct passwd *pwd = getpwuid(getuid());
        username = pwd ? pwd->pw_name : "unknown";
    }
    
    /* Build command string from argv */
    if (argc > 0) {
        size_t total_len = 0;
        int i;
        
        /* Calculate total length needed */
        for (i = 0; i < argc; i++) {
            total_len += strlen(argv[i]) + 1; /* +1 for space or null terminator */
        }
        
        command = malloc(total_len);
        if (command) {
            command[0] = '\0';
            for (i = 0; i < argc; i++) {
                if (i > 0) strcat(command, " ");
                strcat(command, argv[i]);
            }
        }
    }
    
    log_message("INFO", "Policy check for user %s, command: %s", 
               username, command ? command : "none");
    
    /* Check authorization with daemon */
    int authorized = check_sudo_authorization(username, target_user, command ? command : argv[0]);
    
    if (command) {
        free(command);
    }
    
    if (!authorized) {
        *errstr = "Access denied by Warp Portal daemon";
        return -1; /* Access denied */
    }
    
    /* Set command info for sudo */
    *command_info = malloc(2 * sizeof(char *));
    if (*command_info) {
        (*command_info)[0] = strdup("use_pty=false");
        (*command_info)[1] = NULL;
    }
    
    /* Pass through original argv */
    *argv_out = (char **)argv;
    *user_env_out = NULL;
    
    return 1; /* Access granted */
}

/* List user privileges */
static int policy_list(int argc __attribute__((unused)), char * const argv[] __attribute__((unused)), int verbose __attribute__((unused)),
                      const char *list_user, const char **errstr __attribute__((unused))) {
    
    const char *username = list_user ? list_user : getenv("SUDO_USER");
    if (!username) {
        struct passwd *pwd = getpwuid(getuid());
        username = pwd ? pwd->pw_name : "unknown";
    }
    
    log_message("INFO", "List request for user: %s", username);
    
    /* Check if user has any sudo privileges */
    int has_access = check_sudo_authorization(username, "root", "list");
    
    if (has_access) {
        sudo_log(SUDO_CONV_INFO_MSG, "User %s may run the following commands:\n", username);
        sudo_log(SUDO_CONV_INFO_MSG, "    ALL\n");
    } else {
        sudo_log(SUDO_CONV_INFO_MSG, "User %s is not allowed to run sudo on this machine.\n", username);
    }
    
    return has_access ? 1 : -1;
}

/* Validate credentials */
static int policy_validate(const char **errstr) {
    const char *username = getenv("SUDO_USER");
    if (!username) {
        struct passwd *pwd = getpwuid(getuid());
        username = pwd ? pwd->pw_name : "unknown";
    }
    
    log_message("INFO", "Credential validation for user: %s", username);
    
    /* Test daemon connection for validation */
    int sock_fd = connect_to_daemon();
    if (sock_fd == -1) {
        *errstr = "Cannot connect to Warp Portal daemon for validation";
        return -1;
    }
    close(sock_fd);
    
    return 1; /* Validation successful */
}

/* Invalidate credentials */
static void policy_invalidate(int remove) {
    log_message("INFO", "Credential invalidation requested (remove=%d)", remove);
    /* No persistent credentials to invalidate in our implementation */
}
