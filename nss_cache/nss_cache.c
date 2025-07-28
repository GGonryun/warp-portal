#define _GNU_SOURCE
#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#define PASSWD_CACHE_FILE "/var/cache/warp_portal/passwd.cache"
#define GROUP_CACHE_FILE "/var/cache/warp_portal/group.cache"
#define MAX_LINE_LEN 1024
#define MAX_MEMBERS 100

static FILE *passwd_fp = NULL;
static FILE *group_fp = NULL;

static int cache_file_exists(const char *filename) {
    struct stat st;
    return (stat(filename, &st) == 0 && S_ISREG(st.st_mode) && access(filename, R_OK) == 0);
}

static int parse_passwd_line(char *line, struct passwd *pwd, char *buffer, size_t buflen) {
    char *token;
    char *saveptr;
    char *endptr;
    
    if (!line || line[0] == '\0' || line[0] == '#') {
        return 0;
    }
    
    line[strcspn(line, "\n")] = '\0';
    
    token = strtok_r(line, ":", &saveptr);
    if (!token) return 0;
    
    size_t needed = strlen(token) + 1;
    if (needed > buflen) return -1;
    strcpy(buffer, token);
    pwd->pw_name = buffer;
    buffer += needed;
    buflen -= needed;
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) return 0;
    pwd->pw_passwd = "x";
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) return 0;
    pwd->pw_uid = (uid_t)strtol(token, &endptr, 10);
    if (*endptr != '\0') return 0;
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) return 0;
    pwd->pw_gid = (gid_t)strtol(token, &endptr, 10);
    if (*endptr != '\0') return 0;
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) token = "";
    needed = strlen(token) + 1;
    if (needed > buflen) return -1;
    strcpy(buffer, token);
    pwd->pw_gecos = buffer;
    buffer += needed;
    buflen -= needed;
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) token = "";
    needed = strlen(token) + 1;
    if (needed > buflen) return -1;
    strcpy(buffer, token);
    pwd->pw_dir = buffer;
    buffer += needed;
    buflen -= needed;
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) token = "/bin/bash";
    needed = strlen(token) + 1;
    if (needed > buflen) return -1;
    strcpy(buffer, token);
    pwd->pw_shell = buffer;
    
    return 1;
}

static int parse_group_line(char *line, struct group *grp, char *buffer, size_t buflen) {
    char *token;
    char *saveptr;
    char *member_saveptr;
    char *endptr;
    char *members_str;
    
    // Skip empty lines and comments
    if (!line || line[0] == '\0' || line[0] == '#') {
        return 0;
    }
    
    line[strcspn(line, "\n")] = '\0';
    
    token = strtok_r(line, ":", &saveptr);
    if (!token) return 0;
    
    size_t needed = strlen(token) + 1;
    if (needed > buflen) return -1;
    strcpy(buffer, token);
    grp->gr_name = buffer;
    buffer += needed;
    buflen -= needed;
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) return 0;
    grp->gr_passwd = "x";
    
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) return 0;
    grp->gr_gid = (gid_t)strtol(token, &endptr, 10);
    if (*endptr != '\0') return 0;
    
    members_str = strtok_r(NULL, ":", &saveptr);
    if (!members_str) members_str = "";
    
    char **members = (char **)buffer;
    size_t member_ptrs_size = (MAX_MEMBERS + 1) * sizeof(char *);
    if (member_ptrs_size > buflen) return -1;
    buffer += member_ptrs_size;
    buflen -= member_ptrs_size;
    
    grp->gr_mem = members;
    int member_count = 0;
    
    if (strlen(members_str) > 0) {
        char *member = strtok_r(members_str, ",", &member_saveptr);
        while (member && member_count < MAX_MEMBERS) {
            needed = strlen(member) + 1;
            if (needed > buflen) return -1;
            strcpy(buffer, member);
            members[member_count] = buffer;
            buffer += needed;
            buflen -= needed;
            member_count++;
            member = strtok_r(NULL, ",", &member_saveptr);
        }
    }
    
    members[member_count] = NULL; 
    
    return 1;
}

enum nss_status _nss_cache_getpwnam_r(const char *name, struct passwd *pwd,
                                          char *buffer, size_t buflen, int *errnop) {
    FILE *fp;
    char line[MAX_LINE_LEN];
    
    if (!cache_file_exists(PASSWD_CACHE_FILE)) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    
    fp = fopen(PASSWD_CACHE_FILE, "r");
    if (!fp) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strcpy(line_copy, line);
        
        if (parse_passwd_line(line_copy, pwd, buffer, buflen) == 1) {
            if (strcmp(pwd->pw_name, name) == 0) {
                fclose(fp);
                return NSS_STATUS_SUCCESS;
            }
        }
    }
    
    fclose(fp);
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_cache_getpwuid_r(uid_t uid, struct passwd *pwd,
                                          char *buffer, size_t buflen, int *errnop) {
    FILE *fp;
    char line[MAX_LINE_LEN];
    
    if (!cache_file_exists(PASSWD_CACHE_FILE)) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    
    fp = fopen(PASSWD_CACHE_FILE, "r");
    if (!fp) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strcpy(line_copy, line);
        
        if (parse_passwd_line(line_copy, pwd, buffer, buflen) == 1) {
            if (pwd->pw_uid == uid) {
                fclose(fp);
                return NSS_STATUS_SUCCESS;
            }
        }
    }
    
    fclose(fp);
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_cache_setpwent(void) {
    if (passwd_fp) {
        fclose(passwd_fp);
    }
    
    if (!cache_file_exists(PASSWD_CACHE_FILE)) {
        return NSS_STATUS_UNAVAIL;
    }
    
    passwd_fp = fopen(PASSWD_CACHE_FILE, "r");
    return passwd_fp ? NSS_STATUS_SUCCESS : NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_cache_endpwent(void) {
    if (passwd_fp) {
        fclose(passwd_fp);
        passwd_fp = NULL;
    }
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_cache_getpwent_r(struct passwd *pwd, char *buffer,
                                          size_t buflen, int *errnop) {
    char line[MAX_LINE_LEN];
    
    if (!passwd_fp) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    
    while (fgets(line, sizeof(line), passwd_fp)) {
        char line_copy[MAX_LINE_LEN];
        strcpy(line_copy, line);
        
        if (parse_passwd_line(line_copy, pwd, buffer, buflen) == 1) {
            return NSS_STATUS_SUCCESS;
        }
    }
    
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_cache_getgrnam_r(const char *name, struct group *grp,
                                          char *buffer, size_t buflen, int *errnop) {
    FILE *fp;
    char line[MAX_LINE_LEN];
    
    if (!cache_file_exists(GROUP_CACHE_FILE)) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    
    fp = fopen(GROUP_CACHE_FILE, "r");
    if (!fp) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strcpy(line_copy, line);
        
        if (parse_group_line(line_copy, grp, buffer, buflen) == 1) {
            if (strcmp(grp->gr_name, name) == 0) {
                fclose(fp);
                return NSS_STATUS_SUCCESS;
            }
        }
    }
    
    fclose(fp);
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_cache_getgrgid_r(gid_t gid, struct group *grp,
                                          char *buffer, size_t buflen, int *errnop) {
    FILE *fp;
    char line[MAX_LINE_LEN];
    
    if (!cache_file_exists(GROUP_CACHE_FILE)) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    
    fp = fopen(GROUP_CACHE_FILE, "r");
    if (!fp) {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char line_copy[MAX_LINE_LEN];
        strcpy(line_copy, line);
        
        if (parse_group_line(line_copy, grp, buffer, buflen) == 1) {
            if (grp->gr_gid == gid) {
                fclose(fp);
                return NSS_STATUS_SUCCESS;
            }
        }
    }
    
    fclose(fp);
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_cache_setgrent(void) {
    if (group_fp) {
        fclose(group_fp);
    }
    
    if (!cache_file_exists(GROUP_CACHE_FILE)) {
        return NSS_STATUS_UNAVAIL;
    }
    
    group_fp = fopen(GROUP_CACHE_FILE, "r");
    return group_fp ? NSS_STATUS_SUCCESS : NSS_STATUS_UNAVAIL;
}

enum nss_status _nss_cache_endgrent(void) {
    if (group_fp) {
        fclose(group_fp);
        group_fp = NULL;
    }
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_cache_getgrent_r(struct group *grp, char *buffer,
                                          size_t buflen, int *errnop) {
    char line[MAX_LINE_LEN];
    
    if (!group_fp) {
        *errnop = ENOENT;
        return NSS_STATUS_UNAVAIL;
    }
    
    while (fgets(line, sizeof(line), group_fp)) {
        char line_copy[MAX_LINE_LEN];
        strcpy(line_copy, line);
        
        if (parse_group_line(line_copy, grp, buffer, buflen) == 1) {
            return NSS_STATUS_SUCCESS;
        }
    }
    
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}