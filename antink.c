#define FUSE_USE_VERSION 30
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#define MAX_PATH 1024
#define LOG_FILE "/var/log/it24.log"
#define HOST_DIR "/it24_host"

// Logging function
void write_log(const char *action, const char *details) {
    time_t now;
    time(&now);
    struct tm *tm_info = localtime(&now);
    
    char timestamp[20];
    strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", tm_info);
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "[%s] %s: %s\n", timestamp, action, details);
        fclose(log_file);
    }
}

// String reversal for dangerous files
void reverse_string(char *str) {
    if (!str) return;
    
    int length = strlen(str);
    for (int i = 0; i < length / 2; i++) {
        char temp = str[i];
        str[i] = str[length - i - 1];
        str[length - i - 1] = temp;
    }
}

// Check if file is dangerous
int is_dangerous(const char *filename) {
    return strstr(filename, "nafis") || strstr(filename, "kimcun");
}

// ROT13 transformation
void rot13(char *str) {
    for (; *str; str++) {
        if (isalpha(*str)) {
            if ((*str >= 'a' && *str <= 'm') || (*str >= 'A' && *str <= 'M')) {
                *str += 13;
            } else {
                *str -= 13;
            }
        }
    }
}

// FUSE operations
static int antink_getattr(const char *path, struct stat *stbuf) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s%s", HOST_DIR, path);
    
    int res = lstat(full_path, stbuf);
    if (res == -1) return -errno;
    
    return 0;
}

static int antink_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s%s", HOST_DIR, path);
    
    DIR *dp = opendir(full_path);
    if (!dp) return -errno;
    
    struct dirent *de;
    while ((de = readdir(dp))) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        
        char display_name[256];
        strcpy(display_name, de->d_name);
        
        if (is_dangerous(display_name)) {
            reverse_string(display_name);
        }
        
        if (filler(buf, display_name, &st, 0)) break;
    }
    
    closedir(dp);
    return 0;
}

static int antink_open(const char *path, struct fuse_file_info *fi) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s%s", HOST_DIR, path);
    
    int res = open(full_path, fi->flags);
    if (res == -1) return -errno;
    
    close(res);
    
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "READ: %s", path);
    write_log("READ", log_msg);
    
    return 0;
}

static int antink_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s%s", HOST_DIR, path);
    
    int fd = open(full_path, O_RDONLY);
    if (fd == -1) return -errno;
    
    int res = pread(fd, buf, size, offset);
    if (res == -1) {
        close(fd);
        return -errno;
    }
    
    if (!is_dangerous(path) && strstr(path, ".txt")) {
        rot13(buf);
    }
    
    close(fd);
    return res;
}

static int antink_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s%s", HOST_DIR, path);
    
    int fd = open(full_path, fi->flags, mode);
    if (fd == -1) return -errno;
    
    close(fd);
    
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "CREATE: %s", path);
    write_log("CREATE", log_msg);
    
    return 0;
}

static int antink_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s%s", HOST_DIR, path);
    
    int fd = open(full_path, O_WRONLY);
    if (fd == -1) return -errno;
    
    int res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        close(fd);
        return -errno;
    }
    
    close(fd);
    
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "WRITE: %s", path);
    write_log("WRITE", log_msg);
    
    return res;
}

static int antink_unlink(const char *path) {
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s%s", HOST_DIR, path);
    
    int res = unlink(full_path);
    if (res == -1) return -errno;
    
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "DELETE: %s", path);
    write_log("DELETE", log_msg);
    
    return 0;
}

static struct fuse_operations antink_oper = {
    .getattr = antink_getattr,
    .readdir = antink_readdir,
    .open = antink_open,
    .read = antink_read,
    .create = antink_create,
    .write = antink_write,
    .unlink = antink_unlink,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &antink_oper, NULL);
}