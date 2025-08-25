#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#define __USE_GNU 1
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <linux/ptrace.h>
#include <linux/limits.h>

#include "syscall_numbers.h"

#define RED   "\x1B[31m"
#define GREEN "\x1B[32m"
#define BLUE  "\x1B[34m"
#define RESET "\x1B[0m"

#define ERROR   RED   "[X] "
#define SUCCESS GREEN "[+] "
#define INFO    BLUE  "[*] "

// errors for find_executable
#define NO_FILE 1
#define NO_EXEC 2

void print_argv(char **argv) {
    printf("[");

    size_t i = 0;
    while (argv[i] != NULL) {
        printf("\"%s\"", argv[i]);
        if (argv[++i] != NULL) {
            printf(", ");
        }
    }
    printf("]\n");
}

void print_syscall_args(__u64 args[6]) {
    printf("args: [");

    for (size_t i = 0; i < 6; i++) {
        printf("0x%llx", args[i]);
        if (i < 5) {
            printf(", ");
        }
    }
    printf("]\n");
}

bool is_runnable(char *file_path, struct stat stat_buf) {
    bool is_owner = geteuid() == stat_buf.st_uid;
    bool is_group = getegid() == stat_buf.st_gid;

    bool can_run;
    if (is_owner || is_group) {
        mode_t usr_rx = S_IRUSR | S_IXUSR;
        mode_t grp_rx = S_IRGRP | S_IXGRP;
        bool usr_can_run = is_owner && ((stat_buf.st_mode & usr_rx) == usr_rx);
        bool grp_can_run = is_group && ((stat_buf.st_mode & grp_rx) == grp_rx);

        can_run = usr_can_run && grp_can_run;
    } else {
        mode_t other_rx = S_IROTH | S_IXOTH;
        can_run = (stat_buf.st_mode & other_rx) == other_rx;
    }

    return can_run;
}

// search the PATH for the executable and write its path to *out_path
int find_executable(char *filename, char *out_path) {
    char file_path[PATH_MAX] = {0};
    struct stat stat_buf;
    bool found = false;
    bool found_unexec = false;

    // don't mess with paths that contain '/'
    if (strchr(filename, '/') != NULL) {
        strcpy(file_path, filename);

        if (!stat(file_path, &stat_buf)) {
            if (is_runnable(file_path, stat_buf)) {
                found = true;
            } else {
                found_unexec = true;
            }
        }
    } else {
        char *path = getenv("PATH");
        if (path == NULL) {
            printf(ERROR "cannot search for \"%s\" in PATH as it is unset\n" RESET, filename);
            return NO_FILE;
        }
        
        char *path_start = path;
        size_t path_len = strlen(path_start);

        path = path + 5; // cut off the "PATH="
        printf("path: %s\n", path);

        int n;
        for (; path < path_start + path_len; path += n + 1) {
            char *colon = strchr(path, ':');

            if (colon != NULL) {
                n = colon - path;
            } else {
                n = strlen(path);
            }

            int len = n;
            strncpy(file_path, path, n);
            if (file_path[n-1] != '/') {
                file_path[n] = '/';
                len++;
            }

            strncpy(file_path + len, filename, PATH_MAX - len);

            if (!stat(file_path, &stat_buf)) {
                if (is_runnable(file_path, stat_buf)) {
                    found = true;
                    break;
                } else {
                    found_unexec = true;
                }
            }
        }
    }

    strcpy(out_path, file_path);
    if (found) return 0;
    if (found_unexec) return NO_EXEC;
    return NO_FILE;
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(int argc, char **argv, char **envp) {
    init();

    if (argc < 2) {
        puts("usage: tracer [tracee]");
        return EXIT_FAILURE;
    }
    char **tracee_argv = &argv[1];

    char filename[PATH_MAX] = {0};

    int err = find_executable(tracee_argv[0], filename);
    switch (err) {
        case 0:
            break;
        case NO_FILE:
            printf(ERROR "cannot trace \"%s\": file not found\n" RESET, tracee_argv[0]);
            return EXIT_FAILURE;
        case NO_EXEC:
            printf(ERROR "cannot trace \"%s\": file is not executable\n" RESET, tracee_argv[0]);
            return EXIT_FAILURE;
    }

    printf(INFO "tracee argv: ");
    print_argv(tracee_argv);
    printf(RESET);

    pid_t tracee_pid = fork();
    if (!tracee_pid) {
        ptrace(PTRACE_TRACEME);
        execve(filename, tracee_argv, envp);
    }
    
    int tracee_status;
    waitpid(tracee_pid, &tracee_status, 0);
    ptrace(PTRACE_SETOPTIONS, tracee_pid, NULL, PTRACE_O_TRACESYSGOOD);
    
    printf(INFO "tracing \"%s\" with pid %d\n\n" RESET, filename, tracee_pid);
    while (1) {
        struct ptrace_syscall_info syscall_info;
        
        ptrace(PTRACE_SYSCALL, tracee_pid, NULL, 0);
        if (waitpid(tracee_pid, &tracee_status, 0) < 0) {
            printf(ERROR "error waiting for tracee\n" RESET);
            break;
        }

        if (WIFSIGNALED(tracee_status)) {
            printf(ERROR "tracee terminated with signal SIG%s\n" RESET, sigabbrev_np(WTERMSIG(tracee_status)));
            break;
        }
        if (WIFEXITED(tracee_status)) {
            if (WEXITSTATUS(tracee_status)) {
                printf(ERROR "tracee exited with exit code %d\n" RESET, WEXITSTATUS(tracee_status));
            } else {
                printf(SUCCESS "tracee exited with exit code %d\n" RESET, WEXITSTATUS(tracee_status));
            }
            break;
        }

        // the ptrace option PTRACE_O_TRACESYSGOOD makes the signal for stops at syscalls SIGTRAP | 0x80
        if (WIFSTOPPED(tracee_status) && WSTOPSIG(tracee_status) == (SIGTRAP|0x80)) {
            ptrace(PTRACE_GET_SYSCALL_INFO, tracee_pid, sizeof(struct ptrace_syscall_info), &syscall_info);

            switch (syscall_info.op) {
                case (PTRACE_SYSCALL_INFO_ENTRY):
                    printf("tracee entered system call %s\n", syscall_numbers[syscall_info.entry.nr]);
                    print_syscall_args(syscall_info.entry.args);
                    break;
                case (PTRACE_SYSCALL_INFO_EXIT):
                    printf("tracee exited system call with return value 0x%llx\n\n", syscall_info.exit.rval);
                    break;
            }
            continue;
        }
        
        if (WIFSTOPPED(tracee_status)) {
            printf(INFO "tracee stopped with signal SIG%s" RESET, sigabbrev_np(WSTOPSIG(tracee_status)));
            break;
        }
        
        printf(ERROR "tracee stopped for some other reason. status is: %d\n" RESET, tracee_status);
        break;
    }

    return EXIT_SUCCESS;
}
