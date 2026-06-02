#ifndef SYSCALL_EVENT_H
#define SYSCALL_EVENT_H

#include <sys/types.h>

#define SYSCALL_EVENT_PATH_BUFSZ 256

struct syscall_event {
    pid_t pid;
    int entering;              /* 1 na entrada da syscall, 0 na saida */
    long syscall_no;
    long ret;                  /* valido apenas em eventos de saida */
    unsigned long args[6];     /* argumentos capturados na entrada */
    int has_path;              /* caminho lido na entrada, quando aplicavel */
    char path[SYSCALL_EVENT_PATH_BUFSZ];
};

#endif
