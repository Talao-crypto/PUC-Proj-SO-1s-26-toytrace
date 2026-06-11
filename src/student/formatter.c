#include "student_api.h"

#include "syscall_names.h"

#include <stdio.h>

void student_debug_raw_event(const struct syscall_event *ev,
                             char *buf,
                             size_t bufsz)
{
    /*
     * Suporte de depuracao para a Semana 4:
     *
     * Esta funcao existe para inspecionar eventos crus depois que o runtime
     * ja consegue parar em syscalls e preencher struct syscall_event.
     * Ela nao e a formatacao final do projeto.
     *
     * Experimento sugerido:
     * - imprima o nome da syscall;
     * - imprima se o evento e entrada ou saida;
     * - imprima o pid;
     * - em eventos de entrada, observe os argumentos;
     * - em eventos de saida, observe o valor de retorno.
     *
     * Depois compare a saida de:
     *
     *   ./toytrace trace --raw-events -- ./tests/targets/hello_write
     *
     * A pergunta importante da Semana 4 e:
     * por que a mesma syscall aparece duas vezes?
     */
    snprintf(buf, bufsz, "pid=%d %s %s",
             ev->pid,
             syscall_name(ev->syscall_no),
             ev->entering ? "entrada" : "saida");
}

void student_format_event(const struct syscall_event *ev,
                          char *buf,
                          size_t bufsz)
{
    /*
     * TODO Semana 5:
     *
     * Primeiro, formate uma syscall completa em uma linha simples.
     *
     * Depois, adicione casos especiais para:
     *     read(fd, buf, count)
     *     write(fd, buf, count)
     *     openat(dirfd, "path", flags, mode)
     *     execve("path", ...)
     *     exit_group(status)
     *
     * Para caminhos do processo monitorado, use read_child_string().
     * Se a leitura falhar, imprima "<ilegivel>".
     */
    enum {
        X86_64_SYS_READ = 0,
        X86_64_SYS_WRITE = 1,
        X86_64_SYS_EXECVE = 59,
        X86_64_SYS_EXIT_GROUP = 231,
        X86_64_SYS_OPENAT = 257
    };
    extern int read_child_string(pid_t pid,
                                 unsigned long addr,
                                 char *dest,
                                 size_t destsz);
    char path[256];

    if (ev == NULL || buf == NULL || bufsz == 0) {
        return;
    }

    switch (ev->syscall_no) {
    case X86_64_SYS_READ:
        snprintf(buf, bufsz, "read(%d, %#lx, %lu) = %ld",
                 (int)ev->args[0], ev->args[1], ev->args[2], ev->ret);
        return;

    case X86_64_SYS_WRITE:
        snprintf(buf, bufsz, "write(%d, %#lx, %lu) = %ld",
                 (int)ev->args[0], ev->args[1], ev->args[2], ev->ret);
        return;

    case X86_64_SYS_OPENAT:
        if (read_child_string(ev->pid, ev->args[1], path, sizeof(path)) < 0) {
            snprintf(path, sizeof(path), "<ilegivel>");
        }
        snprintf(buf, bufsz, "openat(%d, \"%s\", %#x, %#o) = %ld",
                 (int)ev->args[0],
                 path,
                 (unsigned int)ev->args[2],
                 (unsigned int)ev->args[3],
                 ev->ret);
        return;

    case X86_64_SYS_EXECVE:
        if (read_child_string(ev->pid, ev->args[0], path, sizeof(path)) < 0) {
            snprintf(path, sizeof(path), "<ilegivel>");
        }
        snprintf(buf, bufsz, "execve(\"%s\", ...) = %ld", path, ev->ret);
        return;

    case X86_64_SYS_EXIT_GROUP:
        snprintf(buf, bufsz, "exit_group(%d) = %ld",
                 (int)ev->args[0], ev->ret);
        return;
    }

    snprintf(buf, bufsz, "%s(%#lx, %#lx, %#lx, %#lx, %#lx, %#lx) = %ld",
             syscall_name(ev->syscall_no),
             ev->args[0],
             ev->args[1],
             ev->args[2],
             ev->args[3],
             ev->args[4],
             ev->args[5],
             ev->ret);
}
