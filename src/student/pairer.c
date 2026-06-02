#include "student_api.h"
#include "trace_helpers.h"

#include <stdio.h>
#include <sys/syscall.h>

static void capture_path_argument(struct syscall_event *ev)
{
    unsigned long addr;

    if (ev == NULL) {
        return;
    }

    switch (ev->syscall_no) {
#ifdef SYS_openat
    case SYS_openat:
        addr = ev->args[1];
        break;
#endif
#ifdef SYS_execve
    case SYS_execve:
        addr = ev->args[0];
        break;
#endif
    default:
        return;
    }

    if (read_child_string(ev->pid, addr, ev->path, sizeof(ev->path)) < 0) {
        snprintf(ev->path, sizeof(ev->path), "<ilegivel>");
    }
    ev->has_path = 1;
}

int student_pair_syscall(struct syscall_pairer *pairer,
                         const struct syscall_event *ev,
                         struct syscall_event *out)
{
    /*
     * TODO Semana 5:
     *
     * O runtime chama esta funcao duas vezes para cada syscall:
     *
     *   1. uma vez antes da syscall executar
     *   2. uma vez depois da syscall terminar
     *
     * Na primeira parada, os argumentos estao disponiveis.
     * Na segunda parada, o retorno esta disponivel.
     *
     * Seu trabalho e produzir um evento completo apenas quando ja existirem
     * as duas metades da syscall.
     *
     * Dicas:
     * - ev->entering == 1 indica entrada de syscall.
     * - ev->entering == 0 indica saida de syscall.
     * - para comecar, assuma apenas um processo monitorado.
     *
     * Retorne:
     *   1 se out contem uma syscall completa
     *   0 se ainda nao ha syscall completa
     *  -1 se a sequencia de eventos parece invalida
     */
    if (pairer == NULL || ev == NULL || out == NULL) {
        return -1;
    }

    if (ev->entering) {
#ifdef SYS_exit_group
        if (ev->syscall_no == SYS_exit_group) {
            *out = *ev;
            out->entering = 0;
            out->ret = 0;
            pairer->has_entry = 0;
            return 1;
        }
#endif

        pairer->entry = *ev;
        capture_path_argument(&pairer->entry);
        pairer->has_entry = 1;
        return 0;
    }

    if (!pairer->has_entry) {
        return -1;
    }

    if (pairer->entry.pid != ev->pid ||
        pairer->entry.syscall_no != ev->syscall_no) {
        pairer->has_entry = 0;
        return -1;
    }

    *out = *ev;
    out->args[0] = pairer->entry.args[0];
    out->args[1] = pairer->entry.args[1];
    out->args[2] = pairer->entry.args[2];
    out->args[3] = pairer->entry.args[3];
    out->args[4] = pairer->entry.args[4];
    out->args[5] = pairer->entry.args[5];
    out->has_path = pairer->entry.has_path;
    if (out->has_path) {
        snprintf(out->path, sizeof(out->path), "%s", pairer->entry.path);
    }

    pairer->has_entry = 0;
    return 1;
}
