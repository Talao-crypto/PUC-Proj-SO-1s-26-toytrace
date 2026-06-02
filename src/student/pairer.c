#include "student_api.h"
#include "trace_helpers.h"

#include <stdio.h>
#include <sys/syscall.h>

#define CHILD_STRING_BUFSZ 256

static int pending_has_path;
static pid_t pending_path_pid;
static long pending_path_syscall_no;
static char pending_path[CHILD_STRING_BUFSZ];

static int completed_has_path;
static pid_t completed_path_pid;
static long completed_path_syscall_no;
static char completed_path[CHILD_STRING_BUFSZ];

const char *student_completed_path_for_event(const struct syscall_event *ev)
{
    if (ev == NULL || !completed_has_path) {
        return NULL;
    }

    if (completed_path_pid != ev->pid ||
        completed_path_syscall_no != ev->syscall_no) {
        return NULL;
    }

    return completed_path;
}

static void clear_completed_path(void)
{
    completed_has_path = 0;
    completed_path[0] = '\0';
}

static void capture_path_argument(const struct syscall_event *ev)
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

    if (read_child_string(ev->pid, addr, pending_path, sizeof(pending_path)) < 0) {
        snprintf(pending_path, sizeof(pending_path), "<ilegivel>");
    }
    pending_path_pid = ev->pid;
    pending_path_syscall_no = ev->syscall_no;
    pending_has_path = 1;
}

static void publish_completed_path(const struct syscall_event *entry)
{
    if (entry == NULL || !pending_has_path ||
        pending_path_pid != entry->pid ||
        pending_path_syscall_no != entry->syscall_no) {
        clear_completed_path();
        return;
    }

    snprintf(completed_path, sizeof(completed_path), "%s", pending_path);
    completed_path_pid = pending_path_pid;
    completed_path_syscall_no = pending_path_syscall_no;
    completed_has_path = 1;
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
            pending_has_path = 0;
            clear_completed_path();
            return 1;
        }
#endif

        pairer->entry = *ev;
        pending_has_path = 0;
        capture_path_argument(ev);
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
    publish_completed_path(&pairer->entry);

    pairer->has_entry = 0;
    return 1;
}
