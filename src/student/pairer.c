#include "student_api.h"

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
    enum { X86_64_SYS_EXIT_GROUP = 231 };
    int i;

    if (pairer == NULL || ev == NULL || out == NULL) {
        return -1;
    }

    if (ev->entering) {
        if (ev->syscall_no == X86_64_SYS_EXIT_GROUP) {
            *out = *ev;
            out->entering = 0;
            out->ret = 0;
            pairer->has_entry = 0;
            return 1;
        }

        if (pairer->has_entry) {
            return -1;
        }

        pairer->entry = *ev;
        pairer->has_entry = 1;
        return 0;
    }

    if (!pairer->has_entry ||
        pairer->entry.pid != ev->pid ||
        pairer->entry.syscall_no != ev->syscall_no) {
        pairer->has_entry = 0;
        return -1;
    }

    *out = *ev;
    for (i = 0; i < 6; i++) {
        out->args[i] = pairer->entry.args[i];
    }

    pairer->has_entry = 0;
    return 1;
}
