#include "trace_runtime.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "Este runtime didatico suporta apenas Linux x86_64."
#endif

static void fill_event_from_regs(pid_t pid,
                                 int entering,
                                 const struct user_regs_struct *regs,
                                 struct syscall_event *ev)
{
    /*
     * TODO Semana 4:
     *
     * Preencha struct syscall_event usando os registradores x86_64.
     *
     * Dicas:
     * - regs->orig_rax contem o numero da syscall.
     * - regs->rax contem o retorno, valido na saida.
     * - os seis argumentos ficam em rdi, rsi, rdx, r10, r8 e r9.
     * - ev->entering deve copiar o parametro entering.
     */
        memset(ev, 0, sizeof(*ev));
    ev->pid = pid;
    ev->entering = entering;
    ev->syscall_no = regs->orig_rax;
    ev->ret = regs->rax;
    ev->args[0] = regs->rdi;
    ev->args[1] = regs->rsi;
    ev->args[2] = regs->rdx;
    ev->args[3] = regs->r10;
    ev->args[4] = regs->r8;
    ev->args[5] = regs->r9;
}

static pid_t launch_tracee(char *const argv[])
{
    pid_t pid = fork(); /*DANDO FORK PARA CRIAR O FILHO*/

    if (pid < 0)
    {
        perror("erro ao dar Fork");  /*pid do filho == 0*/ 
        return -1;
    }

    if (pid == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0 ) /*parametros: (comando(trace permite o pai rastrear), pid, addr, data)*/
        {
            perror("Erro ao dar o Traceme");
            exit(1);
        }

        raise(SIGSTOP); /*filho pausa pro pai configurar o trace*/

        execvp(argv[0], argv); /*Filho virando o programa que queremos seguir*/

        perror("erro ao filho receber o processo");
        exit(1);
    }

    return pid;
    
}

static int wait_for_initial_stop(pid_t child){
    int status;

    if (waitpid(child, &status, 0) < 0){
        perror("erro no waitpid inicial"); /*pai espera a parada inicial com waitpid */
        return -1;
    }

    if (!WIFSTOPPED(status)){
        fprintf(stderr, "filho não parou como o esperado"); /*pai verifica se o filho realmente parou*/
        return -1;
    }

    return 0;
}

/* perror: vc fala oq falhou e o SO da a explicação do erro */
/* print(stderr): voce escreve diretamente oq foi o erro*/

static int configure_trace_options(pid_t child)
{
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD) == -1)
    {
        perror("PTRACE_SETOPTIONS: ");
        return -1;
    }

    /*PTRACE_O_TRACESYSGOOD: marca as paradas (do filho) que são causadas por syscall, podendo diferenciar de outros tipos de parada
    -> sem a func: "SIGTRAP" (n sabemos pq ela parou)
    -> com a func: "SIGTRAP" + etiqueta da parada
    -> ele n diferencia a syscall ent qualquer parada por syscall e o mesmo aviso para o kernel
    -> OBS: isso e uma comunicação entre o programa e o kernel*/

    return 0;
}

static int resume_until_next_syscall(pid_t child, int signal_to_deliver)
{
    /* fazer o processo filho continuar executando ate a proxima entrada ou saida de uma syscall */
    
    if (ptrace(PTRACE_SYSCALL, child, NULL, signal_to_deliver) == -1)
    {
        perror("PTRACE_SYSCALL: ");
        return -1;
    }

    return 0;

}

static int wait_for_syscall_stop(pid_t child, int *status)
{
    while (1) {
        if (waitpid(child, status, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
            return 0;
        }

        if (WIFSTOPPED(*status)) {
            int sig = WSTOPSIG(*status);

            /* Parada causada por syscall */
            if (sig == (SIGTRAP | 0x80)) {
                return 1;
            }

            /* SIGTRAP comum não deve ser reenviado */
            if (sig == SIGTRAP) {
                sig = 0;
            }

            /* Continua o processo até a próxima parada */
            if (resume_until_next_syscall(child, sig) == -1) {
                return -1;
            }
        }
        else {
            fprintf(stderr, "para inesperada do filho");
            return -1;
        }
    }
}

int trace_program(char *const argv[],
                  trace_observer_fn observer,
                  void *userdata)
{
    pid_t child;
    int status = 0;
    int entering = 1;

    if (argv == NULL || argv[0] == NULL) {
        fprintf(stderr, "erro: programa alvo ausente\n");
        return -1;
    }

    child = launch_tracee(argv);
    if (child < 0) {  /*child recebe o pid do filho*/
        return -1;
    }

    if (wait_for_initial_stop(child) < 0) {
        return -1; /*pai recebe esse child(pid) e congela*/
    }

    if (configure_trace_options(child) < 0) {
        return -1;
    }

    if (resume_until_next_syscall(child, 0) < 0) {
        return -1;
    }

    while (1) {
        struct user_regs_struct regs;
        struct syscall_event ev;
        int stop_kind;

        stop_kind = wait_for_syscall_stop(child, &status);
        if (stop_kind < 0) {
            return -1;
        }
        if (stop_kind == 0) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 0;
        }

        memset(&regs, 0, sizeof(regs));

        /*O filho esta parado em uma syscall*/
        /*get regs: ele serve para "pegar" os registradores pq eles guardam alguamas coisas
        como: retorno, edereço atual*/

        if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1 )
        {
            perror("ptrace erro no GETREGS");
            return -1;
        }

        fill_event_from_regs(child, entering, &regs, &ev);
        if (observer != NULL) {
            observer(&ev, userdata);
        }

        entering = !entering;

        if (resume_until_next_syscall(child, 0) < 0) {
            return -1;
        }
    }
}
