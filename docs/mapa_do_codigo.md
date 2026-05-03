## Onde o programa começa

O programa começa no arquivo main.c, onde esta função chama a CLI para interpretar os argumentos do usuário

## Onde o processo alvo é criado

Ele é criado na função launch_tracee, essa função ira realizar um fork paracriar o processo filho (que é oq vai ser rastreado)

## Onde o rauntime chama o callback 

É chamado dentro do loop do tracing, quando uma syscall é detectada, é chamado dentro da função trace_program 

if (observer != NULL) {


    observer(&ev, userdata);


}

## Quais arquivos o grupo deve modificar

- src/trace_runtime.c: faz o controle do processo monitorado
- src/student/pairer.c: combina os eventos de entrada e saida de syscall
- src/student/formatter.c: faz ter uma saída legível para os usuários

## Qual TODO aparece primeiro ao executar scaffold

"erro: TODO Semana 2: implementar launch_tracee()"
no arquio src/trace.runtime.c

## Principal dúvida tecnica do grupo 

- O entendimento do runtime com detectando a syscall, que chama o callback.
- Estamos com dificuldades de ir desmembrando as funções com suas chamadas e retornos


