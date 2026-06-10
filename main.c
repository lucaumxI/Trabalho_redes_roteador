#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define TAMANHO_MAXIMO 256

/*
O trabalho possui 5 etapas obrigatórias descritas abaixo:
1 - Estrutura do pacote: Implementar uma estrutura de pacotes contendo IP de origem, IP de destino, TTL e dados. O programa deve permitir criar e exibir pacotes; (feito)
2 - Implementar uma tabela de roteamento contendo rede de destino, máscara e próximo salto. O programa deve permitir adicionar novas rotas e armazenar múltiplas rotas. (feito)
3 - Implementar a lógica de receber pacotes, verificar o TTL, buscar rota e decidir próximo salto. O sistema deve descartar pacotes com TTL =0, indicar erros quando não houver rota e selecionar rota válida. (feito)
4 - Implementar uma tabela ARP. O sistema deve ser capaz de buscar endereço MAC a partir do IP e indicar erro caso não encontre.
5 - O programa final deve:
    Criar pacotes
    Buscar rota
    Resolver ARP
    Exibir encaminhamento
*/

typedef struct{
    uint32_t ip_origem;
    uint32_t ip_destino;
    uint8_t ttl;
    uint8_t dados[256];
}pacote;

// recebe como string os endereços (192.168.0.1) e os dados
pacote criar_pacote(const char* str_ip_origem, const char* str_ip_destino, uint8_t ttl, const char* mensagem) {
    pacote p;
    
    memset(&p, 0, sizeof(pacote)); // zera memória do pacote

    // converte o Ip de string para int32, útil para fazer o máscaramento depois
    // AF_INET indica que é IPv4.
    inet_pton(AF_INET, str_ip_origem, &p.ip_origem);
    inet_pton(AF_INET, str_ip_destino, &p.ip_destino);

    // atribui o TTL
    p.ttl = ttl;

    // copia a mensagem para o array de dados
    // O -1 garante que sempre haverá espaço para o '\0' final de string
    strncpy((char*)p.dados, mensagem, TAMANHO_MAXIMO - 1);

    return p;
}

void exibe_pacote(pacote p){
    char str_ip_origem[INET_ADDRSTRLEN];    // cria buffer para converter os endereços de int32 para string
    char str_ip_destino[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(p.ip_origem), str_ip_origem, INET_ADDRSTRLEN);     // converte de int32 para string
    inet_ntop(AF_INET, &(p.ip_destino), str_ip_destino, INET_ADDRSTRLEN);

    printf("===== PACOTE =====\n");
    printf("Origem : %s\n", str_ip_origem);
    printf("Destino: %s\n", str_ip_destino);
    printf("TTL    : %d\n", p.ttl);
    printf("Dados  : %s\n", p.dados);
    printf("==================\n\n");
}

typedef struct{     // struct que define cada linha da tabela de roteamento
    uint32_t destino;
    uint32_t mascara;
    uint32_t proximo_hop;
}rota;

typedef struct{     // struct da tabela de roteamento
    rota rotas[100];    // fiz como um vetor estático de tamanho 100 mas pode ser qlq outro número ou até mesmo um vetor dinamico (nesse caso precisaria alterar o adicionarRota)
    int qnt_rotas;
}tabela_roteamento;

void adicionarRota(tabela_roteamento *tabela, rota rota){   // funcao para adicionar rotas
    tabela->rotas[tabela->qnt_rotas] = rota;
    tabela->qnt_rotas++;
}

void inicializaTabela(tabela_roteamento *tabela){          // inicializa a qnt_rotas como 0  
    tabela->qnt_rotas = 0;  
}

int simulaRecebimentoPacote(tabela_roteamento tabela, pacote *pacote){
    pacote->ttl--;
    if (pacote->ttl == 0){
        printf("ICMP Time Exceeded (Pacote Descartado)\n");
        return -1;
    }

    uint32_t maior_mascara = 0;
    int indice_rota_escolhida = -1;
    for (int i = 0; i < tabela.qnt_rotas; i++){
        if ((pacote->ip_destino & tabela.rotas[i].mascara) == tabela.rotas[i].destino){
            if(ntohl(tabela.rotas[i].mascara) >= maior_mascara){    // usa o ntohl porque o inet_pton guarda os bits "de tras pra frente"
                indice_rota_escolhida = i;
                maior_mascara = tabela.rotas[i].mascara;
            }
        }
    }

    if (indice_rota_escolhida == -1){
        printf("ICMP Destination Unreachable");
        return -1;
    }

    return indice_rota_escolhida; // na main eu faço um if rota_escolhida == -1 ERRO
}