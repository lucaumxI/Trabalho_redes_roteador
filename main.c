#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define TAMANHO_MAXIMO 256

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

