#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define TAMANHO_MAXIMO 256

typedef struct {
    uint32_t ip_origem;
    uint32_t ip_destino;
    uint8_t ttl;
    uint8_t dados[TAMANHO_MAXIMO];
} pacote;

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
    printf("==================\n");
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

// Funcao auxiliar para adicionar rota convertendo strings diretamente (facilita na main)
void adicionarRotaString(tabela_roteamento *tabela, const char* str_destino, const char* str_mascara, const char* str_prox_hop) {
    rota r;
    inet_pton(AF_INET, str_destino, &r.destino);
    inet_pton(AF_INET, str_mascara, &r.mascara);
    inet_pton(AF_INET, str_prox_hop, &r.proximo_hop);
    adicionarRota(tabela, r);
}

void inicializaTabela(tabela_roteamento *tabela){          // inicializa a qnt_rotas como 0  
    tabela->qnt_rotas = 0;  
}

int simulaRecebimentoPacote(tabela_roteamento tabela, pacote *pacote){
    pacote->ttl--;
    if (pacote->ttl == 0){
        printf("Erro: ICMP Time Exceeded (Pacote Descartado. TTL esgotado)\n");
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
        printf("Erro: ICMP Destination Unreachable (Sem rota para o host)\n");
        return -1;
    }

    return indice_rota_escolhida; 
}


// Resolucao ARP 

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
} entrada_arp;

typedef struct {
    entrada_arp entradas[100];
    int qnt_entradas;
} tabela_arp;

void inicializaARP(tabela_arp *tabela) {
    tabela->qnt_entradas = 0;
}

// Adiciona uma entrada IP -> MAC estática
void adicionarARP(tabela_arp *tabela, const char* str_ip, uint8_t mac[6]) {
    inet_pton(AF_INET, str_ip, &tabela->entradas[tabela->qnt_entradas].ip);
    memcpy(tabela->entradas[tabela->qnt_entradas].mac, mac, 6);
    tabela->qnt_entradas++;
}

// Busca MAC a partir do IP. Retorna 1 se sucesso, 0 se não encontrar.
int buscarARP(tabela_arp tabela, uint32_t ip, uint8_t *mac_saida) {
    for (int i = 0; i < tabela.qnt_entradas; i++) {
        if (tabela.entradas[i].ip == ip) {
            memcpy(mac_saida, tabela.entradas[i].mac, 6);
            return 1; 
        }
    }
    return 0; 
}

// Encaminhamento

void encaminhar_pacote(pacote *p, tabela_roteamento t_rotas, tabela_arp t_arp) {
    printf("\n--- Analisando Pacote ---\n");
    exibe_pacote(*p);

    // Passo 1 e 2: Verifica TTL e Busca Rota
    int indice_rota = simulaRecebimentoPacote(t_rotas, p);
    
    if (indice_rota == -1) {
        // Falhou no TTL ou na Rota. O motivo já foi impresso na função acima.
        printf(">>> ENCAMINHAMENTO FALHOU.\n");
        return;
    }

    // Identificar qual o IP precisamos resolver na tabela ARP (Próximo Hop ou o próprio Destino)
    uint32_t ip_para_arp;
    
    // Se o prõximo salto for 0.0.0.0 (simbolizado por 0 em uint32), a entrega é direta na mesma rede local
    if (t_rotas.rotas[indice_rota].proximo_hop == 0) { 
        ip_para_arp = p->ip_destino;
    } else {
        ip_para_arp = t_rotas.rotas[indice_rota].proximo_hop;
    }

    char str_ip_prox_hop[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_para_arp, str_ip_prox_hop, INET_ADDRSTRLEN);
    printf("Rota encontrada! Encaminhando para IP: %s\n", str_ip_prox_hop);

    // Passo 3: Resolver ARP
    uint8_t mac_destino[6];
    if (buscarARP(t_arp, ip_para_arp, mac_destino)) {
        // Passo 4: Exibir encaminhamento com sucesso
        printf("ARP Resolvido com Sucesso!\n");
        printf("MAC de Destino: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_destino[0], mac_destino[1], mac_destino[2],
               mac_destino[3], mac_destino[4], mac_destino[5]);
        printf(">>> PACOTE ENCAMINHADO COM SUCESSO.\n");
    } else {
        printf("Erro ARP: Endereço MAC não encontrado na tabela para o IP %s.\n", str_ip_prox_hop);
        printf(">>> ENCAMINHAMENTO FALHOU.\n");
    }
}


int main() {
    tabela_roteamento t_rotas;
    inicializaTabela(&t_rotas);

    tabela_arp t_arp;
    inicializaARP(&t_arp);

    // --- POPULANDO DADOS INICIAIS (ROTAS E ARP) ---
    
    // Rota 1 (Genérica): Rede 192.168.1.0/24 sai pelo roteador 10.0.0.1
    adicionarRotaString(&t_rotas, "192.168.1.0", "255.255.255.0", "10.0.0.1");
    
    // Rota 2 (Específica): O Host 192.168.1.100/32 possui um caminho dedicado pelo 10.0.0.2
    adicionarRotaString(&t_rotas, "192.168.1.100", "255.255.255.255", "10.0.0.2");
    
    // Rota 3: Rede 172.16.0.0/16 sai pelo roteador 10.0.0.3 (Que não terá ARP de propósito para teste)
    adicionarRotaString(&t_rotas, "172.16.0.0", "255.255.0.0", "10.0.0.3");

    // Adicionando ARPs correspondentes
    uint8_t mac_gw1[6] = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01};
    adicionarARP(&t_arp, "10.0.0.1", mac_gw1);

    uint8_t mac_gw2[6] = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02};
    adicionarARP(&t_arp, "10.0.0.2", mac_gw2);
    // (O 10.0.0.3 não será adicionado ao ARP para forçar um erro)

    // Experimentos
    printf("\n#####################################################");
    printf("\n# EXPERIMENTO 1: PACOTE COM TTL DESCARTE            #");
    printf("\n#####################################################");
    // Pacote criado com TTL 1. Ao entrar no roteador, cairá para 0 e deve ser descartado.
    pacote p1 = criar_pacote("192.168.0.5", "192.168.1.50", 1, "Ping TTL 1");
    encaminhar_pacote(&p1, t_rotas, t_arp);

    printf("\n#####################################################");
    printf("\n# EXPERIMENTO 2: DESTINO SEM ROTA                   #");
    printf("\n#####################################################");
    // Destino 8.8.8.8 não consta em nenhuma das nossas rotas.
    pacote p2 = criar_pacote("192.168.0.5", "8.8.8.8", 64, "Ping Sem Rota");
    encaminhar_pacote(&p2, t_rotas, t_arp);

    printf("\n#####################################################");
    printf("\n# EXPERIMENTO 3: AUSÊNCIA NA TABELA ARP             #");
    printf("\n#####################################################");
    // Destino 172.16.5.5 possui a Rota 3, apontando para 10.0.0.3. 
    // Porém, não populamos o ARP do 10.0.0.3. A rota é validada, mas a entrega falha no MAC.
    pacote p3 = criar_pacote("192.168.0.5", "172.16.5.5", 64, "Ping Erro ARP");
    encaminhar_pacote(&p3, t_rotas, t_arp);

    printf("\n#####################################################");
    printf("\n# EXPERIMENTO 4: SELEÇÃO DA ROTA MAIS ESPECÍFICA    #");
    printf("\n#####################################################");
    // O destino 192.168.1.100 dá "match" na Rota 1 (/24) e na Rota 2 (/32).
    // O programa deve analisar que /32 tem a máscara maior (ntohl) e selecionar a Rota 2 (GW 10.0.0.2).
    pacote p4 = criar_pacote("192.168.0.5", "192.168.1.100", 64, "Ping Rota Especifica");
    encaminhar_pacote(&p4, t_rotas, t_arp);

    return 0;
}