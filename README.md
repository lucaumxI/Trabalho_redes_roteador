# Simulador de Roteador IPv4 e Resolução ARP

## Descrição do Projeto
Este repositório contém a implementação em linguagem C de um simulador de roteamento de pacotes na Camada de Rede (Camada 3). O sistema emula o comportamento algorítmico interno de um roteador, processando datagramas IP, tomando decisões de encaminhamento lógico e descendo para a camada de enlace para a resolução de endereços físicos.

Projeto desenvolvido para a disciplina de Redes de Computadores no Departamento de Computação da Universidade Federal de São Carlos (UFSCar).

## Funcionalidades
* **Processamento de Pacote IP:** Modelagem de datagramas contendo IP de origem, IP de destino, TTL (Time to Live) e carga útil (payload).
* **Tabela de Roteamento e LPM:** Sistema de roteamento estático que utiliza o algoritmo *Longest Prefix Match* (Casamento de Prefixo Mais Longo) para definir o próximo salto (Gateway) em cenários de rotas concorrentes.
* **Controle de Loop (TTL):** Decremento automático do campo TTL a cada salto lógico, com descarte e notificação (simulando ICMP Time Exceeded) caso o pacote expire.
* **Resolução Física (ARP):** Implementação de uma tabela cache ARP para mapeamento de endereços lógicos (IP) em endereços físicos (MAC).

## Como Compilar e Executar

### Pré-requisitos
* Um compilador C (GCC recomendado).
* Terminal Linux/macOS ou Windows configurado com MSYS2/MinGW.

### Compilação
Clone este repositório e, no terminal aberto na pasta do projeto, execute o comando de compilação:

```bash
gcc main.c -o roteador
