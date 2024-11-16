#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 2048

typedef struct {
    SSL *ssl;
} ssl_info;

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void *receive_messages(void *arg) {
    ssl_info *info = (ssl_info *)arg;
    SSL *ssl = info->ssl;
    char buffer[BUFFER_SIZE];
    int bytes;

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        buffer[bytes] = '\0';
        printf("\nServidor: %s", buffer);
        printf("Tú: ");
        fflush(stdout);
    }

    printf("\nServidor desconectado\n");
    return NULL;
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[BUFFER_SIZE];
    pthread_t thread_id;
    char server_ip[50];
    int server_port;

    // Crear contexto SSL
    ctx = create_ssl_context();

    // Crear socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Error creando socket");
        exit(EXIT_FAILURE);
    }

    printf("Ingrese la IP del servidor: ");
    scanf("%s", server_ip);
    printf("Ingrese el puerto del servidor: ");
    scanf("%d", &server_port);
    getchar(); // Limpiar buffer

    // Configurar dirección del servidor
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Dirección inválida");
        exit(EXIT_FAILURE);
    }

    // Conectar al servidor
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error conectando");
        exit(EXIT_FAILURE);
    }

    // Configurar SSL
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("Conexión SSL establecida usando %s\n", SSL_get_cipher(ssl));

    // Crear estructura para el thread
    ssl_info *info = malloc(sizeof(ssl_info));
    info->ssl = ssl;

    // Crear thread para recibir mensajes
    if (pthread_create(&thread_id, NULL, receive_messages, (void*)info) < 0) {
        perror("Error creando thread");
        exit(EXIT_FAILURE);
    }

    // Loop principal para enviar mensajes
    printf("Chat iniciado. Escribe tus mensajes:\n");
    while (1) {
        printf("Tú: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        
        if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
            printf("Error enviando mensaje\n");
            break;
        }
    }

    // Limpieza
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    free(info);

    return 0;
}