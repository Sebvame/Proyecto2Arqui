#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 10000
#define BUFFER_SIZE 2048
#define CERTIFICATE_FILE "server.crt"
#define PRIVATE_KEY_FILE "server.key"

typedef struct {
    SSL *ssl;
    struct sockaddr_in address;
} client_info;

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx;

    // Inicializar la librería OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Crear nuevo contexto SSL
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Cargar certificado y clave privada
    if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verificar clave privada
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "La clave privada no coincide con el certificado público\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void *handle_client(void *arg) {
    client_info *info = (client_info *)arg;
    SSL *ssl = info->ssl;
    char buffer[BUFFER_SIZE];
    int bytes;

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        buffer[bytes] = '\0';
        printf("\nCliente [%s:%d]: %s", 
               inet_ntoa(info->address.sin_addr), 
               ntohs(info->address.sin_port), 
               buffer);
        printf("Tú: ");
        fflush(stdout);
    }

    printf("\nCliente desconectado\n");
    SSL_free(ssl);
    free(info);
    return NULL;
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    pthread_t thread_id;
    SSL_CTX *ctx;

    // Crear contexto SSL
    ctx = create_ssl_context();

    // Crear socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Error creando socket");
        exit(EXIT_FAILURE);
    }

    // Configurar dirección del servidor
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error en bind");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_sock, 5) < 0) {
        perror("Error en listen");
        exit(EXIT_FAILURE);
    }

    printf("Servidor escuchando en puerto %d...\n", PORT);

    while (1) {
        socklen_t client_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_sock < 0) {
            perror("Error en accept");
            continue;
        }

        printf("Cliente conectado desde %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port));

        // Crear nueva estructura SSL
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        // Crear información del cliente
        client_info *info = malloc(sizeof(client_info));
        info->ssl = ssl;
        info->address = client_addr;

        // Crear thread para el cliente
        if (pthread_create(&thread_id, NULL, handle_client, (void*)info) < 0) {
            perror("Error creando thread");
            SSL_free(ssl);
            free(info);
            close(client_sock);
            continue;
        }

        pthread_detach(thread_id);
    }

    SSL_CTX_free(ctx);
    close(server_sock);
    return 0;
}