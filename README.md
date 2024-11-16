# Proyecto2Arqui
1. Generar un certificado autofirmado y una clave privada:

# Generar clave privada
openssl genrsa -out server.key 2048

# Generar certificado autofirmado
openssl req -new -x509 -key server.key -out server.crt -days 365


2. Compilar los programas (necesitas las bibliotecas de desarrollo de OpenSSL):

# En Ubuntu/Debian
sudo apt-get install libssl-dev

# Compilar
gcc servidor_chat.c -o servidor_chat -pthread -lssl -lcrypto
gcc cliente_chat.c -o cliente_chat -pthread -lssl -lcrypto