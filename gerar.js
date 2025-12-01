/**
 * SCRIPT DE AUTOMAÇÃO DE INFRAESTRUTURA DE CHAVES (PKI)
 * Objetivo: Gerar certificados X.509 autoassinados para ambiente de desenvolvimento.
 * Requisito: OpenSSL instalado no sistema.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log("Iniciando geração de par de chaves e certificado...");

try {
    // Comando OpenSSL para gerar Chave Privada (RSA 2048) e Certificado Público
    // Validade: 365 dias
    // Algoritmo de assinatura: SHA-256
    const command = `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "//CN=localhost"`;

    console.log(` Executando: ${command}`);
    
    // Executa o comando no sistema operacional
    execSync(command);

    console.log("\n✅ ARTEFATOS DE SEGURANÇA GERADOS COM SUCESSO:");
    console.log("   -> key.pem  (Chave Privada - MANTER SIGILO)");
    console.log("   -> cert.pem (Certificado Público - INSTALAR NO NAVEGADOR)");

} catch (error) {
    console.error("Erro ao gerar certificados. Verifique se o OpenSSL está instalado e no PATH do sistema.");
    console.error("Detalhe do erro:", error.message);
}   