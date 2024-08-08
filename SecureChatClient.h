#ifndef SECURECHATCLIENT_H
#define SECURECHATCLIENT_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <aws/core/Aws.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
#include <aws/kms/model/GenerateDataKeyResult.h>
#include <boost/asio.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>
#include "AuthManager.h"

constexpr int PORT = 12345;
constexpr int MAX_RETRIES = 3;

class SSLContext {
private:
    SSL_CTX* ctx;

public:
    SSLContext(bool asServer) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        const SSL_METHOD* method = asServer ? TLS_server_method() : TLS_client_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            throw std::runtime_error("Unable to create SSL context");
        }

        if (asServer) {
            SSL_CTX_set_ecdh_auto(ctx, 1);
            if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384") <= 0) {
                throw std::runtime_error("Failed to set cipher list");
            }
            if (SSL_CTX_use_certificate_file(ctx, "certificate.pem", SSL_FILETYPE_PEM) <= 0 ||
                SSL_CTX_use_PrivateKey_file(ctx, "private_key.pem", SSL_FILETYPE_PEM) <= 0) {
                throw std::runtime_error("Failed to load certificate or private key");
            }
        } else {
            if (SSL_CTX_load_verify_locations(ctx, "ca_certificates.pem", NULL) <= 0) {
                throw std::runtime_error("Failed to load CA certificates");
            }
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
    }

    ~SSLContext() {
        SSL_CTX_free(ctx);
        EVP_cleanup();
    }

    SSL* createSSL(int sock) {
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        return ssl;
    }

    void verifyCertificate(SSL* ssl) {
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            throw std::runtime_error("Certificate verification failed");
        }
    }
};

class SSLWrapper {
private:
    SSL* ssl;

public:
    SSLWrapper(SSLContext& context, int sock, bool asServer) {
        ssl = context.createSSL(sock);
        if (asServer) {
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("SSL Accept failed");
            }
        } else {
            if (SSL_connect(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                throw std::runtime_error("SSL Connect failed");
            }
            context.verifyCertificate(ssl);
        }
    }

    ~SSLWrapper() {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    void send(const std::string& msg) {
        SSL_write(ssl, msg.data(), msg.size());
    }

    std::string receive() {
        char buffer[1024] = {0};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            return std::string(buffer, bytes);
        }
        return "";
    }
};

class SecureChatClient {
private:
    std::map<int, std::unique_ptr<SSLWrapper>> connections;
    std::map<std::string, std::vector<int>> chatRooms;
    std::mutex connectionsMutex;
    std::mutex chatRoomsMutex;
    std::string localIp;
    int localPort;
    SSLContext serverContext{true};
    SSLContext clientContext{false};
    std::vector<unsigned char> encryptionKey;
    std::vector<unsigned char> hmacKey;
    std::chrono::minutes keyRotationInterval{60}; // Rotate keys every 60 minutes
    std::thread keyRotationThread;
    std::atomic<bool> running{true};
    std::vector<std::thread> threads;
    boost::asio::io_context ioContext;
    boost::asio::ip::tcp::acceptor acceptor{ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT)};

    void logError(const std::string& message) {
        BOOST_LOG_TRIVIAL(error) << message;
    }

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generateKeysFromKms() {
        Aws::Client::ClientConfiguration clientConfig;
        Aws::KMS::KMSClient kmsClient(clientConfig);

        Aws::KMS::Model::GenerateDataKeyRequest request;
        request.WithKeyId("alias/your-key-alias") // Replace with your KMS key alias or ARN
               .WithKeySpec(Aws::KMS::Model::DataKeySpec::AES_256);

        auto outcome = kmsClient.GenerateDataKey(request);

        if (!outcome.IsSuccess()) {
            throw std::runtime_error("Failed to generate data key from KMS");
        }

        auto& result = outcome.GetResult();
        auto ciphertextBlob = result.GetCiphertextBlob();
        auto plaintextKey = result.GetPlaintext();

        std::vector<unsigned char> encryptionKey(plaintextKey.begin(), plaintextKey.end());
        std::vector<unsigned char> hmacKey(ciphertextBlob.begin(), ciphertextBlob.end());

        return {encryptionKey, hmacKey};
    }

    void keyRotationTask() {
        while (running) {
            std::this_thread::sleep_for(keyRotationInterval);
            if (running) {
                auto keys = generateKeysFromKms();
                encryptionKey = keys.first;
                hmacKey = keys.second;
                BOOST_LOG_TRIVIAL(info) << "Session keys rotated";
            }
        }
    }

    std::string generateHMAC(const std::string& message) {
        unsigned char* digest;
        digest = HMAC(EVP_sha256(), hmacKey.data(), hmacKey.size(), (unsigned char*)message.c_str(), message.size(), NULL, NULL);
        return std::string((char*)digest, 32);  // 32 bytes for SHA-256
    }

    std::string encryptMessage(const std::string& message) {
        AES_KEY encKey;
        unsigned char iv[AES_BLOCK_SIZE];
        RAND_bytes(iv, AES_BLOCK_SIZE);

        unsigned char ciphertext[1024];
        int ciphertext_len;

        AES_set_encrypt_key(encryptionKey.data(), 256, &encKey);
        AES_cfb128_encrypt((unsigned char*)message.c_str(), ciphertext, message.size(), &encKey, iv, &ciphertext_len, AES_ENCRYPT);

        std::string result((char*)iv, AES_BLOCK_SIZE);
        result += std::string((char*)ciphertext, ciphertext_len);
        return result;
    }

    std::string decryptMessage(const std::string& ciphertext) {
        AES_KEY decKey;
        unsigned char iv[AES_BLOCK_SIZE];
        memcpy(iv, ciphertext.c_str(), AES_BLOCK_SIZE);

        unsigned char decryptedtext[1024];
        int decryptedtext_len;

        AES_set_decrypt_key(encryptionKey.data(), 256, &decKey);
        AES_cfb128_encrypt((unsigned char*)ciphertext.c_str() + AES_BLOCK_SIZE, decryptedtext, ciphertext.size() - AES_BLOCK_SIZE, &decKey, iv, &decryptedtext_len, AES_DECRYPT);

        return std::string((char*)decryptedtext, decryptedtext_len);
    }

    void handleRecoverableError(const std::string& errorMessage) {
        logError(errorMessage);
        for (int i = 0; i < MAX_RETRIES; ++i) {
            try {
                BOOST_LOG_TRIVIAL(info) << "Retrying (" << i + 1 << "/" << MAX_RETRIES << ")...";
            } catch (const std::exception& e) {
                logError(e.what());
                if (i == MAX_RETRIES - 1) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
            }
        }
    }

public:
    SecureChatClient(const std::string& ip, int port) : localIp(ip), localPort(port) {
        try {
            auto keys = generateKeysFromKms();
            encryptionKey = keys.first;
            hmacKey = keys.second;

            threads.emplace_back(&SecureChatClient::acceptConnections, this);
            threads.emplace_back(&SecureChatClient::receiveMessages, this);
            keyRotationThread = std::thread(&SecureChatClient::keyRotationTask, this);
        } catch (const std::exception& e) {
            logError(e.what());
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

    ~SecureChatClient() {
        running = false;
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        if (keyRotationThread.joinable()) {
            keyRotationThread.join();
        }
    }

    void acceptConnections() {
        while (running) {
            try {
                boost::asio::ip::tcp::socket socket(ioContext);
                acceptor.accept(socket);

                std::unique_ptr<SSLWrapper> sslConnection = std::make_unique<SSLWrapper>(serverContext, socket.native_handle(), true);
                {
                    std::lock_guard<std::mutex> lock(connectionsMutex);
                    connections[socket.native_handle()] = std::move(sslConnection);
                }
            } catch (const std::exception& e) {
                logError(e.what());
                std::cerr << "Error: " << e.what() << std::endl;
            }
        }
    }

    void connectToServer(const std::string& serverIp, int serverPort) {
        try {
            boost::asio::ip::tcp::resolver resolver(ioContext);
            boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(serverIp, std::to_string(serverPort));

            boost::asio::ip::tcp::socket socket(ioContext);
            boost::asio::connect(socket, endpoints);

            std::unique_ptr<SSLWrapper> sslConnection = std::make_unique<SSLWrapper>(clientContext, socket.native_handle(), false);
            {
                std::lock_guard<std::mutex> lock(connectionsMutex);
                connections[socket.native_handle()] = std::move(sslConnection);
            }
        } catch (const std::exception& e) {
            handleRecoverableError(e.what());
        }
    }

    void sendToServer(const std::string& message) {
        std::string hmac = generateHMAC(message);
        std::string encryptedMessage = encryptMessage(message + hmac);
        std::lock_guard<std::mutex> lock(connectionsMutex);
        for (auto& conn : connections) {
            try {
                conn.second->send(encryptedMessage);
            } catch (const std::exception& e) {
                handleRecoverableError(e.what());
            }
        }
    }

    void sendToChatRoom(const std::string& room, const std::string& message) {
        std::string hmac = generateHMAC(message);
        std::string encryptedMessage = encryptMessage(message + hmac);
        std::lock_guard<std::mutex> lock(chatRoomsMutex);
        if (chatRooms.find(room) != chatRooms.end()) {
            for (int sock : chatRooms[room]) {
                try {
                    connections[sock]->send(encryptedMessage);
                } catch (const std::exception& e) {
                    handleRecoverableError(e.what());
                }
            }
        }
    }

    void sendDirectMessage(int peerSock, const std::string& message) {
        std::string hmac = generateHMAC(message);
        std::string encryptedMessage = encryptMessage(message + hmac);
        try {
            connections.at(peerSock)->send(encryptedMessage);
        } catch (const std::exception& e) {
            handleRecoverableError(e.what());
        }
    }

    void receiveMessages() {
        while (running) {
            std::lock_guard<std::mutex> lock(connectionsMutex);
            for (auto it = connections.begin(); it != connections.end();) {
                try {
                    std::string encryptedMessage = it->second->receive();
                    if (!encryptedMessage.empty()) {
                        std::string messageWithHmac = decryptMessage(encryptedMessage);
                        std::string message = messageWithHmac.substr(0, messageWithHmac.size() - 32);
                        std::string hmac = messageWithHmac.substr(messageWithHmac.size() - 32);
                        if (generateHMAC(message) == hmac) {
                            BOOST_LOG_TRIVIAL(info) << "Received: " << message;
                        } else {
                            BOOST_LOG_TRIVIAL(error) << "HMAC verification failed.";
                        }
                    }
                    ++it;
                } catch (const std::exception& e) {
                    logError(e.what());
                    std::cerr << "Error: " << e.what() << std::endl;
                    it = connections.erase(it);
                }
            }
        }
    }

    void chatInterface() {
        std::string input;
        while (true) {
            std::cout << "Enter command: ";
            std::getline(std::cin, input);

            if (input == "/quit") {
                running = false;
                break;
            } else if (input.find("/join") == 0) {
                std::string room = input.substr(6);
                std::lock_guard<std::mutex> lock(chatRoomsMutex);
                chatRooms[room] = {};
            } else if (input.find("/send") == 0) {
                size_t spacePos = input.find(' ', 6);
                if (spacePos != std::string::npos) {
                    std::string room = input.substr(6, spacePos - 6);
                    std::string message = input.substr(spacePos + 1);
                    sendToChatRoom(room, message);
                }
            } else if (input.find("/dm") == 0) {
                size_t spacePos = input.find(' ', 4);
                if (spacePos != std::string::npos) {
                    int peerSock = std::stoi(input.substr(4, spacePos - 4));
                    std::string message = input.substr(spacePos + 1);
                    sendDirectMessage(peerSock, message);
                }
            } else {
                sendToServer(input);
            }
        }
    }

    void discoverPeers() {
        BOOST_LOG_TRIVIAL(info) << "Peer discovery not implemented yet.";
    }
};

#endif // SECURECHATCLIENT_H
