#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H

#include <iostream>
#include <string>
#include <sodium.h>
#include <jwt-cpp/jwt.h>

class AuthManager {
public:
    AuthManager() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize sodium");
        }
    }

    std::string hashPassword(const std::string& password) {
        char hashedPassword[crypto_pwhash_STRBYTES];
        if (crypto_pwhash_str(hashedPassword, password.c_str(), password.length(),
                              crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
            throw std::runtime_error("Failed to hash password");
        }
        return std::string(hashedPassword);
    }

    bool verifyPassword(const std::string& hashedPassword, const std::string& password) {
        return crypto_pwhash_str_verify(hashedPassword.c_str(), password.c_str(), password.length()) == 0;
    }

    bool authenticateUser(const std::string& username, const std::string& password) {
        // Placeholder: Replace with actual user lookup and password verification
        std::string storedHashedPassword = hashPassword("password"); // Dummy stored password hash

        if (verifyPassword(storedHashedPassword, password)) {
            std::string token = generateToken(username);
            std::cout << "Authentication successful. Token: " << token << std::endl;
            return true;
        } else {
            return false;
        }
    }

    std::string generateToken(const std::string& username) {
        auto token = jwt::create()
                     .set_issuer("auth_server")
                     .set_type("JWS")
                     .set_audience("chat_users")
                     .set_subject(username)
                     .set_issued_at(std::chrono::system_clock::now())
                     .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{30})
                     .sign(jwt::algorithm::hs256{"secret"});

        return token;
    }

    bool validateToken(const std::string& token) {
        try {
            auto decoded = jwt::decode(token);
            // Verify token with the same secret and check expiry
            return true;
        } catch (...) {
            return false;
        }
    }
};

#endif // AUTHMANAGER_H
