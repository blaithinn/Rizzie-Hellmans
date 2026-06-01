#pragma once
#include <string>

class HttpClient {
public:
    HttpClient();
    ~HttpClient();
    std::string get(const std::string& url, const std::string& token = "");
    std::string post(const std::string& url, const std::string& body,
                     const std::string& token = "");
    std::string put(const std::string& url, const std::string& body,
                    const std::string& token = "");
};
