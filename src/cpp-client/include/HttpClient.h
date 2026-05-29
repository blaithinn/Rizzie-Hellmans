#pragma once
#include <string>

class HttpClient {
public:
    HttpClient();
    ~HttpClient();
    std::string get(const std::string& url);
};
