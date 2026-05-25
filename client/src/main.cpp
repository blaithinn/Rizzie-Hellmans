#include <iostream>
#include "HttpClient.h"

int main() {
    std::cout << "SecureChat C++ Client v0.1" << std::endl;

    HttpClient client;
    std::string response = client.get("https://httpbin.org/get");
    std::cout << "Response: " << response << std::endl;

    return 0;
}
