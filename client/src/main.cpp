#include <iostream>
#include "HttpClient.h"

int main() {
    std::cout << "SecureChat C++ Client v0.1" << std::endl;

    HttpClient client;
    std::string response = client.get("https://rizzie-hellmans.theburkenator.com/health");
    std::cout << "Response: " << response << std::endl;

    return 0;
}
