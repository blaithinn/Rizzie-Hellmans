#include "HttpClient.h"
#include <curl/curl.h>
#include <iostream>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    output->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

HttpClient::HttpClient() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

HttpClient::~HttpClient() {
    curl_global_cleanup();
}

std::string HttpClient::get(const std::string& url, const std::string& token) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        struct curl_slist* headers = nullptr;
        if (!token.empty()) {
            std::string authHeader = "Authorization: Bearer " + token;
            headers = curl_slist_append(headers, authHeader.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return response;
}

std::string HttpClient::post(const std::string& url, const std::string& body,
                              const std::string& token) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        if (!token.empty()) {
            std::string authHeader = "Authorization: Bearer " + token;
            headers = curl_slist_append(headers, authHeader.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return response;
}

std::string HttpClient::put(const std::string& url, const std::string& body,
                             const std::string& token) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        if (!token.empty()) {
            std::string authHeader = "Authorization: Bearer " + token;
            headers = curl_slist_append(headers, authHeader.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return response;
}
