#pragma once

#ifndef EWS_CLIENT_GLOBAL_H
#define EWS_CLIENT_GLOBAL_H

#include "durian.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
// download from http://www.nongnu.org/libntlm/releases/ homepage => http://www.nongnu.org/libntlm/

using namespace std;

namespace ews {
  namespace global {
    const std::string NM_EWS_TYPES("http://schemas.microsoft.com/exchange/services/2006/types");
    const std::string NM_EWS_MESSAGES("http://schemas.microsoft.com/exchange/services/2006/messages");
    const std::string EWS_HOST("localhost:443");
    const std::string EWS_WSDL("/EWS/Services.wsdl");
    std::string USERNAME("username");
    std::string WINDOWS_DOMAIN("domain");
    std::string PASSWORD("passord");
  }

  /*
    for reference, go here:
    http://social.technet.microsoft.com/wiki/contents/articles/7917.how-to-exchange-web-service-with-api-coding-in-native-cc.aspx
  */
  class NtlmHelper {
  public:
    NtlmHelper(const string _host, int _port, const string _path, const string _domain, const string _user, const string _pass) : host(_host), port(_port), path(_path), domain(_domain), user(_user), pass(_pass){};
    ~NtlmHelper(){
      this->destroySSL();
      this->shutdownSSL();
      this->freeSSLContext();
    };
    int login() {

      api::socketImpl s1(host.c_str(), port);
      auto rc1 = s1.connectImpl();
      this->sock = s1.getSocket();

      auto rc = this->initSSL()
        ->sendDummy()
        ->sendAuthorization()
        ->authenticate();

      return this->isAuthenticated;
    };
  private:
    string host, path, domain, user, pass;
    int port, isAuthenticated = 0;
    tSmbNtlmAuthRequest request;
    tSmbNtlmAuthResponse response;
    string encoded, encodedpass, decoded, sBuffer;

    std::shared_ptr<int> sock;
    const SSL_METHOD *meth;
    SSL *ssl;
    BIO *sbio;
    BIO *rbio;
    BIO *wbio;
    SSL_CTX *ctx;

    NtlmHelper* initSSL() {
      SSL_library_init();
      SSL_load_error_strings();
      meth = SSLv23_method();
      ctx = SSL_CTX_new(meth);
      // ssl will be our pipe
      ssl = SSL_new(ctx);
      sbio = BIO_new_socket(*sock, BIO_NOCLOSE);

      SSL_set_bio(ssl, sbio, sbio);
      SSL_connect(ssl);
      return this;
    }

    string readAll(int maxBufSize) {
      char* returnBuf = (char*)malloc(maxBufSize);
      char* destBuf = (char*)malloc(maxBufSize);
      int readBufLen = 0;
      stringstream ss;
      do {
        readBufLen = SSL_read(ssl, returnBuf, maxBufSize);
        memset(destBuf, 0, maxBufSize);
        memcpy(destBuf, returnBuf, readBufLen);
        ss << destBuf;
        memset(returnBuf, 0, maxBufSize);
      } while (readBufLen == maxBufSize);

      free(returnBuf);
      free(destBuf);
      return ss.str();
    }

    NtlmHelper* destroySSL() {
      ERR_free_strings();
      EVP_cleanup();
      return this;
    }
    NtlmHelper* shutdownSSL() {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      return this;
    }
    NtlmHelper* freeSSLContext() {
      SSL_CTX_free(ctx);
      return this;
    }

    /*
      send request to generate a 401 error
    */
    NtlmHelper* sendDummy() {
      stringstream apiRequest;
      apiRequest << "GET " << path << " HTTP/1.1\r\nUser-Agent: test\r\nHost: " << host << ":" << port << "\r\n\r\n";
      auto r = apiRequest.str();
      SSL_write(ssl, r.c_str(), r.size());
      auto resp = this->readAll(1024);
      cout << resp << endl;
      return this;
    }

    NtlmHelper* sendAuthorization() {
      stringstream apiRequest;

      buildSmbNtlmAuthRequest(&this->request, this->user.c_str(), this->domain.c_str());
      if (SmbLength(&request) > 1024){
        return 0;
      }
      // encode request with domain\user
      this->encoded = base64_encode((unsigned char *)&this->request, SmbLength(&this->request));
      apiRequest << "GET " << path << " HTTP/1.1\r\nUser-Agent: test\r\nHost: " << host << ":" << port << "\r\nConnection: Keep-Alive\r\nAuthorization: NTLM " << this->encoded << "\r\n\r\n";
      auto r = apiRequest.str();
      SSL_write(ssl, r.c_str(), r.size());
      
      auto resp = this->readAll(1024);

      std::smatch m;
      std::string first;
      regex e("WWW-Authenticate:\\sNTLM\\s(.*)\\r\\n");
      if (std::regex_search(resp, m, e) && m.size() > 1) {
        first = m.str(1);
        regex f("WWW-Authenticate:\\sNTLM\\s");
        first = regex_replace(first, f, "");
        first = regex_replace(first, regex("\\r|\\n"), "");
      }
      
      this->decoded = base64_decode(first.c_str()); //expect NTLMSSP
      cout << "==========\ndecoded => " << this->decoded.c_str() << "\n==========\n";
      cout << resp << endl;
      return this;
    }

    NtlmHelper* authenticate() {
      stringstream apiRequest;
      
      buildSmbNtlmAuthResponse((tSmbNtlmAuthChallenge *)this->decoded.c_str(), &this->response, this->user.c_str(), this->pass.c_str());
      // encode request with password
      this->encodedpass = base64_encode((unsigned char *)&this->response, SmbLength(&this->response));
      apiRequest << "GET " << path << " HTTP/1.1\r\nUser-Agent: test\r\nHost: " << host << ":" << port << "\r\nConnection: Keep-Alive\r\nAuthorization: NTLM " << this->encodedpass << "\r\n\r\n";
      auto r = apiRequest.str();
      SSL_write(ssl, r.c_str(), r.size());

      auto resp = this->readAll(16384);

      cout << resp << endl;

      std::smatch m;
      if (std::regex_search(resp, m, regex("200\\sOK"))) {
        cout << "SUCCESS!" << endl;
        isAuthenticated = 1;
      } else {
        cout << "FAILED!" << endl;
      }
      return this;
    }

  };
}

#endif