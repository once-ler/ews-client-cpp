#pragma once

#ifndef EWS_CLIENT_GLOBAL_H
#define EWS_CLIENT_GLOBAL_H

#include "durian.h"

//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/bio.h>
// download from http://www.nongnu.org/libntlm/releases/ homepage => http://www.nongnu.org/libntlm/

#include "client_https.hpp"

typedef SimpleWeb::Client<SimpleWeb::HTTPS> HttpsClient;

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
    NtlmHelper(const string _host, const string _path, const string _domain, const string _user, const string _pass) : host(_host), path(_path), domain(_domain), user(_user), pass(_pass){};
    ~NtlmHelper(){};
    int login() {

      //no certificate verification
      client = make_shared<HttpsClient>(this->host, false);
      
      auto rc = this->sendDummy()
        ->sendAuthorization()
        ->authenticate();

      return rc;
    };
  private:
    string host, path, domain, user, pass;
    shared_ptr<HttpsClient> client;
    tSmbNtlmAuthRequest request;
    tSmbNtlmAuthResponse response;
    string encoded, encodedpass, decoded, sBuffer;

    /*
      send request to generate a 401 error
    */
    NtlmHelper* sendDummy() {

      auto r1 = client->request("GET", this->path);
      return this;
    }

    NtlmHelper* sendAuthorization() {

      buildSmbNtlmAuthRequest(&this->request, this->user.c_str(), this->domain.c_str());
      if (SmbLength(&request) > 1024){
        return 0;
      }

      encoded = base64_encode((unsigned char *)&this->request, SmbLength(&this->request));
      
      std::map<std::string, std::string> header;

      header["Connection"] = "Keep-Alive";
      header["Authorization"] = "NTLM " + encoded;
      
      auto r1 = client->request("GET", this->path, "", header);

      // read the answer, r1 = NTLM answer
      stringstream ss;
      ss << r1->content.rdbuf();
      this->decoded = base64_decode(ss.str());
      
      return this;      

    }

    int authenticate() {

      buildSmbNtlmAuthResponse((tSmbNtlmAuthChallenge *)this->decoded.c_str(), &this->response, this->user.c_str(), this->pass.c_str());
      encodedpass = base64_encode((unsigned char *)&this->response, SmbLength(&this->response));
      
      std::map<std::string, std::string> header;

      header["Connection"] = "Keep-Alive";
      header["Authorization"] = "NTLM " + encodedpass;

      auto r1 = client->request("GET", this->path, "", header);

      stringstream ss;
      ss << r1->content.rdbuf();
      this->decoded = base64_decode(ss.str());

      // If IIS answer with 200 then your password was ok !
      if (r1->status_code != "200") {
        return 1;
      }

      return 0;
    }

  };
}

#endif