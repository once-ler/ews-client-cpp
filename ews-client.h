#ifndef EWS_CLIENT_H
#define EWS_CLIENT_H

#include <iostream>
#include "plustache/template.hpp"
#include "plustache/plustache_types.hpp"
#include "plustache/context.hpp"
#include "soap-client.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
// download from http://www.nongnu.org/libntlm/releases/ homepage => http://www.nongnu.org/libntlm/
#include "ntlm.h"
#include "ews-client-global.h"

using namespace SimpleSoap;

namespace ews {
  namespace client {

    namespace XmlElement {
      class Root;
    }

    template<typename xmlelement>
    class base {
    public:
      base(){}
      ~base(){}
      std::string tpl;

      template<typename T>
      string compile(const shared_ptr<T> o){

        //read entire template file 
        std::ifstream file(tpl.c_str());
        std::string tplx((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        if (tplx.size() == 0){
          return "";
        }

        //compile tempplate with context to create a soap message
        Plustache::template_t t;
        std::string result = t.render(tplx, *o);

        return result;
      }
    };

    template<typename xmlelement>
    class generator_impl : public base<xmlelement>{};

    /*
      Root
    */
    template<>
    class generator_impl<XmlElement::Root> : public base<XmlElement::Root>{
    public:
      generator_impl(){ tpl = "tpl/root"; }

    };

  }
}

#endif