#include <iostream>
#include "ews-client.h"

int main(int argc, char *argv[]) {
  ews::NtlmHelper ntlmHelper;
  int rc = ntlmHelper.login();
  return 0;
}