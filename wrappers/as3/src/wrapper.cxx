
#include <cstdlib>
#include <cstddef>

#include <string>

#include <AS3/AS3.h>
#include <AS3/AS3++.h>

#include <virgil/wrapper_utils.h>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include "VirgilRandom.wrapper.cxx"

#include "VirgilAccountId.wrapper.cxx"
#include "VirgilCertificateId.wrapper.cxx"
#include "VirgilTicketId.wrapper.cxx"
#include "VirgilSigntId.wrapper.cxx"

#include "VirgilAccount.wrapper.cxx"
#include "VirgilCertificate.wrapper.cxx"
#include "VirgilTicket.wrapper.cxx"
#include "VirgilUserIdType.wrapper.cxx"
#include "VirgilUserIdTicket.wrapper.cxx"
#include "VirgilUserInfoTicket.wrapper.cxx"
#include "VirgilSign.wrapper.cxx"

#include "VirgilKeyPair.wrapper.cxx"

#include "VirgilDataSource.wrapper.cxx"
#include "VirgilDataSink.wrapper.cxx"

#include "VirgilDataMarshaller.wrapper.cxx"
#include "VirgilJsonDataMarshaller.wrapper.cxx"
#include "VirgilAsn1DataMarshaller.wrapper.cxx"

#include "VirgilCipher.wrapper.cxx"
#include "VirgilSigner.wrapper.cxx"

int main() {
    AS3_GoAsync();
}
