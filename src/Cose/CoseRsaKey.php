<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

class CoseRsaKey extends CoseKey
{
}


//RSAPublicKey ::= SEQUENCE {
//	modulus INTEGER, -- n
//	publicExponent INTEGER -- e
//}

// https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1
// https://datatracker.ietf.org/doc/html/rfc8017#appendix-C

// pkcs-1    OBJECT IDENTIFIER ::= {
//     iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1
// }

// sha256WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 11 }

//SubjectPublicKeyInfo  ::=  SEQUENCE  {
//        algorithm            AlgorithmIdentifier,
//        subjectPublicKey     BIT STRING  }

//AlgorithmIdentifier  ::=  SEQUENCE  {
//    algorithm               OBJECT IDENTIFIER,
//    parameters              ANY DEFINED BY algorithm OPTIONAL  }

// The DER encoded RSAPublicKey is the value of the BIT
//   STRING subjectPublicKey.

//
//   The OID rsaEncryption identifies RSA public keys.
//
//      pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
//                     rsadsi(113549) pkcs(1) 1 }
//
//      rsaEncryption OBJECT IDENTIFIER ::=  { pkcs-1 1}
//
//   The rsaEncryption OID is intended to be used in the algorithm field
//   of a value of type AlgorithmIdentifier.  The parameters field MUST
//   have ASN.1 type NULL for this algorithm identifier.
