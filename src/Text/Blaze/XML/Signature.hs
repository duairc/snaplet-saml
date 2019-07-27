{-# LANGUAGE OverloadedStrings #-}

module Text.Blaze.XML.Signature
    ( namespace
    , signature, signedInfo, signatureValue
    , canonicalizationMethod, signatureMethod, algorithm
    , reference, uri, transforms, transform, digestMethod, digestValue
    , keyInfo, x509Data, x509Certificate
    )
where

-- base ----------------------------------------------------------------------
import           Prelude hiding (id)


-- base64-bytestring ---------------------------------------------------------
import qualified Data.ByteString.Base64 as B64


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze
                     ( Markup, Attribute, AttributeValue, (!), text
                     )
import           Text.Blaze.Internal (customAttribute, customParent)


-- text ----------------------------------------------------------------------
import           Data.Text.Encoding (decodeUtf8)


-- x509 ----------------------------------------------------------------------
import           Data.X509
                     ( SignatureALG (..), HashALG (..), PubKeyALG (..)
                     , SignedCertificate, encodeSignedObject
                     )


------------------------------------------------------------------------------
namespace :: Attribute
namespace = customAttribute "xmlns:ds" "http://www.w3.org/2000/09/xmldsig#"


------------------------------------------------------------------------------
signature :: Markup -> Markup
signature = customParent "ds:Signature" ! namespace


------------------------------------------------------------------------------
signedInfo :: Markup -> Markup
signedInfo = customParent "ds:SignedInfo"


------------------------------------------------------------------------------
canonicalizationMethod :: Markup
canonicalizationMethod = customParent "ds:CanonicalizationMethod" mempty


------------------------------------------------------------------------------
algorithm :: AttributeValue -> Attribute
algorithm = customAttribute "Algorithm"


------------------------------------------------------------------------------
signatureMethod :: SignatureALG -> Markup
signatureMethod = (customParent "ds:SignatureMethod" mempty !) . algorithm
    . go
  where
    go (SignatureALG HashSHA1 PubKeyALG_DSA) =
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
    go (SignatureALG HashSHA256 PubKeyALG_DSA) =
        "http://www.w3.org/2009/xmldsig11#dsa-sha256"
    go (SignatureALG HashMD5 PubKeyALG_RSA) =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"
    go (SignatureALG HashSHA1 PubKeyALG_RSA) =
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    go (SignatureALG HashSHA224 PubKeyALG_RSA) =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
    go (SignatureALG HashSHA256 PubKeyALG_RSA) =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    go (SignatureALG HashSHA384 PubKeyALG_RSA) =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    go (SignatureALG HashSHA512 PubKeyALG_RSA) =
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    go (SignatureALG HashSHA1 PubKeyALG_EC) =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
    go (SignatureALG HashSHA224 PubKeyALG_EC) =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
    go (SignatureALG HashSHA256 PubKeyALG_EC) =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
    go (SignatureALG HashSHA384 PubKeyALG_EC) =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    go (SignatureALG HashSHA512 PubKeyALG_EC) =
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
    go x = error $ "Unsupported signature algorithm: " ++ show x


------------------------------------------------------------------------------
reference :: Markup -> Markup
reference = customParent "ds:Reference"


------------------------------------------------------------------------------
uri :: AttributeValue -> Attribute
uri = customAttribute "URI"


------------------------------------------------------------------------------
transforms :: Markup -> Markup
transforms = customParent "ds:Transforms"


------------------------------------------------------------------------------
transform :: Markup
transform = customParent "ds:Transform" mempty


------------------------------------------------------------------------------
digestMethod :: HashALG -> Markup
digestMethod = (customParent "ds:DigestMethod" mempty !) . algorithm . go
  where
    go HashMD5 = "http://www.w3.org/2001/04/xmldsig-more#md5"
    go HashSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
    go HashSHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224"
    go HashSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    go HashSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    go HashSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
    go x = error $ "Unsupported signature algorithm: " ++ show x


------------------------------------------------------------------------------
digestValue :: Markup -> Markup
digestValue = customParent "ds:DigestValue"


------------------------------------------------------------------------------
signatureValue :: Markup -> Markup
signatureValue = customParent "ds:SignatureValue"


------------------------------------------------------------------------------
keyInfo :: Markup -> Markup
keyInfo = customParent "ds:KeyInfo"


------------------------------------------------------------------------------
x509Data :: Markup -> Markup
x509Data = customParent "ds:X509Data"


------------------------------------------------------------------------------
x509Certificate :: SignedCertificate -> Markup
x509Certificate = customParent "ds:X509Certificate" . text . decodeUtf8
    . B64.encode . encodeSignedObject
