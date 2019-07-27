{-# LANGUAGE OverloadedStrings #-}

module Text.Blaze.SAML.Metadata
    ( namespace
    , entityDescriptor, entityID, id
    , idpSSODescriptor
    , spSSODescriptor, authnRequestsSigned, wantAssertionsSigned
    , singleSignOnService, singleLogoutService, location
    , assertionConsumerService, index
    , nameIDFormat
    , keyDescriptor, use
    , signature, keyInfo
    )
where

-- base ----------------------------------------------------------------------
import           Data.Foldable (for_)
import           Data.Monoid ((<>))
import           Prelude hiding (id)
import qualified Prelude as P (id)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze
                     ( Markup, Attribute, AttributeValue, (!), textValue
                     )
import           Text.Blaze.Internal (customAttribute, customParent)


-- snap-snaplet-saml ---------------------------------------------------------
import qualified Text.Blaze.XML.Signature as DS


-- text ----------------------------------------------------------------------
import qualified Data.Text as T


-- x509 ----------------------------------------------------------------------
import           Data.X509 (SignatureALG, HashALG, SignedCertificate)


------------------------------------------------------------------------------
namespace :: Attribute
namespace = customAttribute "xmlns:md" "urn:oasis:names:tc:SAML:2.0:metadata"


------------------------------------------------------------------------------
entityDescriptor :: Markup -> Markup
entityDescriptor = customParent "md:EntityDescriptor" ! namespace


------------------------------------------------------------------------------
entityID :: AttributeValue -> Attribute
entityID = customAttribute "entityID"


------------------------------------------------------------------------------
id :: AttributeValue -> Attribute
id = customAttribute "ID"


------------------------------------------------------------------------------
spSSODescriptor :: Markup -> Markup
spSSODescriptor = customParent "md:SPSSODescriptor"
    ! customAttribute "protocolSupportEnumeration"
        "urn:oasis:names:tc:SAML:2.0:protocol"


------------------------------------------------------------------------------
idpSSODescriptor :: Markup -> Markup
idpSSODescriptor = customParent "md:IDPSSODescriptor"
    ! customAttribute "protocolSupportEnumeration"
        "urn:oasis:names:tc:SAML:2.0:protocol"


------------------------------------------------------------------------------
authnRequestsSigned :: Bool -> Attribute
authnRequestsSigned = customAttribute "AuthnRequestsSigned" . value
  where
    value True = "true"
    value False = "false"


------------------------------------------------------------------------------
wantAssertionsSigned :: Bool -> Attribute
wantAssertionsSigned = customAttribute "WantAssertionsSigned" . value
  where
    value True = "true"
    value False = "false"


------------------------------------------------------------------------------
singleSignOnService :: Markup
singleSignOnService = customParent "md:SingleSignOnService" mempty
    ! customAttribute "Binding"
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


------------------------------------------------------------------------------
singleLogoutService :: Markup
singleLogoutService = customParent "md:SingleLogoutService" mempty
    ! customAttribute "Binding"
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


------------------------------------------------------------------------------
location :: AttributeValue -> Attribute
location = customAttribute "Location"


------------------------------------------------------------------------------
assertionConsumerService :: Markup
assertionConsumerService = customParent "md:AssertionConsumerService" mempty
    ! customAttribute "Binding"
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


------------------------------------------------------------------------------
index :: Word -> Attribute
index = customAttribute "index" . textValue . T.pack . show


------------------------------------------------------------------------------
nameIDFormat :: Markup
nameIDFormat = customParent "md:NameIDFormat" $
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"


------------------------------------------------------------------------------
keyDescriptor :: Markup -> Markup
keyDescriptor = customParent "md:KeyDescriptor" ! DS.namespace


------------------------------------------------------------------------------
use :: AttributeValue -> Attribute
use = customAttribute "use"


------------------------------------------------------------------------------
signature :: SignatureALG -> HashALG -> Maybe SignedCertificate
    -> Maybe AttributeValue -> Markup
signature sig digest certificate id_ = DS.signature $ do
    DS.signedInfo $ do
        DS.canonicalizationMethod ! DS.algorithm eC14n
        DS.signatureMethod sig
        maybe P.id (flip (!) . DS.uri . ("#" <>)) id_ $ DS.reference $ do
            DS.transforms $ do
                DS.transform ! DS.algorithm enveloped
                DS.transform ! DS.algorithm eC14n
            DS.digestMethod digest
            DS.digestValue mempty
    DS.signatureValue mempty
    for_ certificate $ DS.keyInfo . DS.x509Data . DS.x509Certificate
  where
    eC14n = "http://www.w3.org/2001/10/xml-exc-c14n#"
    enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"


------------------------------------------------------------------------------
keyInfo :: SignedCertificate -> Markup
keyInfo = DS.keyInfo . DS.x509Data . DS.x509Certificate
