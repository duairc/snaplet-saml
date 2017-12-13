{-# LANGUAGE OverloadedStrings #-}

module Text.Blaze.SAML.Protocol
    ( namespace
    , authnRequest, id, assertionConsumerServiceURL, destination
    , issueInstant, SAML.notOnOrAfter
    , response, inResponseTo
    , status, statusCode, success
    , assertion, issuer
    , logoutRequest, nameID, SAML.spNameQualifier, sessionIndex
    , logoutResponse
    , MD.signature
    )
where

-- base ----------------------------------------------------------------------
import           Prelude hiding (id)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze (Markup, Attribute, AttributeValue, (!))
import           Text.Blaze.Internal (customAttribute, customParent)


-- snap-snaplet-saml ---------------------------------------------------------
import qualified Text.Blaze.SAML.Assertion as SAML
import           Text.Blaze.SAML.Assertion (issueInstant, inResponseTo)
import qualified Text.Blaze.SAML.Metadata as MD


------------------------------------------------------------------------------
namespace :: Attribute
namespace = customAttribute "xmlns:samlp"
    "urn:oasis:names:tc:SAML:2.0:protocol"


------------------------------------------------------------------------------
authnRequest :: Markup -> Markup
authnRequest = customParent "samlp:AuthnRequest"
    ! customAttribute "ProtocolBinding"
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    ! customAttribute "Version" "2.0"


------------------------------------------------------------------------------
id :: AttributeValue -> Attribute
id = customAttribute "ID"


------------------------------------------------------------------------------
assertionConsumerServiceURL :: AttributeValue -> Attribute
assertionConsumerServiceURL = customAttribute "AssertionConsumerServiceURL"


------------------------------------------------------------------------------
destination :: AttributeValue -> Attribute
destination = customAttribute "Destination"


------------------------------------------------------------------------------
response :: Markup -> Markup
response = customParent "samlp:Response" ! customAttribute "Version" "2.0"


------------------------------------------------------------------------------
status :: Markup -> Markup
status = customParent "samlp:Status"


------------------------------------------------------------------------------
statusCode :: Markup
statusCode = customParent "samlp:StatusCode" mempty


------------------------------------------------------------------------------
success :: Attribute
success = customAttribute "Value" "urn:oasis:names:tc:SAML:2.0:status:Success"


------------------------------------------------------------------------------
assertion :: Markup -> Markup
assertion = SAML.assertion ! SAML.namespace


------------------------------------------------------------------------------
issuer :: Markup -> Markup
issuer = SAML.issuer ! SAML.namespace


------------------------------------------------------------------------------
logoutRequest :: Markup -> Markup
logoutRequest = customParent "samlp:LogoutRequest"
    ! customAttribute "Version" "2.0"


------------------------------------------------------------------------------
nameID :: Markup -> Markup
nameID = SAML.nameID ! SAML.namespace


------------------------------------------------------------------------------
sessionIndex :: Markup -> Markup
sessionIndex = customParent "samlp:SessionIndex"


------------------------------------------------------------------------------
logoutResponse :: Markup -> Markup
logoutResponse = customParent "samlp:LogoutResponse"
    ! customAttribute "Version" "2.0"
