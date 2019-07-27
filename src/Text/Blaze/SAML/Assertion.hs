{-# LANGUAGE OverloadedStrings #-}

module Text.Blaze.SAML.Assertion
    ( namespace
    , issuer
    , assertion, id, issueInstant
    , subject, nameID, spNameQualifier, subjectConfirmation
    , subjectConfirmationData, inResponseTo, recipient
    , conditions, notBefore, notOnOrAfter, audienceRestriction, audience
    , signature
    , authnStatement, authnInstant, sessionIndex, sessionNotOnOrAfter
    , authnContext, authnContextClassRef
    , attributeStatement, attribute, attributeValue
    )
where

-- base ----------------------------------------------------------------------
import           Prelude hiding (id)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze
                     ( Markup, Attribute, AttributeValue, (!), text, textValue
                     )
import           Text.Blaze.Internal (customAttribute, customParent)


-- snap-snaplet-saml ---------------------------------------------------------
import           Text.Blaze.SAML.Metadata (signature)


-- text ----------------------------------------------------------------------
import           Data.Text (Text)
import qualified Data.Text as T


-- time ----------------------------------------------------------------------
import           Data.Time.Clock (UTCTime)
import           Data.Time.Format (formatTime, defaultTimeLocale)


------------------------------------------------------------------------------
namespace :: Attribute
namespace = customAttribute "xmlns:saml"
    "urn:oasis:names:tc:SAML:2.0:assertion"


------------------------------------------------------------------------------
issuer :: Markup -> Markup
issuer = customParent "saml:Issuer"


------------------------------------------------------------------------------
assertion :: Markup -> Markup
assertion = customParent "saml:Assertion" ! namespace
    ! customAttribute "xmlns:xs" "http://www.w3.org/2001/XMLSchema"
    ! customAttribute "xmlns:xsi" "http://www.w3.org/2001/XMLSchema-instance"
    ! customAttribute "Version" "2.0"


------------------------------------------------------------------------------
id :: AttributeValue -> Attribute
id = customAttribute "ID"


------------------------------------------------------------------------------
issueInstant :: UTCTime -> Attribute
issueInstant = customAttribute "IssueInstant" . timeValue


------------------------------------------------------------------------------
subject :: Markup -> Markup
subject = customParent "saml:Subject"


------------------------------------------------------------------------------
nameID :: Markup -> Markup
nameID = customParent "saml:NameID" ! customAttribute "Format"
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"


------------------------------------------------------------------------------
spNameQualifier :: AttributeValue -> Attribute
spNameQualifier = customAttribute "SPNameQualifier"


------------------------------------------------------------------------------
subjectConfirmation :: Markup -> Markup
subjectConfirmation = customParent "saml:SubjectConfirmation"
    ! customAttribute "Method" "urn:oasis:names:tc:SAML:2.0:cm:bearer"


------------------------------------------------------------------------------
subjectConfirmationData :: Markup
subjectConfirmationData = customParent "saml:SubjectConfirmationData" mempty


------------------------------------------------------------------------------
inResponseTo :: AttributeValue -> Attribute
inResponseTo = customAttribute "InResponseTo"


------------------------------------------------------------------------------
recipient :: AttributeValue -> Attribute
recipient = customAttribute "Recipient"


------------------------------------------------------------------------------
conditions :: Markup -> Markup
conditions = customParent "saml:Conditions"


------------------------------------------------------------------------------
notBefore :: UTCTime -> Attribute
notBefore = customAttribute "NotBefore" . timeValue


------------------------------------------------------------------------------
notOnOrAfter :: UTCTime -> Attribute
notOnOrAfter = customAttribute "NotOnOrAfter" . timeValue


------------------------------------------------------------------------------
audienceRestriction :: Markup -> Markup
audienceRestriction = customParent "saml:AudienceRestriction"


------------------------------------------------------------------------------
audience :: Markup -> Markup
audience = customParent "saml:Audience"


------------------------------------------------------------------------------
authnStatement :: Markup -> Markup
authnStatement = customParent "saml:AuthnStatement"


------------------------------------------------------------------------------
authnInstant :: UTCTime -> Attribute
authnInstant = customAttribute "AuthnInstant" . timeValue


------------------------------------------------------------------------------
sessionNotOnOrAfter :: UTCTime -> Attribute
sessionNotOnOrAfter = customAttribute "SessionNotOnOrAfter" . timeValue


------------------------------------------------------------------------------
sessionIndex :: AttributeValue -> Attribute
sessionIndex = customAttribute "SessionIndex"


------------------------------------------------------------------------------
authnContext :: Markup -> Markup
authnContext = customParent "saml:AuthnContext"


------------------------------------------------------------------------------
authnContextClassRef :: Markup
authnContextClassRef = customParent "saml:AuthnContextClassRef"
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"


------------------------------------------------------------------------------
attributeStatement :: Markup -> Markup
attributeStatement = customParent "saml:AttributeStatement"


------------------------------------------------------------------------------
attribute :: Text -> Markup -> Markup
attribute name = customParent "saml:Attribute"
    ! customAttribute "Name" (textValue name)
    ! customAttribute "NameFormat"
        "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"


------------------------------------------------------------------------------
attributeValue :: Text -> Markup
attributeValue value = customParent "saml:AttributeValue"
    ! customAttribute "xsi:type" "xs:string"
    $ text value


------------------------------------------------------------------------------
timeValue :: UTCTime -> AttributeValue
timeValue = textValue . T.pack . formatTime defaultTimeLocale "%FT%TZ"
