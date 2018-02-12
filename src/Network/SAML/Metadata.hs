{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -fno-warn-unused-top-binds #-}

module Network.SAML.Metadata
    ( IDP (IDP), buildIDP, buildSignIDP, parseIDP, parseVerifyIDP
    , SP (SP), buildSP, buildSignSP, parseSP, parseVerifySP
    , SAMLMetadataException (..)
    )
where

-- base ----------------------------------------------------------------------
import           Control.Exception (Exception, throw, throwIO)
import           Control.Monad ((>=>))
import           Data.Bifunctor (first)
import           Data.Function ((&))
import           Data.Semigroup ((<>))
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze (Markup, (!), textValue)


-- base64-bytestring ---------------------------------------------------------
import qualified Data.ByteString.Base64 as B64


-- hashable ------------------------------------------------------------------
import           Data.Hashable (hash)


-- layers --------------------------------------------------------------------
import           Monad.Catch (try)


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, ParseException, mkURI, render)


-- snap-snaplet-saml ---------------------------------------------------------
import qualified Text.Blaze.SAML.Metadata as MD
import qualified Text.XML.Signature as X


-- text ----------------------------------------------------------------------
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding (encodeUtf8)


-- x509 ----------------------------------------------------------------------
import           Data.X509
                     ( HashALG (HashSHA256)
                     , SignatureALG (SignatureALG)
                     , PrivKey, SignedCertificate
                     , privkeyToAlg
                     , decodeSignedObject
                     )


-- xml-conduit ---------------------------------------------------------------
import           Text.XML (Document)
import           Text.XML.Cursor
                     ( fromDocument
                     , ($/), (&/), element, attribute, content, attributeIs
                     )


------------------------------------------------------------------------------
data SAMLMetadataException
    = NoMetadataURL
    | NoLoginURL
    | NoLogoutURL
    | NoSignCertificate
    | NoEncryptCertiifcate
    | UnparsableURL !ParseException
    | UnparsableCertificate !String
    | SignatureVerificationFailed
  deriving
    (Eq, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
data IDP = IDP
    { url :: !URI
    , login :: !URI
    , logout :: !URI
    , signing:: !SignedCertificate
    , encryption :: !SignedCertificate
    }
  deriving (Eq, Show, Generic, Typeable)


------------------------------------------------------------------------------
buildIDP :: IDP -> Markup
buildIDP = buildIDPCommon Nothing


------------------------------------------------------------------------------
buildSignIDP :: PrivKey -> IDP -> IO Markup
buildSignIDP key sp = X.signMarkup key $ buildIDPCommon (Just key) sp


------------------------------------------------------------------------------
buildIDPCommon :: Maybe PrivKey -> IDP -> Markup
buildIDPCommon mkey idp@(IDP metadata in_ out sign encrypt) = do
    MD.entityDescriptor ! MD.namespace ! MD.entityID metadataURL ! id_ $ do
        case mkey of
            Just key -> MD.signature sigAlg hashAlg (Just sign) Nothing
              where
                sigAlg = SignatureALG hashAlg (privkeyToAlg key)
                hashAlg = HashSHA256
            Nothing -> pure ()
        MD.idpSSODescriptor ! MD.authnRequestsSigned True $ do
            MD.nameIDFormat
            MD.singleSignOnService ! MD.location inURL
            MD.singleLogoutService ! MD.location outURL
            MD.keyDescriptor ! MD.use "signing" $ MD.keyInfo sign
            MD.keyDescriptor ! MD.use "encryption" $ MD.keyInfo encrypt
  where
    id_ = MD.id $ textValue $ "_" <> T.pack (show (hash (show idp)))
    metadataURL = textValue $ render metadata
    inURL = textValue $ render in_
    outURL = textValue $ render out


------------------------------------------------------------------------------
parseIDP :: Document -> Either SAMLMetadataException IDP
parseIDP document = do
    metadataURL <- (parseURL =<<) . single NoMetadataURL $ xml &
        attribute "entityID"
    loginURL <- (parseURL =<<) . single NoLoginURL $ xml
        $/ element idpSSODescriptor
        &/ element singleSignOnService
        >=> attribute "Location"
    logoutURL <- (parseURL =<<) . single NoLoginURL $ xml
        $/ element idpSSODescriptor
        &/ element singleLogoutService
        >=> attribute "Location"
    signCert <- (parseCertificate =<<) . single NoSignCertificate $ xml
        $/ element idpSSODescriptor
        &/ element keyDescriptor
        >=> attributeIs "use" "signing"
        &/ element keyInfo
        &/ element x509Data
        &/ element x509Certificate
        &/ content
    encryptCert <- (parseCertificate =<<) . single NoEncryptCertiifcate $ xml
        $/ element idpSSODescriptor
        &/ element keyDescriptor
        >=> attributeIs "use" "encryption"
        &/ element keyInfo
        &/ element x509Data
        &/ element x509Certificate
        &/ content
    pure $ IDP metadataURL loginURL logoutURL signCert encryptCert
  where
    xml = fromDocument document
    idpSSODescriptor =
        "{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor"
    singleSignOnService =
        "{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"
    singleLogoutService =
        "{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService"
    keyDescriptor = "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor"
    keyInfo = "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    x509Data = "{http://www.w3.org/2000/09/xmldsig#}X509Data"
    x509Certificate = "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
parseVerifyIDP :: Bool -> [SignedCertificate] -> Document -> IO IDP
parseVerifyIDP self certificates xml = do
    sp <- either throwIO pure $ parseIDP xml
    verifies <- X.verifyDocument self certificates xml
    if verifies
        then pure sp
        else throwIO SignatureVerificationFailed


------------------------------------------------------------------------------
data SP = SP
    { url :: !URI
    , login :: !URI
    , logout :: !URI
    , signing :: !SignedCertificate
    , encryption :: !SignedCertificate
    }
  deriving (Eq, Show, Generic, Typeable)


------------------------------------------------------------------------------
buildSP :: SP -> Markup
buildSP = buildSPCommon Nothing


------------------------------------------------------------------------------
buildSignSP :: PrivKey -> SP -> IO Markup
buildSignSP key sp = X.signMarkup key $ buildSPCommon (Just key) sp


------------------------------------------------------------------------------
buildSPCommon :: Maybe PrivKey -> SP -> Markup
buildSPCommon mkey sp@(SP metadata in_ out sign encrypt) = do
    MD.entityDescriptor ! MD.namespace ! MD.entityID metadataURL ! id_ $ do
        case mkey of
            Just key -> MD.signature sigAlg hashAlg (Just sign) Nothing
              where
                sigAlg = SignatureALG hashAlg (privkeyToAlg key)
                hashAlg = HashSHA256
            Nothing -> pure ()
        MD.spSSODescriptor ! MD.authnRequestsSigned True $ do
            MD.assertionConsumerService ! MD.location inURL ! MD.index 0
            MD.singleLogoutService ! MD.location outURL
            MD.keyDescriptor ! MD.use "signing" $ MD.keyInfo sign
            MD.keyDescriptor ! MD.use "encryption" $ MD.keyInfo encrypt
  where
    id_ = MD.id $ textValue $ "_" <> T.pack (show (hash (show sp)))
    metadataURL = textValue $ render metadata
    inURL = textValue $ render in_
    outURL = textValue $ render out


------------------------------------------------------------------------------
parseSP :: Document -> Either SAMLMetadataException SP
parseSP document = do
    metadataURL <- (parseURL =<<) . single NoMetadataURL $ xml &
        attribute "entityID"
    loginURL <- (parseURL =<<) . single NoLoginURL $ xml
        $/ element spSSODescriptor
        &/ element assertionConsumerService
        >=> attribute "Location"
    logoutURL <- (parseURL =<<) . single NoLoginURL $ xml
        $/ element spSSODescriptor
        &/ element singleLogoutService
        >=> attribute "Location"
    signCert <- (parseCertificate =<<) . single NoSignCertificate $ xml
        $/ element spSSODescriptor
        &/ element keyDescriptor
        >=> attributeIs "use" "signing"
        &/ element keyInfo
        &/ element x509Data
        &/ element x509Certificate
        &/ content
    encryptCert <- (parseCertificate =<<) . single NoEncryptCertiifcate $ xml
        $/ element spSSODescriptor
        &/ element keyDescriptor
        >=> attributeIs "use" "encryption"
        &/ element keyInfo
        &/ element x509Data
        &/ element x509Certificate
        &/ content
    pure $ SP metadataURL loginURL logoutURL signCert encryptCert
  where
    xml = fromDocument document
    spSSODescriptor =
        "{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor"
    assertionConsumerService =
        "{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService"
    singleLogoutService =
        "{urn:oasis:names:tc:SAML:2.0:metadata}SingleLogoutService"
    keyDescriptor = "{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor"
    keyInfo = "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    x509Data = "{http://www.w3.org/2000/09/xmldsig#}X509Data"
    x509Certificate = "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
parseVerifySP :: Bool -> [SignedCertificate] -> Document -> IO SP
parseVerifySP self certificates xml = do
    sp <- either throwIO pure $ parseSP xml
    verifies <- X.verifyDocument self certificates xml
    if verifies
        then pure sp
        else throwIO SignatureVerificationFailed


------------------------------------------------------------------------------
parseURL :: Text -> Either SAMLMetadataException URI
parseURL = either throw id . fmap (first UnparsableURL) . try . mkURI


------------------------------------------------------------------------------
parseCertificate :: Text -> Either SAMLMetadataException SignedCertificate
parseCertificate text = first UnparsableCertificate $ do
    B64.decode (encodeUtf8 text) >>= decodeSignedObject
