{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -fno-warn-unused-top-binds #-}

module Network.SAML.Protocol
    ( Request (Request)
    , newRequest, buildSignNewRequest, buildRequest, buildSignRequest
    , parseRequest, parseVerifyRequest
    , Response (Response)
    , newResponse, buildSignNewResponse, buildResponse, buildSignResponse
    , parseResponse, parseVerifyResponse
    , LogoutRequest (LogoutRequest)
    , idpLogoutRequest, buildSignIDPLogoutRequest
    , spLogoutRequest, buildSignSPLogoutRequest
    , buildLogoutRequest, buildSignLogoutRequest
    , parseLogoutRequest, parseVerifyLogoutRequest
    , LogoutResponse (LogoutResponse)
    , newLogoutResponse, buildSignNewLogoutResponse
    , buildLogoutResponse, buildSignLogoutResponse
    , parseLogoutResponse, parseVerifyLogoutResponse
    , SAMLProtocolException (..)
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
import           Text.Blaze (Markup, (!), text, textValue)


-- hashable ------------------------------------------------------------------
import           Data.Hashable (hash)


-- layers --------------------------------------------------------------------
import           Monad.Catch (try)


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, ParseException, mkURI, render)


-- snap-snaplet-saml ---------------------------------------------------------
import           Network.SAML.Assertion
                     ( Assertion (Assertion), Attributes, Session
                     , newAssertion, parseAssertion
                     , newName
                     )
import qualified Network.SAML.Assertion as A
import           Network.SAML.Metadata (IDP (IDP), SP (SP))
import qualified Text.Blaze.SAML.Assertion as SAML
import qualified Text.Blaze.SAML.Protocol as SAMLP
import qualified Text.XML.Signature as X


-- text ----------------------------------------------------------------------
import           Data.Text (Text)
import qualified Data.Text as T


-- time ----------------------------------------------------------------------
import           Data.Time.Clock
                     ( UTCTime, NominalDiffTime, getCurrentTime, addUTCTime
                     )
import           Data.Time.Format (parseTimeM, defaultTimeLocale)


-- x509 ----------------------------------------------------------------------
import           Data.X509
                     ( HashALG (HashSHA256)
                     , SignatureALG (SignatureALG)
                     , PrivKey, SignedCertificate
                     , privkeyToAlg
                     )


-- xml-conduit ---------------------------------------------------------------
import           Text.XML (Document)
import qualified Text.XML as X
import           Text.XML.Cursor
                     ( Cursor, fromDocument
                     , ($/), (&/), element, attribute, content, node
                     )


------------------------------------------------------------------------------
data SAMLProtocolException
    = NoIDPURL
    | NoSPURL
    | NoLoginURL
    | NoAssertion
    | NoInstant
    | UnparsableURL !ParseException
    | UnparsableTime !Text
    | UnparsableAssertion !A.SAMLAssertionException
    | SignatureVerificationFailed
  deriving
    (Eq, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
data Request = Request
    { idp :: !URI
    , sp :: !URI
    , login :: !URI
    , time :: !UTCTime
    }
  deriving (Eq, Show, Generic, Typeable)


------------------------------------------------------------------------------
newRequest :: IDP -> SP -> IO Request
newRequest (IDP idpURL _ _ _ _) (SP spURL loginURL _ _ _) = do
    now <- getCurrentTime
    pure $ Request idpURL spURL loginURL now


------------------------------------------------------------------------------
buildSignNewRequest :: IDP -> SP -> PrivKey -> IO (Request, Markup)
buildSignNewRequest idp_ sp_@(SP _ _ _ certificate _) key = do
    rq <- newRequest idp_ sp_
    markup <- X.signMarkup key $
        buildRequestCommon (Just key) (Just certificate) rq
    pure (rq, markup)


------------------------------------------------------------------------------
buildRequest :: Request -> Markup
buildRequest = buildRequestCommon Nothing Nothing


------------------------------------------------------------------------------
buildSignRequest :: PrivKey -> Request -> IO Markup
buildSignRequest key = X.signMarkup key
    . buildRequestCommon (Just key) Nothing


------------------------------------------------------------------------------
buildRequestCommon :: Maybe PrivKey -> Maybe SignedCertificate -> Request
    -> Markup
buildRequestCommon mkey certificate rq = SAMLP.authnRequest
    ! SAMLP.namespace
    ! SAMLP.destination idpMetadataURL
    ! SAMLP.assertionConsumerServiceURL spLoginURL
    ! SAMLP.issueInstant instant_
    ! SAMLP.id id_
    $ do
        case mkey of
            Just key -> SAMLP.signature sigAlg hashAlg certificate Nothing
              where
                sigAlg = SignatureALG hashAlg (privkeyToAlg key)
                hashAlg = HashSHA256
            Nothing -> pure ()
        SAMLP.issuer spMetadataURL
  where
    Request idpMetadata spMetadata spLogin instant_ = rq
    id_ = textValue $ "_" <> T.pack (show (hash (show rq)))
    idpMetadataURL = textValue $ render idpMetadata
    spLoginURL = textValue $ render spLogin
    spMetadataURL = text $ render spMetadata


------------------------------------------------------------------------------
parseRequest :: Document -> Either SAMLProtocolException Request
parseRequest document = do
    idpMetadata <- (parseURL =<<) . single NoIDPURL $ xml &
        attribute "Destination"
    spLogin <- (parseURL =<<) . single NoLoginURL $ xml &
        attribute "AssertionConsumerServiceURL"
    instant_ <- (parseTime =<<) . single NoInstant $ xml &
        attribute "IssueInstant"
    spMetadata <- (parseURL =<<) . single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    pure $ Request idpMetadata spMetadata spLogin instant_
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
parseVerifyRequest :: [SignedCertificate] -> Document -> IO Request
parseVerifyRequest certificates xml = do
    rq <- either throwIO pure $ parseRequest xml
    verifies <- X.verifyDocument certificates xml
    if verifies
        then pure rq
        else throwIO SignatureVerificationFailed


------------------------------------------------------------------------------
newtype Response = Response Assertion
  deriving (Eq, Ord, Show, Generic, Typeable)


------------------------------------------------------------------------------
newResponse :: IDP -> SP -> NominalDiffTime -> Attributes -> Text -> Session
    -> IO Response
newResponse i s d a n h = Response <$> newAssertion i s d a n h


------------------------------------------------------------------------------
buildSignNewResponse :: IDP -> SP -> NominalDiffTime -> Attributes -> Text
    -> Session -> PrivKey -> IO (Response, Markup)
buildSignNewResponse i s d a n h key = do
    (assertion, assertionMarkup) <- A.buildSignNewAssertion i s d a n h key
    let response = Response assertion
    markup <- X.signMarkup key $ buildResponseCommon (Just key)
         (Just certificate) (const assertionMarkup) response
    pure (response, markup)
  where
    IDP _ _ _ certificate _ = i


------------------------------------------------------------------------------
buildResponse :: Response -> Markup
buildResponse = buildResponseCommon Nothing Nothing A.buildAssertion


------------------------------------------------------------------------------
buildSignResponse :: PrivKey -> Response -> IO Markup
buildSignResponse key = X.signMarkup key
    . buildResponseCommon (Just key) Nothing A.buildAssertion


------------------------------------------------------------------------------
buildResponseCommon :: Maybe PrivKey -> Maybe SignedCertificate
    -> (Assertion -> Markup) -> Response -> Markup
buildResponseCommon mkey certificate buildAssertion response = SAMLP.response
    ! SAMLP.namespace
    ! SAMLP.destination (textValue $ render loginURL)
    ! SAMLP.inResponseTo (textValue rqID)
    ! SAMLP.issueInstant start
    ! SAMLP.id id_
    $ do
        case mkey of
            Just key -> SAMLP.signature sigAlg hashAlg certificate Nothing
              where
                sigAlg = SignatureALG hashAlg (privkeyToAlg key)
                hashAlg = HashSHA256
            Nothing -> pure ()
        SAMLP.issuer $ text $ render idpURL
        SAMLP.status $ SAMLP.statusCode ! SAMLP.success
        buildAssertion assertion
  where
    Response assertion = response
    id_ = textValue $ "_" <> T.pack (show (hash (show response)))
    Assertion idpURL _ loginURL start _ _ _ rqID _ = assertion


------------------------------------------------------------------------------
parseResponse :: Document -> Either SAMLProtocolException Response
parseResponse document = fmap Response $
    (first UnparsableAssertion . parseAssertion . toDocument =<<)
        . single NoAssertion $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
parseVerifyResponse :: [SignedCertificate] -> Document -> IO Response
parseVerifyResponse certificates document = do
    assertionXML <- either throwIO (pure . toDocument) $ single NoAssertion $
        xml $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
    assertion <- either (throwIO . UnparsableAssertion) pure $
        parseAssertion assertionXML
    assertionVerifies <- X.verifyDocument certificates assertionXML
    if assertionVerifies
       then pure $ Response assertion
       else do
            verifies <- X.verifyDocument certificates document
            if verifies
                then pure $ Response assertion
                else throwIO SignatureVerificationFailed
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
data LogoutRequest = LogoutRequest
    { sender :: !URI
    , sp :: !URI
    , logout :: !URI
    , beginning :: !UTCTime
    , ending :: !UTCTime
    , name :: !Text
    , session :: !Text
    }
  deriving (Eq, Ord, Show, Generic, Typeable)


------------------------------------------------------------------------------
idpLogoutRequest :: IDP -> SP -> NominalDiffTime -> IO LogoutRequest
idpLogoutRequest idp_ sp_ diff = do
    start <- getCurrentTime
    let finish = diff `addUTCTime` start
    nameID <- newName
    sessionID <- newName
    pure $ LogoutRequest sendURL spURL logoutURL start finish nameID sessionID
  where
    IDP sendURL _ _ _ _ = idp_
    SP spURL _ logoutURL _ _ = sp_


------------------------------------------------------------------------------
spLogoutRequest :: IDP -> SP -> NominalDiffTime -> IO LogoutRequest
spLogoutRequest idp_ sp_ diff = do
    start <- getCurrentTime
    let finish = diff `addUTCTime` start
    nameID <- newName
    sessionID <- newName
    pure $ LogoutRequest spURL spURL logoutURL start finish nameID sessionID
  where
    IDP _ _ logoutURL _ _ = idp_
    SP spURL _ _ _ _ = sp_


------------------------------------------------------------------------------
buildSignIDPLogoutRequest :: IDP -> SP -> NominalDiffTime -> PrivKey
    -> IO (LogoutRequest, Markup)
buildSignIDPLogoutRequest idp_ sp_ diff key = do
    logoutRequest <- idpLogoutRequest idp_ sp_ diff
    markup <- X.signMarkup key $ buildLogoutRequestCommon (Just key)
        (Just certificate) logoutRequest
    pure (logoutRequest, markup)
  where
    IDP _ _ _ certificate _ = idp_


------------------------------------------------------------------------------
buildSignSPLogoutRequest :: IDP -> SP -> NominalDiffTime -> PrivKey
    -> IO (LogoutRequest, Markup)
buildSignSPLogoutRequest idp_ sp_ diff key = do
    logoutRequest <- spLogoutRequest idp_ sp_ diff
    markup <- X.signMarkup key $ buildLogoutRequestCommon (Just key)
        (Just certificate) logoutRequest
    pure (logoutRequest, markup)
  where
    SP _ _ _ certificate _ = sp_


------------------------------------------------------------------------------
buildLogoutRequest :: LogoutRequest -> Markup
buildLogoutRequest = buildLogoutRequestCommon Nothing Nothing


------------------------------------------------------------------------------
buildSignLogoutRequest :: PrivKey -> LogoutRequest -> IO Markup
buildSignLogoutRequest key = X.signMarkup key
    . buildLogoutRequestCommon (Just key) Nothing


------------------------------------------------------------------------------
buildLogoutRequestCommon :: Maybe PrivKey -> Maybe SignedCertificate
    -> LogoutRequest -> Markup
buildLogoutRequestCommon mkey certificate logoutRequest = SAMLP.logoutRequest
    ! SAMLP.namespace
    ! SAMLP.destination (textValue $ render logoutURL)
    ! SAMLP.issueInstant start
    ! SAMLP.notOnOrAfter finish
    ! SAMLP.id id_
    $ do
        case mkey of
            Just key -> SAMLP.signature sigAlg hashAlg certificate Nothing
              where
                sigAlg = SignatureALG hashAlg (privkeyToAlg key)
                hashAlg = HashSHA256
            Nothing -> pure ()
        SAMLP.issuer $ text $ render sendURL
        SAMLP.nameID ! SAML.spNameQualifier (textValue (render spURL))
            $ text nameID
        SAMLP.sessionIndex $ text sessionID
  where
    LogoutRequest sendURL spURL logoutURL start finish nameID sessionID =
        logoutRequest
    id_ = textValue $ "_" <> T.pack (show (hash (show logoutRequest)))


------------------------------------------------------------------------------
parseLogoutRequest :: Document -> Either SAMLProtocolException LogoutRequest
parseLogoutRequest document = do
    sendURL <- (parseURL =<<) . single NoIDPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    spURL <- (parseURL =<<) . single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        >=> attribute "SPNameQualifier"
    logoutURL <- (parseURL =<<) . single NoLoginURL $ xml
        & attribute "Destination"
    start <- (parseTime =<<) . single NoInstant $ xml
        & attribute "IssueInstant"
    finish <- (parseTime =<<) . single NoInstant $ xml
        & attribute "NotOnOrAfter"
    nameID <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        &/ content
    sessionID <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:protocol}SessionIndex"
        &/ content
    pure $ LogoutRequest sendURL spURL logoutURL start finish nameID sessionID
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
parseVerifyLogoutRequest :: [SignedCertificate] -> Document
    -> IO LogoutRequest
parseVerifyLogoutRequest certificates xml = do
    logoutRequest <- either throwIO pure $ parseLogoutRequest xml
    verifies <- X.verifyDocument certificates xml
    if verifies
        then pure logoutRequest
        else throwIO SignatureVerificationFailed


------------------------------------------------------------------------------
data LogoutResponse = LogoutResponse
    { sender :: !URI
    , logout :: !URI
    , instant :: !UTCTime
    , request :: !Text
    }
  deriving (Eq, Ord, Show, Generic, Typeable)


------------------------------------------------------------------------------
newLogoutResponse :: IDP -> SP -> LogoutRequest -> IO LogoutResponse
newLogoutResponse idp_ sp_ logoutRequest = do
    now <- getCurrentTime
    pure $ LogoutResponse sendURL logoutURL now requestID
  where
    IDP _ _ logoutURL _ _ = idp_
    SP sendURL _ _ _ _ = sp_
    LogoutRequest _ _ _ _ _ requestID _ = logoutRequest


------------------------------------------------------------------------------
buildSignNewLogoutResponse  :: IDP -> SP -> LogoutRequest -> PrivKey
    -> IO (LogoutResponse, Markup)
buildSignNewLogoutResponse idp_ sp_ logoutRequest key = do
    logoutResponse <- newLogoutResponse idp_ sp_ logoutRequest
    markup <- X.signMarkup key $
        buildLogoutResponseCommon (Just key) (Just certificate) logoutResponse
    pure (logoutResponse, markup)
  where
    SP _ _ _ certificate _ = sp_


------------------------------------------------------------------------------
buildLogoutResponse :: LogoutResponse -> Markup
buildLogoutResponse = buildLogoutResponseCommon Nothing Nothing


------------------------------------------------------------------------------
buildSignLogoutResponse :: PrivKey -> LogoutResponse -> IO Markup
buildSignLogoutResponse key = X.signMarkup key
    . buildLogoutResponseCommon (Just key) Nothing


------------------------------------------------------------------------------
buildLogoutResponseCommon :: Maybe PrivKey -> Maybe SignedCertificate
    -> LogoutResponse -> Markup
buildLogoutResponseCommon mkey certificate logoutResponse = do
    SAMLP.logoutResponse ! SAMLP.namespace ! SAMLP.id id_
        ! SAMLP.issueInstant instant_
        ! SAMLP.destination (textValue (render logoutURL))
        ! SAMLP.inResponseTo (textValue requestID)
        $ do
            case mkey of
                Just key -> SAMLP.signature sigAlg hashAlg certificate Nothing
                  where
                    sigAlg = SignatureALG hashAlg (privkeyToAlg key)
                    hashAlg = HashSHA256
                Nothing -> pure ()
            SAMLP.issuer $ text $ render sendURL
            SAMLP.status $ SAMLP.statusCode ! SAMLP.success
  where
    LogoutResponse sendURL logoutURL instant_ requestID = logoutResponse
    id_ = textValue $ "_" <> T.pack (show (hash (show logoutResponse)))


------------------------------------------------------------------------------
parseLogoutResponse :: Document -> Either SAMLProtocolException LogoutResponse
parseLogoutResponse document = do
    sendURL <- (parseURL =<<) . single NoIDPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    logoutURL <- (parseURL =<<) . single NoLoginURL $ xml
        & attribute "Destination"
    instant_ <- (parseTime =<<) . single NoInstant $ xml
        & attribute "IssueInstant"
    requestID <- single NoSPURL $ xml
        & attribute "InResponseTo"
    pure $ LogoutResponse sendURL logoutURL instant_ requestID
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
parseVerifyLogoutResponse :: [SignedCertificate] -> Document
    -> IO LogoutResponse
parseVerifyLogoutResponse certificates xml = do
    logoutResponse <- either throwIO pure $ parseLogoutResponse xml
    verifies <- X.verifyDocument certificates xml
    if verifies
        then pure logoutResponse
        else throwIO SignatureVerificationFailed


------------------------------------------------------------------------------
toDocument :: Cursor -> Document
toDocument cursor = case node cursor of
    X.NodeElement e -> X.Document (X.Prologue [] Nothing []) e []
    _ -> error "toDocument: Cursor is not focused on an element"


------------------------------------------------------------------------------
parseURL :: Text -> Either SAMLProtocolException URI
parseURL = either throw id . fmap (first UnparsableURL) . try . mkURI


------------------------------------------------------------------------------
parseTime :: Text -> Either SAMLProtocolException UTCTime
parseTime a = maybe (Left $ UnparsableTime a) Right
    $ parseTimeM False defaultTimeLocale "%FT%TZ" $ T.unpack a
