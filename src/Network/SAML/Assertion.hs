{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings #-}

{-# OPTIONS_GHC -fno-warn-unused-top-binds #-}

module Network.SAML.Assertion
    ( Attributes
    , FromAttributes, fromAttributes, ToAttributes, toAttributes
    , Assertion (Assertion)
    , newAssertion, buildSignNewAssertion, buildAssertion, buildSignAssertion
    , parseAssertion
    , Session (Session), newSession
    , SAMLAssertionException (..)
    , newName
    )
where

-- base ----------------------------------------------------------------------
import           Control.Exception (Exception, throw, throwIO)
import           Control.Monad ((>=>))
import           Data.Bifunctor (first)
import           Data.Foldable (for_)
import           Data.Function ((&))
import           Data.Semigroup ((<>))
import           Data.Typeable (Typeable)
import           Data.Word (Word64)
import           GHC.Generics (Generic)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze (Markup, (!), text, textValue)


-- hashable ------------------------------------------------------------------
import           Data.Hashable (hash)


-- layers --------------------------------------------------------------------
import           Monad.Catch (try)


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, ParseException, mkURI, render)


-- random --------------------------------------------------------------------
import           System.Random (randomIO)


-- snap-snaplet-saml ---------------------------------------------------------
import           Network.SAML.Metadata (IDP (IDP), SP (SP))
import qualified Text.Blaze.SAML.Assertion as SAML
import qualified Text.XML.Signature as X


-- text ----------------------------------------------------------------------
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as LT
import           Data.Text.Lazy.Builder (toLazyText)
import           Data.Text.Lazy.Builder.Int (hexadecimal)


-- time ----------------------------------------------------------------------
import           Data.Time.Clock
                     ( UTCTime, getCurrentTime
                     , NominalDiffTime, addUTCTime
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
data SAMLAssertionException
    = NoIDPURL
    | NoSPURL
    | NoLoginURL
    | NoName
    | NoBeginning
    | NoEnding
    | NoSession
    | UnparsableURL !ParseException
    | UnparsableTime !Text
    | SignatureVerificationFailed
  deriving
    (Eq, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
type Attributes = [(Text, [Text])]


------------------------------------------------------------------------------
class FromAttributes a where
    fromAttributes :: Attributes -> Maybe a


------------------------------------------------------------------------------
class ToAttributes a where
    toAttributes :: a -> Attributes


------------------------------------------------------------------------------
data Assertion = Assertion
    { idp :: !URI
    , sp :: !URI
    , login :: !URI
    , beginning :: !UTCTime
    , ending :: !UTCTime
    , attributes :: !Attributes
    , name :: !Text
    , request :: !Text
    , session :: !Session
    }
  deriving (Eq, Ord, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
newAssertion :: IDP -> SP -> NominalDiffTime -> Attributes -> Text -> Session
    -> IO Assertion
newAssertion idp_ sp_ diff attrs rqID session_ = do
    start <- getCurrentTime
    let finish = diff `addUTCTime` start
    nameID <- newName
    pure $ Assertion idpURL spURL loginURL start finish attrs nameID rqID
        session_
  where
    IDP idpURL _ _ _ _ = idp_
    SP spURL loginURL _ _ _ = sp_


------------------------------------------------------------------------------
buildSignNewAssertion :: IDP -> SP -> NominalDiffTime -> Attributes -> Text
    -> Session -> PrivKey -> IO (Assertion, Markup)
buildSignNewAssertion idp_ sp_ diff attrs rqID session_ key = do
    assertion <- newAssertion idp_ sp_ diff attrs rqID session_
    markup <- X.signMarkup key $
        buildAssertionCommon (Just key) (Just certificate) assertion
    pure (assertion, markup)
  where
    IDP _ _ _ certificate _ = idp_


------------------------------------------------------------------------------
buildAssertion :: Assertion -> Markup
buildAssertion = buildAssertionCommon Nothing Nothing


------------------------------------------------------------------------------
buildSignAssertion :: PrivKey -> Assertion -> IO Markup
buildSignAssertion key = X.signMarkup key
    . buildAssertionCommon (Just key) Nothing


------------------------------------------------------------------------------
buildAssertionCommon :: Maybe PrivKey -> Maybe SignedCertificate -> Assertion
    -> Markup
buildAssertionCommon mkey certificate assertion = SAML.assertion ! SAML.id id_
    ! SAML.namespace
    ! SAML.issueInstant start
    $ do
        case mkey of
            Just key -> SAML.signature sigAlg hashAlg certificate Nothing
                where
                sigAlg = SignatureALG hashAlg (privkeyToAlg key)
                hashAlg = HashSHA256
            Nothing -> pure ()
        SAML.issuer $ text $ render idpURL
        SAML.subject $ do
            SAML.nameID ! SAML.spNameQualifier (textValue (render spURL))
                $ text nameID
            SAML.subjectConfirmation $ SAML.subjectConfirmationData
                ! SAML.inResponseTo (textValue rqID)
                ! SAML.notOnOrAfter finish
                ! SAML.recipient (textValue (render spLoginURL))
        SAML.conditions ! SAML.notBefore start ! SAML.notOnOrAfter finish $ do
            SAML.audienceRestriction $ do
                SAML.audienceRestriction $ text $ render spURL
        buildSession session_
        SAML.attributeStatement $ for_ attrs $ \(key, values) -> do
            SAML.attribute key $ for_ values $ SAML.attributeValue
  where
    id_ = textValue $ "_" <> T.pack (show (hash (show assertion)))
    Assertion idpURL spURL spLoginURL start finish attrs nameID rqID session_
        = assertion


------------------------------------------------------------------------------
parseAssertion :: Document -> Either SAMLAssertionException Assertion
parseAssertion document = do
    start <- (parseTime =<<) . single NoBeginning $ xml &
        attribute "IssueInstant"
    idpURL <- (parseURL =<<) . single NoIDPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    spURL <- (parseURL =<<) . single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        >=> attribute "SPNameQualifier"
    nameID <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        &/ content
    rqID <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element subjectConfirmation &/ element subjectConfirmationData
        >=> attribute "InResponseTo"
    loginURL <- (parseURL =<<) . single NoLoginURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element subjectConfirmation &/ element subjectConfirmationData
        >=> attribute "Recipient"
    finish <- (parseTime =<<) . single NoLoginURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element subjectConfirmation &/ element subjectConfirmationData
        >=> attribute "NotOnOrAfter"
    session_ <- (parseSession . toDocument =<<) . single NoSession $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement"
    pure $ Assertion idpURL spURL loginURL start finish attrs nameID rqID
        session_
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left err)
    subjectConfirmation =
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation"
    subjectConfirmationData =
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData"
    attributeStatement =
        "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
    attribute_ = "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
    attributeValue = "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
    attrs = do
        key <- xml $/ element attributeStatement &/ element attribute_
        name_ <- key & attribute "Name"
        let values = key $/ element attributeValue &/ content
        pure (name_, values)


------------------------------------------------------------------------------
parseVerifyAssertion :: [SignedCertificate] -> Document -> IO Assertion
parseVerifyAssertion certificates xml = do
    assertion <- either throwIO pure $ parseAssertion xml
    verifies <- X.verifyDocument certificates xml
    if verifies
        then pure assertion
        else throwIO SignatureVerificationFailed


------------------------------------------------------------------------------
data Session = Session
    { name :: !Text
    , beginning :: !UTCTime
    , ending :: !UTCTime
    }
  deriving (Eq, Ord, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
newSession :: Either NominalDiffTime (UTCTime, UTCTime) -> IO Session
newSession (Right (start, finish)) = do
    nameID <- newName
    pure $ Session nameID start finish
newSession (Left diff) = do
    nameID <- newName
    start <- getCurrentTime
    let finish = diff `addUTCTime` start
    pure $ Session nameID start finish


------------------------------------------------------------------------------
buildSession :: Session -> Markup
buildSession (Session nameID start finish) = SAML.authnStatement
    ! SAML.authnInstant start ! SAML.sessionNotOnOrAfter finish
    ! SAML.sessionIndex (textValue nameID)
    $ SAML.authnContext $ SAML.authnContextClassRef


------------------------------------------------------------------------------
parseSession :: Document -> Either SAMLAssertionException Session
parseSession document = do
    nameID <- single NoName $ xml & attribute "SessionIndex"
    start <- (parseTime =<<) . single NoBeginning $ xml &
        attribute "AuthnInstant"
    finish <- (parseTime =<<) . single NoEnding $ xml &
        attribute "SessionNotOnOrAfter"
    pure $ Session nameID start finish
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left err)


------------------------------------------------------------------------------
toDocument :: Cursor -> Document
toDocument cursor = case node cursor of
    X.NodeElement e -> X.Document (X.Prologue [] Nothing []) e []
    _ -> error "toDocument: Cursor is not focused on an element"


------------------------------------------------------------------------------
parseURL :: Text -> Either SAMLAssertionException URI
parseURL = either throw id . fmap (first UnparsableURL) . try . mkURI


------------------------------------------------------------------------------
parseTime :: Text -> Either SAMLAssertionException UTCTime
parseTime a = maybe (Left $ UnparsableTime a) Right
    $ parseTimeM False defaultTimeLocale "%FT%TZ" $ T.unpack a


------------------------------------------------------------------------------
newName :: IO Text
newName = do
    a <- hexadecimal <$> randomWord
    b <- hexadecimal <$> randomWord
    c <- hexadecimal <$> randomWord
    d <- hexadecimal <$> randomWord
    pure $ LT.toStrict $ toLazyText $ a <> b <> c <> d
  where
    randomWord :: IO Word64
    randomWord = randomIO
