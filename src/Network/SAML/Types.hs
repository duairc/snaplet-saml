{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SAML.Types
    ( Assertion (Assertion), newAssertion, Session (Session), newSession
    , Request (Request), newRequest, Response (Response), newResponse
    , LogoutRequest (LogoutRequest), idpLogoutRequest, spLogoutRequest
    , LogoutResponse (LogoutResponse), idpLogoutResponse, spLogoutResponse
    , SAMLException (..)
    , parseURL
    )
where

-- base ----------------------------------------------------------------------
import           Control.Exception (Exception, toException, SomeException)
import           Control.Monad ((>=>))
import           Data.Bifunctor (first)
import           Data.Foldable (for_)
import           Data.Function ((&))
import           Data.Functor.Identity (runIdentity)
import           Data.Semigroup ((<>))
import           Data.Typeable (Typeable)
import           Data.Word (Word64)
import           GHC.Generics (Generic)
import           Prelude hiding (id)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze (Markup, (!), text, textValue)


-- insert-ordered-containers -------------------------------------------------
import qualified Data.HashMap.Strict.InsOrd as IM
import qualified Data.HashSet.InsOrd as IS


-- layers --------------------------------------------------------------------
import           Monad.Catch (try)


-- lens ----------------------------------------------------------------------
import           Control.Lens.Indexed (ifor_)


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, ParseException, mkURI, render)


-- random --------------------------------------------------------------------
import           System.Random (randomIO)


-- snap-snaplet-saml ---------------------------------------------------------
import           Network.SAML.Common
                     ( Attributes, NameID, RequestID, ResponseID, SessionIndex
                     )
import           Network.SAML.Message
                     ( Message, Param (SAMLRequest, SAMLResponse)
                     )
import qualified Network.SAML.Message as M
import           Network.SAML.Metadata (IDP (IDP), SP (SP))
import qualified Text.Blaze.SAML.Assertion as SAML
import qualified Text.Blaze.SAML.Protocol as SAMLP


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


-- xml-conduit ---------------------------------------------------------------
import           Text.XML (Document)
import qualified Text.XML as X
import           Text.XML.Cursor
                     ( Cursor, fromDocument
                     , ($/), (&/), element, attribute, content, node
                     )


------------------------------------------------------------------------------
data SAMLException
    = NoID
    | NoIDPURL
    | NoSPURL
    | NoLoginURL
    | NoName
    | NoBeginning
    | NoEnding
    | NoSession
    | NoAssertion
    | NoInstant
    | UnparsableURL !ParseException
    | UnparsableTime !Text
  deriving (Eq, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
data Assertion = Assertion
    { id :: !ResponseID
    , idp :: !URI
    , sp :: !URI
    , login :: !URI
    , beginning :: !UTCTime
    , ending :: !UTCTime
    , attributes :: !Attributes
    , name :: !NameID
    , request :: !RequestID
    , session :: !Session
    }
  deriving (Eq, Show, Generic, Typeable)


------------------------------------------------------------------------------
instance Message Assertion where
    param _ = SAMLResponse
    build = buildAssertion
    parse = parseAssertion
    destination (Assertion _ _ _ destination _ _ _ _ _ _) = destination


------------------------------------------------------------------------------
newAssertion :: IDP -> SP -> NominalDiffTime -> Attributes -> Request
    -> Session -> IO Assertion
newAssertion idp sp diff attributes request session = do
    id <- newName
    beginning <- getCurrentTime
    let ending = diff `addUTCTime` beginning
    pure $ Assertion id idp' sp' login beginning ending attributes name
        requestID session
  where
    Request requestID _ _ _ _ = request
    IDP idp' _ _ _ _ = idp
    SP sp' login _ _ _ = sp
    Session name _ _ = session


------------------------------------------------------------------------------
buildAssertion :: Monad m
    => Assertion -> (Markup -> m Markup) -> Markup -> m Markup
buildAssertion assertion wrap children = wrap $ SAML.assertion
    ! SAML.id (textValue id)
    ! SAML.issueInstant beginning
    $ do
        SAML.issuer $ text $ render idp
        children
        SAML.subject $ do
            SAML.nameID ! SAML.spNameQualifier (textValue (render sp))
                $ text name
            SAML.subjectConfirmation $ SAML.subjectConfirmationData
                ! SAML.inResponseTo (textValue request)
                ! SAML.notOnOrAfter ending
                ! SAML.recipient (textValue (render login))
        SAML.conditions
            ! SAML.notBefore beginning ! SAML.notOnOrAfter ending
            $ SAML.audienceRestriction $ SAML.audience $ text $ render sp
        buildSession session
        SAML.attributeStatement $ ifor_ attributes $ \key values -> do
            SAML.attribute key $ for_ values $ SAML.attributeValue
  where
    Assertion id idp sp login beginning ending attributes name request session
        = assertion


------------------------------------------------------------------------------
parseAssertion :: Document -> Either SomeException Assertion
parseAssertion document = do
    id <- single NoID $ xml & attribute "ID"
    beginning <- (parseTime =<<) . single NoBeginning $ xml &
        attribute "IssueInstant"
    idp <- (parseURL =<<) . single NoIDPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    sp <- (parseURL =<<) . single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        >=> attribute "SPNameQualifier"
    name <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        &/ content
    request <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element subjectConfirmation &/ element subjectConfirmationData
        >=> attribute "InResponseTo"
    login <- (parseURL =<<) . single NoLoginURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element subjectConfirmation &/ element subjectConfirmationData
        >=> attribute "Recipient"
    ending <- (parseTime =<<) . single NoLoginURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
        &/ element subjectConfirmation &/ element subjectConfirmationData
        >=> attribute "NotOnOrAfter"
    session <- (parseSession . toDocument =<<) . single NoSession $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement"
    pure $ Assertion id idp sp login beginning ending attributes name request
        session
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left $ toException err)
    subjectConfirmation =
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation"
    subjectConfirmationData =
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData"
    attributeStatement =
        "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
    attribute_ = "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
    attributeValue = "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
    attributes = IM.fromList $ do
        key <- xml $/ element attributeStatement &/ element attribute_
        name <- key & attribute "Name"
        let values = key $/ element attributeValue &/ content
        pure (name, IS.fromList values)


------------------------------------------------------------------------------
data Session = Session
    { name :: !SessionIndex
    , beginning :: !UTCTime
    , ending :: !UTCTime
    }
  deriving (Eq, Ord, Show, Generic, Typeable)


------------------------------------------------------------------------------
newSession :: Either NominalDiffTime (UTCTime, UTCTime) -> IO Session
newSession (Right (beginning, ending)) = do
    name <- newName
    pure $ Session name beginning ending
newSession (Left diff) = do
    name <- newName
    beginning <- getCurrentTime
    let ending = diff `addUTCTime` beginning
    pure $ Session name beginning ending


------------------------------------------------------------------------------
buildSession :: Session -> Markup
buildSession (Session name beginning ending) = SAML.authnStatement
    ! SAML.authnInstant beginning ! SAML.sessionNotOnOrAfter ending
    ! SAML.sessionIndex (textValue name)
    $ SAML.authnContext $ SAML.authnContextClassRef


------------------------------------------------------------------------------
parseSession :: Document -> Either SomeException Session
parseSession document = do
    name <- single NoName $ xml & attribute "SessionIndex"
    beginning <- (parseTime =<<) . single NoBeginning $ xml &
        attribute "AuthnInstant"
    ending <- (parseTime =<<) . single NoEnding $ xml &
        attribute "SessionNotOnOrAfter"
    pure $ Session name beginning ending
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left $ toException err)


------------------------------------------------------------------------------
data Request = Request
    { id :: !RequestID
    , idp :: !URI
    , sp :: !URI
    , login :: !URI
    , time :: !UTCTime
    }
  deriving (Eq, Show, Generic, Typeable)


------------------------------------------------------------------------------
instance Message Request where
    param _ = SAMLRequest
    build = buildRequest
    parse = parseRequest
    destination (Request _ destination _ _ _) = destination


------------------------------------------------------------------------------
newRequest :: IDP -> SP -> IO Request
newRequest (IDP _ idp _ _ _) (SP sp login _ _ _) = do
    id <- newName
    now <- getCurrentTime
    pure $ Request id idp sp login now


------------------------------------------------------------------------------
buildRequest :: Monad m
    => Request -> (Markup -> m Markup) -> Markup -> m Markup
buildRequest request wrap children = wrap $ SAMLP.authnRequest
    ! SAMLP.destination (textValue $ render idp)
    ! SAMLP.assertionConsumerServiceURL (textValue $ render login)
    ! SAMLP.issueInstant instant
    ! SAMLP.id (textValue id)
    $ do
        SAMLP.issuer $ text $ render sp
        children
  where
    Request id idp sp login instant = request


------------------------------------------------------------------------------
parseRequest :: Document -> Either SomeException Request
parseRequest document = do
    id <- single NoID $ xml & attribute "ID"
    idp <- (parseURL =<<) . single NoIDPURL $ xml & attribute "Destination"
    login <- (parseURL =<<) . single NoLoginURL $ xml &
        attribute "AssertionConsumerServiceURL"
    instant <- (parseTime =<<) . single NoInstant $ xml &
        attribute "IssueInstant"
    sp <- (parseURL =<<) . single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    pure $ Request id idp sp login instant
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left $ toException err)


------------------------------------------------------------------------------
data Response = Response
    { id :: !ResponseID
    , assertion :: !Assertion
    }
  deriving (Eq, Show, Generic, Typeable)


------------------------------------------------------------------------------
instance Message Response where
    param _ = SAMLResponse
    build = buildResponse
    parse = parseResponse
    destination (Response _ assertion) = M.destination assertion


------------------------------------------------------------------------------
newResponse :: IDP -> SP -> NominalDiffTime -> Attributes -> Request
    -> Session -> IO Response
newResponse i s d a r h = Response <$> newName <*> newAssertion i s d a r h


------------------------------------------------------------------------------
buildResponse :: Monad m
    => Response -> (Markup -> m Markup) -> Markup -> m Markup
buildResponse response wrap children = do
    -- FIXME: this doesn't work
    -- child <- buildAssertion assertion wrap children
    wrap $ SAMLP.response
        ! SAMLP.destination (textValue $ render login)
        ! SAMLP.inResponseTo (textValue request)
        ! SAMLP.issueInstant beginning
        ! SAMLP.id (textValue id)
        $ do
            SAML.issuer $ text $ render idp
            children
            SAMLP.status $ SAMLP.statusCode ! SAMLP.success
            -- child
            runIdentity $ buildAssertion assertion pure mempty
  where
    Response id assertion = response
    Assertion _ idp _ login beginning _ _ _ request _ = assertion


------------------------------------------------------------------------------
parseResponse :: Document -> Either SomeException Response
parseResponse document = do
    id <- single NoID $ xml & attribute "ID"
    assertion <- (parseAssertion . toDocument =<<) . single NoAssertion $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
    pure $ Response id assertion
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left $ toException err)


------------------------------------------------------------------------------
data LogoutRequest = LogoutRequest
    { id :: !RequestID
    , sender :: !URI
    , sp :: !URI
    , destination :: !URI
    , beginning :: !UTCTime
    , ending :: !UTCTime
    , name :: !NameID
    , session :: !SessionIndex
    }
  deriving (Eq, Ord, Show, Generic, Typeable)


------------------------------------------------------------------------------
instance Message LogoutRequest where
    param _ = SAMLRequest
    build = buildLogoutRequest
    parse = parseLogoutRequest
    destination (LogoutRequest _ _ _ destination _ _ _ _) = destination


------------------------------------------------------------------------------
idpLogoutRequest :: IDP -> SP -> NameID -> SessionIndex -> NominalDiffTime
    -> IO LogoutRequest
idpLogoutRequest idp sp name session diff = do
    id <- newName
    beginning <- getCurrentTime
    let ending = diff `addUTCTime` beginning
    pure $ LogoutRequest id sender sp' destination beginning ending name
        session
  where
    IDP sender _ _ _ _ = idp
    SP sp' _ destination _ _ = sp


------------------------------------------------------------------------------
spLogoutRequest :: IDP -> SP -> NameID -> SessionIndex -> NominalDiffTime
    -> IO LogoutRequest
spLogoutRequest idp sp name session diff = do
    id <- newName
    beginning <- getCurrentTime
    let ending = diff `addUTCTime` beginning
    pure $ LogoutRequest id sp' sp' destination beginning ending name session 
  where
    IDP _ _ destination _ _ = idp
    SP sp' _ _ _ _ = sp


------------------------------------------------------------------------------
buildLogoutRequest :: Monad m
    => LogoutRequest -> (Markup -> m Markup) -> Markup -> m Markup
buildLogoutRequest request wrap children = wrap $ SAMLP.logoutRequest
    ! SAMLP.destination (textValue $ render destination)
    ! SAMLP.issueInstant beginning
    ! SAMLP.notOnOrAfter ending
    ! SAMLP.id (textValue id)
    $ do
        SAMLP.issuer $ text $ render sender
        children
        SAMLP.nameID ! SAML.spNameQualifier (textValue (render sp))
            $ text name
        SAMLP.sessionIndex $ text session
  where
    LogoutRequest id sender sp destination beginning ending name session =
        request


------------------------------------------------------------------------------
parseLogoutRequest :: Document -> Either SomeException LogoutRequest
parseLogoutRequest document = do
    id <- single NoID $ xml & attribute "ID"
    sender <- (parseURL =<<) . single NoIDPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    sp <- (parseURL =<<) . single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        >=> attribute "SPNameQualifier"
    destination <- (parseURL =<<) . single NoLoginURL $ xml
        & attribute "Destination"
    beginning <- (parseTime =<<) . single NoInstant $ xml
        & attribute "IssueInstant"
    ending <- (parseTime =<<) . single NoInstant $ xml
        & attribute "NotOnOrAfter"
    name <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        &/ content
    session <- single NoSPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:protocol}SessionIndex"
        &/ content
    pure $ LogoutRequest id sender sp destination beginning ending name
        session
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left $ toException err)


------------------------------------------------------------------------------
data LogoutResponse = LogoutResponse
    { id :: !ResponseID
    , sender :: !URI
    , destination :: !URI
    , instant :: !UTCTime
    , request :: !RequestID
    }
  deriving (Eq, Ord, Show, Generic, Typeable)


------------------------------------------------------------------------------
instance Message LogoutResponse where
    param _ = SAMLResponse
    build = buildLogoutResponse
    parse = parseLogoutResponse
    destination (LogoutResponse _ _ destination _ _) = destination


------------------------------------------------------------------------------
idpLogoutResponse :: IDP -> SP -> RequestID -> IO LogoutResponse
idpLogoutResponse idp sp request = do
    id <- newName
    instant <- getCurrentTime
    pure $ LogoutResponse id sender destination instant request
  where
    IDP sender _ _ _ _ = idp
    SP _ _ destination _ _ = sp


------------------------------------------------------------------------------
spLogoutResponse :: IDP -> SP -> LogoutRequest -> IO LogoutResponse
spLogoutResponse idp sp logoutRequest = do
    id <- newName
    instant <- getCurrentTime
    pure $ LogoutResponse id sender destination instant request
  where
    IDP _ _ destination _ _ = idp
    SP sender _ _ _ _ = sp
    LogoutRequest request _ _ _ _ _ _ _ = logoutRequest


------------------------------------------------------------------------------
buildLogoutResponse :: Monad m
    => LogoutResponse -> (Markup -> m Markup) -> Markup -> m Markup
buildLogoutResponse response wrap children = wrap $ SAMLP.logoutResponse
    ! SAMLP.id (textValue id)
    ! SAMLP.issueInstant instant
    ! SAMLP.destination (textValue (render destination))
    ! SAMLP.inResponseTo (textValue request)
    $ do
        SAMLP.issuer $ text $ render sender
        children
        SAMLP.status $ SAMLP.statusCode ! SAMLP.success
  where
    LogoutResponse id sender destination instant request = response


------------------------------------------------------------------------------
parseLogoutResponse :: Document -> Either SomeException LogoutResponse
parseLogoutResponse document = do
    id <- single NoID $ xml & attribute "ID"
    sender <- (parseURL =<<) . single NoIDPURL $ xml
        $/ element "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        &/ content
    destination <- (parseURL =<<) . single NoLoginURL $ xml
        & attribute "Destination"
    instant <- (parseTime =<<) . single NoInstant $ xml
        & attribute "IssueInstant"
    request <- single NoSPURL $ xml
        & attribute "InResponseTo"
    pure $ LogoutResponse id sender destination instant request
  where
    xml = fromDocument document
    single err = foldr (const . Right) (Left $ toException err)


------------------------------------------------------------------------------
toDocument :: Cursor -> Document
toDocument cursor = case node cursor of
    X.NodeElement e -> X.Document (X.Prologue [] Nothing []) e []
    _ -> error "toDocument: Cursor is not focused on an element"


------------------------------------------------------------------------------
parseURL :: Text -> Either SomeException URI
parseURL = (>>= first (toException . UnparsableURL)) . try . mkURI


------------------------------------------------------------------------------
parseTime :: Text -> Either SomeException UTCTime
parseTime a = maybe (Left $ toException $ UnparsableTime a) Right
    $ parseTimeM False defaultTimeLocale "%FT%TZ" $ T.unpack a


------------------------------------------------------------------------------
newName :: IO Text
newName = do
    a <- hexadecimal <$> randomWord
    b <- hexadecimal <$> randomWord
    c <- hexadecimal <$> randomWord
    d <- hexadecimal <$> randomWord
    pure $ LT.toStrict $ toLazyText $ "_" <> a <> b <> c <> d
  where
    randomWord :: IO Word64
    randomWord = randomIO
