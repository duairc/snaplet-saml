{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedStrings #-}

module Snap.Snaplet.SAML
    ( SAMLConfig (SAMLConfig), SAML, samlInit, login, logout
    )
where

-- base ----------------------------------------------------------------------
import           Control.Applicative ((<|>))
import           Control.Exception (throwIO)
import           Control.Monad.IO.Class (liftIO)
import           Data.Function ((&))
import           Data.Monoid ((<>))
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- base64-bytestring ---------------------------------------------------------
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.Lazy as L64


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze.Renderer.Utf8 (renderMarkup)


-- bytestring ----------------------------------------------------------------
import qualified Data.ByteString.Lazy as L


-- configurator --------------------------------------------------------------
import           Data.Configurator (require, lookupDefault)
import qualified Data.Configurator.Types as C


-- filepath ------------------------------------------------------------------
import           System.FilePath ((</>))


-- lens ----------------------------------------------------------------------
import           Control.Lens.Setter ((%~))


-- modern-uri ----------------------------------------------------------------
import           Text.URI
                     ( URI, QueryParam (QueryParam)
                     , mkURI, mkQueryKey, mkQueryValue, mkPathPiece
                     , render, renderBs
                     )
import           Text.URI.Lens (uriPath, uriQuery)


-- mtl -----------------------------------------------------------------------
import           Control.Monad.Reader.Class (ask)


-- snap ----------------------------------------------------------------------
import           Snap.Snaplet
                     ( SnapletInit, Initializer, makeSnaplet, withTop'
                     , getSnapletRootURL, getSnapletUserConfig
                     , getSnapletFilePath
                     , Handler, addRoutes
                     )


-- snap-core -----------------------------------------------------------------
import           Snap.Core
                     ( modifyResponse, setContentType, getParam
                     , withRequest, rqURI, redirect, writeLBS, pass
                     )


-- snap-snaplet-saml ---------------------------------------------------------
import qualified Data.X509.IO as XIO
import           Network.SAML.Assertion
                     ( Assertion (Assertion), Session (Session)
                     )
import           Network.SAML.Metadata
                     ( IDP (IDP), parseIDP, SP (SP), buildSignSP
                     )
import           Network.SAML.Protocol
                     ( Response (Response), parseVerifyResponse
                     , buildSignNewRequest
                     , parseLogoutRequest
                     , buildSignSPLogoutRequest
                     , buildSignNewLogoutResponse
                     )
import           Paths_snaplet_saml (getDataDir)


-- text ----------------------------------------------------------------------
import           Data.Text (Text)
import           Data.Text.Encoding (decodeUtf8)


-- time ----------------------------------------------------------------------
import           Data.Time.Clock (UTCTime)


-- x509 ----------------------------------------------------------------------
import           Data.X509 (PrivKey, SignedCertificate)


-- xml-conduit ---------------------------------------------------------------
import qualified Text.XML as X


-- zlib ----------------------------------------------------------------------
import           Codec.Compression.Zlib.Raw (compress, decompress)


------------------------------------------------------------------------------
data SAMLConfig = SAMLConfig
    { _host :: !Text
    , _self :: !Bool
    }
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
mkSAMLConfig :: C.Config -> IO SAMLConfig
mkSAMLConfig config = SAMLConfig
    <$> require config "host"
    <*> lookupDefault False config "allow-self-signed"


------------------------------------------------------------------------------
configDir :: Maybe (IO FilePath)
configDir = Just $ (</> "config") <$> getDataDir


------------------------------------------------------------------------------
type LoginHandler b = ([(Text, [Text])] -> UTCTime -> Handler b b ())


------------------------------------------------------------------------------
type LogoutHandler b = Handler b b ()


------------------------------------------------------------------------------
data SAML b = SAML
    { _idp :: !IDP
    , _sp :: !SP
    , _key :: !PrivKey
    , _certificate :: ![SignedCertificate]
    , _self :: !Bool
    , _doLogin :: !(LoginHandler b)
    , _doLogout :: !(LogoutHandler b)
    }
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
loadSAMLConfig :: LoginHandler b -> LogoutHandler b -> SAMLConfig
    -> Initializer b (SAML b) (SAML b)
loadSAMLConfig doLogin doLogout config = do
    dir <- getSnapletFilePath
    addRoutes
        [ ("metadata", metadata)
        , ("login", login)
        , ("logout", logout)
        ]
    getSnapletRootURL >>= go dir
  where
    SAMLConfig host self = config
    idpPath = "idp.xml"
    keyPath = "key.pem"
    certificatePath = "certificate.pem"
    go dir path = liftIO $ do
        idpDocument <- X.readFile X.def (dir </> idpPath)
        idp <- either throwIO pure $ parseIDP idpDocument
        [key] <- XIO.readKeyFile (dir </> keyPath)
        certificate : cas <- XIO.readCertificateFile (dir </> certificatePath)
        samlBaseURL <- mkURI $ "https://" <> host <> "/" <> decodeUtf8 path
        metadataURL <- appendPath samlBaseURL <$> mkPathPiece "metadata"
        loginURL <- appendPath samlBaseURL <$> mkPathPiece "login"
        logoutURL <- appendPath samlBaseURL <$> mkPathPiece "logout"
        let sp = SP metadataURL loginURL logoutURL certificate certificate
        pure $ SAML idp sp key cas self doLogin doLogout
      where
        appendPath uri piece = uri & uriPath %~ (++ [piece])


------------------------------------------------------------------------------
samlInit :: LoginHandler b -> LogoutHandler b -> SnapletInit b (SAML b)
samlInit doLogin doLogout =
    makeSnaplet "saml" "SAML Service Provider snaplet" configDir $
        getSnapletUserConfig >>= liftIO . mkSAMLConfig
            >>= loadSAMLConfig doLogin doLogout


------------------------------------------------------------------------------
metadata :: Handler b (SAML b) ()
metadata = do
    SAML _ sp key _ _ _ _ <- ask
    modifyResponse $ setContentType "application/xml"
    markup <- liftIO $ buildSignSP key sp
    writeLBS $ renderMarkup markup


------------------------------------------------------------------------------
login :: Handler b (SAML b) a
login = receiveLogin <|> sendLogin


------------------------------------------------------------------------------
logout :: Handler b (SAML b) a
logout = receiveLogout <|> sendLogout


------------------------------------------------------------------------------
sendLogin :: Handler b (SAML b) a
sendLogin = do
    SAML idp@(IDP _ loginURL _ _ _) sp key _ _ _ _ <- ask
    (_, request) <- liftIO $ buildSignNewRequest idp sp key
    skey <- liftIO $ mkQueryKey "SAMLRequest"
    svalue <- liftIO $ mkQueryValue $ decodeUtf8 $ L.toStrict $ L64.encode
        $ compress $ renderMarkup request
    let sparam = QueryParam skey svalue
    rkey <- liftIO $ mkQueryKey "RelayState"
    rvalue <- getCurrentURI >>= liftIO . mkQueryValue . render
    let rparam = QueryParam rkey rvalue
    let url = loginURL & uriQuery %~ (++ [sparam, rparam])
    redirect $ renderBs url


------------------------------------------------------------------------------
receiveLogin :: Handler b (SAML b) a
receiveLogin = do
    param <- getParam "SAMLResponse" >>= maybe pass pure
    document <- liftIO $ either fail pure (B64.decode param) >>=
        either throwIO pure . X.parseLBS X.def . L.fromStrict
    SAML (IDP _ _ _ certificate _) _ _ cas self doLogin _ <- ask
    response <- liftIO $ parseVerifyResponse self (certificate : cas) document
    case response of
        Response (Assertion _ _ _ _ _ attributes _ _ (Session _ _ ending)) ->
            withTop' id $ doLogin attributes ending
    getParam "RelayState" >>= redirect . maybe "/" id


------------------------------------------------------------------------------
sendLogout :: Handler b (SAML b) a
sendLogout = do
    SAML idp@(IDP _ _ logoutURL _ _) sp key _ _ _ doLogout <- ask
    withTop' id doLogout
    (_, markup) <- liftIO $ buildSignSPLogoutRequest idp sp 300 key
    skey <- liftIO $ mkQueryKey "SAMLRequest"
    svalue <- liftIO $ mkQueryValue $ decodeUtf8 $ L.toStrict $ L64.encode
        $ compress $ renderMarkup markup
    let sparam = QueryParam skey svalue
    redirect $ renderBs $ logoutURL & uriQuery %~ (++ [sparam])


------------------------------------------------------------------------------
receiveLogout :: Handler b (SAML b) a
receiveLogout = do
    param <- getParam "SAMLRequest" >>= maybe pass pure
    SAML idp@(IDP _ _ logoutURL _ _) sp key _ _ _ doLogout <- ask
    logoutRequest <- liftIO $
        either fail pure (L64.decode $ L.fromStrict param)
            >>= either throwIO pure . X.parseLBS X.def . decompress
            >>= either throwIO pure . parseLogoutRequest
    withTop' id doLogout
    (_, markup) <- liftIO $
        buildSignNewLogoutResponse idp sp logoutRequest key
    skey <- liftIO $ mkQueryKey "SAMLResponse"
    svalue <- liftIO $ mkQueryValue $ decodeUtf8 $ L.toStrict $ L64.encode
        $ compress $ renderMarkup markup
    let sparam = QueryParam skey svalue
    mrelayState <- getParam "RelayState"
    sparams <- liftIO $ case mrelayState of
        Nothing -> pure [sparam]
        Just relayState -> do
            rkey <- mkQueryKey "RelayState"
            rvalue <- mkQueryValue $ decodeUtf8 relayState
            pure [sparam, QueryParam rkey rvalue]
    redirect $ renderBs $ logoutURL & uriQuery %~ (++ sparams)


------------------------------------------------------------------------------
getCurrentURI :: Handler b (SAML b) URI
getCurrentURI = withRequest $ liftIO . mkURI . decodeUtf8 . rqURI
