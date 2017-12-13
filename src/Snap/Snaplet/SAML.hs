{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

module Snap.Snaplet.SAML
    ( SAML, samlInit, tryGetSession, getSession
    , FromAttributes, fromAttributes
    )
where

-- base ----------------------------------------------------------------------
import           Control.Exception (throwIO)
import           Control.Monad.IO.Class (liftIO)
import           Data.Foldable (for_, traverse_)
import           Data.Function ((&))
import           Data.IORef (IORef, newIORef, atomicModifyIORef')
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


-- hashable ------------------------------------------------------------------
import           Data.Hashable (Hashable)


-- hostname ------------------------------------------------------------------
import           Network.HostName (getHostName)


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
import           Snap
                     ( Handler, modifyResponse, getParam
                     , getsRequest, withRequest, rqIsSecure, rqURI, getHeader
                     , Cookie (Cookie), cookieValue, getCookie, expireCookie
                     , addResponseCookie
                     , setContentType
                     , redirect, writeLBS
                     , SnapletInit, makeSnaplet, addRoutes
                     )


-- snap-snaplet-saml ---------------------------------------------------------
import qualified Data.X509.IO as XIO
import           Network.SAML.Assertion
                     ( FromAttributes, fromAttributes
                     , Assertion (Assertion), Session (Session)
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


-- text ----------------------------------------------------------------------
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding (decodeUtf8, encodeUtf8)


-- time ----------------------------------------------------------------------
import           Data.Time.Clock (UTCTime, getCurrentTime)


-- unordered-containers ------------------------------------------------------
import           Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as H


-- uuid ----------------------------------------------------------------------
import           Data.UUID (UUID)
import qualified Data.UUID as UUID
import           Data.UUID.V4 (nextRandom)


-- x509 ----------------------------------------------------------------------
import           Data.X509 (PrivKey, SignedCertificate)


-- xml-conduit ---------------------------------------------------------------
import qualified Text.XML as X


-- zlib ----------------------------------------------------------------------
import           Codec.Compression.Zlib.Raw (compress, decompress)


------------------------------------------------------------------------------
data SAML u = SAML !IDP !SP !PrivKey ![SignedCertificate] !(Sessions u)
  deriving (Eq, Generic, Typeable)


------------------------------------------------------------------------------
type Sessions u = IORef (HashMap UUID (u, UTCTime))


------------------------------------------------------------------------------
samlInit :: FromAttributes u
    => Text -> FilePath -> FilePath -> FilePath -> SnapletInit b (SAML u)
samlInit samlBase idpPath keyPath certificatePath = do
    makeSnaplet "saml" "SAML Service Provider" Nothing $ do
        saml <- liftIO $ configure samlBase idpPath keyPath certificatePath
        addRoutes
            [ ("metadata", metadata)
            , ("login", login)
            , ("logout", logout)
            ]
        pure saml


------------------------------------------------------------------------------
configure :: Text -> FilePath -> FilePath -> FilePath -> IO (SAML u)
configure samlBase idpPath keyPath certificatePath = do
    idpDocument <- X.readFile X.def idpPath
    idp <- either throwIO pure $ parseIDP idpDocument
    [key] <- XIO.readKeyFile keyPath
    certificate : cas <- XIO.readCertificateFile certificatePath
    samlBaseURL <- mkURI samlBase
    metadataURL <- appendPath samlBaseURL <$> mkPathPiece "metadata"
    loginURL <- appendPath samlBaseURL <$> mkPathPiece "login"
    logoutURL <- appendPath samlBaseURL <$> mkPathPiece "logout"
    let sp = SP metadataURL loginURL logoutURL certificate certificate
    sessions <- newIORef mempty
    pure $ SAML idp sp key cas sessions
  where
    appendPath uri piece = uri & uriPath %~ (++ [piece])


------------------------------------------------------------------------------
metadata :: Handler b (SAML u) ()
metadata = do
    SAML _ sp key _ _ <- ask
    modifyResponse $ setContentType "application/xml"
    markup <- liftIO $ buildSignSP key sp
    writeLBS $ renderMarkup markup


------------------------------------------------------------------------------
login :: FromAttributes u => Handler b (SAML u) a
login = do
    SAML (IDP _ _ _ certificate _) _ _ cas ref <- ask
    param <- failMaybe =<< getParam "SAMLResponse"
    document <- liftIO $ either fail pure (B64.decode param)
        >>= either throwIO pure . X.parseLBS X.def . L.fromStrict
    response <- liftIO $ parseVerifyResponse (certificate : cas) document
    uuid <- liftIO $ nextRandom
    value <- getValue response
    let end = ending response
    liftIO $ atomicModifyIORef' ref $ flip (,) () . H.insert uuid (value, end)
    host <- getHost
    let cookie = Cookie "saml-session" (UUID.toASCIIBytes uuid) (Just end)
         (Just (encodeUtf8 host)) (Just "/") True True
    modifyResponse $ addResponseCookie cookie
    getParam "RelayState" >>= redirect . maybe "/" id
  where
    failMaybe = maybe (liftIO $ fail "Parameter not found") pure
    getValue response = maybe (liftIO $ message) pure $ fromAttributes attrs
      where
        Response (Assertion _ _ _ _ _ attrs _ _ _) = response
        message = fail "Unknown format of SAMLResponse attributes"
    ending (Response (Assertion _ _ _ _ _ _ _ _ (Session _ _ e))) = e


------------------------------------------------------------------------------
logout :: Handler b (SAML u) a
logout = do
    SAML (IDP _ _ logoutURL _ _) _ _ _ _ <- ask
    expire
    qparams <- getParam "SAMLRequest" >>= maybe spLogout idpLogout
    redirect $ renderBs $ logoutURL & uriQuery %~ (++ qparams)
  where
    expire = do
        SAML _ _ _ _ ref <- ask
        cookie <- getCookie "saml-session"
        for_ (cookie >>= UUID.fromASCIIBytes . cookieValue) $ \uuid ->
            liftIO $ atomicModifyIORef' ref $ \m -> (H.delete uuid m, ())
        traverse_ expireCookie cookie
    idpLogout param = do
        SAML idp sp key _ _ <- ask
        mrelayState <- getParam "RelayState"
        liftIO $ do
            logoutRequest <-
                either decodeError pure (L64.decode $ L.fromStrict param)
                    >>= either throwIO pure . X.parseLBS X.def . decompress
                    >>= either throwIO pure . parseLogoutRequest
            (_, markup) <- buildSignNewLogoutResponse idp sp logoutRequest key
            skey <- mkQueryKey "SAMLResponse"
            svalue <- mkQueryValue $ decodeUtf8 $ L.toStrict $ L64.encode
                $ compress $ renderMarkup markup
            let sparam = QueryParam skey svalue
            case mrelayState of
                Nothing -> pure [sparam]
                Just relayState -> do
                    rkey <- mkQueryKey "RelayState"
                    rvalue <- mkQueryValue $ decodeUtf8 relayState
                    pure [sparam, QueryParam rkey rvalue]
      where
        decodeError = fail "Error decoding SAMLRequest"
    spLogout = do
        SAML idp sp key _ _<- ask
        liftIO $ do
            (_, markup) <- buildSignSPLogoutRequest idp sp 300 key
            skey <- mkQueryKey "SAMLRequest"
            svalue <- mkQueryValue $ decodeUtf8 $ L.toStrict $ L64.encode
                $ compress $ renderMarkup markup
            pure [QueryParam skey svalue]


------------------------------------------------------------------------------
tryGetSession :: Handler b (SAML u) (Maybe u)
tryGetSession = do
    SAML _ _ _ _ ref <- ask
    now <- liftIO $ getCurrentTime
    cookie <- getCookie "saml-session"
    case cookie >>= UUID.fromASCIIBytes . cookieValue of
        Nothing -> pure Nothing
        Just uuid -> liftIO $ atomicModifyIORef' ref (go now uuid)
  where
    go now uuid sessions = updateWith update Nothing uuid sessions
      where
        update (value, time) | time >= now = (Just (value, time), Just value)
        update _ = (Nothing, Nothing)


------------------------------------------------------------------------------
getSession :: Handler b (SAML u) u
getSession = tryGetSession >>= maybe redirectLogin pure
  where
    redirectLogin = do
        SAML idp@(IDP _ loginURL _ _ _) sp key _ _ <- ask
        (_, request) <- liftIO $ buildSignNewRequest idp sp key
        skey <- liftIO $ mkQueryKey "SAMLRequest"
        svalue <- liftIO $ mkQueryValue $ decodeUtf8 $ L.toStrict $ L64.encode
            $ compress $ renderMarkup request
        let sparam = QueryParam skey svalue
        rkey <- liftIO $ mkQueryKey "RelayState"
        currentURI <- getCurrentURI
        rvalue <- liftIO $ mkQueryValue (render currentURI)
        let rparam = QueryParam rkey rvalue
        let url = loginURL & uriQuery %~ (++ [sparam, rparam])
        redirect $ renderBs url


------------------------------------------------------------------------------
getCurrentURI :: Handler b v URI
getCurrentURI = getHost >>= withRequest . go
  where
    go host request = liftIO $ mkURI $ scheme <> "://" <> host <> "/"
        <> path
      where
        scheme = if rqIsSecure request then "https" else "http"
        path = decodeUtf8 $ rqURI request


------------------------------------------------------------------------------
getHost :: Handler b v Text
getHost = getsRequest (getHeader "Host") >>= liftIO . go
  where
    go Nothing = T.pack <$> getHostName
    go (Just host) = pure $ decodeUtf8 host


------------------------------------------------------------------------------
updateWith :: (Eq k, Hashable k)
    => (a -> (Maybe a, b)) -> b -> k -> HashMap k a -> (HashMap k a, b)
updateWith f b = alterWith go
  where
    go Nothing = (Nothing, b)
    go (Just a) = f a


------------------------------------------------------------------------------
alterWith :: (Eq k, Hashable k)
    => (Maybe a -> (Maybe a, b)) -> k -> HashMap k a -> (HashMap k a, b)
alterWith f k m = case f (H.lookup k m) of
    (Nothing, b) -> (H.delete k m, b)
    (Just v, b) -> (H.insert k v m, b)
