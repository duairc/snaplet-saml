{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

module Snap.Snaplet.SAML.SP
    ( SP, init, login, logout
    , Attributes
    )
where

-- base ----------------------------------------------------------------------
import           Control.Applicative ((<|>), empty)
import           Control.Exception (throwIO)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.Function ((&))
import           Data.Monoid ((<>))
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)
import           Prelude hiding (init)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze.Renderer.Utf8 (renderMarkup)


-- filepath ------------------------------------------------------------------
import           System.FilePath ((</>))


-- lens ----------------------------------------------------------------------
import           Control.Lens.Setter ((%~))


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, mkURI, mkPathPiece, renderBs)
import           Text.URI.Lens (uriPath)


-- mtl -----------------------------------------------------------------------
import           Control.Monad.Reader.Class (MonadReader, ask, asks, local)


-- snap ----------------------------------------------------------------------
import           Snap.Snaplet
                     ( SnapletInit, Initializer, makeSnaplet, withTop'
                     , getSnapletRootURL, getSnapletUserConfig
                     , getSnapletFilePath
                     , Handler, addRoutes
                     )


-- snap-core -----------------------------------------------------------------
import           Snap.Core
                     ( modifyResponse, setContentType, redirect, writeLBS
                     )


-- snap-snaplet-saml ---------------------------------------------------------
import qualified Data.X509.IO as XIO
import           Network.SAML.Common (Attributes, NameID, SessionIndex)
import           Network.SAML.Message (Message)
import           Network.SAML.Metadata (parseIDP, buildSignSP)
import qualified Network.SAML.Metadata as M
import           Network.SAML.Protocol.SP (MonadSP, Env)
import qualified Network.SAML.Protocol.SP as N
import           Snap.Snaplet.SAML.Binding (Binding)
import qualified Snap.Snaplet.SAML.Binding as B
import           Snap.Snaplet.SAML.Binding.Redirect (Proxy (Redirect))
import           Snap.Snaplet.SAML.Binding.POST (Proxy (POST))
import           Snap.Snaplet.SAML.Config (Config)
import qualified Snap.Snaplet.SAML.Config as C


-- text ----------------------------------------------------------------------
import           Data.Text.Encoding (decodeUtf8)


-- time ----------------------------------------------------------------------
import           Data.Time.Clock (UTCTime)


-- x509 ----------------------------------------------------------------------
import           Data.X509 (PrivKey, SignedCertificate)


-- xml-conduit ---------------------------------------------------------------
import qualified Text.XML as X


------------------------------------------------------------------------------
data SP b = SP
    { environment :: !Env
    , certificate :: !SignedCertificate
    , key :: !PrivKey
    , on :: !(Login b)
    , off :: !(Logout b)
    }
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
newtype SPM b a = SPM
    { run :: Handler b (SP b) a
    }
  deriving (Functor, Applicative, Monad, MonadIO)


------------------------------------------------------------------------------
instance MonadReader Env (SPM b) where
    ask = SPM $ asks environment
    local f (SPM m) = SPM $ local f' m
      where
        f' (SP e c k n o) = SP (f e) c k n o


------------------------------------------------------------------------------
instance MonadSP (SPM b) where
    on a n s t = SPM $ do
        on <- asks on
        withTop' id $ on a n s t
    off n s = SPM $ do
        off <- asks off
        withTop' id $ off n s


------------------------------------------------------------------------------
send :: (Binding binding, Message a)
    => proxy binding -> a -> Maybe URI -> Handler b (SP b) x
send binding message relay = do
    key <- asks key
    certificate <- asks certificate
    B.send binding (pure (key, pure certificate)) message relay


------------------------------------------------------------------------------
receive :: (Binding binding, Message a)
    => proxy binding -> Handler b (SP b) (a, Maybe URI)
receive binding = do
    N.Env (M.IDP _ _ _ certificate _) _ <- asks environment
    B.receive binding (pure [certificate])


------------------------------------------------------------------------------
type Login b = Attributes -> NameID -> SessionIndex -> UTCTime
    -> Handler b b ()


------------------------------------------------------------------------------
type Logout b = Maybe NameID -> Maybe SessionIndex
    -> Handler b b (NameID, SessionIndex)


------------------------------------------------------------------------------
load :: Login b -> Logout b -> Config -> Initializer b (SP b) (SP b)
load on off config = do
    dir <- getSnapletFilePath
    addRoutes
        [ ("metadata", metadata)
        , ("login", login)
        , ("logout", logout)
        ]
    getSnapletRootURL >>= go dir
  where
    C.Config host = config
    idpPath = "idp.xml"
    keyPath = "key.pem"
    certificatePath = "certificate.pem"
    go dir path = liftIO $ do
        idpDocument <- X.readFile X.def (dir </> idpPath)
        idp <- either throwIO pure $ parseIDP idpDocument
        [key] <- XIO.readKeyFile (dir </> keyPath)
        certificate : _ <- XIO.readCertificateFile (dir </> certificatePath)
        samlBaseURL <- mkURI $ "https://" <> host <> "/" <> decodeUtf8 path
        metadataURL <- appendPath samlBaseURL <$> mkPathPiece "metadata"
        loginURL <- appendPath samlBaseURL <$> mkPathPiece "login"
        logoutURL <- appendPath samlBaseURL <$> mkPathPiece "logout"
        let sp = M.SP metadataURL loginURL logoutURL certificate certificate
        let env = N.Env idp sp
        pure $ SP env certificate key on off
      where
        appendPath uri piece = uri & uriPath %~ (++ [piece])


------------------------------------------------------------------------------
init :: Login b -> Logout b -> SnapletInit b (SP b)
init on off = makeSnaplet "sp" description C.dir $
    getSnapletUserConfig >>= liftIO . C.load >>= load on off
  where
    description = "SAML Service Provider snaplet"


------------------------------------------------------------------------------
metadata :: Handler b (SP b) ()
metadata = do
    SP (N.Env _ sp) _ key _ _ <- ask
    modifyResponse $ setContentType "application/xml"
    markup <- liftIO $ buildSignSP key sp
    writeLBS $ renderMarkup markup


------------------------------------------------------------------------------
login :: Handler b (SP b) a
login = receiveLogin <|> sendLogin


------------------------------------------------------------------------------
logout :: Handler b (SP b) a
logout = receiveLogout <|> receiveLogoutResponse <|> sendLogout


------------------------------------------------------------------------------
sendLogin :: Handler b (SP b) a
sendLogin = do
    request <- run N.prelogin
    send Redirect request empty


------------------------------------------------------------------------------
receiveLogin :: Handler b (SP b) a
receiveLogin = do
    (response, relay) <- receive POST
    run $ N.postlogin response
    redirect $ maybe "/" renderBs relay


------------------------------------------------------------------------------
sendLogout :: Handler b (SP b) a
sendLogout = do
    request <- run N.precologout
    send Redirect request empty


------------------------------------------------------------------------------
receiveLogout :: Handler b (SP b) a
receiveLogout = do
    (request, relay) <- receive Redirect
    response <- run $ N.logout request
    send Redirect response relay


------------------------------------------------------------------------------
receiveLogoutResponse :: Handler b (SP b) a
receiveLogoutResponse = do
    (response, relay) <- receive Redirect
    run $ N.postcologout response
    redirect $ maybe "/" renderBs relay
