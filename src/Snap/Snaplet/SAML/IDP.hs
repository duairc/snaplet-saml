{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

module Snap.Snaplet.SAML.IDP
    ( IDP, init, login, logout
    , Attributes
    )
where

-- base ----------------------------------------------------------------------
import           Control.Applicative ((<|>))
import           Control.Arrow ((&&&))
import           Control.Exception (throwIO)
import           Control.Monad ((>=>))
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.IORef (IORef, atomicModifyIORef')
import           Data.Function ((&))
import           Data.Monoid ((<>))
import           Data.Tuple (swap)
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)
import           Prelude hiding (init, lookup)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze.Renderer.Utf8 (renderMarkupBuilder)


-- directory -----------------------------------------------------------------
import           System.Directory (createDirectoryIfMissing, listDirectory)


-- filepath ------------------------------------------------------------------
import           System.FilePath ((</>), takeExtension)


-- lens ----------------------------------------------------------------------
import           Control.Lens.Setter ((%~))


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, mkURI, mkPathPiece, render, renderBs)
import           Text.URI.Lens (uriPath)


-- mtl -----------------------------------------------------------------------
import           Control.Monad.Reader.Class (MonadReader, ask, asks, local)
import           Control.Monad.State.Class (MonadState)
import qualified Control.Monad.State.Class


-- snap ----------------------------------------------------------------------
import           Snap.Snaplet
                     ( SnapletInit, Initializer, makeSnaplet, withTop'
                     , getSnapletRootURL, getSnapletUserConfig
                     , getSnapletFilePath
                     , Handler, addRoutes
                     )


-- snap-core -----------------------------------------------------------------
import           Snap.Core
                     ( modifyResponse, setContentType, redirect, writeBuilder
                     )


-- snap-snaplet-saml ---------------------------------------------------------
import qualified Data.X509.IO as XIO
import           Network.SAML.Common (Attributes, SessionIndex)
import           Network.SAML.Message (Message)
import           Network.SAML.Metadata (parseSP, buildSignIDP)
import qualified Network.SAML.Metadata as M
import           Network.SAML.Protocol.IDP (MonadIDP, Env, State)
import qualified Network.SAML.Protocol.IDP as N
import           Snap.Snaplet.SAML.Binding (Binding)
import qualified Snap.Snaplet.SAML.Binding as B
import           Snap.Snaplet.SAML.Binding.Redirect (Proxy (Redirect))
import           Snap.Snaplet.SAML.Binding.POST (Proxy (POST))
import           Snap.Snaplet.SAML.Common (current)
import           Snap.Snaplet.SAML.Config (Config)
import qualified Snap.Snaplet.SAML.Config as C


-- text ----------------------------------------------------------------------
import           Data.Text.Encoding (decodeUtf8)


-- time ----------------------------------------------------------------------
import           Data.Time.Clock (UTCTime)


-- unordered-containers ------------------------------------------------------
import qualified Data.HashMap.Strict as H


-- x509 ----------------------------------------------------------------------
import           Data.X509 (PrivKey, SignedCertificate)


-- xml-conduit ---------------------------------------------------------------
import qualified Text.XML as X


------------------------------------------------------------------------------
data IDP b = IDP
    { environment :: !Env
    , state :: !(IORef State)
    , certificate :: !SignedCertificate
    , key :: !PrivKey
    , on :: !(Login b)
    , off :: !(Logout b)
    , lookup :: !(Lookup b)
    }
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
newtype IDPM b a = IDPM
    { run :: Handler b (IDP b) a
    }
  deriving (Functor, Applicative, Monad, MonadIO)


------------------------------------------------------------------------------
instance MonadReader Env (IDPM b) where
    ask = IDPM $ asks environment
    local f (IDPM m) = IDPM $ local f' m
      where
        f' (IDP e s c k n o l) = IDP (f e) s c k n o l


------------------------------------------------------------------------------
instance MonadState State (IDPM b) where
    state f = IDPM $ do
        ref <- asks state
        liftIO $ atomicModifyIORef' ref (swap . f)


------------------------------------------------------------------------------
instance MonadIDP (IDPM b) where
    on = IDPM $ asks on >>= withTop' id
    off = IDPM $ asks off >>= withTop' id
    lookup = IDPM $ asks lookup >>= withTop' id


------------------------------------------------------------------------------
send :: (Binding binding, Message a)
    => proxy binding -> a -> Maybe URI -> Handler b (IDP b) x
send binding message relay = do
    key <- asks key
    certificate <- asks certificate
    B.send binding (pure (key, pure certificate)) message relay


------------------------------------------------------------------------------
receive :: (Binding binding, Message a)
    => proxy binding -> Handler b (IDP b) (a, Maybe URI)
receive binding = do
    N.Env _ sps <- asks environment
    let certificates = foldMap go sps
    B.receive binding (pure certificates)
  where
    go (M.SP _ _ _ certificate _) = [certificate]


------------------------------------------------------------------------------
type Login b = Handler b b (SessionIndex, Attributes, UTCTime)


------------------------------------------------------------------------------
type Logout b = Handler b b ()


------------------------------------------------------------------------------
type Lookup b = Handler b b (Maybe SessionIndex)


------------------------------------------------------------------------------
load :: Login b -> Logout b -> Lookup b -> Config
    -> Initializer b (IDP b) (IDP b)
load on off lookup config = do
    dir <- getSnapletFilePath
    addRoutes
        [ ("metadata", metadata)
        , ("login", login)
        , ("logout", logout)
        ]
    getSnapletRootURL >>= go dir
  where
    C.Config host = config
    spPath = "sp"
    keyPath = "key.pem"
    certificatePath = "certificate.pem"
    go dir path = liftIO $ do
        let dir' = dir </> spPath
        createDirectoryIfMissing False dir'
        spFiles <- filter ((== ".xml") . takeExtension) <$> listDirectory dir'
        let spPaths = (dir' </>) <$> spFiles
        sps <- traverse (X.readFile X.def >=> either throwIO pure . parseSP)
            spPaths
        let sps' = H.fromList $ (spUrl &&& id) <$> sps
        [key] <- XIO.readKeyFile (dir </> keyPath)
        certificate : _ <- XIO.readCertificateFile (dir </> certificatePath)
        samlBaseURL <- mkURI $ "https://" <> host <> "/" <> decodeUtf8 path
        metadataURL <- appendPath samlBaseURL <$> mkPathPiece "metadata"
        loginURL <- appendPath samlBaseURL <$> mkPathPiece "login"
        logoutURL <- appendPath samlBaseURL <$> mkPathPiece "logout"
        let idp = M.IDP metadataURL loginURL logoutURL certificate certificate
        let env = N.Env idp sps'
        state <- liftIO N.init
        pure $ IDP env state certificate key on off lookup
      where
        appendPath uri piece = uri & uriPath %~ (++ [piece])
        spUrl (M.SP url _ _ _ _) = render url


------------------------------------------------------------------------------
init :: Login b -> Logout b -> Lookup b -> SnapletInit b (IDP b)
init on off lookup = makeSnaplet "saml" description C.dir $
    getSnapletUserConfig >>= liftIO . C.load >>= load on off lookup
  where
    description = "SAML Identity Provider snaplet"


------------------------------------------------------------------------------
metadata :: Handler b (IDP b) ()
metadata = do
    IDP (N.Env idp _) _ _ key _ _ _ <- ask
    modifyResponse $ setContentType "application/xml; charset=utf-8"
    markup <- liftIO $ buildSignIDP key idp
    writeBuilder $ renderMarkupBuilder markup


------------------------------------------------------------------------------
login :: Handler b (IDP b) a
login = receiveLogin


------------------------------------------------------------------------------
logout :: Handler b (IDP b) a
logout = receiveLogout <|> receiveLogoutResponse <|> sendLogout


------------------------------------------------------------------------------
receiveLogin :: Handler b (IDP b) a
receiveLogin = do
    (request, relay) <- receive Redirect
    response <- run $ N.login request
    send POST response relay


------------------------------------------------------------------------------
sendLogout :: Handler b (IDP b) a
sendLogout = do
    mrequest <- run N.prelogout
    case mrequest of
        Nothing -> redirect "/"
        Just request -> send Redirect request . pure =<< current


------------------------------------------------------------------------------
receiveLogout :: Handler b (IDP b) a
receiveLogout = do
    (request, relay) <- receive Redirect
    reply <- run $ N.cologout request
    either (send Redirect) (send Redirect) reply relay


------------------------------------------------------------------------------
receiveLogoutResponse :: Handler b (IDP b) a
receiveLogoutResponse = do
    (response, relay) <- receive Redirect
    meresponse <- run $ N.postlogout response
    case meresponse of
        Nothing -> case relay of
            Nothing -> redirect "/"
            Just uri -> redirect $ renderBs uri
        Just reply -> do
            either (send Redirect) (send Redirect) reply relay
