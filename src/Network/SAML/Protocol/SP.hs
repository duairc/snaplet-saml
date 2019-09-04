{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MonoLocalBinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.SAML.Protocol.SP
    ( MonadSP (on, off), Env (Env)
    , prelogin, postlogin, logout, precologout, postcologout
    )
where

-- base ----------------------------------------------------------------------
import           Control.Applicative (empty)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- mtl -----------------------------------------------------------------------
import           Control.Monad.Reader.Class (MonadReader, ask)


-- snaplet-saml --------------------------------------------------------------
import           Network.SAML.Common (Attributes, NameID, SessionIndex)
import           Network.SAML.Metadata (IDP, SP)
import           Network.SAML.Types
                     ( Assertion (Assertion), Session (Session)
                     , Request, Response (Response)
                     , LogoutRequest (LogoutRequest), LogoutResponse
                     , newRequest
                     , spLogoutRequest, spLogoutResponse
                     )


-- time ----------------------------------------------------------------------
import           Data.Time.Clock (UTCTime)


------------------------------------------------------------------------------
class (MonadIO m, MonadReader Env m) => MonadSP m where
    on :: Attributes -> NameID -> SessionIndex -> UTCTime -> m ()
    off :: Maybe NameID -> Maybe SessionIndex -> m (NameID, SessionIndex)


------------------------------------------------------------------------------
data Env = Env
    { idp :: !IDP
    , sp :: !SP
    }
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
prelogin :: MonadSP m => m Request
prelogin = do
    Env idp sp <- ask
    liftIO $ newRequest idp sp


------------------------------------------------------------------------------
postlogin :: MonadSP m => Response -> m ()
postlogin (Response _ (Assertion _ _ _ _ _ _ attributes _ name session)) = do
    on attributes name sessionIndex ending
  where
    Session sessionIndex _ ending = session


------------------------------------------------------------------------------
logout :: MonadSP m => LogoutRequest -> m LogoutResponse
logout request@(LogoutRequest _ _ _ _ _ name session) = do
    Env idp sp <- ask
    _ <- off (pure name) (pure session)
    liftIO $ spLogoutResponse idp sp request


------------------------------------------------------------------------------
precologout :: MonadSP m => m LogoutRequest
precologout = do
    Env idp sp <- ask
    (name, session) <- off empty empty
    liftIO $ spLogoutRequest idp sp name session


------------------------------------------------------------------------------
postcologout :: MonadSP m => LogoutResponse -> m ()
postcologout _ = pure ()
