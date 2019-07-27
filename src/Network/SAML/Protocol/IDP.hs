{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonoLocalBinds #-}
{-# LANGUAGE NamedFieldPuns #-}

module Network.SAML.Protocol.IDP
    ( MonadIDP, on, off, lookup, Env (Env), State, init
    , login, prelogout, postlogout, cologout
    )
where

-- base ----------------------------------------------------------------------
import           Control.Applicative ((<|>), empty)
import           Control.Concurrent (forkIO, threadDelay)
import           Control.Monad (forever, join)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.Functor (void)
import           Data.IORef (IORef, newIORef, atomicModifyIORef')
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)
import           Prelude hiding (id, init, lookup)


-- insert-ordered-containers -------------------------------------------------
import qualified Data.HashMap.Strict.InsOrd as IOM


-- modern-uri ----------------------------------------------------------------
import           Text.URI (render)


-- mtl -----------------------------------------------------------------------
import           Control.Monad.Reader.Class (MonadReader, ask)
import           Control.Monad.State.Class (MonadState, modify, state)


-- snaplet-saml --------------------------------------------------------------
import           Network.SAML.Common (Attributes, RequestID, SessionIndex)
import           Network.SAML.Metadata (IDP, SP)
import           Network.SAML.Types
                     ( Request (Request), Response
                     , LogoutRequest (LogoutRequest)
                     , LogoutResponse (LogoutResponse)
                     , newResponse
                     , idpLogoutRequest, idpLogoutResponse
                     )
import qualified Network.SAML.Types as T


-- transformers --------------------------------------------------------------
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.Maybe (MaybeT (MaybeT), runMaybeT)


-- text ----------------------------------------------------------------------
import           Data.Text (Text)


-- time ----------------------------------------------------------------------
import           Data.Time.Clock
                     ( UTCTime, addUTCTime, diffUTCTime, getCurrentTime
                     )


-- timeoutmap ----------------------------------------------------------------
import           Data.TimeoutMap (TimeoutMap)
import qualified Data.TimeoutMap as TO


-- unordered-containers ------------------------------------------------------
import           Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as H
import           Data.HashSet (HashSet)
import qualified Data.HashSet as HS


------------------------------------------------------------------------------
class (MonadIO m, MonadReader Env m, MonadState State m) => MonadIDP m where
    on :: m (SessionIndex, Attributes, UTCTime)
    off :: m ()
    lookup :: m (Maybe SessionIndex)


------------------------------------------------------------------------------
type URL = Text


------------------------------------------------------------------------------
data Env = Env
    { idp :: !IDP
    , sps :: !(HashMap URL SP)
    }
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
type State = TimeoutMap SessionIndex Session


------------------------------------------------------------------------------
off' :: MonadIDP m => SessionIndex -> m ()
off' index = do
    now <- liftIO getCurrentTime
    modify $ TO.delete now index
    off


------------------------------------------------------------------------------
data Session = Session
    { attributes :: !Attributes
    , services :: !(HashSet URL)
    , logout :: !(Maybe (URL, RequestID))
    }
  deriving (Show, Generic, Typeable)


------------------------------------------------------------------------------
instance Semigroup Session where
    Session a s l <> Session a' s' l' =
        Session (IOM.unionWith (<>) a a') (s <> s') (l <|> l')


------------------------------------------------------------------------------
instance Monoid Session where
    mempty = Session mempty mempty empty


------------------------------------------------------------------------------
init :: IO (IORef State)
init = do
    ref <- newIORef mempty
    _ <- forkIO $ go ref
    pure ref
  where
    go ref = forever $ do
        threadDelay 600000000
        now <- getCurrentTime
        atomicModifyIORef' ref $ flip (,) () . TO.clean now


------------------------------------------------------------------------------
isession :: MonadIDP m
    => (UTCTime -> SessionIndex -> Session -> UTCTime -> (Session, a))
    -> m (Maybe a)
isession f = do
    mindex <- lookup
    case mindex of
        Nothing -> do
            pure Nothing
        Just index -> do
            now <- liftIO getCurrentTime
            state $ go now index
  where
    go now index sessions = case TO.lookup now index sessions of
        Just (timeout, session) -> (pure result, sessions')
          where
            expiry = addUTCTime timeout now
            (session', result) = f now index session expiry
            (sessions', _) = TO.insert timeout session' now index sessions
        _ -> (empty, sessions)


------------------------------------------------------------------------------
login :: MonadIDP m => Request -> m Response
login request@(Request _ _ url _ _) = do
    Env idp sps <- ask
    sp <- maybe (liftIO empty) pure $ H.lookup service sps
    now <- liftIO getCurrentTime
    (index, attributes, end) <- isession go >>= maybe (new now) pure
    let session = T.Session index now end
    liftIO $ newResponse idp sp 300 attributes request session
  where
    service = render url
    go _ index session end = (session', (index, attributes, end))
      where
        Session attributes services logout = session
        services' = HS.insert service services
        session' = Session attributes services' logout
    new now = do
        result@(index, attributes, end) <- on
        modify $ subgo index attributes end
        pure result
      where
        subgo index attributes end sessions = sessions'
          where
            duration = diffUTCTime end now
            session = Session attributes (HS.singleton service) empty
            (sessions', _) = TO.insert duration session now index sessions


------------------------------------------------------------------------------
send :: MonadIDP m => SessionIndex -> SP -> m LogoutRequest
send index sp = do
    Env idp _ <- ask
    liftIO $ idpLogoutRequest idp sp index index duration
  where
    duration = 300


------------------------------------------------------------------------------
next :: MonadIDP m => m (Maybe SP)
next = do
    Env _ sps <- ask
    fmap join $ isession $ go sps
  where
    go sps _ _ session _ = (session, sp)
      where
        Session _ services _ = session
        shead xs = case mx of
            Nothing -> Nothing
            Just x -> H.lookup x sps <|> shead xs'
              where
                xs' = HS.delete x xs
          where
            mx = foldr (const . pure) empty xs
        sp = shead services


------------------------------------------------------------------------------
remove :: MonadIDP m => URL -> m ()
remove service = void $ isession go
  where
    go _ _ session _ = (session', (services, services'))
      where
        Session attributes services logout = session
        services' = HS.delete service services
        session' = Session attributes services' logout
    

------------------------------------------------------------------------------
finish :: (Show a, MonadIDP m) => m (Maybe a) -> m (Maybe a)
finish = (>>= go)
  where
    go Nothing = off *> pure Nothing
    go (Just a) = pure $ Just a


------------------------------------------------------------------------------
reply :: MonadIDP m => SP -> RequestID -> m LogoutResponse
reply sp request = do
    Env idp _ <- ask
    liftIO $ idpLogoutResponse idp sp request


------------------------------------------------------------------------------
prelogout :: MonadIDP m => m (Maybe LogoutRequest)
prelogout = finish $ runMaybeT $ do
    index <- MaybeT lookup
    sp <- MaybeT next
    MaybeT $ isession go
    lift $ send index sp
  where
    go _ _ session _ = (session', ())
      where
        Session index services _ = session
        session' = Session index services empty


------------------------------------------------------------------------------
postlogout :: MonadIDP m
    => LogoutResponse -> m (Maybe (Either LogoutRequest LogoutResponse))
postlogout input = finish $ runMaybeT $ do
    (index, minitiator) <- MaybeT $ isession $ \_ i s _ -> (s, (i, logout s))
    lift $ remove service
    msp <- lift next
    case msp of
        Nothing -> fmap Right $ case minitiator of
            Nothing -> empty
            Just (initiator, request) -> do
                Env _ sps <- ask
                sp <- maybe empty pure $ H.lookup initiator sps
                lift $ off' index
                lift $ reply sp request
        Just sp -> fmap Left $ lift $ send index sp
  where
    LogoutResponse _ url _ _ _ = input
    service = render url


------------------------------------------------------------------------------
cologout :: MonadIDP m
    => LogoutRequest -> m (Either LogoutRequest LogoutResponse)
cologout (LogoutRequest request url _ _ _ _ _ index) = do
    mindex <- lookup
    case mindex of
        Just index' | index == index' -> do
            remove service
            _ <- isession go
            msp <- next
            case msp of
                Nothing -> off' index *> respond
                Just sp -> fmap Left $ send index sp
        _ -> respond
  where
    service = render url
    go _ _ session _ = (session', ())
      where
        Session index_ services _ = session
        session' = Session index_ services (pure (service, request))
    respond = do
        Env _ sps <- ask
        sp <- maybe (liftIO empty) pure $ H.lookup service sps
        fmap Right $ reply sp request
