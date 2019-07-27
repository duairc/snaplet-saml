{-# LANGUAGE OverloadedStrings #-}

module Snap.Snaplet.SAML.Common
    ( current
    )
where

-- base ----------------------------------------------------------------------
import           Control.Monad.IO.Class (liftIO)


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, mkURI)


-- snap-core -----------------------------------------------------------------
import           Snap.Core (MonadSnap, rqURI, withRequest)


-- text ----------------------------------------------------------------------
import           Data.Text.Encoding (decodeUtf8)


------------------------------------------------------------------------------
current :: MonadSnap m => m URI
current = withRequest $ liftIO . mkURI . decodeUtf8 . rqURI
