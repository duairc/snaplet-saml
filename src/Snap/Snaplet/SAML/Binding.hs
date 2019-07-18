{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}

module Snap.Snaplet.SAML.Binding
    ( Binding (send, receive)
    , SignatureVerificationFailed (SignatureVerificationFailed)
    , UnsupportedSignatureAlgorithm (UnsupportedSignatureAlgorithm)
    )
where

-- base ----------------------------------------------------------------------
import           Control.Exception (Exception)
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI)


-- snap-core -----------------------------------------------------------------
import           Snap.Core (MonadSnap)


-- snap-snaplet-saml ---------------------------------------------------------
import           Network.SAML.Message (Message)


-- x509 ----------------------------------------------------------------------
import           Data.X509 (PrivKey, SignedCertificate)


------------------------------------------------------------------------------
data SignatureVerificationFailed = SignatureVerificationFailed
  deriving (Eq, Ord, Read, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
data UnsupportedSignatureAlgorithm = UnsupportedSignatureAlgorithm
  deriving (Eq, Ord, Read, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
class Binding binding where
    send :: (Message a, MonadSnap m) => proxy binding
        -> Maybe (PrivKey, Maybe SignedCertificate) -> a -> Maybe URI -> m b
    receive :: (Message a, MonadSnap m) => proxy binding
        -> Maybe [SignedCertificate] -> m (a, Maybe URI)
