{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}

module Network.SAML.Message
    ( Message (param, parse, build, destination)
    , Param (SAMLRequest, SAMLResponse)
    , SignatureVerificationFailed (SignatureVerificationFailed)
    )
where

-- base ----------------------------------------------------------------------
import           Control.Exception (Exception, SomeException)
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze (Markup)


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI)


-- xml-conduit ---------------------------------------------------------------
import           Text.XML (Document)


------------------------------------------------------------------------------
data SignatureVerificationFailed = SignatureVerificationFailed
  deriving (Eq, Ord, Read, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
data Param = SAMLRequest | SAMLResponse
  deriving (Eq, Ord, Read, Show, Generic, Typeable)


------------------------------------------------------------------------------
class Message a where
    param :: proxy a -> Param
    parse :: Document -> Either SomeException a
    build :: Monad m => a -> (Markup -> m Markup) -> Markup -> m Markup
    destination :: a -> URI
