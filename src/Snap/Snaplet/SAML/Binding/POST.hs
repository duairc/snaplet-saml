{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Snap.Snaplet.SAML.Binding.POST
    ( POST, Proxy (POST), send, receive
    )
where

-- base ----------------------------------------------------------------------
import           Control.Applicative (empty)
import           Control.Exception (throwIO)
import           Control.Monad (unless)
import           Control.Monad.IO.Class (liftIO)
import           Data.Foldable (for_)
import           Data.Proxy (Proxy (Proxy))
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- base64-bytestring ---------------------------------------------------------
import qualified Data.ByteString.Base64.Lazy as L64


-- blaze-html ----------------------------------------------------------------
import qualified Text.Blaze.XHtml5 as H
import qualified Text.Blaze.XHtml5.Attributes as HA


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze (Markup, (!), textValue)
import           Text.Blaze.Renderer.Utf8 (renderMarkup, renderMarkupBuilder)


-- bytestring ----------------------------------------------------------------
import qualified Data.ByteString.Lazy as L


-- modern-uri ----------------------------------------------------------------
import           Text.URI (URI, render)


-- snap-core -----------------------------------------------------------------
import           Snap.Core
                     ( MonadSnap, finishWith, getParam, getResponse
                     , modifyResponse, setContentType, writeBuilder
                     )


-- snap-snaplet-saml ---------------------------------------------------------
import           Network.SAML.Message
                     ( Param (SAMLRequest, SAMLResponse)
                     , Message, build, parse
                     )
import qualified Network.SAML.Message as M
import           Network.SAML.Types (parseURL)
import           Snap.Snaplet.SAML.Binding
                     ( Binding
                     , SignatureVerificationFailed (..)
                     )
import qualified Snap.Snaplet.SAML.Binding as B
import qualified Text.Blaze.SAML.Protocol as SAMLP
import qualified Text.XML.Signature as X


-- text ----------------------------------------------------------------------
import           Data.Text.Encoding (decodeUtf8)


-- x509 ----------------------------------------------------------------------
import           Data.X509
                     ( HashALG (HashSHA256), SignatureALG (SignatureALG)
                     , PrivKey, SignedCertificate, privkeyToAlg
                     )


-- xml-conduit ---------------------------------------------------------------
import           Text.XML (Document)
import qualified Text.XML as X


------------------------------------------------------------------------------
data POST
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
pattern POST :: Proxy POST
pattern POST = Proxy
{-# COMPLETE POST #-}


------------------------------------------------------------------------------
instance Binding POST where
    send _ = send
    receive _ = receive


------------------------------------------------------------------------------
send :: forall a m b. (Message a, MonadSnap m)
    => Maybe (PrivKey, Maybe SignedCertificate) -> a -> Maybe URI -> m b
send key message relay = do
    payload <- liftIO $ sign key message
    let markup = form (M.destination message) (M.param a) payload relay
    modifyResponse $ setContentType "text/html; charset=utf-8"
    writeBuilder $ renderMarkupBuilder markup
    getResponse >>= finishWith
  where
    a :: Proxy a
    a = Proxy


------------------------------------------------------------------------------
receive :: forall a m. (Message a, MonadSnap m)
    => Maybe [SignedCertificate] -> m (a, Maybe URI)
receive certificates = do
    param <- maybe empty pure =<< getParam (case M.param (Proxy :: Proxy a) of
        SAMLRequest -> "SAMLRequest"
        SAMLResponse -> "SAMLResponse")
    message <- liftIO $ either fail pure (L64.decode $ L.fromStrict param)
        >>= either throwIO pure . X.parseLBS X.def >>= verify certificates
    relay <- getParam "RelayState" >>=
        traverse (either (liftIO . throwIO) pure . parseURL . decodeUtf8)
    pure (message, relay)


------------------------------------------------------------------------------
sign :: Message a
    => Maybe (PrivKey, Maybe SignedCertificate) -> a -> IO Markup
sign Nothing message = build message pure mempty
sign (Just (key, certificate)) message = build message (X.signMarkup key) $
    SAMLP.signature sigAlg hashAlg certificate empty
  where
    sigAlg = SignatureALG hashAlg (privkeyToAlg key)
    hashAlg = HashSHA256


------------------------------------------------------------------------------
verify :: Message a => Maybe [SignedCertificate] -> Document -> IO a
verify Nothing document = either throwIO pure $ parse document
verify (Just certificates) document = do
    valid <- X.verifyDocument certificates document
    unless valid $ throwIO SignatureVerificationFailed
    either throwIO pure $ parse document


------------------------------------------------------------------------------
form :: URI -> Param -> Markup -> Maybe URI -> Markup
form destination param payload mrelay = H.docTypeHtml $ do
    H.head $ do
        H.title "POST data"
        H.script "window.onload = function() {document.forms[0].submit()}"
    H.body $ H.form ! HA.method "post" ! HA.action action $ do
        H.input ! HA.type_ "hidden" ! HA.name name ! HA.value value
        for_ mrelay $ \relay -> H.input ! HA.type_ "hidden"
            ! HA.name "RelayState" ! HA.value (textValue $ render relay)
        H.noscript $ do
            H.p "To complete the login, click the button to proceed."
            H.input ! HA.type_ "submit" ! HA.value "Submit"
  where
    name = textValue $ case param of
        SAMLRequest -> "SAMLRequest"
        SAMLResponse -> "SAMLResponse"
    value = textValue $ decodeUtf8 $ L.toStrict $ L64.encode $
        renderMarkup payload
    action = textValue $ render destination
