{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Snap.Snaplet.SAML.Binding.Redirect
    ( Redirect, Proxy (Redirect), send, receive
    )
where

-- asn1-encoding -------------------------------------------------------------
import           Data.ASN1.BinaryEncoding (BER (BER), DER (DER))
import           Data.ASN1.Encoding (encodeASN1', decodeASN1')


-- asn1-types ----------------------------------------------------------------
import           Data.ASN1.Types
                     ( ASN1 (Start, IntVal, End)
                     , ASN1ConstructionType (Sequence)
                     )


-- base ----------------------------------------------------------------------
import           Control.Applicative (empty)
import           Control.Exception (Exception, throwIO)
import           Control.Monad (unless)
import           Control.Monad.IO.Class (liftIO)
import           Data.Bitraversable (bitraverse)
import           Data.Bits ((.&.), shiftR)
import           Data.Char (intToDigit, isAlphaNum)
import           Data.Foldable (fold, traverse_)
import           Data.Function ((&))
import           Data.List (intersperse)
import           Data.Maybe (mapMaybe)
import           Data.Monoid (Any (Any), Ap (Ap), getAp)
import           Data.Proxy (Proxy (Proxy))
import           Data.Tuple (swap)
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- base64-bytestring ---------------------------------------------------------
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.Lazy as L64


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze.Renderer.Utf8 (renderMarkup)


-- bytestring ----------------------------------------------------------------
import           Data.ByteString (ByteString)
import           Data.ByteString.Builder (byteString, toLazyByteString)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as L


-- cryptonite ----------------------------------------------------------------
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import           Crypto.PubKey.RSA.Types (Error)


-- lens ----------------------------------------------------------------------
import           Control.Lens.Setter ((%~))


-- modern-uri ----------------------------------------------------------------
import           Text.URI
                     ( QueryParam (QueryParam), mkQueryKey, mkQueryValue
                     , URI, render, renderBs
                     )
import           Text.URI.Lens (uriQuery)


-- snap-core -----------------------------------------------------------------
import           Snap.Core


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
                     , UnsupportedSignatureAlgorithm (..)
                     )
import qualified Snap.Snaplet.SAML.Binding as B


-- text ----------------------------------------------------------------------
import           Data.Text (Text)
import           Data.Text.Encoding (decodeUtf8, encodeUtf8)
import           Data.Text.Lazy (toStrict)
import           Data.Text.Lazy.Builder (fromText, singleton, toLazyText)


-- x509 ----------------------------------------------------------------------
import           Data.X509
                     ( HashALG (HashSHA256), SignatureALG (SignatureALG)
                     , PubKey, PrivKey, SignedCertificate, privkeyToAlg
                     , certPubKey, getCertificate
                     )
import qualified Data.X509 as X509


-- xml-conduit ---------------------------------------------------------------
import qualified Text.XML as X


-- zlib ----------------------------------------------------------------------
import           Codec.Compression.Zlib.Raw (compress, decompress)


------------------------------------------------------------------------------
data Redirect
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
pattern Redirect :: Proxy Redirect
pattern Redirect = Proxy
{-# COMPLETE Redirect #-}


------------------------------------------------------------------------------
instance Binding Redirect where
    send _ = send
    receive _ = receive


------------------------------------------------------------------------------
receive :: forall a m. (Message a, MonadSnap m)
    => Maybe [SignedCertificate] -> m (a, Maybe URI)
receive mcertificates = do
    qparam <- maybe empty pure =<< getParam param
    message <- liftIO $ either fail pure (L64.decode (L.fromStrict qparam))
        >>= either throwIO pure . X.parseLBS X.def . decompress
        >>= either throwIO pure . parse
    relay <- getParam "RelayState" >>=
        traverse (either (liftIO . throwIO) pure . parseURL . decodeUtf8)
    traverse_ validate mcertificates
    pure (message, relay)
  where
    a :: Proxy a
    a = Proxy
    param = case M.param a of
        SAMLRequest -> "SAMLRequest"
        SAMLResponse -> "SAMLResponse"
    validate certificates = do
        malgorithm <- (>>= flip lookup (map swap algorithms) . decodeUtf8)
            <$> getParam "SigAlg"
        hash <- liftIO $ case malgorithm of
            Just (SignatureALG hash _) -> pure hash
            _ -> throwIO UnsupportedSignatureAlgorithm
        signature <- getParam "Signature"
            >>= maybe (liftIO (throwIO SignatureVerificationFailed)) pure
            >>= either (liftIO . fail) pure . B64.decode
        query <- getsRequest rqQueryString
        let go key = verify key hash (toverify query) signature
        Any valid <- liftIO $ getAp $ foldMap (Ap . fmap Any . go) keys
        liftIO $ unless valid $ throwIO SignatureVerificationFailed
      where
        encode k v = byteString k <> "=" <> byteString v
        toverify query = L.toStrict $ toLazyByteString $ fold $
            intersperse "&" $ mapMaybe go [param, "RelayState", "SigAlg"]
          where
            go = fmap (uncurry encode) . flip locate query
        keys = certPubKey . getCertificate <$> certificates
    locate key query = fmap ((,) key) value
      where
        needle = key <> "="
        n = B.length needle
        value = go query
        go bytes = case B.breakSubstring needle bytes of
            (before, after) -> case B.unsnoc before of
                Just (_, c) | c /= '&' -> go after'
                _ | B.null after -> empty
                _ -> pure $ B.takeWhile (/= '&') after'
              where
                after' = B.drop n after


------------------------------------------------------------------------------
send :: forall a m b. (Message a, MonadSnap m)
    => Maybe (PrivKey, Maybe SignedCertificate) -> a -> Maybe URI -> m b
send mkey message relay = case mkey of
    Nothing -> go $ (param, value) : maybe empty pure mrelay
    Just (key, _) -> do
        aparam <- either (liftIO . throwIO) pure eaparam
        go =<< liftIO (params aparam)
      where
        algorithm = privkeyToAlg key
        hash = HashSHA256
        eaparam = maybe err (pure . (,) "SigAlg") $ lookup alg algorithms
          where
            alg = SignatureALG hash algorithm
            err = Left UnsupportedSignatureAlgorithm
        params (akey, avalue) = do
            signature <- sign key hash tosign
            let svalue = decodeUtf8 $ B64.encode signature
            pure $ (param, value) : maybe id (:) mrelay
                [(akey, avalue), (skey, svalue)]
          where
            tosign = encodeUtf8 $ toStrict $ toLazyText $ mconcat
                [ encode param value
                , maybe mempty (("&" <>) . uncurry encode) mrelay
                , "&" <> encode akey avalue
                ]
              where
                encode k v = mconcat
                    [ fromText $ percent $ encodeUtf8 k
                    , "="
                    , fromText $ percent $ encodeUtf8 v
                    ]
            skey = "Signature"
  where
    a :: Proxy a
    a = Proxy
    param = case M.param a of
        SAMLRequest -> "SAMLRequest"
        SAMLResponse -> "SAMLResponse"
    value = decodeUtf8 $ L.toStrict $ L64.encode $ compress $ renderMarkup $
        build message mempty
    mrelay = ((,) "RelayState") . render <$> relay
    go params = do
        qparams <- liftIO $ traverse qparam params
        let uri' = uri & uriQuery %~ (++ qparams)
        redirect $ renderBs uri'
      where
        qparam = fmap (uncurry QueryParam) . bitraverse mkQueryKey mkQueryValue
        uri = M.destination message


------------------------------------------------------------------------------
sign :: PrivKey -> HashALG -> ByteString -> IO ByteString
sign key hash = case key of
    X509.PrivKeyDSA dsa -> fmap fromSignature . go
      where
        go = case hash of
            X509.HashMD2 -> DSA.sign dsa Hash.MD2
            X509.HashMD5 -> DSA.sign dsa Hash.MD5
            X509.HashSHA1 -> DSA.sign dsa Hash.SHA1
            X509.HashSHA224 -> DSA.sign dsa Hash.SHA224
            X509.HashSHA256 -> DSA.sign dsa Hash.SHA256
            X509.HashSHA384 -> DSA.sign dsa Hash.SHA384
            X509.HashSHA512 -> DSA.sign dsa Hash.SHA512
    X509.PrivKeyRSA rsa -> (>>= either (throwIO . E) pure) . go rsa
      where
        go = case hash of
            X509.HashMD2 -> RSA.signSafer (Just Hash.MD2)
            X509.HashMD5 -> RSA.signSafer (Just Hash.MD5)
            X509.HashSHA1 -> RSA.signSafer (Just Hash.SHA1)
            X509.HashSHA224 -> RSA.signSafer (Just Hash.SHA224)
            X509.HashSHA256 -> RSA.signSafer (Just Hash.SHA256)
            X509.HashSHA384 -> RSA.signSafer (Just Hash.SHA384)
            X509.HashSHA512 -> RSA.signSafer (Just Hash.SHA512)
    _ -> \_ -> throwIO UnsupportedSignatureAlgorithm


------------------------------------------------------------------------------
verify :: PubKey -> HashALG -> ByteString -> ByteString -> IO Bool
verify key hash = case key of
    X509.PubKeyDSA dsa -> \input msignature -> case toSignature msignature of
        Nothing -> pure False
        Just signature -> pure $ go dsa signature input
      where
        go = case hash of
            X509.HashMD2 -> DSA.verify Hash.MD2
            X509.HashMD5 -> DSA.verify Hash.MD5
            X509.HashSHA1 -> DSA.verify Hash.SHA1
            X509.HashSHA224 -> DSA.verify Hash.SHA224
            X509.HashSHA256 -> DSA.verify Hash.SHA256
            X509.HashSHA384 -> DSA.verify Hash.SHA384
            X509.HashSHA512 -> DSA.verify Hash.SHA512
    X509.PubKeyRSA rsa -> (pure .) . go rsa
      where
        go = case hash of
            X509.HashMD2 -> RSA.verify (Just Hash.MD2)
            X509.HashMD5 -> RSA.verify (Just Hash.MD5)
            X509.HashSHA1 -> RSA.verify (Just Hash.SHA1)
            X509.HashSHA224 -> RSA.verify (Just Hash.SHA224)
            X509.HashSHA256 -> RSA.verify (Just Hash.SHA256)
            X509.HashSHA384 -> RSA.verify (Just Hash.SHA384)
            X509.HashSHA512 -> RSA.verify (Just Hash.SHA512)
    _ -> \_ _ -> throwIO UnsupportedSignatureAlgorithm


------------------------------------------------------------------------------
algorithms :: [(SignatureALG, Text)]
algorithms =
    [ (alg rsa sha1, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    , (alg rsa sha256, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    , (alg rsa sha384, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
    , (alg rsa sha512, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")
    , (alg dsa sha1, "http://www.w3.org/2000/09/xmldsig#dsa-sha1")
    ]
  where
    alg = flip SignatureALG
    dsa = X509.PubKeyALG_DSA
    rsa = X509.PubKeyALG_RSA
    sha1 = X509.HashSHA1
    sha256 = X509.HashSHA256
    sha384 = X509.HashSHA384
    sha512 = X509.HashSHA512


------------------------------------------------------------------------------
percent :: ByteString -> Text
percent = percentWith "!$'()*,-./:;?@_~"


------------------------------------------------------------------------------
percentWith :: String -> ByteString -> Text
percentWith set = toStrict . toLazyText . foldMap go . B.unpack
  where
    go c
        | c == ' ' = "+"
        | escape c = "%" <> singleton h <> singleton l
        | otherwise = singleton c
      where
        i = fromEnum c
        h = intToDigit $ (i `shiftR` 4) .&. 0xf
        l = intToDigit $ i .&. 0xf
    escape x = not $ isAlphaNum x || elem x set


------------------------------------------------------------------------------
toSignature :: ByteString -> Maybe DSA.Signature
toSignature b = case decodeASN1' BER b of
    Right (Start Sequence : IntVal r : IntVal s : End Sequence : _) ->
        pure $ DSA.Signature r s
    _ -> empty


------------------------------------------------------------------------------
fromSignature :: DSA.Signature -> ByteString
fromSignature (DSA.Signature r s) =
    encodeASN1' DER [Start Sequence, IntVal r, IntVal s, End Sequence]


------------------------------------------------------------------------------
newtype E = E Error
  deriving (Show, Typeable, Exception)
