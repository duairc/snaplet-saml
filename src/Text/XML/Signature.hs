{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Text.XML.Signature
    ( signDocument, signMarkup, signFile
    , verifyDocument, verifyMarkup, verifyFile
    , XMLSecException (XMLSecException)
    )
where

-- base ----------------------------------------------------------------------
import           Control.Applicative (empty)
import           Control.Concurrent (forkIO)
import           Control.Exception (Exception, finally, throwIO)
import           Control.Monad (when)
import           Data.Foldable (traverse_)
import           Data.Functor (void)
import           Data.Traversable (for)
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)
import           System.Exit (ExitCode (ExitSuccess, ExitFailure))
import           System.IO (Handle, hClose, openBinaryTempFile)


-- base64-bytestring ---------------------------------------------------------
import qualified Data.ByteString.Base64 as B64


-- blaze-markup --------------------------------------------------------------
import           Text.Blaze (Markup, unsafeByteString)
import           Text.Blaze.Renderer.Utf8 (renderMarkup)


-- bytestring ----------------------------------------------------------------
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L


-- directory -----------------------------------------------------------------
import           System.Directory
                     ( canonicalizePath, getTemporaryDirectory
                     , removeFile, renameFile
                     )


-- process -------------------------------------------------------------------
import           System.Process
                     ( CreateProcess (std_in, std_out, std_err), createProcess
                     , proc
                     , StdStream (CreatePipe, UseHandle, NoStream)
                     , ProcessHandle
                     , terminateProcess, waitForProcess
                     )
import           System.Process.Internals
                     ( ProcessHandle (ProcessHandle), stopDelegateControlC
                     )


-- resource ------------------------------------------------------------------
import           Data.Resource (Resource, resource, with)


-- snap-snaplet-saml ---------------------------------------------------------
import           Data.X509.IO (writeKeyBytesLazy, writeCertificateBytesLazy)


-- text ----------------------------------------------------------------------
import           Data.Text.Encoding (encodeUtf8)


-- transformers --------------------------------------------------------------
import           Control.Monad.Trans.Class (lift)


-- x509 ----------------------------------------------------------------------
import           Data.X509


-- xml-conduit ---------------------------------------------------------------
import           Text.XML (Document)
import qualified Text.XML as X
import           Text.XML.Cursor ((&/), ($/), fromDocument)
import qualified Text.XML.Cursor as X


------------------------------------------------------------------------------
data XMLSecException = XMLSecException !ExitCode !ByteString
  deriving (Eq, Ord, Read, Show, Generic, Typeable, Exception)


------------------------------------------------------------------------------
signDocument :: PrivKey -> Document -> IO Document
signDocument key xml = signBytes key writeXML readXML
  where
    writeXML = flip L.hPutStr (X.renderLBS X.def xml)
    readXML = X.readFile X.def


------------------------------------------------------------------------------
signMarkup :: PrivKey -> Markup -> IO Markup
signMarkup key xml = signBytes key writeXML readXML
  where
    writeXML = flip L.hPutStr (renderMarkup xml)
    readXML = fmap unsafeByteString . B.readFile


------------------------------------------------------------------------------
signFile :: PrivKey -> FilePath -> FilePath -> IO ()
signFile key xml destination = signBytes key writeXML readXML
  where
    writeXML = (L.readFile xml >>=) . L.hPutStr
    readXML source = renameFile source destination


------------------------------------------------------------------------------
signBytes :: PrivKey -> (Handle -> IO ()) -> (FilePath -> IO a) -> IO a
signBytes key xml run = flip with pure $ do
    keyPath <- tempPath "key.pem" $ flip L.hPutStr (writeKeyBytesLazy [key])
    xmlPath <- tempPath "tosign.xml" xml
    (resultPath, resultHandle) <- tempFile "signed.xml"
    (Nothing, Nothing, Just e, p) <- process (cp keyPath xmlPath resultHandle)
    lift $ waitForProcess p >>= \exitCode -> case exitCode of
        ExitSuccess -> do
            hClose resultHandle
            run resultPath
        code@(ExitFailure _) -> do
            errorText <- B.hGetContents e
            throwIO $ XMLSecException code errorText
  where
    cp keyPath xmlPath resultHandle = cp'
        { std_in = NoStream
        , std_out = UseHandle resultHandle
        , std_err = CreatePipe
        }
      where
        cp' = proc "xmlsec1"
            [ "sign", "--privkey-pem", keyPath
            , "--id-attr:ID", "EntityDescriptor", "--id-attr:ID", "Response"
            , "--id-attr:ID", "Request", "--id-attr:ID", "Assertion", xmlPath
            ]


------------------------------------------------------------------------------
verifyDocument :: [SignedCertificate] -> Document -> IO Bool
verifyDocument certs xml = verifyBytes certs $ \handle -> do
    L.hPutStr handle $ X.renderLBS X.def xml
    pure xml


------------------------------------------------------------------------------
verifyMarkup :: [SignedCertificate] -> Markup -> IO Bool
verifyMarkup certs xml = verifyBytes certs $ \handle -> do
    L.hPutStr handle bytes
    either throwIO pure $ X.parseLBS X.def bytes
  where
    bytes = renderMarkup xml


------------------------------------------------------------------------------
verifyFile :: [SignedCertificate] -> FilePath -> IO Bool
verifyFile certs xml = verifyBytes certs $ \handle -> do
    bytes <- L.readFile xml
    L.hPutStr handle bytes
    either throwIO pure $ X.parseLBS X.def bytes


------------------------------------------------------------------------------
verifyBytes :: [SignedCertificate] -> (Handle -> IO Document) -> IO Bool
verifyBytes certs xml = flip with pure $ do
    certPaths <- for certs $ tempPath "cert.pem" . flip L.hPutStr
        . writeCertificateBytesLazy . pure
    (xmlPath, document) <- tempPath' "toverify.xml" xml
    (Nothing, Nothing, Nothing, p) <- process (cp certPaths xmlPath)
    lift $ waitForProcess p >>= \exitCode -> pure $ case exitCode of
        ExitSuccess -> maybe True sameKey $ signatureCertificate document
          where
            sameKey cert = any ((== key) . getKey) certs
              where
                key = getKey cert
            getKey = certPubKey . getCertificate
        _ -> False
  where
    cp certPaths xmlPath = cp'
        { std_in = NoStream
        , std_out = NoStream
        , std_err = NoStream
        }
      where
        cp' = proc "xmlsec1" $ ["verify"] ++ pubkeys ++ intermediates ++ attrs
            ++ [xmlPath]
        pubkeys = foldMap ((:) "--pubkey-cert-pem" . pure) certPaths
        intermediates = foldMap ((:) "--untrusted-pem" . pure) certPaths
        attrs =
            [ "--id-attr:ID", "EntityDescriptor", "--id-attr:ID", "Response"
            , "--id-attr:ID", "Request", "--id-attr:ID", "Assertion"
            ]


------------------------------------------------------------------------------
signatureCertificate :: Document -> Maybe SignedCertificate
signatureCertificate xml = do
    cert64 <- foldr (const . pure) empty $ fromDocument xml
        $/ X.element "{http://www.w3.org/2000/09/xmldsig#}Signature"
        &/ X.element "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
        &/ X.element "{http://www.w3.org/2000/09/xmldsig#}X509Data"
        &/ X.element "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
        &/ X.content
    bytes <- either (const empty) pure $ B64.decode (encodeUtf8 cert64)
    either (const empty) pure $ decodeSignedObject bytes


------------------------------------------------------------------------------
process :: CreateProcess
    -> Resource IO (Maybe Handle, Maybe Handle, Maybe Handle, ProcessHandle)
process cp = resource (createProcess cp) release
  where
    release (i, o, e, p@(ProcessHandle m ctrlC l)) = do
        terminateProcess p `finally` traverse_ hClose i
            `finally` traverse_ hClose o `finally` traverse_ hClose e
        when ctrlC stopDelegateControlC
        void $ forkIO (waitForProcess p' >> pure ())
      where
        p' = ProcessHandle m False l


------------------------------------------------------------------------------
tempFile :: String -> Resource IO (FilePath, Handle)
tempFile prefix = resource acquire release
  where
    acquire = getTemporaryDirectory >>= canonicalizePath
        >>= flip openBinaryTempFile prefix
    release (path, handle) = hClose handle `finally` removeFile path


------------------------------------------------------------------------------
tempPath :: String -> (Handle -> IO ()) -> Resource IO FilePath
tempPath prefix run = do
    (path, handle) <- tempFile prefix
    lift $ run handle >> hClose handle >> pure path


------------------------------------------------------------------------------
tempPath' :: String -> (Handle -> IO a) -> Resource IO (FilePath, a)
tempPath' prefix run = do
    (path, handle) <- tempFile prefix
    lift $ run handle >>= \a -> hClose handle >> pure (path, a)
