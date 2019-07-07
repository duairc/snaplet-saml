{-# OPTIONS_GHC -fno-warn-orphans #-}

module Data.X509.IO
    ( readASN1ObjectBytes, readASN1ObjectBytesLazy, readASN1ObjectFile
    , writeASN1ObjectBytes, writeASN1ObjectBytesLazy, writeASN1ObjectFile
    , readSignedObjectBytes, readSignedObjectBytesLazy, readSignedObjectFile
    , writeSignedObjectBytes, writeSignedObjectBytesLazy
    , writeSignedObjectFile
    , readKeyBytes, readKeyBytesLazy, readKeyFile
    , writeKeyBytes, writeKeyBytesLazy, writeKeyFile
    , readCertificateBytes, readCertificateBytesLazy, readCertificateFile
    , writeCertificateBytes, writeCertificateBytesLazy, writeCertificateFile
    )
where

-- asn1-types ----------------------------------------------------------------
import           Data.ASN1.Types
                     ( ASN1Object, fromASN1, toASN1
                     , ASN1
                        ( Start, BitString, IntVal, OctetString, OID, Null
                        , End
                        )
                     , ASN1Class (Context)
                     , ASN1ConstructionType (Container, Sequence)
                     )
import           Data.ASN1.BitArray (BitArray (BitArray), bitArrayGetData)


-- asn1-encoding -------------------------------------------------------------
import           Data.ASN1.BinaryEncoding (BER (BER), DER (DER))
import           Data.ASN1.Encoding (encodeASN1', decodeASN1')


-- base ----------------------------------------------------------------------
import           Data.Bifunctor (first)
import           Data.Either (rights)


-- bytestring ----------------------------------------------------------------
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L


-- cryptonite ----------------------------------------------------------------
import           Crypto.Number.Serialize (i2osp, os2ip)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA as RSA
import           Crypto.PubKey.ECC.Types (CurveName (..))


-- pem -----------------------------------------------------------------------
import           Data.PEM
                     ( PEM (PEM), pemWriteBS, pemParseBS
                     , pemWriteLBS, pemParseLBS
                     )


-- x509 ----------------------------------------------------------------------
import           Data.X509
                     ( PrivKey (PrivKeyRSA, PrivKeyDSA, PrivKeyEC)
                     , PrivKeyEC (PrivKeyEC_Named, PrivKeyEC_Prime)
                     , SerializedPoint (SerializedPoint)
                     , SignedCertificate, SignedExact
                     , decodeSignedObject, encodeSignedObject
                     )
import           Data.X509.EC (lookupCurveNameByOID)


------------------------------------------------------------------------------
instance ASN1Object RSA.PrivateKey where
    fromASN1 (Start Sequence : IntVal 0 : IntVal n : IntVal e : IntVal d
        : IntVal p : IntVal q : IntVal dP : IntVal dQ : IntVal qinv
        : End Sequence : as) = pure (key, as)
      where
        key = RSA.PrivateKey (RSA.PublicKey (go n 1) n e) d p q dP dQ qinv
        go m i
            | 2 ^ (i * 8) > m = i
            | otherwise = go m (i + 1)
    fromASN1 (Start Sequence : IntVal 0 : Start Sequence
        : OID [1, 2, 840, 113549, 1, 1, 1] : Null : End Sequence
        : OctetString bytes : End Sequence : as) = do
            asn1 <- first failure $ decodeASN1' BER bytes
            fmap (const as) <$> fromASN1 asn1
      where
        failure = ("RSA.PrivateKey.fromASN1: " ++) . show
    fromASN1 _ = Left "RSA.PrivateKey.fromASN1: unexpected format"

    toASN1 key = (++)
        [ Start Sequence, IntVal 0, IntVal n, IntVal e, IntVal d, IntVal p
        , IntVal q, IntVal dP, IntVal dQ, IntVal qinv, End Sequence
        ]
      where
        RSA.PrivateKey (RSA.PublicKey _ n e) d p q dP dQ qinv = key


------------------------------------------------------------------------------
instance ASN1Object DSA.PrivateKey where
    fromASN1 (Start Sequence : IntVal 0 : IntVal p : IntVal q : IntVal g
        : IntVal _ : IntVal x : End Sequence : as) =
            pure (DSA.PrivateKey (DSA.Params p g q) x, as)
    fromASN1 (Start Sequence : IntVal 0 : Start Sequence
        : OID [1, 2, 840, 10040, 4, 1] : Start Sequence : IntVal p : IntVal q
        : IntVal g : End Sequence : End Sequence : OctetString bytes
        : End Sequence : as) = case decodeASN1' BER bytes of
            Right [IntVal x] -> pure (DSA.PrivateKey (DSA.Params p g q) x, as)
            Right _ -> Left "DSA.PrivateKey.fromASN1: unexpected format"
            Left e -> Left $ "DSA.PrivateKey.fromASN1: " ++ show e
    fromASN1 _ = Left "DSA.PrivateKey.fromASN1: unexpected format"

    toASN1 (DSA.PrivateKey params@(DSA.Params p g q) y) = (++)
        [ Start Sequence, IntVal 0, IntVal p, IntVal q, IntVal g, IntVal x
        , IntVal y, End Sequence
        ]
      where
        x = DSA.calculatePublic params y


------------------------------------------------------------------------------
instance ASN1Object PrivKeyEC where
    fromASN1 = go []
      where
        failing = ("ECDSA.PrivateKey.fromASN1: " ++)
        go acc (Start Sequence : IntVal 1 : OctetString bytes : rest) = do
            key <- subgo (oid ++ acc)
            case rest'' of
                End Sequence : rest''' -> pure (key, rest''')
                _ -> Left $ failing "unexpected EC format"
          where
            d = os2ip bytes
            (oid, rest') = spanTag 0 rest
            (_, rest'') = spanTag 1 rest'
            subgo (OID oid_ : _) = maybe failure success mcurve
              where
                failure = Left $ failing $ "unknown curve " ++ show oid_
                success = Right . flip PrivKeyEC_Named d
                mcurve = lookupCurveNameByOID oid_
            subgo (Start Sequence : IntVal 1 : Start Sequence
                : OID [1, 2, 840, 10045, 1, 1] : IntVal p : End Sequence
                : Start Sequence : OctetString a : OctetString b : BitString s
                : End Sequence : OctetString g : IntVal o : IntVal c
                : End Sequence : _) =
                    pure $ PrivKeyEC_Prime d a' b' p g' o c s'
              where
                a' = os2ip a
                b' = os2ip b
                g' = SerializedPoint g
                s' = os2ip $ bitArrayGetData s
            subgo (Null : rest_) = subgo rest_
            subgo [] = Left $ failing "curve is missing"
            subgo _ = Left $ failing "unexpected curve format"
        go acc (Start Sequence : IntVal 0 : Start Sequence
            : OID [1, 2, 840, 10045, 2, 1] : rest) = case rest' of
                (OctetString bytes : rest'') -> do
                    asn1 <- first (failing . show) (decodeASN1' BER bytes)
                    fmap (const rest'') <$> go (oid ++ acc) asn1
                _ -> Left $ failing "unexpected EC format"
          where
            (oid, rest') = spanEnd 0 rest
        go _ _ = Left $ failing "unexpected EC format"

    toASN1 (PrivKeyEC_Named curveName d) = (++)
        [ Start Sequence, IntVal 1, OctetString (i2osp d)
        , Start (Container Context 0), OID oid, End (Container Context 0)
        , End Sequence
        ]
      where
        oid = case curveName of
            SEC_p112r1 -> [1, 3, 132, 0, 6]
            SEC_p112r2 -> [1, 3, 132, 0, 7]
            SEC_p128r1 -> [1, 3, 132, 0, 28]
            SEC_p128r2 -> [1, 3, 132, 0, 29]
            SEC_p160k1 -> [1, 3, 132, 0, 9]
            SEC_p160r1 -> [1, 3, 132, 0, 8]
            SEC_p160r2 -> [1, 3, 132, 0, 30]
            SEC_p192k1 -> [1, 3, 132, 0, 31]
            SEC_p192r1 -> [1, 2, 840, 10045, 3, 1, 1]
            SEC_p224k1 -> [1, 3, 132, 0, 32]
            SEC_p224r1 -> [1, 3, 132, 0, 33]
            SEC_p256k1 -> [1, 3, 132, 0, 10]
            SEC_p256r1 -> [1, 2, 840, 10045, 3, 1, 7]
            SEC_p384r1 -> [1, 3, 132, 0, 34]
            SEC_p521r1 -> [1, 3, 132, 0, 35]
            SEC_t113r1 -> [1, 3, 132, 0, 4]
            SEC_t113r2 -> [1, 3, 132, 0, 5]
            SEC_t131r1 -> [1, 3, 132, 0, 22]
            SEC_t131r2 -> [1, 3, 132, 0, 23]
            SEC_t163k1 -> [1, 3, 132, 0, 1]
            SEC_t163r1 -> [1, 3, 132, 0, 2]
            SEC_t163r2 -> [1, 3, 132, 0, 15]
            SEC_t193r1 -> [1, 3, 132, 0, 24]
            SEC_t193r2 -> [1, 3, 132, 0, 25]
            SEC_t233k1 -> [1, 3, 132, 0, 26]
            SEC_t233r1 -> [1, 3, 132, 0, 27]
            SEC_t239k1 -> [1, 3, 132, 0, 3]
            SEC_t283k1 -> [1, 3, 132, 0, 16]
            SEC_t283r1 -> [1, 3, 132, 0, 17]
            SEC_t409k1 -> [1, 3, 132, 0, 36]
            SEC_t409r1 -> [1, 3, 132, 0, 37]
            SEC_t571k1 -> [1, 3, 132, 0, 38]
            SEC_t571r1 -> [1, 3, 132, 0, 39]
    toASN1 (PrivKeyEC_Prime d a b p g o c s) = (++)
        [ Start Sequence, IntVal 1, OctetString (i2osp d)
        , Start (Container Context 0), Start Sequence, IntVal 1
        , Start Sequence, OID [1, 2, 840, 10045, 1, 1], IntVal p, End Sequence
        , Start Sequence, OctetString a', OctetString b', BitString s'
        , End Sequence, OctetString g' , IntVal o, IntVal c, End Sequence
        , End (Container Context 0), End Sequence
        ]
      where
        a' = i2osp a
        b' = i2osp b
        SerializedPoint g' = g
        s' = BitArray (8 * fromIntegral (B.length bytes)) bytes
          where
            bytes = i2osp s


------------------------------------------------------------------------------
asn1ToPEM :: String -> [ASN1] -> PEM
asn1ToPEM name = PEM name [] . encodeASN1' DER


------------------------------------------------------------------------------
pemToASN1 :: PEM -> Either String [ASN1]
pemToASN1 (PEM _ _ content) = first show $ decodeASN1' BER content


------------------------------------------------------------------------------
asn1ObjectToPEM :: ASN1Object a => String -> a -> PEM
asn1ObjectToPEM name = asn1ToPEM name . flip toASN1 []


------------------------------------------------------------------------------
pemToASN1Object :: ASN1Object a => PEM -> Either String a
pemToASN1Object pem = fmap fst $ pemToASN1 pem >>= fromASN1


------------------------------------------------------------------------------
readASN1ObjectBytes :: ASN1Object a => ByteString -> [a]
readASN1ObjectBytes = either (const []) (rights . fmap pemToASN1Object)
    . pemParseBS


------------------------------------------------------------------------------
readASN1ObjectBytesLazy :: ASN1Object a => L.ByteString -> [a]
readASN1ObjectBytesLazy = either (const []) (rights . fmap pemToASN1Object)
    . pemParseLBS


------------------------------------------------------------------------------
readASN1ObjectFile :: ASN1Object a => FilePath -> IO [a]
readASN1ObjectFile = fmap readASN1ObjectBytes . B.readFile


------------------------------------------------------------------------------
writeASN1ObjectBytes :: ASN1Object a => String -> [a] -> ByteString
writeASN1ObjectBytes name = foldMap (pemWriteBS . asn1ObjectToPEM name)


------------------------------------------------------------------------------
writeASN1ObjectBytesLazy :: ASN1Object a => String -> [a] -> L.ByteString
writeASN1ObjectBytesLazy name = foldMap (pemWriteLBS . asn1ObjectToPEM name)


------------------------------------------------------------------------------
writeASN1ObjectFile :: ASN1Object a => String -> FilePath -> [a] -> IO ()
writeASN1ObjectFile name path = L.writeFile path
    . writeASN1ObjectBytesLazy name


------------------------------------------------------------------------------
signedObjectToPEM :: (ASN1Object a, Eq a, Show a)
    => String -> SignedExact a -> PEM
signedObjectToPEM name = PEM name [] . encodeSignedObject


------------------------------------------------------------------------------
pemToSignedObject :: (ASN1Object a, Eq a, Show a)
    => PEM -> Either String (SignedExact a)
pemToSignedObject (PEM _ _ content) = decodeSignedObject content


------------------------------------------------------------------------------
readSignedObjectBytes :: (Eq a, Show a, ASN1Object a)
    => ByteString -> [SignedExact a]
readSignedObjectBytes = either (const []) (rights . fmap pemToSignedObject)
    . pemParseBS


------------------------------------------------------------------------------
readSignedObjectBytesLazy :: (Eq a, Show a, ASN1Object a)
    => L.ByteString -> [SignedExact a]
readSignedObjectBytesLazy = either (const []) (rights . fmap pemToSignedObject)
    . pemParseLBS


------------------------------------------------------------------------------
readSignedObjectFile :: (Eq a, Show a, ASN1Object a)
    => FilePath -> IO [SignedExact a]
readSignedObjectFile = fmap readSignedObjectBytes . B.readFile


------------------------------------------------------------------------------
writeSignedObjectBytes :: (Eq a, Show a, ASN1Object a)
    => String -> [SignedExact a] -> ByteString
writeSignedObjectBytes = foldMap . (pemWriteBS .) . signedObjectToPEM


------------------------------------------------------------------------------
writeSignedObjectBytesLazy :: (Eq a, Show a, ASN1Object a)
    => String -> [SignedExact a] -> L.ByteString
writeSignedObjectBytesLazy = foldMap . (pemWriteLBS .) . signedObjectToPEM


------------------------------------------------------------------------------
writeSignedObjectFile :: (Eq a, Show a, ASN1Object a)
    => String -> FilePath -> [SignedExact a] -> IO ()
writeSignedObjectFile name path = L.writeFile path
    . writeSignedObjectBytesLazy name


------------------------------------------------------------------------------
pemToKey :: PEM -> Either String PrivKey
pemToKey pem@(PEM "PRIVATE KEY" _ _) = pemToASN1Object pem
pemToKey pem@(PEM "RSA PRIVATE KEY" _ _) = PrivKeyRSA <$> pemToASN1Object pem
pemToKey pem@(PEM "DSA PRIVATE KEY"  _ _) = PrivKeyDSA <$> pemToASN1Object pem
pemToKey pem@(PEM "EC PRIVATE KEY" _ _) = PrivKeyEC <$> pemToASN1Object pem
pemToKey (PEM name _ _) = Left $ "Not a key: " ++ name


------------------------------------------------------------------------------
keyToPEM :: PrivKey -> PEM
keyToPEM (PrivKeyRSA key) = asn1ObjectToPEM "RSA PRIVATE KEY" key
keyToPEM (PrivKeyDSA key) = asn1ObjectToPEM "DSA PRIVATE KEY" key
keyToPEM (PrivKeyEC key) = asn1ObjectToPEM "EC PRIVATE KEY" key
keyToPEM key = asn1ObjectToPEM "PRIVATE KEY" key


------------------------------------------------------------------------------
readKeyBytes :: ByteString -> [PrivKey]
readKeyBytes = either (const []) (rights . fmap pemToKey) . pemParseBS


------------------------------------------------------------------------------
readKeyBytesLazy :: L.ByteString -> [PrivKey]
readKeyBytesLazy = either (const []) (rights . fmap pemToKey) . pemParseLBS


------------------------------------------------------------------------------
readKeyFile :: FilePath -> IO [PrivKey]
readKeyFile = fmap readKeyBytes . B.readFile


------------------------------------------------------------------------------
writeKeyBytes :: [PrivKey] -> ByteString
writeKeyBytes = foldMap (pemWriteBS . keyToPEM)


------------------------------------------------------------------------------
writeKeyBytesLazy :: [PrivKey] -> L.ByteString
writeKeyBytesLazy = foldMap (pemWriteLBS . keyToPEM)


------------------------------------------------------------------------------
writeKeyFile :: FilePath -> [PrivKey] -> IO ()
writeKeyFile path = L.writeFile path . writeKeyBytesLazy


------------------------------------------------------------------------------
readCertificateBytes :: ByteString -> [SignedCertificate]
readCertificateBytes = readSignedObjectBytes


------------------------------------------------------------------------------
readCertificateBytesLazy :: L.ByteString -> [SignedCertificate]
readCertificateBytesLazy = readSignedObjectBytesLazy


------------------------------------------------------------------------------
readCertificateFile :: FilePath -> IO [SignedCertificate]
readCertificateFile = readSignedObjectFile


------------------------------------------------------------------------------
writeCertificateBytes :: [SignedCertificate] -> ByteString
writeCertificateBytes = writeSignedObjectBytes "CERTIFICATE"


------------------------------------------------------------------------------
writeCertificateBytesLazy :: [SignedCertificate] -> L.ByteString
writeCertificateBytesLazy = writeSignedObjectBytesLazy "CERTIFICATE"


------------------------------------------------------------------------------
writeCertificateFile :: FilePath -> [SignedCertificate] -> IO ()
writeCertificateFile = writeSignedObjectFile "CERTIFICATE"


------------------------------------------------------------------------------
spanEnd :: Word -> [ASN1] -> ([ASN1], [ASN1])
spanEnd = go id
  where
    go dlist n (a@(Start _) : as) = go (dlist . (a :)) (n + 1) as
    go dlist 0 (End _ : as) = (dlist [], as)
    go dlist n (a@(End _) : as) = go (dlist . (a :)) (n - 1) as
    go dlist n (a : as) = go (dlist . (a :)) n as
    go dlist _ [] = (dlist [], [])


------------------------------------------------------------------------------
spanTag :: Int -> [ASN1] -> ([ASN1], [ASN1])
spanTag a (Start (Container _ b) : as) | a == b = spanEnd 0 as
spanTag _ as = ([], as)
