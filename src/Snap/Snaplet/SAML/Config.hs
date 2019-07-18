{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Snap.Snaplet.SAML.Config
    ( Config (Config), load, dir
    )
where

-- base ----------------------------------------------------------------------
import           Data.Typeable (Typeable)
import           GHC.Generics (Generic)


-- configurator --------------------------------------------------------------
import           Data.Configurator (require)
import qualified Data.Configurator.Types as C


-- filepath ------------------------------------------------------------------
import           System.FilePath ((</>))


-- snap-snaplet-saml ---------------------------------------------------------
import           Paths_snaplet_saml (getDataDir)


-- text ----------------------------------------------------------------------
import           Data.Text (Text)


------------------------------------------------------------------------------
data Config = Config
    { host :: !Text
    }
  deriving (Generic, Typeable)


------------------------------------------------------------------------------
load :: C.Config -> IO Config
load config = Config
    <$> require config "host"


------------------------------------------------------------------------------
dir :: Maybe (IO FilePath)
dir = Just $ (</> "config") <$> getDataDir
