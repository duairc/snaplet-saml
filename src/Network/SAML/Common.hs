module Network.SAML.Common
    ( Attributes, NameID, RequestID, ResponseID, SessionIndex
    )
where

-- insert-ordered-containers -------------------------------------------------
import           Data.HashMap.Strict.InsOrd (InsOrdHashMap)
import           Data.HashSet.InsOrd (InsOrdHashSet)


-- text ----------------------------------------------------------------------
import           Data.Text (Text)


------------------------------------------------------------------------------
type Attributes = InsOrdHashMap Text (InsOrdHashSet Text)


------------------------------------------------------------------------------
type NameID = Text


------------------------------------------------------------------------------
type RequestID = Text


------------------------------------------------------------------------------
type ResponseID = Text


------------------------------------------------------------------------------
type SessionIndex = Text
