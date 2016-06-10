-- | pure hash interface, supported hash algorithms:
--
-- * SHA1
--
-- * SHA224/SHA256
--
-- * SHA384/SHA512
--
-- * MD5
--
-- * Whirlpool
--
-- NOTE: performance is just about 1 \/ 5 - 1 \/ 15 of C/ASM implementations.
--
module Crypto.Hash (
    HashAlgorithm(..)
  , SHA1
  , SHA224    
  , SHA256
  , SHA384
  , SHA512
  , MD5
  , Whirlpool
  , hash
  , hashLazy
  ) where

import qualified Data.ByteString.Lazy as LBS
import Data.ByteString (ByteString)

import Crypto.Hash.ADT

import Crypto.Hash.SHA1
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512
import Crypto.Hash.MD5
import Crypto.Hash.Whirlpool

-- | Hash strict byte string
hash :: (HashAlgorithm a) => ByteString -> a
hash = hashFinal . hashUpdate hashInit

-- | Hash lazy byte string
hashLazy :: (HashAlgorithm a) => LBS.ByteString -> a
hashLazy = hashFinal . LBS.foldlChunks hashUpdate hashInit
