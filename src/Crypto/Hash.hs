module Crypto.Hash (
    HashAlgorithm(..)
  , SHA1
  , SHA224    
  , SHA256
  , SHA384
  , SHA512
  , hash
  , hashLazy
  ) where

import qualified Data.ByteString.Lazy as LBS
import Data.ByteString (ByteString)

import Crypto.Hash.ADT

import Crypto.Hash.SHA1
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512

hash :: (HashAlgorithm a) => ByteString -> a
hash = hashFinal . hashUpdate hashInit

hashLazy :: (HashAlgorithm a) => LBS.ByteString -> a
hashLazy = hashFinal . LBS.foldlChunks hashUpdate hashInit
