{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Hash (
    HasHash(..)
  , SHA224    
  , SHA256
  , SHA512
  , hash
  , hashLazy
  ) where

import qualified Data.ByteString.Lazy as LBS
import Data.ByteString (ByteString)

import Crypto.Hash.ADT

import Crypto.Hash.SHA256
import Crypto.Hash.SHA512

hash :: (HasHash a) => ByteString -> a
hash = hashFinal . hashUpdate hashInit

hashLazy :: (HasHash a) => LBS.ByteString -> a
hashLazy = hashFinal . LBS.foldlChunks hashUpdate hashInit
