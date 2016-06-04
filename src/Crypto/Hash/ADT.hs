{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Hash.ADT (
  HasHash(..)
  ) where

import qualified Data.ByteString.Lazy as LBS
import           Data.ByteString (ByteString)
import           Data.Monoid
import           Data.List(foldl')

class HasHash a c d where
  type HashCtx a c
  type HashDigest a d
  hashInit :: HashCtx a c
  hashUpdate :: HashCtx a c -> ByteString -> HashCtx a c
  hashFinal :: HashCtx a c -> HashDigest a d

{-
hash :: (HasHash a c d) => ByteString -> HashDigest a d
hash = hashFinal . hashUpdate hashInit

hashLazy :: (HasHash a c d) => LBS.ByteString -> HashDigest a d
hashLazy = hashFinal . foldl' (hashUpdate hashInit) . LBS.toChunks
-}
