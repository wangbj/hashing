{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Hash.ADT (
    Context(..)
  , HashAlgorithm(..)
  , Digest (..)
  ) where

import           Data.ByteString (ByteString)
import           Data.Int

data Context a = Context {
      ctxTotalBytesRead :: {-# UNPACK #-} !Int64
    , ctxBufferRead     :: {-# UNPACK #-} !Int
    , ctxBuffer         :: {-# UNPACK #-} !ByteString
    , ctxHashValueAcc   :: {-# UNPACK #-} !a
    }

instance Functor Context where
  fmap f (Context t r b v) = Context t r b (f v)

newtype Digest a = Digest String deriving Show

class HashAlgorithm a where
    hashBlockSize :: a -> Int
    hashDigestSize :: a -> Int
    hashInit   :: Context a
    hashUpdate :: Context a -> ByteString -> Context a
    hashFinal  :: Context a -> a
