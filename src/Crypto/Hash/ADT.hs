{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Hash.ADT (
    Context(..)
  , HasHash(..)
  , Digest (..)
  ) where

import           Data.ByteString (ByteString)
import           Data.Int

data Context a = Context {
      ctxTotalBytesRead :: {-# UNPACK #-} !Int64
    , ctxBufferRead     :: {-# UNPACK #-} !Int
    , ctxBuffer         :: {-# UNPACK #-} !ByteString
    , ctxHashValueAcc   :: !a
    } deriving Show

newtype Digest a = Digest String deriving Show

class HasHash a where
    type HashAlg a
    hashBlockSize :: a -> Int
    hashDigestSize :: a -> Int
    hashInit   :: Context (HashAlg a)
    hashUpdate :: Context (HashAlg a) -> ByteString -> Context (HashAlg a)
    hashFinal  :: Context (HashAlg a) -> a
