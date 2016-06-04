{-# LANGUAGE TypeFamilies #-}
module Crypto.Hash (
    HasHash(..)
  , SHA256
  , SHA256Ctx    
  , SHA224
  , SHA224Ctx    
  , SHA512
  , SHA512Ctx    
  ) where

import Data.ByteString (ByteString)

import Crypto.Hash.ADT

import Crypto.Hash.SHA256
import Crypto.Hash.SHA512


