{-# LANGUAGE TemplateHaskell #-}

module ByteSwap (
    bswap
  , hostToBE
  , hostToLE
  , beToHost
  , leToHost
  ) where

import Endian
import TH

instance ByteSwappable Int where
  bswap = $(bswapi)

hostToBE :: (ByteSwappable a) => a -> a
hostToBE = case hostEndian of
  BigEndian    -> id
  LittleEndian -> bswap

hostToLE :: (ByteSwappable a) => a -> a
hostToLE = case hostEndian of
  BigEndian    -> bswap
  LittleEndian -> id

beToHost :: (ByteSwappable a) => a -> a
beToHost = hostToBE

leToHost :: (ByteSwappable a) => a -> a
leToHost = hostToLE
