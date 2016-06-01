{-# LANGUAGE TemplateHaskell #-}

module TH (
    hostEndian
  , bswapi
  ) where

import Data.Bits
import Data.Word
import Data.Int
import Endian

detectEndian = case x .&. 0xff of
  0x12 -> BigEndian
  0x34 -> LittleEndian
  where x = 0x1234 :: Word16

hostEndian = $([| detectEndian |])

bswapi = [| let i1 = (maxBound :: Int)
                i2 = (maxBound :: Int64)
            in if fromIntegral i1 == fromIntegral i2 then fromIntegral . bswap64 . fromIntegral
               else fromIntegral . bswap32 . fromIntegral |]
