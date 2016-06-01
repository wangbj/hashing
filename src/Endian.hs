module Endian (
    Endian(..)
  , ByteSwappable(..)
  , bswap16, bswap32, bswap64
  ) where

import Data.Int
import Data.Bits
import Data.Word

data Endian = LittleEndian | BigEndian deriving (Show, Eq)

class (Enum a, Bounded a) => ByteSwappable a where
  bswap :: a -> a

bswap16 :: Word16 -> Word16
bswap16 w = (w0 `shiftL` 8) .|. w1
  where w0 = w .&. 0xff
        w1 = (w `shiftR` 8) .&. 0xff

bswap32 :: Word32 -> Word32
bswap32 w = (w0 `shiftL` 24) .|. (w1 `shiftL` 16) .|. (w2 `shiftL` 8) .|. w3
  where w0 = w .&. 0xff
        w1 = (w `shiftR` 8) .&. 0xff
        w2 = (w `shiftR` 16) .&. 0xff
        w3 = (w `shiftR` 24) .&. 0xff

bswap64 :: Word64 -> Word64
bswap64 w = (w0 `shiftL` 56) .|. (w1 `shiftL` 48) .|. (w2 `shiftL` 40)
        .|. (w3 `shiftL` 32) .|. (w4 `shiftL` 24) .|. (w5 `shiftL` 16)
        .|. (w6 `shiftL` 8)  .|. (w7)
  where w0 = w .&. 0xff
        w1 = (w `shiftR` 8) .&. 0xff
        w2 = (w `shiftR` 16) .&. 0xff
        w3 = (w `shiftR` 24) .&. 0xff
        w4 = (w `shiftR` 32) .&. 0xff
        w5 = (w `shiftR` 40) .&. 0xff
        w6 = (w `shiftR` 48) .&. 0xff
        w7 = (w `shiftR` 56) .&. 0xff        

instance ByteSwappable Word8 where
  bswap = id

instance ByteSwappable Int8 where
  bswap = id

instance ByteSwappable Word16 where
  bswap = bswap16

instance ByteSwappable Int16 where
  bswap = fromIntegral . bswap16 . fromIntegral

instance ByteSwappable Word32 where
  bswap = bswap32

instance ByteSwappable Int32 where
  bswap = fromIntegral . bswap32 . fromIntegral

instance ByteSwappable Word64 where
  bswap = bswap64

instance ByteSwappable Int64 where
  bswap = fromIntegral . bswap64 . fromIntegral

