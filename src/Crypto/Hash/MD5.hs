{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Safe #-}

module Crypto.Hash.MD5 (
    MD5
  ) where

import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString as B
import           Data.ByteString (ByteString)
import           Data.ByteString.Builder
import           Data.Array.Unboxed
import           Data.Int
import           Data.Word
import           Data.Bits
import           Data.Monoid
import           Data.List(foldl')

import           Crypto.Hash.ADT

initSs :: UArray Int Int
initSs = listArray (0, 63) [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22
  , 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20
  , 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23
  , 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21  ]

initKs :: UArray Int Word32
initKs = listArray (0, 63) [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee
  , 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
  , 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be
  , 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
  , 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa
  , 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8
  , 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed
  , 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
  , 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c
  , 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70
  , 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05
  , 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
  , 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039
  , 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1
  , 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1
  , 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391  ]

data MD5 = MD5 {-# UNPACK #-} !Word32
           {-# UNPACK #-} !Word32
           {-# UNPACK #-} !Word32
           {-# UNPACK #-} !Word32
         deriving Eq           

instance Show MD5 where
  show = LC.unpack . toLazyByteString . foldMap (word32HexFixed . byteSwap32) . toList
    where toList (MD5 a b c d) = a:b:c:[d]

initHash :: MD5
initHash = MD5 0x67452301 0xefcdab89 0x98badcfe 0x10325476

encodeInt64Helper :: Int64 -> [Word8]
encodeInt64Helper x_ = [w0, w1, w2, w3, w4, w5, w6, w7]
  where x = x_ * 8
        w7 = fromIntegral $ (x `shiftR` 56) .&. 0xff
        w6 = fromIntegral $ (x `shiftR` 48) .&. 0xff
        w5 = fromIntegral $ (x `shiftR` 40) .&. 0xff
        w4 = fromIntegral $ (x `shiftR` 32) .&. 0xff
        w3 = fromIntegral $ (x `shiftR` 24) .&. 0xff
        w2 = fromIntegral $ (x `shiftR` 16) .&. 0xff
        w1 = fromIntegral $ (x `shiftR`  8) .&. 0xff
        w0 = fromIntegral $ (x `shiftR`  0) .&. 0xff

encodeInt64 :: Int64 -> ByteString
encodeInt64 = B.pack . encodeInt64Helper

md5BlockSize :: Int
md5BlockSize = 64

md5DigestSize :: Int
md5DigestSize = 16

lastChunk :: Int64 -> ByteString -> [ByteString]
lastChunk msglen s
  | len < (md5BlockSize - 8)  = [s <> B.cons 0x80 (B.replicate (md5BlockSize - 9 - len) 0x0)  <> encodedLen]
  | len < (2*md5BlockSize - 8) = helper (s <> B.cons 0x80 (B.replicate (2*md5BlockSize -9 - len) 0x0) <> encodedLen)
  where
    len        = B.length s
    encodedLen = encodeInt64 msglen
    helper bs   = [s1, s2]
      where (!s1, !s2) = B.splitAt 64 bs

readW32 :: ByteString -> Word32
readW32 = byteSwap32 . B.foldl' acc 0
  where acc x c = x `shiftL` 8 + fromIntegral c
        {-# INLINE acc #-}
{-# INLINE readW32 #-}        

prepareBlock :: ByteString -> UArray Int Word32
prepareBlock = listArray (0, 15) . go
  where go s
          | B.null s  = []
          | otherwise = let !s1 = B.take 4 s
                            !s' = B.drop 4 s
                        in readW32 s1 : go s'
        {-# INLINE go #-}

md5BlockUpdate :: MD5 -> UArray Int Word32 -> MD5
md5BlockUpdate h u = foldl' blkUpdate h [0..63]
  where
    blkUpdate (MD5 a b c d) i = MD5 d b' b c
      where
        !(!f, !g)
          | i < 16  = ((d `xor` (b .&. (c `xor` d))), i)
          | i < 32  = ((c `xor` (d .&. (b `xor` c))), (5*i+1) .&. 0xf)
          | i < 48  = (b `xor` c `xor` d, (3*i+5) .&. 0xf)
          | i < 64  = ((c `xor` (b .|. (complement d))), (7*i) .&. 0xf)
        !b'      = b + (a+f+(initKs!i)+(u!g)) `rotateL` (initSs!i)
    blkUpdate :: MD5 -> Int -> MD5
    {-# INLINE blkUpdate #-}

{-# INLINE encodeChunk #-}
encodeChunk :: MD5 -> ByteString -> MD5
encodeChunk hv@(MD5 a b c d) bs = MD5 (a+a') (b+b') (c+c') (d+d')
  where
    MD5 a' b' c' d' = md5BlockUpdate hv (prepareBlock bs)

{-# NOINLINE md5Hash #-}
md5Hash :: LBS.ByteString -> MD5
md5Hash = md5Final . LBS.foldlChunks md5Update md5Init

md5Init :: Context MD5
md5Init = Context 0 0 B.empty initHash

md5Update :: Context MD5 -> ByteString -> Context MD5
md5Update ctx@(Context n k w hv) s
  | B.null s               = ctx
  | sizeRead  < sizeToRead = Context (n + fromIntegral sizeRead) (k + sizeRead) (w <> s1) hv
  | sizeRead >= sizeToRead = md5Update (Context (n + fromIntegral sizeToRead) 0 mempty (encodeChunk hv (w <> s1))) s'
  where
    !sizeToRead  = md5BlockSize - k
    !s1          = B.take sizeToRead s
    !s'          = B.drop sizeToRead s
    !sizeRead    = B.length s1

{-# NOINLINE md5Final #-}
md5Final :: Context MD5 -> MD5
md5Final (Context n _ w hv) = foldl' encodeChunk hv (lastChunk n w)

instance HashAlgorithm MD5 where
  hashBlockSize = const md5BlockSize
  hashDigestSize = const md5DigestSize
  hashInit = md5Init
  hashUpdate = md5Update
  hashFinal = md5Final
