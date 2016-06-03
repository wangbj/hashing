{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE BangPatterns #-}

module Crypto.Hash.SHA256
    (
      SHA256
    , SHA224
    , SHA256Ctx
    , SHA224Ctx
    , sha256Hash
    , sha256Init
    , sha256Update
    , sha256Final
    , sha224Hash
    , sha224Init
    , sha224Update
    , sha224Final
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.ByteString (ByteString)
import           Data.ByteString.Builder
import           Control.Monad.ST
import           Data.Int
import           Data.Word
import           Data.Bits
import           Data.Monoid
import           Data.Array.Unboxed
import           Data.Array.Unsafe
import           Data.Array.ST
import           Data.List(foldl')

initHs :: [Word32]
initHs = [
    0x6a09e667 , 0xbb67ae85 , 0x3c6ef372 , 0xa54ff53a
  , 0x510e527f , 0x9b05688c , 0x1f83d9ab , 0x5be0cd19  ]

initKs :: [Word32]
initKs = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ]

encodeInt64Helper :: Int64 -> [Word8]
encodeInt64Helper x_ = [w7, w6, w5, w4, w3, w2, w1, w0]
  where x = x_ * 8
        w7 = fromIntegral $ (x `shiftR` 56) .&. 0xff
        w6 = fromIntegral $ (x `shiftR` 48) .&. 0xff
        w5 = fromIntegral $ (x `shiftR` 40) .&. 0xff
        w4 = fromIntegral $ (x `shiftR` 32) .&. 0xff
        w3 = fromIntegral $ (x `shiftR` 24) .&. 0xff
        w2 = fromIntegral $ (x `shiftR` 16) .&. 0xff
        w1 = fromIntegral $ (x `shiftR`  8) .&. 0xff
        w0 = fromIntegral $ (x `shiftR`  0) .&. 0xff

encodeInt64 = B.pack . encodeInt64Helper

lastChunk :: Int64 -> ByteString -> [ByteString]
lastChunk msglen s
  | len < 56  = [s <> B.cons 0x80 (B.replicate (55 - len) 0x0)  <> encodedLen]
  | len < 120 = helper (s <> B.cons 0x80 (B.replicate (119 - len) 0x0) <> encodedLen)
  where
    len        = B.length s
    encodedLen = encodeInt64 msglen
    helper bs   = [s1, s2]
      where (s1, s2) = B.splitAt 64 bs

data SHA256 = SHA256  {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
          deriving Eq

data SHA224 = SHA224  {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
          deriving Eq

initHash :: SHA256
initHash = fromList initHs
  where fromList (a:b:c:d:e:f:g:h:_) = SHA256 a b c d e f g h

initHash224 :: SHA256
initHash224 = fromList [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
  where fromList (a:b:c:d:e:f:g:h:_) = SHA256 a b c d e f g h

instance Show SHA256 where
  show = LC.unpack . toLazyByteString . foldMap word32HexFixed . toList
    where toList (SHA256 a b c d e f g h) = a:b:c:d:e:f:g:[h]

instance Show SHA224 where
  show = LC.unpack . toLazyByteString . foldMap word32HexFixed . toList
    where toList (SHA224 a b c d e f g) = a:b:c:d:e:f:[g]

{-# INLINABLE sha256BlockUpdate #-}
sha256BlockUpdate :: SHA256 -> Word32 -> SHA256
sha256BlockUpdate (SHA256 a b c d e f g h) w =
    let
      !s1    = (e `rotateR` 6) `xor` (e `rotateR` 11) `xor` (e `rotateR` 25)
      !ch    = (e .&. f) `xor` (complement e .&. g)
      !temp1 = h + s1 + ch + w
      !s0    = (a `rotateR` 2) `xor` (a `rotateR` 13) `xor` (a `rotateR` 22)
      !maj   = (a .&. b) `xor` (a .&. c) `xor` (b .&. c)
      !temp2 = s0 + maj
    in SHA256 (temp1 + temp2) a b c (d + temp1) e f g

{-# INLINE readW64 #-}
readW64 :: ByteString -> Word64
readW64 = B.foldl' acc 0 . B.take 8
  where acc x c = x `shiftL` 8 + fromIntegral c
        acc :: Word64 -> Word8 -> Word64
        {-# INLINE acc #-}

prepareBlock :: ByteString -> UArray Int Word32
prepareBlock s = runST $ do
  iou <- newArray (0, 63) 0 :: ST s (STUArray s Int Word32)
  let
    !w1 = readW64 s
    !w2 = readW64 (B.drop 8 s)
    !w3 = readW64 (B.drop 16 s)
    !w4 = readW64 (B.drop 24 s)
    !w5 = readW64 (B.drop 32 s)
    !w6 = readW64 (B.drop 40 s)
    !w7 = readW64 (B.drop 48 s)
    !w8 = readW64 (B.drop 56 s)
    write2 k x = writeArray iou (2*k)     (fromIntegral (x `shiftR` 32)) >>
                 writeArray iou (1+2*k)   (fromIntegral (x .&. 0xffffffff))
    {-# INLINE write2 #-}
  write2 0 w1
  write2 1 w2
  write2 2 w3
  write2 3 w4
  write2 4 w5
  write2 5 w6
  write2 6 w7
  write2 7 w8
  let go i = readArray iou (i-16) >>= \x1 ->
        readArray iou (i-15) >>= \x2 ->
        readArray iou (i- 7) >>= \x3 ->
        readArray iou (i- 2) >>= \x4 ->
        let !s0 = (x2 `rotateR`  7) `xor` (x2 `rotateR` 18) `xor` (x2 `shiftR`  3)
            !s1 = (x4 `rotateR` 17) `xor` (x4 `rotateR` 19) `xor` (x4 `shiftR` 10)
        in writeArray iou i (x1 + s0 + x3 + s1)
--      {-# INLINE go #-}
  mapM_ go [16..63]
  unsafeFreeze iou

{-# INLINE encodeChunk #-}
encodeChunk :: SHA256 -> ByteString -> SHA256
encodeChunk hv@(SHA256 a b c d e f g h) bs = SHA256 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')
  where
    SHA256 a' b' c' d' e' f' g' h' = foldl' sha256BlockUpdate hv (zipWith (+) (elems (prepareBlock bs)) initKs)

{-# NOINLINE sha256Hash #-}
sha256Hash :: LBS.ByteString -> SHA256
sha256Hash = sha256Final . LBS.foldlChunks sha256Update sha256Init

data SHA256Ctx = SHA256Ctx {
    totalBytesRead     :: {-# UNPACK #-} !Int64
  , leftOverSize       :: {-# UNPACK #-} !Int
  , leftOver           :: {-# UNPACK #-} !ByteString
  , hashValue          :: {-# UNPACK #-} !SHA256
  } deriving Show

sha256Init :: SHA256Ctx
sha256Init = SHA256Ctx 0 0 B.empty initHash

{-# NOINLINE sha256Update #-}
sha256Update :: SHA256Ctx -> ByteString -> SHA256Ctx
sha256Update ctx@(SHA256Ctx n k w hv) s
  | B.null s               = ctx
  | sizeRead  < sizeToRead = SHA256Ctx (n + fromIntegral sizeRead) (k + sizeRead) (w <> s1) hv
  | sizeRead >= sizeToRead = sha256Update (SHA256Ctx (n + fromIntegral sizeToRead) 0 mempty (encodeChunk hv (w <> s1))) s'
  where
    !sizeToRead  = 64 - k
    (!s1, !s')   = B.splitAt sizeToRead s
    !sizeRead    = B.length s1

{-# NOINLINE sha256Final #-}
sha256Final :: SHA256Ctx -> SHA256
sha256Final ctx@(SHA256Ctx n k w hv) = foldl' encodeChunk hv (lastChunk n w)

type SHA224Ctx = SHA256Ctx

fromSHA256 (SHA256 a b c d e f g _) = SHA224 a b c d e f g

sha224Init   = SHA256Ctx 0 0 B.empty initHash224
sha224Update = sha256Update
sha224Final  = fromSHA256 . sha256Final

{-# NOINLINE sha224Hash #-}
sha224Hash :: LBS.ByteString -> SHA224
sha224Hash = sha224Final . LBS.foldlChunks sha224Update sha224Init
