{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE BangPatterns #-}

module Crypto.Hash.SHA256
    (
      SHA256
    , sha256Hash
    , sha256Init
    , sha256Update
    , sha256Final
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.ByteString (ByteString)
import           Data.ByteString.Builder
import           Control.Monad
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

encodeInt64     = B.pack . encodeInt64Helper

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

initHash :: SHA256
initHash = fromList initHs
  where fromList (a:b:c:d:e:f:g:h:_) = SHA256 a b c d e f g h

instance Show SHA256 where
  show = LC.unpack . toLazyByteString . foldMap word32HexFixed . toList
    where toList (SHA256 a b c d e f g h) = a:b:c:d:e:f:g:[h]

compression :: SHA256 -> (Word32, Word32) -> SHA256
compression (SHA256 a b c d e f g h) (!w, !z) =
    let
      !s1    = (e `rotateR` 6) `xor` (e `rotateR` 11) `xor` (e `rotateR` 25)
      !ch    = (e .&. f) `xor` (complement e .&. g)
      !temp1 = h + s1 + ch + z + w
      !s0    = (a `rotateR` 2) `xor` (a `rotateR` 13) `xor` (a `rotateR` 22)
      !maj   = (a .&. b) `xor` (a .&. c) `xor` (b .&. c)
      !temp2 = s0 + maj
    in SHA256 (temp1 + temp2) a b c (d + temp1) e f g
{-# INLINABLE compression #-}

data PI = PI {-# UNPACK #-} !Word32 {-# UNPACK #-} !Word32 {-# UNPACK #-} !Word32 {-# UNPACK #-} !Word32

{-# INLINE readPI #-}
readPI mv i = liftM4 PI (readArray mv w)
    (readArray mv x)
    (readArray mv y)
    (readArray mv z)
  where !w = i - 16
        !x = i - 15
        !y = i -  7
        !z = i -  2

round2 :: [Word32] -> UArray Int Word32
round2 w16 = runST $ do
  iou <- newArray (0, 63) 0 :: ST s (STUArray s Int Word32)
  mapM_ (uncurry (writeArray iou)) (zip [0..] w16)
  acc iou
  unsafeFreeze iou
    where acc mv = mapM_ go [16..63]
            where go i = readPI mv i >>= \(PI w1 w3 w2 w4) ->
                      let !s0 = (w3 `rotateR`  7) `xor` (w3 `rotateR` 18) `xor` (w3 `shiftR`  3)
                          !s1 = (w4 `rotateR` 17) `xor` (w4 `rotateR` 19) `xor` (w4 `shiftR` 10)
                      in writeArray mv i (w1 + s0 + w2 + s1)
                  {-# INLINE go #-}
          {-# INLINE acc #-}

{-# INLINE fromBS #-}
fromBS :: ByteString -> [Word32]
fromBS bs = if B.null s then [] else x : fromBS bs'
    where (!s, !bs') = B.splitAt 4 bs
          !x         = B.foldl' acc 0 s
            where acc r c = r `shiftL` 8 + fromIntegral c
                  acc :: Word32 -> Word8 -> Word32
                  {-# INLINE acc #-}

{-# INLINE encodeChunk #-}
encodeChunk :: SHA256 -> ByteString -> SHA256
encodeChunk hv@(SHA256 a b c d e f g h) bs = SHA256 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')
  where !r = round2 (fromBS bs)
        (SHA256 a' b' c' d' e' f' g' h') = foldl' compression hv (zip (elems r) initKs)

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

