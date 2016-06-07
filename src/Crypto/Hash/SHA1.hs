{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE UnboxedTuples #-}

module Crypto.Hash.SHA1
    (
      SHA1
    ) where

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString as B
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
import           Debug.Trace
import           Crypto.Hash.ADT

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

encodeInt64 :: Int64 -> ByteString
encodeInt64 = B.pack . encodeInt64Helper

sha1BlockSize :: Int
sha1BlockSize = 64

lastChunk :: Int64 -> ByteString -> [ByteString]
lastChunk msglen s
  | len < (sha1BlockSize - 8)     = [s <> B.cons 0x80 (B.replicate (sha1BlockSize - 9 - len) 0x0)  <> encodedLen]
  | len < (2 * sha1BlockSize - 8) = helper (s <> B.cons 0x80 (B.replicate (2 * sha1BlockSize - 9 - len) 0x0) <> encodedLen)
  where
    len        = B.length s
    encodedLen = encodeInt64 msglen
    helper bs   = [s1, s2]
      where (s1, s2) = B.splitAt 64 bs

data SHA1 = SHA1  {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
          deriving Eq

initHash :: SHA1
initHash = SHA1 0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0

instance Show SHA1 where
  show = LC.unpack . toLazyByteString . foldMap word32HexFixed . toList
    where toList (SHA1 a b c d e) = a:b:c:d:[e]

sha1BlockUpdate :: SHA1 -> UArray Int Word32 -> SHA1
sha1BlockUpdate hv = foldl' acc hv . assocs
  where acc (SHA1 a b c d e) !(!i, !w) = SHA1 temp a (b `rotateL` 30) c d
          where fk i b c d
                  | i < 20 = ( (b .&. c) .|. ( (complement b) .&. d), 0x5a827999)
                  | i < 40 = ( (b `xor` c `xor` d), 0x6ed9eba1)
                  | i < 60 = ( ( (b .&. c) .|. (b .&. d) .|. (c .&. d) ), 0x8f1bbcdc)
                  | i < 80 = ( (b `xor` c `xor` d), 0xca62c1d6)
                fk :: Int -> Word32 -> Word32 -> Word32 -> (Word32, Word32)
                {-# INLINE fk #-}
                (!f, !k)   = fk i b c d
                !temp      = (a `rotateL` 5) + f + e + k + w
        {-# INLINE acc #-}

{-# INLINE readW64 #-}
readW64 :: ByteString -> Word64
readW64 = B.foldl' acc 0 . B.take 8
  where acc x c = x `shiftL` 8 + fromIntegral c
        acc :: Word64 -> Word8 -> Word64
        {-# INLINE acc #-}

prepareBlock :: ByteString -> UArray Int Word32
prepareBlock s = runST $ do
  iou <- newArray (0, 79) 0 :: ST s (STUArray s Int Word32)
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
        readArray iou (i-14) >>= \x2 ->
        readArray iou (i- 8) >>= \x3 ->
        readArray iou (i- 3) >>= \x4 ->
        let !wi = (x1 `xor` x2 `xor` x3 `xor` x4) `rotateL` 1
        in writeArray iou i wi
      {-# INLINE go #-}
  mapM_ go [16..79]
  unsafeFreeze iou

{-# INLINE encodeChunk #-}
encodeChunk :: SHA1 -> ByteString -> SHA1
encodeChunk hv@(SHA1 a b c d e) bs = SHA1 (a+a') (b+b') (c+c') (d+d') (e+e')
  where
    SHA1 a' b' c' d' e' = sha1BlockUpdate hv (prepareBlock bs)

sha1Init :: Context SHA1
sha1Init = Context 0 0 B.empty initHash

{-# NOINLINE sha1Update #-}
sha1Update :: Context SHA1 -> ByteString -> Context SHA1
sha1Update ctx@(Context n k w hv) s
  | B.null s               = ctx
  | sizeRead  < sizeToRead = Context (n + fromIntegral sizeRead) (k + sizeRead) (w <> s1) hv
  | sizeRead >= sizeToRead = sha1Update (Context (n + fromIntegral sizeToRead) 0 mempty (encodeChunk hv (w <> s1))) s'
  where
    !sizeToRead  = sha1BlockSize - k
    !s1          = B.take sizeToRead s
    !s'          = B.drop sizeToRead s
    !sizeRead    = B.length s1

{-# NOINLINE sha1Final #-}
sha1Final :: Context SHA1 -> SHA1
sha1Final (Context n _ w hv) = foldl' encodeChunk hv (lastChunk n w)

{-# NOINLINE sha1Hash #-}
sha1Hash :: LBS.ByteString -> SHA1
sha1Hash = sha1Final . LBS.foldlChunks sha1Update sha1Init

instance HashAlgorithm SHA1 where
  hashBlockSize = const sha1BlockSize
  hashDigestSize = const 20
  hashInit = sha1Init
  hashUpdate = sha1Update
  hashFinal = sha1Final
