{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Crypto.Hash.SHA512
    (
      SHA512
    , SHA384
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

import           Crypto.Hash.ADT

initHs :: [Word64]
initHs = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
  , 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179  ]

initKs :: [Word64]
initKs = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538
  , 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe
  , 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235
  , 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
  , 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab
  , 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725
  , 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed
  , 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b
  , 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218
  , 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53
  , 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373
  , 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
  , 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c
  , 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6
  , 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc
  , 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817  ]

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

sha512ChunkSize :: Int
sha512ChunkSize = 128  -- | 1024-bit

lastChunk :: Int64 -> ByteString -> [ByteString]
lastChunk msglen s
  | len < 120  = [s <> B.cons 0x80 (B.replicate (119 - len) 0x0)  <> encodedLen]
  | len < 248 = helper (s <> B.cons 0x80 (B.replicate (247 - len) 0x0) <> encodedLen)
  where
    len        = B.length s
    encodedLen = encodeInt64 msglen
    helper bs   = [s1, s2]
      where (s1, s2) = B.splitAt sha512ChunkSize bs

data SHA512 = SHA512  {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
          deriving Eq

data SHA384 = SHA384  {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64
              {-# UNPACK #-} !Word64

initHash :: SHA512
initHash = fromList initHs
  where fromList (a:b:c:d:e:f:g:h:_) = SHA512 a b c d e f g h

initHash384 :: SHA512
initHash384 = fromList [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
           0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]
  where fromList (a:b:c:d:e:f:g:h:_) = SHA512 a b c d e f g h

instance Show SHA512 where
  show = LC.unpack . toLazyByteString . foldMap word64HexFixed . toList
    where toList (SHA512 a b c d e f g h) = a:b:c:d:e:f:g:[h]

instance Show SHA384 where
  show = LC.unpack . toLazyByteString . foldMap word64HexFixed . toList
    where toList (SHA384 a b c d e f _ _) = a:b:c:d:e:[f]

instance Eq SHA384 where
  (SHA384 a1 b1 c1 d1 e1 f1 _ _) == (SHA384 a2 b2 c2 d2 e2 f2 _ _) =
    a1 == a2 && b1 == b2 && c1 == c2 && d1 == d2 && e1 == e2 && f1 == f2

{-# INLINABLE sha512BlockUpdate #-}
sha512BlockUpdate :: SHA512 -> Word64 -> SHA512
sha512BlockUpdate (SHA512 a b c d e f g h) w =
    let
      !s1    = mkS1 e
      !ch    = (e .&. f) `xor` (complement e .&. g)
      !temp1 = h + s1 + ch + w
      !s0    = mkS0 a
      !maj   = (a .&. b) `xor` (a .&. c) `xor` (b .&. c)
      !temp2 = s0 + maj
    in SHA512 (temp1 + temp2) a b c (d + temp1) e f g

{-# INLINE readW64 #-}
readW64 :: ByteString -> Word64
readW64 = B.foldl' acc 0 . B.take 8
  where acc x c = x `shiftL` 8 + fromIntegral c
        acc :: Word64 -> Word8 -> Word64
        {-# INLINE acc #-}

mkS0 :: Word64 -> Word64
mkS1 :: Word64 -> Word64
mkS0 x = (x `rotateR` 28) `xor` (x `rotateR` 34) `xor` (x `rotateR` 39)
mkS1 x = (x `rotateR` 14) `xor` (x `rotateR` 18) `xor` (x `rotateR` 41)
{-# INLINE mkS0 #-}
{-# INLINE mkS1 #-}

mkS00 :: Word64 -> Word64
mkS01 :: Word64 -> Word64
mkS00 x = (x `rotateR`  1) `xor` (x `rotateR`  8) `xor` (x `shiftR`  7)
mkS01 x = (x `rotateR` 19) `xor` (x `rotateR` 61) `xor` (x `shiftR`  6)

prepareBlock :: ByteString -> UArray Int Word64
prepareBlock s = runST $ do
  iou <- newArray (0, 79) 0 :: ST s (STUArray s Int Word64)
  let
    !w1  = readW64 s
    !w2  = readW64 (B.drop 8 s)
    !w3  = readW64 (B.drop 16 s)
    !w4  = readW64 (B.drop 24 s)
    !w5  = readW64 (B.drop 32 s)
    !w6  = readW64 (B.drop 40 s)
    !w7  = readW64 (B.drop 48 s)
    !w8  = readW64 (B.drop 56 s)
    !w9  = readW64 (B.drop 64 s)
    !w10 = readW64 (B.drop 72 s)
    !w11 = readW64 (B.drop 80 s)
    !w12 = readW64 (B.drop 88 s)
    !w13 = readW64 (B.drop 96 s)
    !w14 = readW64 (B.drop 104 s)
    !w15 = readW64 (B.drop 112 s)
    !w16 = readW64 (B.drop 120 s)
  writeArray iou 0 w1 >> writeArray iou 1 w2 >> writeArray iou 2 w3 >> writeArray iou 3 w4 >>
    writeArray iou 4 w5 >> writeArray iou 5 w6 >> writeArray iou 6 w7 >> writeArray iou 7 w8 >>
    writeArray iou 8 w9 >> writeArray iou 9 w10 >> writeArray iou 10 w11 >> writeArray iou 11 w12 >>
    writeArray iou 12 w13 >> writeArray iou 13 w14 >> writeArray iou 14 w15 >> writeArray iou 15 w16
  let go i = readArray iou (i-16) >>= \x1 ->
        readArray iou (i-15) >>= \x2 ->
        readArray iou (i- 7) >>= \x3 ->
        readArray iou (i- 2) >>= \x4 ->
        let !s0 = mkS00 x2
            !s1 = mkS01 x4
        in writeArray iou i (x1 + s0 + x3 + s1)
  mapM_ go [16..79]
  unsafeFreeze iou

{-# INLINE encodeChunk #-}
encodeChunk :: SHA512 -> ByteString -> SHA512
encodeChunk hv@(SHA512 a b c d e f g h) bs = SHA512 (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')
  where
    SHA512 a' b' c' d' e' f' g' h' = foldl' sha512BlockUpdate hv (zipWith (+) (elems (prepareBlock bs)) initKs)

{-# NOINLINE sha512Hash #-}
sha512Hash :: LBS.ByteString -> SHA512
sha512Hash = sha512Final . LBS.foldlChunks sha512Update sha512Init

sha512Init :: Context SHA512
sha512Init = Context 0 0 B.empty initHash

{-# NOINLINE sha512Update #-}
sha512Update :: Context SHA512 -> ByteString -> Context SHA512
sha512Update ctx@(Context n k w hv) s
  | B.null s               = ctx
  | sizeRead  < sizeToRead = Context (n + fromIntegral sizeRead) (k + sizeRead) (w <> s1) hv
  | sizeRead >= sizeToRead = sha512Update (Context (n + fromIntegral sizeToRead) 0 mempty (encodeChunk hv (w <> s1))) s'
  where
    !sizeToRead  = sha512ChunkSize - k
    (!s1, !s')   = B.splitAt sizeToRead s
    !sizeRead    = B.length s1

{-# NOINLINE sha512Final #-}
sha512Final :: Context SHA512 -> SHA512
sha512Final (Context n _ w hv) = foldl' encodeChunk hv (lastChunk n w)

instance HashAlgorithm SHA512 where
  hashBlockSize = const 128
  hashDigestSize = const 64
  hashInit = sha512Init
  hashUpdate = sha512Update
  hashFinal = sha512Final

fromSHA384 :: SHA384 -> SHA512
fromSHA512 :: SHA512 -> SHA384
fromSHA384 (SHA384 a b c d e f g h) = SHA512 a b c d e f g h
fromSHA512 (SHA512 a b c d e f g h) = SHA384 a b c d e f g h

sha384Init :: Context SHA384
sha384Init   = fmap fromSHA512 (Context 0 0 B.empty initHash384)
sha384Update :: Context SHA384 -> ByteString -> Context SHA384
sha384Update = fmap (fmap fromSHA512) . sha512Update . fmap fromSHA384
sha384Final :: Context SHA384 -> SHA384
sha384Final = fromSHA512 . sha512Final . fmap fromSHA384

instance HashAlgorithm SHA384 where
  hashBlockSize = const 128
  hashDigestSize = const 48
  hashInit = sha384Init
  hashUpdate = sha384Update
  hashFinal = sha384Final
