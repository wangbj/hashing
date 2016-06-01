{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module SHA
    (
      toChunks
    , digest
    ) where

import qualified Data.Vector.Unboxed.Mutable as MV
import qualified Data.Vector.Unboxed as U
import           Data.Vector(Vector)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.Serialize as S
import           Data.ByteString (ByteString)
import           Data.ByteString.Builder
import           Control.Monad.ST
import           Control.Monad
import           Data.Int
import           Data.Word
import           Data.Char
import           Data.Bits
import           Data.Monoid

initHs = [
    0x6a09e667 , 0xbb67ae85 , 0x3c6ef372 , 0xa54ff53a
  , 0x510e527f , 0x9b05688c , 0x1f83d9ab , 0x5be0cd19  ] :: [Word32]

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

initKv :: U.Vector Word32
initKv = U.fromList initKs

encodeInt64 :: Int64 -> ByteString
encodeInt64 x_ = B.pack [w7, w6, w5, w4, w3, w2, w1, w0]
  where x = (x_ * 8)
        w7 = fromIntegral $ (x `shiftR` 56) .&. 0xff
        w6 = fromIntegral $ (x `shiftR` 48) .&. 0xff
        w5 = fromIntegral $ (x `shiftR` 40) .&. 0xff
        w4 = fromIntegral $ (x `shiftR` 32) .&. 0xff
        w3 = fromIntegral $ (x `shiftR` 24) .&. 0xff
        w2 = fromIntegral $ (x `shiftR` 16) .&. 0xff
        w1 = fromIntegral $ (x `shiftR`  8) .&. 0xff
        w0 = fromIntegral $ (x `shiftR`  0) .&. 0xff

lastChunk :: Int64 -> ByteString -> [ByteString]
lastChunk msglen s
  | len < 56  = [s <> B.cons 0x80 (B.replicate (55 - len) 0x0)  <> encodedLen]
  | len < 120 = helper (s <> B.cons 0x80 (B.replicate (119 - len) 0x0) <> encodedLen)
  where
    len        = B.length s
    encodedLen = encodeInt64 msglen
    helper s   = [s1, s2]
      where (s1, s2) = B.splitAt 64 s

to64BChunks initialLen s
  | LBS.null s'         = lastChunk initialLen s2
  | (not . LBS.null) s' = s2 : to64BChunks initialLen s'
  where
    (s1, s') = LBS.splitAt 64 s
    s2       = LBS.toStrict s1

toChunks s = to64BChunks (LBS.length s) s
{-# INLINE toChunks #-}

data HV = HV  {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
              {-# UNPACK #-} !Word32
          deriving (Eq)

fromList :: [Word32] -> HV
toList   :: HV -> [Word32]
fromList (a:b:c:d:e:f:g:h:_) = HV a b c d e f g h
toList (HV a b c d e f g h) = a:b:c:d:e:f:g:[h]
{-# INLINE initHash #-}
initHash = fromList initHs

instance Show HV where
  show hv@(HV a b c d e f g h) = LC.unpack . toLazyByteString . foldMap word32HexFixed . toList $ hv

compression (HV a b c d e f g h) (!w, !z) =
    let
      !s1    = (e `rotateR` 6) `xor` (e `rotateR` 11) `xor` (e `rotateR` 25)
      !ch    = (e .&. f) `xor` (complement e .&. g)
      !temp1 = h + s1 + ch + z + w
      !s0    = (a `rotateR` 2) `xor` (a `rotateR` 13) `xor` (a `rotateR` 22)
      !maj   = (a .&. b) `xor` (a .&. c) `xor` (b .&. c)
      !temp2 = s0 + maj
    in HV (temp1 + temp2) a b c (d + temp1) e f g
{-# INLINE compression #-}

encodeChunk :: HV -> ByteString -> HV
encodeChunk hv@(HV a b c d e f g h) bs = runST $ do
  mv <- MV.new 64 :: ST s (MV.MVector s Word32)
  let msg = {-# SCC deser #-} S.runGet (replicateM 16 S.get) bs :: (Either String [Word32])
  case msg of
    Left err      -> error $ "encodeChunk failed: make sure ByteString passed is 64 bytes"
    Right encoded -> do
      mapM_ ( uncurry (MV.write mv) ) (zip [0..15] encoded)
      {-# SCC forLoop #-} forM_ [16..63] (\i ->
                       MV.unsafeRead mv (i-2) >>= \w4 ->
                       MV.unsafeRead mv (i-7) >>= \w2 ->
                       MV.unsafeRead mv (i-15) >>= \w3 ->
                       MV.unsafeRead mv (i-16) >>= \w1 ->
                       let !s0 = (w3 `rotateR`  7) `xor` (w3 `rotateR` 18) `xor` (w3 `shiftR`  3)
                           !s1 = (w4 `rotateR` 17) `xor` (w4 `rotateR` 19) `xor` (w4 `shiftR` 10)
                       in MV.write mv i (w1 + s0 + w2 + s1) )
      v <- U.unsafeFreeze mv
      let hv'@(HV a' b' c' d' e' f' g' h') = {-# SCC foldLoop #-} foldl compression hv (zip (U.toList v) initKs )
      return $! HV (a+a') (b+b') (c+c') (d+d') (e+e') (f+f') (g+g') (h+h')

digest :: LBS.ByteString -> HV
digest = foldl encodeChunk initHash . toChunks
