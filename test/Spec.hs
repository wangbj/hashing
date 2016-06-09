{-# LANGUAGE PackageImports #-}
{-# LANGUAGE TemplateHaskell #-}

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString      as B
import           Data.ByteString.Internal
import           Test.QuickCheck
import           Test.QuickCheck.Monadic
import           Control.Monad
import "hashing" Crypto.Hash
import           Foreign.ForeignPtr
import           Foreign.Ptr

import qualified "cryptonite" Crypto.Hash as H

data BoxedBS = BoxedBS {
    unBoxedLBS :: ByteString
  } deriving Show

instance Arbitrary BoxedBS where
  arbitrary = do
    g <- resize (2^10) (listOf arbitrary)
    return $! BoxedBS (B.pack g)

data BoxedLBS = BoxedLBS {
    unBoxedBS :: LBS.ByteString
  } deriving Show

instance Arbitrary BoxedLBS where
  arbitrary = do
    g <- resize (2^10) (listOf arbitrary)
    return $! BoxedLBS (LBS.pack g)

prop_ByteStringPtrAlignedTo8Bytes :: BoxedBS -> Property
prop_ByteStringPtrAlignedTo8Bytes (BoxedBS (PS fptr _ _)) = monadicIO $ do
  t <-  run (withForeignPtr fptr $ \ptr ->
              return $! alignPtr ptr 8 == ptr)
  assert t

prop_SHA256HashLazyEqualsHashStrict (BoxedLBS lbs) = lhs == rhs
  where lhs = hashLazy lbs :: SHA256
        rhs = hashFinal . foldl hashUpdate hashInit . LBS.toChunks $ lbs

prop_SHA224HashLazyEqualsHashStrict (BoxedLBS lbs) = lhs == rhs
  where lhs = hashLazy lbs :: SHA224
        rhs = hashFinal . foldl hashUpdate hashInit . LBS.toChunks $ lbs

prop_MD5HashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: MD5
        rhs = H.hashlazy lbs :: H.Digest H.MD5

prop_WhirlpoolHashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: Whirlpool
        rhs = H.hashlazy lbs :: H.Digest H.Whirlpool

prop_SHA1HashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: SHA1
        rhs = H.hashlazy lbs :: H.Digest H.SHA1

prop_SHA224HashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: SHA224
        rhs = H.hashlazy lbs :: H.Digest H.SHA224

prop_SHA256HashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: SHA256
        rhs = H.hashlazy lbs :: H.Digest H.SHA256

prop_SHA384HashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: SHA384
        rhs = H.hashlazy lbs :: H.Digest H.SHA384

prop_SHA512HashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: SHA512
        rhs = H.hashlazy lbs :: H.Digest H.SHA512

prop_SHA512HashIsCorrect (BoxedLBS lbs) = show lhs == show rhs
  where lhs = hashLazy lbs :: SHA512
        rhs = H.hashlazy lbs :: H.Digest H.SHA512

return []
runTests = $quickCheckAll

main :: IO ()
main = void runTests
