{-# LANGUAGE TemplateHaskell #-}

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString      as B
import           Data.ByteString (ByteString)
import           Data.ByteString.Internal
import           Test.QuickCheck
import           Test.QuickCheck.Monadic
import           Control.Monad
import           Control.Applicative
import           Data.Word
import           Crypto.Hash
import           Foreign.ForeignPtr
import           Foreign.Ptr

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

--monadicTests = quickCheck propM_ByteStringAlignedTo8Bytes

return []
runTests = $quickCheckAll

main :: IO ()
main = void runTests
