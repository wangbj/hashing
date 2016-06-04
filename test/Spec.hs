{-# LANGUAGE TemplateHaskell #-}

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString      as B
import           Data.ByteString (ByteString)

import           Test.QuickCheck
import           Control.Monad
import           Control.Applicative
import           Data.Word
import           Crypto.Hash

data BoxedLBS = BoxedLBS {
    unBoxedLBS :: LBS.ByteString
  } deriving Show

instance Arbitrary BoxedLBS where
  arbitrary = do
    g <- resize (2^10) (listOf arbitrary)
    return $! BoxedLBS (LBS.pack g)

prop_SHA256HashLazyEqualsHashStrict (BoxedLBS lbs) = lhs == rhs
  where lhs = hashLazy lbs :: Digest SHA256
        rhs = hashFinal . foldl hashUpdate hashInit . LBS.toChunks $ lbs

prop_SHA224HashLazyEqualsHashStrict (BoxedLBS lbs) = lhs == rhs
  where lhs = hashLazy lbs :: Digest SHA224
        rhs = hashFinal . foldl hashUpdate hashInit . LBS.toChunks $ lbs

return []
runTests = $quickCheckAll

main :: IO ()
main = void runTests
