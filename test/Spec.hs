{-# LANGUAGE TemplateHaskell #-}

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString      as B
import           Data.ByteString (ByteString)

import           Test.QuickCheck
import           Control.Monad
import           Control.Applicative
import           Data.Word
import           ByteSwap
import           SHA

data BoxedLBS = BoxedLBS {
    unBoxedLBS :: LBS.ByteString
  } deriving Show

instance Arbitrary BoxedLBS where
  arbitrary = do
    g <- resize (2^10) (listOf arbitrary)
    return $! BoxedLBS (LBS.pack g)

prop_toChunksAlignedCorrectly :: BoxedLBS -> Bool
prop_toChunksAlignedCorrectly = all (== 64) . map B.length . toChunks . unBoxedLBS

data BoxedSwappable = BoxedSwappable Word8 Word16 Word32 Word64 deriving Show
instance Arbitrary BoxedSwappable where
  arbitrary = BoxedSwappable
          <$> arbitrary
          <*> arbitrary
          <*> arbitrary
          <*> arbitrary

prop_byteswapTwiceEqualsId :: BoxedSwappable -> Bool
prop_byteswapTwiceEqualsId (BoxedSwappable a b c d) =
     a == (bswap (bswap a))
  && b == (bswap (bswap b))
  && c == (bswap (bswap c))
  && d == (bswap (bswap d))     

return []
runTests = $quickCheckAll

main :: IO ()
main = void runTests
