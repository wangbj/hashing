module Main where

import qualified Data.ByteString.Lazy as LBS

import           SHA

main :: IO ()
main = LBS.getContents >>= print . digest
