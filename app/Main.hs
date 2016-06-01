module Main where

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString as B
import Data.ByteString (ByteString)

import SHA

main :: IO ()
main = LBS.getContents >>= print . digest
