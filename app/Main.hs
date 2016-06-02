module Main where

import qualified Data.ByteString.Lazy as LBS

import           Crypto.Hash

main :: IO ()
main = LBS.getContents >>= print . sha256Hash
