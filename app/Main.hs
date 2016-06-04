module Main where

import qualified Data.ByteString.Lazy as LBS
import           Data.ByteString (ByteString)
import           Crypto.Hash

main :: IO ()
main = LBS.getContents >>= \_ -> return ()
