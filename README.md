# roblox-decryptor

## What is this?
This is a static decryptor for Roblox. Essentially, it decrypts all the code pages manually by fetching the encryption keys from Hyperion, instead of following the usual dynamic approach, which forces Hyperion to decrypt the pages at runtime.

## How does this work?
Hyperion uses a modified version of Chacha20 to encrypt the pages. They change the constant, adjust the round count, and also transform the initial key before using it. The initial key is usually smaller than the required Chacha20 key, and the rest is extended during the transformation.
