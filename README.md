# roblox-decryptor

## UPDATE:
I have added decryption for the INT3 emulators, since this is not included in the original release. Enjoy your dumps! Below is an example of decompilation without INT3s decrypted, vs with:
![Without](https://i.imgur.com/uSKhNX9.png)
![With](https://i.imgur.com/TZn0bIR.png)

## What is this?
This is a static decryptor for Roblox. Essentially, it decrypts all the code pages manually by fetching the encryption keys from Hyperion, instead of following the usual dynamic approach, which forces Hyperion to decrypt the pages at runtime.

## How does this work?
Hyperion uses a modified version of Chacha20 to encrypt the pages. They change the constant, adjust the round count, and also transform the initial key before using it. The initial key is usually smaller than the required Chacha20 key, and the rest is extended during the transformation.

## How to use
After compiling the project, place the target Roblox version in the same directory as the compiled executable. Ensure that both `RobloxPlayerBeta.dll` and `RobloxPlayerBeta.exe` are in that directory. Once everything is set, simply run the compiled binary. It will automatically attempt to locate the page info array inside Hyperion and begin decrypting.
