# PS4SaveDataDecryptingTools
CURRENTLY IN NON-WORKING STATE

## PS4DumpSealedKeyAndSecret

Just dumps to USB the sealed key and secret as shown here:

http://www.psdevwiki.com/ps4/Keys#Sealed_Key_Values

## PS4DecryptSaveDataKey

Working code based on the wiki code:

http://www.psdevwiki.com/ps4/Sealedkey_/_pfsSKKey

Put the encrypted PFS key you want to decrypt in your first USB drive and name it pfskeyencrypted

This payload spits out a decryptedSaveDataKey.bin file on your USB
