# dirKey
Semi-silly encryption program that uses an RC4-like cipher to encrypt data. Eventually I'd like to be able to make it make USB sticks function like literal physical keys for files (that would be pretty cool).

Encrypt a directory
-----
`dirkey.exe -e keyDirectory encryptionDirectory`

Generates a key from the contents of directory `keyDirectory` and uses it to pack `encryptionDirectory` into a single encrypted file.

Decrypt a directory/package
-----
`dirkey.exe -d keyDirectory decryptionDirectory`

Searches the directory `decryptionDirectory` for any encrypted package files, and decrypts them using a key generated from `keyDirectory` if possible.

`dirkey.exe -d keyDirectory packageFile`

Decrypts the specified package file `packageFile` using a key generated from `keyDirectory` if possible.