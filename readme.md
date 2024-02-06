# safe

A little Go program for storing secrets that are protected by a passphrase.

It supports three commands:

- new
- cat
- edit
- write

Editing is done in neovim without plugins or write capabilities. To save the secret file, you have to execute the following command:

```
:w !safe write filename.pass
```

## How it works

We generate an AES key from the passphrase + salt.

We generate a public / private keypair and encrypt it via the AES key.

We store the salt and aes-encrypted public / private keys in the final file.

When editing, we temporarily store the public key in an environment variable `SECRET_KEY` so that neovim can save.

Save uses `SECRET_KEY` to save the data, but does *not* overwrite the salt or key info in the file-- just the file content.

Saved secret files look like this:

```
base64url_encoded_salt
aes_encrypted_public_key
aes_encrypted_private_key
content (can be multi-line)
```

Cat and edit both generate the AES key, decrypt the *private* key, and then use that to decrypt the remaining content.

