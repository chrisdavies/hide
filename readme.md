# hide

A little Go program for storing secrets that are protected by a passphrase.

It supports three commands:

- new
- edit
- help

Editing is done in neovim without plugins or write capabilities. To save the secret file, you have to execute the following command:

```
:w !hide
```

## How it works

We generate an AES key from your passphrase + salt.

Encrypted files are stored in `~/.hide/`.

They are edited in neovim. When editing, we place a line at the top of the file which contains the file name, salt, and key. This line is removed before saving, and is only there to prevent keeping the secret or password in an environment variable or other trivially inspected place.

To save the file from neovim, run:

`:w !hide`

