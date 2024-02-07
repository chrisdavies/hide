# hide

A little Go program for storing secrets that are protected by a passphrase.

It supports three commands:

```
hide new somefile
hide edit somefile
hide help
```

The `new` and `edit` commands can also take additional flags which will be passed through to neovim:

```
hide edit somefile --noplugin
```

By default, the passphrase is displayed as you type. It is not stored in history, etc. If you are in a place where you don't want your passphrase to be displayed, you probably shouldn't be editing the secret files, either. That said, if you want to keep your passphrase hidden as you type, you can pass the `--mask` flag.

Editing is done in neovim without scratch or write capabilities. To save the secret file, you have to execute the following command:

```
:w !hide
```

## How it works

We generate an AES key from your passphrase + salt.

Encrypted files are stored in `~/.hide/` with the salt as the first line.

They are edited in neovim. When editing, we place a line at the top of the file which contains the file name, salt, and key. This line is removed before saving, and is only there to prevent keeping the secret or passphrase in an environment variable or other trivially inspected place.

