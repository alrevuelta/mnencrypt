# mnencrypt
Encrypts and decrypts a mnemonic with a password so that it's safer to store. Use at your own risk. Better to use offline and with a 32 bytes password.

```
go build
```

## encrypt

```
./main --raw-mnemonic="your mnemonic"  --password="your-password-better-32-bytes"
```

## decrypt

```
./main --encrypted-mnemonic="0xyourencriptedmnemonic" --password="your-password-better-32-bytes"
```