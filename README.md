# KVage

 terminal cli for saving and retrieving key-value pairs in a yaml file encrypting the values using [AGE encryption](https://github.com/FiloSottile/age) 


 ## Usage

Optional flags

```
-f --file <file> : specify the file to save the key-value pairs
-k --key <key> : specify the file key to use for encryption
```

 List all key-value pairs

 ```bash
 kvage list
 ```

Save a key-value pair

```bash
kvage set <key> <value>
```

Update a key-value pair

```bash
kvage up <key> <value>
```

Get a value by key

```bash
kvage get <key>
```

Delete a key-value pair

```bash
kvage rm <key>
```

Generate an AGE key pair

```bash
kvage generate-key
```
