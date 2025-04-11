# KVage

 terminal cli for saving and retrieving key-value pairs in a yaml file encrypting the values using [AGE encryption](https://github.com/FiloSottile/age) 


 ## Usage

Optional flags

```
-f --file <file> : specify the file to save the key-value pairs
-k --key <key> : specify the file key to use for encryption
```

 List all key-value pairs

 `--filter <filter>` : filter the key-value pairs by key

 ```bash
 kvage list
 ```

 Generate a exportable env variables

 `--filter <filter>` : filter the key-value pairs by key

 ```bash
 kvage export
 ```
> generate a list like:
> ```bash
> export MY_KEY="my_value"
> export MY_KEY2="my_value2"
> ```

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

## New .kvagerc file

.kvagerc is a file encrypted with kvage that contains the shell code commands, ideal for storing private env variables in your repository

1. encrypt the file with the command, encrypt command receives from the standard input the file to encrypt, and the output is the encrypted file:

```bash
kvage encrypt < decrypted_file >.kvagerc
```
2. install the shell command in your .bashrc

```bash
echo 'eval "$(kvage shellrc)"' >> ~/.bashrc
```

Now you can move into the directory with a .kvagerc file and the shell code decrypted will be available in your shell automatically

Also you can decrypt the file with the command:

```bash
kvage decrypt < .kvagerc > decrypted_file
```


## Tasks

### build

Build the release for all platforms

```bash
bash scripts/build.sh
```

### install:dependencies

Install the dependencies declared in the go.mod file

```bash
go mod tidy
```
