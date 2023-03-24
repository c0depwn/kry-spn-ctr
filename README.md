# spn-ctr

This project contains a naive CTR-mode and SPN implementation
which decrypts the contents of a file (`chiffre.txt`) and writes
the decrypted output to `decrypted.txt`.

## Building application

The application uses the gradle build tool. 
The following are some helpful commands to build and run the application:
```shell
# ensure proper permissions on gradle wrapper
chmod +x ./gradlew
# build application
./gradlew clean build
# run application with gradle application plugin
./gradlew run
```

Alternatively, consult you IDEs documentation to execute the program,
if you prefer to use your integrated IDE gradle extension.

## TODO
- make SPN and CTR parameters configurable (currently hardcoded in Main)
- do not use `int` for the encryption/decryption process as bit alignment is very much a pain to deal with
- allow passing CLI arguments to configure parameters