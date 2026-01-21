# SubstAgent-JVMTI
A Java Agent written in C that listens for strings containing environment variables (`${env_variable}`) and substitutes them accordingly. It is intended for use with Spigot plugins to enable environment variable support in their configuration files.

# How to use
`java -agentpath:/full/path/to/libsubstagent.so [rest of your command as normal]`\
For example:\
`java -agentpath:/full/path/to/libsubstagent.so -jar server.jar nogui`

# How to build
```
$ git clone https://github.com/SKBotNL/SubstAgent-JVMTI
$ cd SubstAgent-JVMTI
$ mkdir build
$ cd build
$ cmake ..
$ make
```

# Tests
The test script assumes that the generator is set to make (`-G "Unix Makefiles"`)