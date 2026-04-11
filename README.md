# SubstAgent-JVMTI
A Java Agent written in C that listens for strings containing environment variables and substitutes them accordingly. It is intended for use with Spigot plugins to enable environment variable support in their configuration files.

# How to use
`java -agentpath:/full/path/to/libsubstagent.so [rest of your command as normal]`\
For example:\
`java -agentpath:/full/path/to/libsubstagent.so -jar server.jar nogui`

You can now use environment variables in your config files like so:\
`^{ENV_VAR_NAME}`

# How to build
```
$ git clone https://github.com/SKBotNL/SubstAgent-JVMTI
$ cd SubstAgent-JVMTI
$ cmake -B build
$ cmake --build build
```

# Tests
The tests can be run by executing the `run_tests.sh` script.