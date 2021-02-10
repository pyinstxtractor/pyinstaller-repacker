# Pyinstaller Repacker

Tool to extract and repack pyinstaller generated windows executables. Supports recent versions of pyinstaller. Python 3 only. Doesn't support encrypted PYZ archives.

# Dependencies

```
pip install lxml
pip install lief
```

# Usage

To extract a exe run

```
$ python pyinst-repacker.py extract test.exe
```

This will extract the exe under the directory `test.exe-repacker`.

To build exe from this directory run,

```
$ python pyinst-repacker.py build test.exe-repacker
```

Optionally use the `--scanpy` argument to use the corresponding .py file instead of .pyc (if it exists).

```
$ python pyinst-repacker.py build --scanpy test.exe-repacker
```

The `--ignore-missing` option can used during build to ignore any non-existent files. Useful when trying to rebuild after deleting some files.

Repacked exe will be written to `test.exe-repacker\test-repacked.exe`.



# License

Licensed Under MIT
