# Pyinstaller repacker

Tool to extract and repack pyinstaller generated windows executables. Supports recent versions of pyinstaller. Python 3 only.

# Dependencies

```
pip install lxml
pip install lief
```

# Usage

To extract a exe run

```
$ python pyinst-repacker.py --extract test.exe
```

This will extract the exe under the directory `test.exe-repacker`.

To build exe from this directory run,

```
$ python pyinst-repacker.py --build test.exe-repacker
```

Output file will be written to `test.exe-repacker\generated.exe`.

# License

Licensed Under MIT
