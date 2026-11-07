# NetSentry on Windows

## Prerequisites

1. Install Visual Studio 2022 or Build Tools with **Desktop development with C++** and a Windows SDK.
2. Install CMake 3.16+, Python 3, and VS Code. In VS Code, the CMake Tools extension is recommended.
3. Open the NetSentry folder in VS Code and select a Visual Studio x64 kit. Alternatively, open Developer PowerShell in this directory.

## Configure, build, and test

Run:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

## Generate a sample capture and run the CLI

```powershell
python .\tools\generate_test_pcap.py .\build\netsentry_sample.pcap
.\build\Release\netsentry.exe --input .\build\netsentry_sample.pcap --output .\build\sample-report --threads 2 --scan-threshold 3 --syn-threshold 100
```

The generated capture is synthetic. Reports are written to `build\sample-report.json` and `build\sample-report.csv`.

## Start the local dashboard

After building:

```powershell
python .\web\server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in a browser. The service binds to loopback only; stop it with `Ctrl+C`.

The offline reader does not require Npcap or libpcap. NetSentry does not perform live capture or network blocking. See [README.md](README.md) for CLI options, Linux instructions, tested features, and limitations.
