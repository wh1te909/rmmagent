### Tactical RMM Agent
https://github.com/wh1te909/tacticalrmm


### Building the windows agent with custom branding
Download and install the following prereqs
- [TDM-GCC](https://github.com/jmeubank/tdm-gcc/releases/download/v9.2.0-tdm64-1/tdm64-gcc-9.2.0.exe)
- [Golang](https://golang.org/dl/go1.15.5.windows-amd64.msi)
- [Inno Setup](https://jrsoftware.org/isdl.php)
- [Git bash](https://github.com/git-for-windows/git/releases/download/v2.29.1.windows.1/Git-2.29.1-64-bit.exe)


Run the following commands in git bash
```
mkdir c:/users/public/documents/rmmagent && cd c:/users/public/documents/rmmagent
git clone https://github.com/wh1te909/rmmagent.git .
go mod download
go get github.com/tc-hib/goversioninfo/cmd/goversioninfo
```

Read through the code / build files and change all references of ```Tactical RMM``` to ```Your Company RMM```

Do __not__ change any of the following or this will break on the RMM end
- The service names of the 3 windows services ```tacticalagent```, ```checkrunner``` and ```tacticalrpc```. You can however change the display names and descriptions of these.
- The ```TacticalAgent``` folder name in Program Files.
- The actual binary name ```tacticalrmm.exe```. Change the ```FileDescription``` in ```versioninfo.json``` which is what will show up in task manager.

Build the 64 bit agent
```
goversioninfo -64
env CGO_ENABLED=1 GOARCH=amd64 go build -o tacticalrmm.exe
"c:/Program Files (x86)\Inno Setup 6\ISCC.exe" build/setup.iss
```

Build the 32 bit agent
```
rm resource.syso tacticalrmm.exe
goversioninfo
env CGO_ENABLED=1 GOARCH=386 go build -o tacticalrmm.exe
"c:/Program Files (x86)\Inno Setup 6\ISCC.exe" build/setup-x86.iss
```

Binaries will be in ```build\Output```

From the RMM, choose the 'Manual' method when generating an agent to get the command line args to pass to the binary.

