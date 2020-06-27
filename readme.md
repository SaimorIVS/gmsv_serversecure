# gmsv_serversecure

[![Build Status](https://metamann.visualstudio.com/GitHub%20danielga/_apis/build/status/danielga.gmsv_serversecure?branchName=master)](https://metamann.visualstudio.com/GitHub%20danielga/_build/latest?definitionId=7&branchName=master)  
A module for Garry's Mod that mitigates exploits on the Source engine.  
Based on these plugins from AzuiSleet:  
[serverplugin_serversecure][1]  
[serverplugin_serversecure2][2]  
[serversecure3][3]

## Compiling

The only supported compilation platforms for this project on Windows are **Visual Studio 2015**, **Visual Studio 2017** and **Visual Studio 2019** on **release** mode.  
On Linux, everything should work fine as is, on **release** mode.  
For Mac OSX, any **Xcode version (using the GCC compiler)** *MIGHT* work as long as the **Mac OSX 10.7 SDK** is used, on **release** mode.  
These restrictions are not random; they exist because of ABI compatibility reasons.  
If stuff starts erroring or fails to work, be sure to check the correct line endings (`\n` and such) are present in the files for each OS.

## Requirements

This project requires [garrysmod_common][2], a framework to facilitate the creation of compilations files (Visual Studio, make, XCode, etc). Simply set the environment variable `GARRYSMOD_COMMON` or the premake option `--gmcommon=path` to the path of your local copy of [garrysmod_common][2].  
We also use [SourceSDK2013][3]. The previous links to [SourceSDK2013][3] point to my own fork of VALVe's repo and for good reason: Garry's Mod has lots of backwards incompatible changes to interfaces and it's much smaller, being perfect for automated build systems like Azure Pipelines (which is used for this project).

  [1]: https://github.com/azuisleet/gmodmodules/tree/master/serverplugin_serversecure
  [2]: https://github.com/azuisleet/gmodmodules/tree/master/serverplugin_serversecure2
  [3]: https://github.com/azuisleet/gmodmodules/tree/master/serversecure3
  [4]: https://github.com/danielga/garrysmod_common
  [5]: https://github.com/danielga/sourcesdk-minimal
