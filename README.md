# xeca
xeca is a project that creates encrypted PowerShell payloads for offensive purposes.

Creating position independent shellcode from DLL files is also possible.

## Table of Contents
- [xeca](#xeca)
  * [Install](#install)
  * [How It Works](#how-it-works)
  * [Mitigations](#mitigations)
  * [Examples](#examples)
    + [Empire](#empire)
    + [Merlin](#merlin)
    + [Sliver](#sliver)
  * [Acknowledgements](#acknowledgements)
  * [License](#license)

## Install
Firstly ensure that rust is [installed](https://www.rust-lang.org/tools/install), then build the project with the following command:
```
cargo build
```

## How It Works
1. Identify and encrypt the payload. Load encrypted payload into a powershell script and save to a file named "launch.txt"
3. The key to decrypt the payload is saved to a file named "safe.txt"
3. Execute "launch.txt" on a remote host
   - The script will call back to the attacker defined web server to retrieve the decryption key "safe.txt"
   - Decrypt the payload in memory
   - Execute the intended payload in memory

## Mitigations
If users must have access to programs such as powershell.exe, consider minimising security risks with [Just Enough Administration](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7) and [PowerShell Logging](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/whats-new/script-logging?view=powershell-7). Application control policies can be deployed via a whitelisting technology such as [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview).

## Examples
### Empire
[Empire](https://github.com/bc-security/empire) PowerShell payload.
![gif](https://github.com/postrequest/storage/blob/master/xeca/empire.gif?raw=true)

### Merlin
[Merlin](https://github.com/Ne0nd0g/merlin) DLL payload.
![gif](https://github.com/postrequest/storage/blob/master/xeca/merlin.gif?raw=true)

### Sliver
[Sliver](https://github.com/BishopFox/sliver) Shellcode payload.
![gif](https://github.com/postrequest/storage/blob/master/xeca/sliver.gif?raw=true)

## Acknowledgements
This tool would not be possible without the sharing of knowledge and information. Ideas, snippets and code from from the following authors should be acknowledged:  
[@monoxgas](https://github.com/monoxgas)  
[H0neyBadger](https://github.com/H0neyBadger)  
[@stephenfewer](https://github.com/stephenfewer)  
[@dismantl](https://github.com/dismantl)  

## License
xeca is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html), some sub-components may have separate licenses. See their respective references in this project for details.
