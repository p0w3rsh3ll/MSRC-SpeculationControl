function Get-SpeculationControlSettings {
  <#

  .SYNOPSIS
  This function queries the speculation control settings for the system.

  .DESCRIPTION
  This function queries the speculation control settings for the system.

  .PARAMETER Quiet
  This parameter suppresses host output that is displayed by default.
  
  #>

  [CmdletBinding()]
  param (
    [switch]$Quiet
  )
  
  process {

    $NtQSIDefinition = @'
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength);
'@
    
    $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru


    [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

    $object = New-Object -TypeName PSObject

    try {
   
        $cpu = Get-CimInstance Win32_Processor

        if ($cpu -is [array]) {
            $cpu = $cpu[0]
        }

        $manufacturer = $cpu.Manufacturer
 
        #
        # Query branch target injection information.
        #

        if ($Quiet -ne $true) {

            Write-Host "For more information about the output below, please refer to https://support.microsoft.com/en-in/help/4074629" -ForegroundColor Cyan
            Write-Host
            Write-Host "Speculation control settings for CVE-2017-5715 [branch target injection]" -ForegroundColor Cyan

            if ($manufacturer -eq "AuthenticAMD") {
                Write-Host "AMD CPU detected: mitigations for branch target injection on AMD CPUs have additional registry settings for this mitigation, please refer to FAQ #15 at https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV180002" -ForegroundColor Cyan
            }

            Write-Host
        }

        $btiHardwarePresent = $false
        $btiWindowsSupportPresent = $false
        $btiWindowsSupportEnabled = $false
        $btiDisabledBySystemPolicy = $false
        $btiDisabledByNoHardwareSupport = $false

        $ssbdAvailable = $false
        $ssbdHardwarePresent = $false
        $ssbdSystemWide = $false
        $ssbdRequired = $null
    
        [System.UInt32]$systemInformationClass = 201
        [System.UInt32]$systemInformationLength = 4

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

        if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
            # fallthrough
        }
        elseif ($retval -ne 0) {
            throw (("Querying branch target injection information failed with error {0:X8}" -f $retval))
        }
        else {
    
            [System.UInt32]$scfBpbEnabled = 0x01
            [System.UInt32]$scfBpbDisabledSystemPolicy = 0x02
            [System.UInt32]$scfBpbDisabledNoHardwareSupport = 0x04
            [System.UInt32]$scfHwReg1Enumerated = 0x08
            [System.UInt32]$scfHwReg2Enumerated = 0x10
            [System.UInt32]$scfHwMode1Present = 0x20
            [System.UInt32]$scfHwMode2Present = 0x40
            [System.UInt32]$scfSmepPresent = 0x80
            [System.UInt32]$scfSsbdAvailable = 0x100
            [System.UInt32]$scfSsbdSupported = 0x200
            [System.UInt32]$scfSsbdSystemWide = 0x400
            [System.UInt32]$scfSsbdRequired = 0x1000

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

            $btiHardwarePresent = ((($flags -band $scfHwReg1Enumerated) -ne 0) -or (($flags -band $scfHwReg2Enumerated)))
            $btiWindowsSupportPresent = $true
            $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)

            if ($btiWindowsSupportEnabled -eq $false) {
                $btiDisabledBySystemPolicy = (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                $btiDisabledByNoHardwareSupport = (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
            }
            
            $ssbdAvailable = (($flags -band $scfSsbdAvailable) -ne 0)

            if ($ssbdAvailable -eq $true) {
                $ssbdHardwarePresent = (($flags -band $scfSsbdSupported) -ne 0)
                $ssbdSystemWide = (($flags -band $scfSsbdSystemWide) -ne 0)
                $ssbdRequired = (($flags -band $scfSsbdRequired) -ne 0)
            }

            if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                Write-Host "BpbEnabled                   :" (($flags -band $scfBpbEnabled) -ne 0)
                Write-Host "BpbDisabledSystemPolicy      :" (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                Write-Host "BpbDisabledNoHardwareSupport :" (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
                Write-Host "HwReg1Enumerated             :" (($flags -band $scfHwReg1Enumerated) -ne 0)
                Write-Host "HwReg2Enumerated             :" (($flags -band $scfHwReg2Enumerated) -ne 0)
                Write-Host "HwMode1Present               :" (($flags -band $scfHwMode1Present) -ne 0)
                Write-Host "HwMode2Present               :" (($flags -band $scfHwMode2Present) -ne 0)
                Write-Host "SmepPresent                  :" (($flags -band $scfSmepPresent) -ne 0)
                Write-Host "SsbdAvailable                :" (($flags -band $scfSsbdAvailable) -ne 0)
                Write-Host "SsbdSupported                :" (($flags -band $scfSsbdSupported) -ne 0)
                Write-Host "SsbdSystemWide               :" (($flags -band $scfSsbdSystemWide) -ne 0)
                Write-Host "SsbdRequired                 :" (($flags -band $scfSsbdRequired) -ne 0)
            }
        }

        if ($Quiet -ne $true) {
            Write-Host "Hardware support for branch target injection mitigation is present:"($btiHardwarePresent)
            Write-Host "Windows OS support for branch target injection mitigation is present:"($btiWindowsSupportPresent)
            Write-Host "Windows OS support for branch target injection mitigation is enabled:"($btiWindowsSupportEnabled)
  
            if ($btiWindowsSupportPresent -eq $true -and $btiWindowsSupportEnabled -eq $false) {
                Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by system policy:"($btiDisabledBySystemPolicy)
                Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by absence of hardware support:"($btiDisabledByNoHardwareSupport)
            }
        }
        
        $object | Add-Member -MemberType NoteProperty -Name BTIHardwarePresent -Value $btiHardwarePresent
        $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportPresent -Value $btiWindowsSupportPresent
        $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportEnabled -Value $btiWindowsSupportEnabled
        $object | Add-Member -MemberType NoteProperty -Name BTIDisabledBySystemPolicy -Value $btiDisabledBySystemPolicy
        $object | Add-Member -MemberType NoteProperty -Name BTIDisabledByNoHardwareSupport -Value $btiDisabledByNoHardwareSupport

        #
        # Query kernel VA shadow information.
        #
        
        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for CVE-2017-5754 [rogue data cache load]" -ForegroundColor Cyan
            Write-Host    
        }

        $kvaShadowRequired = $true
        $kvaShadowPresent = $false
        $kvaShadowEnabled = $false
        $kvaShadowPcidEnabled = $false
        
        $l1tfRequired = $true
        $l1tfMitigationPresent = $false
        $l1tfMitigationEnabled = $false
        $l1tfFlushSupported = $false
        $l1tfInvalidPteBit = $null

        [System.UInt32]$systemInformationClass = 196
        [System.UInt32]$systemInformationLength = 4

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

        if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
        }
        elseif ($retval -ne 0) {
            throw (("Querying kernel VA shadow information failed with error {0:X8}" -f $retval))
        }
        else {
    
            [System.UInt32]$kvaShadowEnabledFlag = 0x01
            [System.UInt32]$kvaShadowUserGlobalFlag = 0x02
            [System.UInt32]$kvaShadowPcidFlag = 0x04
            [System.UInt32]$kvaShadowInvpcidFlag = 0x08
            [System.UInt32]$kvaShadowRequiredFlag = 0x10
            [System.UInt32]$kvaShadowRequiredAvailableFlag = 0x20
            
            [System.UInt32]$l1tfInvalidPteBitMask = 0xfc0
            [System.UInt32]$l1tfInvalidPteBitShift = 6
            [System.UInt32]$l1tfFlushSupportedFlag = 0x1000
            [System.UInt32]$l1tfMitigationPresentFlag = 0x2000

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

            $kvaShadowPresent = $true
            $kvaShadowEnabled = (($flags -band $kvaShadowEnabledFlag) -ne 0)
            $kvaShadowPcidEnabled = ((($flags -band $kvaShadowPcidFlag) -ne 0) -and (($flags -band $kvaShadowInvpcidFlag) -ne 0))
            
            if (($flags -band $kvaShadowRequiredAvailableFlag) -ne 0) {
                $kvaShadowRequired = (($flags -band $kvaShadowRequiredFlag) -ne 0)
            }
            else {

                if ($manufacturer -eq "AuthenticAMD") {
                    $kvaShadowRequired = $false
                }
                elseif ($manufacturer -eq "GenuineIntel") {
                    $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
                    $result = $regex.Match($cpu.Description)
            
                    if ($result.Success) {
                        $family = [System.UInt32]$result.Groups[1].Value
                        $model = [System.UInt32]$result.Groups[2].Value
                        $stepping = [System.UInt32]$result.Groups[3].Value
                
                        if (($family -eq 0x6) -and 
                            (($model -eq 0x1c) -or
                             ($model -eq 0x26) -or
                             ($model -eq 0x27) -or
                             ($model -eq 0x36) -or
                             ($model -eq 0x35))) {

                            $kvaShadowRequired = $false
                        }
                    }
                }
                else {
                    throw ("Unsupported processor manufacturer: {0}" -f $manufacturer)
                }
            }

            $l1tfRequired = $kvaShadowRequired

            $l1tfInvalidPteBit = ($flags -band $l1tfInvalidPteBitMask) -shr $l1tfInvalidPteBitShift

            $l1tfMitigationEnabled = ($l1tfInvalidPteBit -ne 0)
            $l1tfFlushSupported = (($flags -band $l1tfFlushSupportedFlag) -ne 0)

            if (($flags -band $l1tfMitigationPresentFlag) -or
                ($l1tfMitigationEnabled -eq $true) -or 
                ($l1tfFlushSupported -eq $true)) {
                $l1tfMitigationPresent = $true
            }

            if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                Write-Host "KvaShadowEnabled             :" (($flags -band $kvaShadowEnabledFlag) -ne 0)
                Write-Host "KvaShadowUserGlobal          :" (($flags -band $kvaShadowUserGlobalFlag) -ne 0)
                Write-Host "KvaShadowPcid                :" (($flags -band $kvaShadowPcidFlag) -ne 0)
                Write-Host "KvaShadowInvpcid             :" (($flags -band $kvaShadowInvpcidFlag) -ne 0)
                Write-Host "KvaShadowRequired            :" $kvaShadowRequired
                Write-Host "KvaShadowRequiredAvailable   :" (($flags -band $kvaShadowRequiredAvailableFlag) -ne 0)
                Write-Host "L1tfRequired                 :" $l1tfRequired
                Write-Host "L1tfInvalidPteBit            :" $l1tfInvalidPteBit
                Write-Host "L1tfFlushSupported           :" $l1tfFlushSupported
            }
        }
        
        if ($Quiet -ne $true) {
            Write-Host "Hardware requires kernel VA shadowing:"$kvaShadowRequired

            if ($kvaShadowRequired) {

                Write-Host "Windows OS support for kernel VA shadow is present:"$kvaShadowPresent
                Write-Host "Windows OS support for kernel VA shadow is enabled:"$kvaShadowEnabled

                if ($kvaShadowEnabled) {
                    Write-Host "Windows OS support for PCID performance optimization is enabled: $kvaShadowPcidEnabled [not required for security]"
                }
            }
        }
        
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowRequired -Value $kvaShadowRequired
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportPresent -Value $kvaShadowPresent
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportEnabled -Value $kvaShadowEnabled
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowPcidEnabled -Value $kvaShadowPcidEnabled

        #
        # Speculation Control Settings for CVE-2018-3639 (Speculative Store Bypass)
        #
        
        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for CVE-2018-3639 [speculative store bypass]" -ForegroundColor Cyan
            Write-Host    
        }
        
        if ($Quiet -ne $true) {
            if (($ssbdAvailable -eq $true)) {
                Write-Host "Hardware is vulnerable to speculative store bypass:"$ssbdRequired
                if ($ssbdRequired -eq $true) {
                    Write-Host "Hardware support for speculative store bypass disable is present:"$ssbdHardwarePresent
                    Write-Host "Windows OS support for speculative store bypass disable is present:"$ssbdAvailable
                    Write-Host "Windows OS support for speculative store bypass disable is enabled system-wide:"$ssbdSystemWide
                }
            }
            else {
                Write-Host "Windows OS support for speculative store bypass disable is present:"$ssbdAvailable
            }
        }

        $object | Add-Member -MemberType NoteProperty -Name SSBDWindowsSupportPresent -Value $ssbdAvailable
        $object | Add-Member -MemberType NoteProperty -Name SSBDHardwareVulnerable -Value $ssbdRequired
        $object | Add-Member -MemberType NoteProperty -Name SSBDHardwarePresent -Value $ssbdHardwarePresent
        $object | Add-Member -MemberType NoteProperty -Name SSBDWindowsSupportEnabledSystemWide -Value $ssbdSystemWide

        
        #
        # Speculation Control Settings for CVE-2018-3620 (L1 Terminal Fault)
        #
        
        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for CVE-2018-3620 [L1 terminal fault]" -ForegroundColor Cyan
            Write-Host    
        }
        
        if ($Quiet -ne $true) {
            Write-Host "Hardware is vulnerable to L1 terminal fault:"$l1tfRequired

            if ($l1tfRequired -eq $true) {
                Write-Host "Windows OS support for L1 terminal fault mitigation is present:"$l1tfMitigationPresent
                Write-Host "Windows OS support for L1 terminal fault mitigation is enabled:"$l1tfMitigationEnabled
            }
        }

        $object | Add-Member -MemberType NoteProperty -Name L1TFHardwareVulnerable -Value $l1tfRequired
        $object | Add-Member -MemberType NoteProperty -Name L1TFWindowsSupportPresent -Value $l1tfMitigationPresent
        $object | Add-Member -MemberType NoteProperty -Name L1TFWindowsSupportEnabled -Value $l1tfMitigationEnabled
        $object | Add-Member -MemberType NoteProperty -Name L1TFInvalidPteBit -Value $l1tfInvalidPteBit
        $object | Add-Member -MemberType NoteProperty -Name L1DFlushSupported -Value $l1tfFlushSupported

        #
        # Provide guidance as appropriate.
        #

        $actions = @()
        
        if ($btiHardwarePresent -eq $false) {
            $actions += "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
        }

        if (($btiWindowsSupportPresent -eq $false) -or 
            ($kvaShadowPresent -eq $false) -or
            ($ssbdAvailable -eq $false) -or
            ($l1tfMitigationPresent -eq $false)) {
            $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
        }

        if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or 
            ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false) -or
            ($l1tfRequired -eq $true -and $l1tfMitigationEnabled -eq $false)) {
            $guidanceUri = ""
            $guidanceType = ""

            
            $os = Get-WmiObject Win32_OperatingSystem

            if ($os.ProductType -eq 1) {
                # Workstation
                $guidanceUri = "https://support.microsoft.com/help/4073119"
                $guidanceType = "Client"
            }
            else {
                # Server/DC
                $guidanceUri = "https://support.microsoft.com/help/4072698"
                $guidanceType = "Server"
            }

            $actions += "Follow the guidance for enabling Windows $guidanceType support for speculation control mitigations described in $guidanceUri"
        }

        if ($Quiet -ne $true -and $actions.Length -gt 0) {

            Write-Host
            Write-Host "Suggested actions" -ForegroundColor Cyan
            Write-Host 

            foreach ($action in $actions) {
                Write-Host " *" $action
            }
        }

        return $object

    }
    finally
    {
        if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
        }
 
        if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
        }
    }    
  }
}

# SIG # Begin signature block
# MIIdhAYJKoZIhvcNAQcCoIIddTCCHXECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJF6qQg/Js6mpQCQIvVpsmcMA
# mWqgghhSMIIEwjCCA6qgAwIBAgITMwAAAMM7uBDWq3WchAAAAAAAwzANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODUx
# WhcNMTgwOTA3MTc1ODUxWjCBsjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEMMAoGA1UECxMDQU9DMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046
# RDIzNi0zN0RBLTk3NjExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCiOG2wDGVZj5ZH
# gCl0ZaExy6HZQZ9T2uupPuxqtiWqXH2oIj762GqMc1JPYHkpEo5alygWdvB3D6FS
# qpA8al+mGJTMktlA+ydstLPRr6CBoEF+hm6RBzwVlsN9z6BVppwIZWt2lEVG6r1Y
# W1y1rb0d4FsA8qwRSI0sB8sAw9IHXi/J4Jd6klQvw2m6oLXl9C73/1DldPPZYGOT
# DQ98RxIaYewvksnNqblmvFpOx8Kuedkxl4jtAKl0F/2+QqRfU32OAiCiYFgZIgOP
# B4A8UbHmLIyn7pNqtom4NqMiZz9G4Bm5bwILhElYcZPMq/P1Hr38/WoAD99WAm3W
# FpXSFZejAgMBAAGjggEJMIIBBTAdBgNVHQ4EFgQUc3cXeGMQ8QV4IbaO4PEw84WH
# F6gwHwYDVR0jBBgwFoAUIzT42VJGcArtQPt2+7MrsMM1sw8wVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljcm9zb2Z0VGltZVN0YW1wUENBLmNybDBYBggrBgEFBQcBAQRMMEowSAYIKwYB
# BQUHMAKGPGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0VGltZVN0YW1wUENBLmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQUFAAOCAQEASOPK1ntqWwaIWnNINY+LlmHQ4Q88h6TON0aE+6cZ2RrjBUU4
# 9STkyQ2lgvKpmIkQYWJbuNRh65IJ1HInwhD8XWd0f0JXAIrzTlL0zw3SdbrtyZ9s
# P4NxqyjQ23xBiI/d13CrtfTAVlGYIY1Ahl80+0KGyuUzJLTi9350/gHaI0Jz3irw
# rJ+htxF1UW/NT0AYJyRYe2el9JhgeudeKOKav3fQBlzALQmk4Ekoyq3muJHGoqfe
# No4zsP/M+WQ6oBMlUq8/49sg/ryuP0EeVtNiePuxPmX5i6Knzpd3rPgKPS+9Tq1d
# KLts1K4rjpASoKSs8Ubv3rwQSw0O/zTd1bc8EjCCBf8wggPnoAMCAQICEzMAAAED
# XiUcmR+jHrgAAAAAAQMwDQYJKoZIhvcNAQELBQAwfjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2ln
# bmluZyBQQ0EgMjAxMTAeFw0xODA3MTIyMDA4NDhaFw0xOTA3MjYyMDA4NDhaMHQx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xHjAcBgNVBAMTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBANGUdjbmhqs2/mn5RnyLiFDLkHB/sFWpJB1+OecFnw+se5eyznMK+9SbJFwW
# tTndG34zbBH8OybzmKpdU2uqw+wTuNLvz1d/zGXLr00uMrFWK040B4n+aSG9PkT7
# 3hKdhb98doZ9crF2m2HmimRMRs621TqMd5N3ZyGctloGXkeG9TzRCcoNPc2y6aFQ
# eNGEiOIBPCL8r5YIzF2ZwO3rpVqYkvXIQE5qc6/e43R6019Gl7ziZyh3mazBDjEW
# jwAPAf5LXlQPysRlPwrjo0bb9iwDOhm+aAUWnOZ/NL+nh41lOSbJY9Tvxd29Jf79
# KPQ0hnmsKtVfMJE75BRq67HKBCMCAwEAAaOCAX4wggF6MB8GA1UdJQQYMBYGCisG
# AQQBgjdMCAEGCCsGAQUFBwMDMB0GA1UdDgQWBBRHvsDL4aY//WXWOPIDXbevd/dA
# /zBQBgNVHREESTBHpEUwQzEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xFjAUBgNVBAUTDTIzMDAxMis0Mzc5NjUwHwYDVR0jBBgwFoAU
# SG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29kU2lnUENBMjAxMV8yMDEx
# LTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYBBQUHMAKGRWh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljQ29kU2lnUENBMjAxMV8y
# MDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQCf
# 9clTDT8NJuyiRNgN0Z9jlgZLPx5cxTOjpMNsrx/AAbrrZeyeMxAPp6xb1L2QYRfn
# MefDJrSs9SfTSJOGiP4SNZFkItFrLTuoLBWUKdI3luY1/wzOyAYWFp4kseI5+W4O
# eNgMG7YpYCd2NCSb3bmXdcsBO62CEhYigIkVhLuYUCCwFyaGSa/OfUUVQzSWz4Fc
# GCzUk/Jnq+JzyD2jzfwyHmAc6bAbMPssuwculoSTRShUXM2W/aDbgdi2MMpDsfNI
# wLJGHF1edipYn9Tu8vT6SEy1YYuwjEHpqridkPT/akIPuT7pDuyU/I2Au3jjI6d4
# W7JtH/lZwX220TnJeeCDHGAK2j2w0e02v0UH6Rs2buU9OwUDp9SnJRKP5najE7NF
# WkMxgtrYhK65sB919fYdfVERNyfotTWEcfdXqq76iXHJmNKeWmR2vozDfRVqkfEU
# 9PLZNTG423L6tHXIiJtqv5hFx2ay1//OkpB15OvmhtLIG9snwFuVb0lvWF1pKt5T
# S/joynv2bBX5AxkPEYWqT5q/qlfdYMb1cSD0UaiayunR6zRHPXX6IuxVP2oZOWsQ
# 6Vo/jvQjeDCy8qY4yzWNqphZJEC4OmekB1+g/tg7SRP7DOHtC22DUM7wfz7g2Qjo
# jCFKQcLe645b7gPDHW5u5lQ1ZmdyfBrqUvYixHI/rjCCBgcwggPvoAMCAQICCmEW
# aDQAAAAAABwwDQYJKoZIhvcNAQEFBQAwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZ
# MBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJv
# b3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTA3MDQwMzEyNTMwOVoXDTIxMDQw
# MzEzMDMwOVowdzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEh
# MB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAn6Fssd/bSJIqfGsuGeG94uPFmVEjUK3O3RhOJA/u
# 0afRTK10MCAR6wfVVJUVSZQbQpKumFwwJtoAa+h7veyJBw/3DgSY8InMH8szJIed
# 8vRnHCz8e+eIHernTqOhwSNTyo36Rc8J0F6v0LBCBKL5pmyTZ9co3EZTsIbQ5ShG
# Lieshk9VUgzkAyz7apCQMG6H81kwnfp+1pez6CGXfvjSE/MIt1NtUrRFkJ9IAEpH
# ZhEnKWaol+TTBoFKovmEpxFHFAmCn4TtVXj+AZodUAiFABAwRu233iNGu8QtVJ+v
# HnhBMXfMm987g5OhYQK1HQ2x/PebsgHOIktU//kFw8IgCwIDAQABo4IBqzCCAacw
# DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUIzT42VJGcArtQPt2+7MrsMM1sw8w
# CwYDVR0PBAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMIGYBgNVHSMEgZAwgY2AFA6s
# gmBAVieX5SUT/CrhClOVWeSkoWOkYTBfMRMwEQYKCZImiZPyLGQBGRYDY29tMRkw
# FwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCEHmtFqFKoKWtTHNY9AcTLmUwUAYDVR0f
# BEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUFBwEBBEgwRjBEBggr
# BgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNy
# b3NvZnRSb290Q2VydC5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcN
# AQEFBQADggIBABCXisNcA0Q23em0rXfbznlRTQGxLnRxW20ME6vOvnuPuC7UEqKM
# bWK4VwLLTiATUJndekDiV7uvWJoc4R0Bhqy7ePKL0Ow7Ae7ivo8KBciNSOLwUxXd
# T6uS5OeNatWAweaU8gYvhQPpkSokInD79vzkeJkuDfcH4nC8GE6djmsKcpW4oTmc
# Zy3FUQ7qYlw/FpiLID/iBxoy+cwxSnYxPStyC8jqcD3/hQoT38IKYY7w17gX606L
# f8U1K16jv+u8fQtCe9RTciHuMMq7eGVcWwEXChQO0toUmPU8uWZYsy0v5/mFhsxR
# VuidcJRsrDlM1PZ5v6oYemIp76KbKTQGdxpiyT0ebR+C8AvHLLvPQ7Pl+ex9teOk
# qHQ1uE7FcSMSJnYLPFKMcVpGQxS8s7OwTWfIn0L/gHkhgJ4VMGboQhJeGsieIiHQ
# Q+kr6bv0SMws1NgygEwmKkgkX1rqVu+m3pmdyjpvvYEndAYR7nYhv5uCwSdUtrFq
# PYmhdmG0bqETpr+qR/ASb/2KMmyy/t9RyIwjyWa9nR2HEmQCPS2vWY+45CHltbDK
# Y7R4VAXUQS5QrJSwpXirs6CWdRrZkocTdSIvMqgIbqBbjCW/oO+EyiHW6x5PyZru
# SeD3AWVviQt9yGnI5m7qp5fOMSn/DsVbXNhNG6HY+i+ePy5VFmvJE6P9MIIHejCC
# BWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJv
# b3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcN
# MjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2
# WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSH
# fpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQ
# z7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHml
# SSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3o
# iU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6
# nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6ep
# ZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf
# 28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCn
# q47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx
# 7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O
# 9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0G
# A1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMA
# dQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAW
# gBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQy
# MDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZC
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQy
# MDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCB
# gzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9k
# b2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABf
# AHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEB
# CwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LR
# bYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r
# 4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb
# 7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6v
# mSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/
# sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad2
# 5UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUf
# FL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWx
# m6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMj
# aHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7
# qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCBJwwggSY
# AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAm
# BgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAEDXiUc
# mR+jHrgAAAAAAQMwCQYFKw4DAhoFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQUGJSbusll0VLRGe86wRnHMtlpptwwUAYKKwYBBAGCNwIBDDFCMECgFoAUAFAA
# bwB3AGUAcgBTAGgAZQBsAGyhJoAkaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1Bv
# d2VyU2hlbGwgMA0GCSqGSIb3DQEBAQUABIIBAA5KlS0v/7Z8NhqIFP7MqJ0i+KJF
# mmcc7tLP5wIcv4nHQMMIaTWYy9VnAvE3zU6uvV3Uft9tD0u7SHEwAhlQ5OzG3aPF
# /uFpXJ8jyQtAIXZemGH5Drb45Jnq/aRHTKYBrZtmcIScfuihlyD+0xHZN7vRdOFd
# rG6MIz1MUg9uHXWZTk4OW4ClCLX0kUdIt13x8o0TqTjbdRsp5XlQCYhDYi7g18/Y
# QIRIzNrUjUqmuJUHeFMUxv2cO1xeEqJLOPYy8ll9e9Zogo6U+5Rs1FhnGXUhsRVP
# H4Yj8ElOexroEJO8CkG+O7wFDsJ0gN0PXV4sgDqV2+3YdXto6iOE8Ps6seGhggIo
# MIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4wdzELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBAhMzAAAAwzu4ENardZyEAAAAAADDMAkGBSsOAwIaBQCgXTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xODA4MTEwMDM2MDVa
# MCMGCSqGSIb3DQEJBDEWBBTJ2QMYXExVChea9cLUgCd5crGXfzANBgkqhkiG9w0B
# AQUFAASCAQAPftSKw3E0J6QpHzaHw2q0mLqjIHxO1idQWkIH62YW34VOY3Tw8tY6
# jzUu7VbREd2PELercmoTT8MKiz0XEzc8RROF0CoZIpb5swJSha7oxZHtj06ks+HO
# RD6OLw+bzkrJeDJ4JtIg+kMttIAkgxZht9khADoSsEVw7sbW5fBhGDl1qZy41Cpt
# w3sHXcxAtdX8FJVBWvncnn2XHEzfuBVSKrRCa9YBYGVWzn4hMz/PKLQuu2cRBmwm
# rpHFybyB2oJm+63AyxGUFO9HAqcV9A/HpUqUaj+b8GI2eyscPA7fv1Lcikb7qv1y
# MDHmzCP6VND+izX2N40TuZFwR6nIsc+H
# SIG # End signature block
