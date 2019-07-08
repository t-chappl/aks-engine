

# TODO: remove - dead code?
function
Set-VnetPluginMode()
{
    Param(
        [Parameter(Mandatory=$true)][string]
        $AzureCNIConfDir,
        [Parameter(Mandatory=$true)][string]
        $Mode
    )
    # Sets Azure VNET CNI plugin operational mode.
    $fileName  = [Io.path]::Combine("$AzureCNIConfDir", "10-azure.conflist")
    (Get-Content $fileName) | %{$_ -replace "`"mode`":.*", "`"mode`": `"$Mode`","} | Out-File -encoding ASCII -filepath $fileName
}


function
Install-VnetPlugins
{
    Param(
        [Parameter(Mandatory=$true)][string]
        $AzureCNIConfDir,
        [Parameter(Mandatory=$true)][string]
        $AzureCNIBinDir,
        [Parameter(Mandatory=$true)][string]
        $VNetCNIPluginsURL
    )
    # Create CNI directories.
    mkdir $AzureCNIBinDir
    mkdir $AzureCNIConfDir

    # Download Azure VNET CNI plugins.
    # Mirror from https://github.com/Azure/azure-container-networking/releases
    $zipfile =  [Io.path]::Combine("$AzureCNIDir", "azure-vnet.zip")
    DownloadFileOverHttp -Url $VNetCNIPluginsURL -DestinationPath $zipfile
    Expand-Archive -path $zipfile -DestinationPath $AzureCNIBinDir
    del $zipfile

    # Windows does not need a separate CNI loopback plugin because the Windows
    # kernel automatically creates a loopback interface for each network namespace.
    # Copy CNI network config file and set bridge mode.
    move $AzureCNIBinDir/*.conflist $AzureCNIConfDir
}

# TODO: remove - dead code?
function
Set-AzureNetworkPlugin()
{
    # Azure VNET network policy requires tunnel (hairpin) mode because policy is enforced in the host.
    Set-VnetPluginMode "tunnel"
}

function
Set-AzureCNIConfig
{
    Param(
        [Parameter(Mandatory=$true)][string]
        $AzureCNIConfDir,
        [Parameter(Mandatory=$true)][string]
        $KubeDnsSearchPath,
        [Parameter(Mandatory=$true)][string]
        $KubeClusterCIDR,
        [Parameter(Mandatory=$true)][string]
        $MasterSubnet,
        [Parameter(Mandatory=$true)][string]
        $KubeServiceCIDR,
        [Parameter(Mandatory=$true)][string]
        $VNetCIDR,
        [Parameter(Mandatory=$true)][string]
        $TargetEnvironment
    )
    # Fill in DNS information for kubernetes.
    $fileName  = [Io.path]::Combine("$AzureCNIConfDir", "10-azure.conflist")
    $configJson = Get-Content $fileName | ConvertFrom-Json
    $configJson.plugins.dns.Nameservers[0] = $KubeDnsServiceIp
    $configJson.plugins.dns.Search[0] = $KubeDnsSearchPath
    $configJson.plugins.AdditionalArgs[0].Value.ExceptionList[0] = $KubeClusterCIDR
    $configJson.plugins.AdditionalArgs[0].Value.ExceptionList[1] = $MasterSubnet
    $configJson.plugins.AdditionalArgs[1].Value.DestinationPrefix  = $KubeServiceCIDR
    $configJson.plugins.AdditionalArgs[0].Value.ExceptionList += $VNetCIDR

    if ($TargetEnvironment -ieq "AzureStackCloud") {
        Add-Member -InputObject $configJson.plugins[0].ipam -MemberType NoteProperty -Name "environment" -Value "mas"
    }

    $configJson | ConvertTo-Json -depth 20 | Out-File -encoding ASCII -filepath $fileName
}

function
GenerateAzureStackCNIConfig
{
    Param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $TenantId,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $SubscriptionId,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $AADClientId,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $AADClientSecret,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $ResourceGroup,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $NetworkInterface,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $NetworkAPIVersion,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $SubnetPrefix,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $ServiceManagementEndpoint,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $ActiveDirectoryEndpoint,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $ResourceManagerEndpoint,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]
        $IdentitySystem
    )

    $nicConfigFile = "C:\k\network-interfaces.json"
    $azureCNIInterfaceFile = "C:\k\interfaces.json"

    Write-Log "------------------------------------------------------------------------"
    Write-Log "Parameters"
    Write-Log "------------------------------------------------------------------------"
    Write-Log "TenantId:                  $TenantId"
    Write-Log "SubscriptionId:            $SubscriptionId"
    Write-Log "AADClientId:               ..."
    Write-Log "AADClientSecret:           ..."
    Write-Log "ResourceGroup:             $ResourceGroup"
    Write-Log "NetworkInterface:          $NetworkInterface"
    Write-Log "NetworkAPIVersion:         $NetworkAPIVersion"
    Write-Log "SubnetPrefix:              $SubnetPrefix"
    Write-Log "ServiceManagementEndpoint: $ServiceManagementEndpoint"
    Write-Log "ActiveDirectoryEndpoint:   $ActiveDirectoryEndpoint"
    Write-Log "ResourceManagerEndpoint:   $ResourceManagerEndpoint"
    Write-Log "------------------------------------------------------------------------"
    Write-Log "Variables"
    Write-Log "------------------------------------------------------------------------"
    Write-Log "azureCNIInterfaceFile: $azureCNIInterfaceFile"
    Write-Log "networkInterfacesFile:   $nicConfigFile"
    Write-Log "------------------------------------------------------------------------"

    Write-Log "Generating token for Azure Resource Manager"

    $tokenURL = ""
    if($IdentitySystem -ieq "adfs") {
        $tokenURL = "$($ActiveDirectoryEndpoint)adfs/oauth2/token"
    } else {
        $tokenURL = "$($ActiveDirectoryEndpoint)$TenantId/oauth2/token"
    }

    $encodedSecret = [System.Web.HttpUtility]::UrlEncode($AADClientSecret)

    $body = "grant_type=client_credentials&client_id=$AADClientId&client_secret=$encodedSecret&resource=$ServiceManagementEndpoint"

    $token = Invoke-RestMethod -Uri $tokenURL -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' | select -ExpandProperty access_token

    Write-Log "Fetching network interface configuration for node"

    $interfacesUri = "$($ResourceManagerEndpoint)subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/networkInterfaces/$($NetworkInterface)?api-version=$NetworkAPIVersion"
    $headers = @{Authorization="Bearer $token"}

    Invoke-RestMethod -Uri $interfacesUri -Method Get -ContentType 'application/json' -Headers $headers -OutFile $nicConfigFile

    Write-Log "Generating Azure CNI interface file"

    $nicConfig = Get-Content $nicConfigFile | ConvertFrom-Json

    $ipAddresses = $nicConfig.properties.ipConfigurations | % { @{"Address"=$_.properties.privateIPAddress; "IsPrimary"=$_.properties.primary}}

    $config = @{Interfaces = @(@{
        MacAddress = $nicConfig.properties.macAddress
        IsPrimary = $nicConfig.properties.primary
        IPSubnets = @(@{
            Prefix = $SubnetPrefix
            IPAddresses = $ipAddresses
        })
    })}

    $config | ConvertTo-Json -Depth 6 | Out-File -FilePath $azureCNIInterfaceFile -Encoding ascii
}

