function ConvertTo-ProductKey {
    <#   
    .SYNOPSIS   
        Converts registry key value to windows product key.
         
    .DESCRIPTION   
        Converts registry key value to windows product key. Specifically the following keys:
            SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId
            SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId4
        
    .PARAMETER Registry
        Either DigitalProductId or DigitalProductId4 (as described in the description)
         
    .NOTES   
        Author: Zachary Loeber
        Original Author: Boe Prox
        Version: 1.0
         - Took the registry setting retrieval portion from Boe's original script and converted it
           to this basic conversion function. This is to be used in conjunction with my other
           function, get-remoteregistryinformation
     
    .EXAMPLE 
     PS > $reg_ProductKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
     PS > $a = Get-RemoteRegistryInformation -Key $reg_ProductKey -AsObject
     PS > ConvertTo-ProductKey $a.DigitalProductId
     
            XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
            
     PS > ConvertTo-ProductKey $a.DigitalProductId4 -x64
     
            XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
         
        Description 
        ----------- 
        Retrieves the product key information from the local machine and converts it to a readible format.
    #>      
    [cmdletbinding()]
    param (
        [parameter(Mandatory=$True,Position=0)]
        $Registry,
        [parameter()]
        [Switch]$x64
    )
    begin {
        $map="BCDFGHJKMPQRTVWXY2346789" 
    }
    process {
        $ProductKey = ""

        $prodkey = $Registry[0x34..0x42]

        for ($i = 24; $i -ge 0; $i--) 
        { 
            $r = 0 
            for ($j = 14; $j -ge 0; $j--) 
            {
                $r = ($r * 256) -bxor $prodkey[$j] 
                $prodkey[$j] = [math]::Floor([double]($r/24)) 
                $r = $r % 24 
            } 
            $ProductKey = $map[$r] + $ProductKey 
            if (($i % 5) -eq 0 -and $i -ne 0)
            { 
                $ProductKey = "-" + $ProductKey
            }
        }
        $ProductKey
    }
}
