
function Test-ESPStream {
    <#
    .SYNOPSIS
        Analyse ESP Stream within multiple .pcap file to check for packet loss.

    .DESCRIPTION
        .

    .PARAMETER TsharkPath
        The path the the tshark executable. Points to the default installation on Windows 

    .PARAMETER Input
        The location of the directory where all files .pcap files should be analyzed.

    .PARAMETER ErspanId
        If packets are captured using ERSPAN and the analysing should only contain a certain id
        If this parameter is not set, no filtering based on ERSPAN is done  

    .PARAMETER PrintOutputResult
        If true the summery is written into the console window.

    .OUTPUTS
        Outputs an array where each item is a summery of the ESP stream. Items contain the following properties:
        Spi,SpiAsHex, PacketLoss, Total, Percentage, Source, Destination, 

    .EXAMPLE
        Test-ESPStream 

        Analyze the .pcap files in the current directory and output the summery into the console

        Test-ESPStream  -Input C:/PacketSniffing/Session1 -PrintOutputResult $false | Format-Table -Property Source, Destination, SpiAsHex, Total

        Analyze the .pcap files in the directory C:/PacketSniffing/Session1. The result are printed as a table, where each row has the properties Source,Destination,SpiAsHex and Total

        Test-ESPStream -ErspanId 4

         Analyze the .pcap files in the current directory. Only ESP stream that are captured by ERSPAN with an Id of 4 are analyzed and part of the result set

    .LINK
        https://github.com/just-the-benno/PS-ESPStream-Analyzer/

    #>
    param (
        [Parameter(Mandatory = $false)][string]$TsharkPath = "C:\Program Files\Wireshark\tshark.exe",
        [Parameter(Mandatory = $false)][string]$Input = ".\",
        [Parameter(Mandatory = $false)][string]$ErspanId,
        [Parameter(Mandatory = $false)][bool]$PrintOutputResult = $true
    )

    Write-Host "Analysing ESP Packet stream for lost packets"

    $files = Get-ChildItem -Path $Input -Filter "*.pcap";

    $spis = new-object "System.Collections.Generic.Dictionary[[int],[object]]"
    $results = @();
    foreach ($file in $files) {
        Write-Host "Reading file $file ..."
        $entries = & $TsharkPath  -r $($file.FullName) -Y esp -T fields -E header=n -e esp.spi -e esp.sequence -e ip.src -e ip.dst
        foreach ($line in $entries) {
            $parts = $line.Split("`t");
            $castedSpi = [System.Convert]::ToInt32($parts[0], 16);
            $sequenceNumber = [System.Convert]::ToUInt32($parts[1]);
            $sourceAddress = $parts[2];
            if ($sourceAddress.Contains(',') -eq $true) {
                $addressParts = $sourceAddress.Split(',')
                $sourceAddress = $addressParts[$addressParts.Length - 1];
            }

            $destinationAddress = $parts[3];
            if ($destinationAddress.Contains(',') -eq $true) {
                $addressParts = $destinationAddress.Split(',')
                $destinationAddress = $addressParts[$addressParts.Length - 1];
            }

            if ($spis.ContainsKey($castedSpi) -eq $false) {
                $entryAsTable = @{
                    Spi             = $castedSpi
                    SpiAsHex        = "0x" + $castedSpi.ToString("X4") 
                    PacketLoss      = 0
                    Total           = 1
                    Percentage      = 0.0
                    ExpectedSequnce = $sequenceNumber + 1
                    Source          = $sourceAddress
                    Destination     = $destinationAddress
                }

                $entry = New-Object psobject -Property $entryAsTable; $o
                $results += , $entry;
                $spis.Add($castedSpi, $entry)

                continue;
            }

            $spiEntry = $spis[$castedSpi];

            if ($sequenceNumber -ne $spiEntry.ExpectedSequnce) {
                $amountOfLostPackets = ($sequenceNumber - $spiEntry.ExpectedSequnce);
                $spiEntry.PacketLoss += $amountOfLostPackets;
                $spiEntry.Total += $amountOfLostPackets;
                # Write-Host "Packet loss detected: SPI: $($spiEntry.SpiAsHex) has lost $amountOfLostPackets packets" -ForegroundColor DarkRed
            }
            else {
                $spiEntry.Total++;
            }

            if ($sequenceNumber -eq [uint32]::MaxValue) {
                $spiEntry.ExpectedSequnce = 0;
            }
            else {
                $spiEntry.ExpectedSequnce = $sequenceNumber + 1;
            }
        }
    }

    foreach ($item in $results) {
        $item.Percentage = (100.0 * $item.PacketLoss) / $item.Total
    }

    if ($PrintOutputResult -eq $true) {
        $results | Sort-Object -Property Percentage -Descending | Format-Table -Property Source, Destination, SpiAsHex, PacketLoss, Total, Percentage | Out-String | Write-Host
    }

    return $results
}