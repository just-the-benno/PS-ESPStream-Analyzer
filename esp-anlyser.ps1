
function Test-ESPStream {
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