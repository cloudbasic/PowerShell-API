<#
Sample PowerShell script to call the CLOUDBASIC API
#>

$method = 'POST'
$service = 'cloudbasic'

$region = 'us-east-1' <#DO NOT CHANGE! This is a constant in the CLOUDBASIC API#>
$scheme="AWS4"
$algorithm = 'AWS4-HMAC-SHA256'

<# API Method and body content for it #>

$host1 = 'YOUR.HOST.NAME.HERE:YOUR_PORT' <#10.10.10.2:82#>
$canonical_uri = 'API_CALL_PATH' <#/api/GetReplicationsList#>
$endpoint = 'http://' + $host1 + $canonical_uri

$access_key = 'YOUR_CLOUDBASIC_API_KEY' <#https://cloudbasic.net/documentation/api/#> 
$secret_key = 'YOUR_CLOUDBASIC_SECRET_API_KEY' <#https://cloudbasic.net/documentation/api/#> 

$bodyContent ='{"replicationId":""}' <#Put any expected parameters in here. Leave blank if no parameters are expected.#>

function getStringHash([String] $String,$HashName = "SHA256") 
{ 
	$StringBuilder = New-Object System.Text.StringBuilder 
	[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
		[Void]$StringBuilder.Append($_.ToString("x2")) 
	} 
	$StringBuilder.ToString() 
}

function computeKeyedHash($key, $data)
{
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.key = $key
    return $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($data))
}

function hash($request) 
{
 	$hash =getStringHash($request)
	return $hash
}

$contentHash = hash $bodyContent;

$amz_date = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$datestamp = [DateTime]::UtcNow.ToString('yyyyMMdd')

<# canonical headers #>
$canonical_headers = 'content-type:' + "application/xml" + "`n";
$canonical_headers = $canonical_headers +'host:' + $host1 + "`n"
$canonical_headers = $canonical_headers + 'x-amz-content-sha256:' + $contentHash + "`n";
$canonical_headers = $canonical_headers + 'x-amz-date:' + $amz_date;
$canonical_header_names = 'content-type;host;x-amz-content-sha256;x-amz-date'; 
 
<#---------------------------#>
$credential_scope = $datestamp + '/' + $region + '/' + $service + '/' + "aws4_request" 
 
function getSignatureKey($key, $dateStamp, $regionName, $serviceName)
{
    $kSecret = [Text.Encoding]::UTF8.GetBytes(("AWS4" + $key).toCharArray())
    $kDate = computeKeyedHash  $kSecret  $dateStamp;
    $kRegion = computeKeyedHash $kDate   $regionName;
    $kService = computeKeyedHash $kRegion $serviceName;
    $kSigning = computeKeyedHash $kService "aws4_request";
  
    return $kSigning; 
}

function canonicalizeRequest($uri, $httpMethod, $queryParameters, $canonicalizedHeaderNames, $canonicalizedHeaders, $bodyHash)
{
	$canonicalRequest=""
	$canonicalRequest += $httpMethod + "`n"
	$canonicalRequest += $uri + "`n"
	$canonicalRequest += $queryParameters + "`n"
	$canonicalRequest += $canonicalizedHeaders + "`n`n"
	$canonicalRequest += $canonicalizedHeaderNames + "`n"
	$canonicalRequest += $bodyHash 
	
	return $canonicalRequest
}  
$canonical_request1= canonicalizeRequest $canonical_uri "POST" "" $canonical_header_names  $canonical_headers  $contentHash
Write-Host "`n Request `n" 
Write-Host $canonical_request1
Write-Host "`n ----------------------"
 
$canonical_request_hash = hash -request $canonical_request1 
$string_to_sign = $algorithm + "`n" +  $amz_date + "`n" +  $credential_scope + "`n" +  $canonical_request_hash
Write-Host "`n String to sign: `n" $string_to_sign 
Write-Host "`n ----------------------"
 
$signing_key = getSignatureKey $secret_key $datestamp $region $service
$signatureHash =  computeKeyedHash -key $signing_key -data $string_to_sign
$signature= [System.BitConverter]::ToString($signatureHash).Replace('-','').ToLower()
Write-Host "`n Signature:" $signature 
 
$auth_string=  $algorithm + " Credential="+$access_key+"/"+$credential_scope + ", SignedHeaders=" +$canonical_header_names + ", Signature=" + $signature
Write-Host "`n" $auth_string 

<# Setting HTTP headers for the Invoke-WebRequest call #>
$iwr_headers=@{'host' = '3.230.35.98:82'; 'x-amz-content-sha256' = $contentHash; 'x-amz-date' = $amz_date; 'content-type' = 'application/xml'; 'authorization' = $auth_string }

<# executing Invoke-WebRequest call #>
$r= iwr -URI $endpoint -Method 'POST' -Headers $iwr_headers -Body $bodyContent

Write-Host "`n" $r

