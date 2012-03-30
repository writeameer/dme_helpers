# ------------------------
# Functions
# ------------------------

$modRoot = Split-Path $script:MyInvocation.MyCommand.Path
. $modRoot\DmeKeys.ps1


$code = @"
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace DmeTools
{
    public class DmeClient : WebRequest
    {
        public string BaseUri { get; set; } 
        public string ApiKey { get; set; }
        public string SecretKey { get; set; }

        public HttpWebRequest ApiRequest;

        public DmeClient (string apiKey, string secretKey)  {
            SecretKey = secretKey;
            ApiKey = apiKey;
            BaseUri= "http://api.dnsmadeeasy.com/V1.2/";
            //BaseUri = "http://api.sandbox.dnsmadeeasy.com/V1.2/";
        }
 

        public void AddDmeHeaders() {
            // Generate DNS Made Easy Hash
            var rfcDate = Helpers.GetDateTimeRfc822();
            var dnsMeHash = Helpers.GenerateDnsMeHash(SecretKey, rfcDate);

            // Add Headers
            ApiRequest.Headers.Clear();
            
            
            ApiRequest.ContentType = "application/xml";
            ApiRequest.Accept = "application/xml";
            ApiRequest.Headers.Add("x-dnsme-apiKey", ApiKey);
            ApiRequest.Headers.Add("x-dnsme-requestDate", rfcDate);
            ApiRequest.Headers.Add("x-dnsme-hmac", dnsMeHash);
        }

        public HttpWebResponse Get( string url ) {
            return DoWebRequest( url, "GET" );
        }
        
        public HttpWebResponse Delete( string url ) {
            return DoWebRequest( url, "DELETE" );
        }

        public HttpWebResponse DoWebRequest( string url, string method ) {
            HttpWebResponse response;

            // Create request url
            ApiRequest = (HttpWebRequest)Create( BaseUri + url );
            ApiRequest.Method = method;
            // Add DME Http Headers
            AddDmeHeaders();

            // Make Request 
            try {
                response = (HttpWebResponse)ApiRequest.GetResponse();
            }
            catch (WebException webException) {
                response = (HttpWebResponse)webException.Response;
            }

            // Return response
            return response;
        }
        
        public HttpWebResponse Put(string url, string postData) {
            return Post(url, postData, "PUT");
        }
        
        public HttpWebResponse Post(string url, string postData) {
            return Post(url, postData, "POST");
        }
        
        public HttpWebResponse Post( string url, string postData, string verb ) {
            HttpWebResponse response;

            // Create request url
            ApiRequest = (HttpWebRequest)Create(BaseUri + url);
            ApiRequest.Method = verb;
            AddDmeHeaders();

            // Add POST data
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);
            ApiRequest.ContentLength = byteArray.Length;
            var dataStream = ApiRequest.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            // Make Request 
            try  {
                response = (HttpWebResponse)ApiRequest.GetResponse();
            }
            catch (WebException webException) {
                response = (HttpWebResponse)webException.Response;
            }

            // Return response
            return response;
        }
    }


    public class Helpers {
        public static string GetDateTimeRfc822() {
            // Get date time in GMT
            DateTime dateTime = DateTime.Now.ToUniversalTime();

            // Format to RFC 822 string
            string rfcdateTime = dateTime.ToString("ddd, dd MMM yyyy HH':'mm':'ss 'GMT'");

            return rfcdateTime;
        }

        public static string GenerateDnsMeHash(string key, string message) {
            var encoding = new ASCIIEncoding();

            // Encode key,Message
            byte[] keyBytes = encoding.GetBytes(key);

            byte[] messageBytes = encoding.GetBytes(message);

            // Create an HMAC  object using the given key
            var myhash = new HMACSHA1(keyBytes, false);

            // Compute the hash for the given message
            byte[] hashmessage = myhash.ComputeHash(messageBytes);

            // Convert message to string and return
            return ByteToString(hashmessage);
        }

        public static string ByteToString(byte[] byteArray) {
            var byteString = "";

            foreach (byte byteValue in byteArray)
                byteString += byteValue.ToString("X2").ToLower();

            return (byteString);
        }

        public static XmlDocument GetResponseContentXml(HttpWebResponse response) { 
            var reader = new StreamReader(response.GetResponseStream());
            var xmlDoc = new XmlDocument();
            var httpContent = reader.ReadToEnd();

            if (!String.IsNullOrEmpty(httpContent))
            {
                xmlDoc.LoadXml(httpContent);
				return xmlDoc;
            }

            return null;
        }
    }
}
"@

Add-Type -TypeDefinition $code -ReferencedAssemblies System.Xml -Language CSharpVersion3



function Resolve-Error ( $ErrorRecord=$Error[0] ) {
   $ErrorRecord | Format-List * -Force
   $ErrorRecord.InvocationInfo |Format-List *
   $Exception = $ErrorRecord.Exception
   for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException))
   {   "$i" * 80
       $Exception |Format-List * -Force
   }
}

function Get-DmeDomains() {
    $dmeClient = New-Object DmeTools.DmeClient($DmeApiKey, $DmeSecretKey)
	$httpResponse = $dmeClient.Get("domains")
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	$httpResponseXml.listWrapper
}

function Get-DmeDomain() {
	Param(
		[parameter(Mandatory=$true)] [string] $domain
	)
    $dmeClient = New-Object DmeTools.DmeClient($DmeApiKey, $DmeSecretKey)
	$httpResponse = $dmeClient.Get("domains/$domain")
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	$httpResponseXml.domain
}

function Add-DmeDomain(){
    Param( 
            [parameter(Mandatory=$true)] [string] $domain,
            [string] $gtdEnabled = "false"
         )
    
    # Create XML for new record. 
    # <nameServers> are not set because they seem to be set by the defaults for the dme account 
	$newRecord = "<domain><name>$domain</name><gtdEnabled>$gtdEnabled</gtdEnabled</domain>"
	
	# Make API Call
	$dmeClient = New-Object DmeTools.DmeClient($DmeApiKey, $DmeSecretKey)
	$httpResponse = $dmeClient.Put("domains/$domain",$newRecord)
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	$expectedError = "Record with this type, name, and value already exists"
	
	# Check for Errors
	if ($httpResponse.StatusCode -eq 201) {
		"Updated Recorded Successfully!"
	}
	elseif ($httpResponse.StatusCode -eq 400 -and $httpResponseXml.errors.error.Contains($expectedError)) {
		"Record already exists, this is an acceptable error..."
	}
	else {
		Resolve-Error $httpResponseXml.errors
	}
}

function Get-DmeRecords() {
	Param(
		[parameter(Mandatory=$true)] [string] $domain
	)
	
	$dmeClient = New-Object DmeTools.DmeClient($DmeApiKey, $DmeSecretKey)
	$httpResponse = $dmeClient.Get( "domains/$domain/records" )
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	$httpResponseXml.records
}

function Get-DmeRecord() {
	Param(
		[parameter(Mandatory=$true)] [string] $domain,
        [parameter(Mandatory=$true)] [string] $dnsId
	)
	
	$dmeClient = New-Object DmeTools.DmeClient($DmeApiKey, $DmeSecretKey)
	$httpResponse = $dmeClient.Get( "domains/$domain/records/$dnsId" )
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	$httpResponseXml.record
}

function Add-DmeRecord() {
	Param (
		    [Parameter(Mandatory=$true,ParameterSetName='ARecord')][switch] $A,
            [Parameter(Mandatory=$true,ParameterSetName='CNAMERecord')][switch] $CNAME,
            [Parameter(Mandatory=$true,ParameterSetName='MXRecord')][switch] $MX,
            
            [Parameter(Mandatory=$true,ParameterSetName='ARecord')] [string] $ipAddress,
            
            [Parameter(Mandatory=$true,ParameterSetName='CNAMERecord')] [string] $target,
            
            [Parameter(Mandatory=$true,ParameterSetName='MXRecord')][int] $priority,
            [Parameter(Mandatory=$true,ParameterSetName='MXRecord')][string] $mailServer,
            
            # these are common for all of the above ParameterSets
            [Parameter(Mandatory=$true)] [string] $domain,
		    [Parameter(Mandatory=$true)] [string] $name,
            
            [int] $ttl = 1800,
            [string] $gtdLocation = 'default'
	      )
	
    # Create XML for new record, do it by type
    if ( $A ) {
        $newRecord = "<record><type>A</type><name>$name</name><data>$ipAddress</data><ttl>$ttl</ttl><gtdLocation>$gtdLocation</gtdLocation></record>"
    }
    if ( $CNAME ) {
        $newRecord = "<record><type>CNAME</type><name>$name</name><data>$Target</data><ttl>$ttl</ttl><gtdLocation>$gtdLocation</gtdLocation></record>"
    }
    if ( $MX ) {
        $newRecord = "<record><type>MX</type><name>$name</name><data>$priority $mailServer</data><ttl>$ttl</ttl><gtdLocation>$gtdLocation</gtdLocation></record>"
    }
	
	# Make API Call
	$dmeClient = New-Object DmeTools.DmeClient($DmeApiKey, $DmeSecretKey)
	$httpResponse = $dmeClient.Post( "domains/$domain/records", $newRecord )
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	$expectedError = "Record with this type, name, and value already exists"
	
	# Check for Errors
	if ($httpResponse.StatusCode -eq 201) {
		"Updated Recorded Successfully!"
	}
	elseif ($httpResponse.StatusCode -eq 400 -and $httpResponseXml.errors.error.Contains($expectedError)) {
		"Record already exists, this is an acceptable error..."
	}
	else {
		Resolve-Error $httpResponseXml.errors
	}
}

function Update-DmeRecord() {
    Param(
		[parameter(Mandatory=$true)] [string] $domain,
		[parameter(Mandatory=$true)] [string] $dnsId
	)
    
    Write-Host "function not implimented"
}

function Remove-DmeRecord() {
	Param(
		[parameter(Mandatory=$true)] [string] $domain,
		[parameter(Mandatory=$true)] [string] $dnsId
	)
	
	$dmeClient = New-Object DmeTools.DmeClient($DmeApiKey, $DmeSecretKey)
	$httpResponse = $dmeClient.Delete("domains/$domain/records/$dnsId")
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	if ($httpResponse.StatusCode -eq 200) {
		"Recorded Deleted Successfully!"
	}
	else {
		Write-Error "Error deleting record, dump HTTP headers:"
		$httpResponse | fl *
	}
}

