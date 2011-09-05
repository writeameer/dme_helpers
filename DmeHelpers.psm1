# ------------------------
# Functions
# ------------------------

function Add-DmeTools()
{

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

        public HttpWebResponse Get(string url) {
            return DoWebRequest(url, "GET");
        }

        public HttpWebResponse Delete (string url)
        {
            return DoWebRequest(url, "DELETE");
        }

        public HttpWebResponse DoWebRequest (string url, string method) {
            HttpWebResponse response;

            // Create request url
            ApiRequest = (HttpWebRequest)Create(BaseUri + url);
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

        public HttpWebResponse Post(string url, string postData) {
            HttpWebResponse response;

            // Create request url
            ApiRequest = (HttpWebRequest)Create(BaseUri + url);
            ApiRequest.Method = "POST";
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
}

function Resolve-Error ($ErrorRecord=$Error[0])
{
   $ErrorRecord | Format-List * -Force
   $ErrorRecord.InvocationInfo |Format-List *
   $Exception = $ErrorRecord.Exception
   for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException))
   {   "$i" * 80
       $Exception |Format-List * -Force
   }
}

function Add-ARecord()
{
	Param(
		[parameter(Mandatory=$true)] [string] $apiKey,
		[parameter(Mandatory=$true)] [string] $secretKey,
		[parameter(Mandatory=$true)] [string] $domain,
		[parameter(Mandatory=$true)] [string] $subDomain,
		[parameter(Mandatory=$true)] [string] $ipAddress
		
	)
	
	# Create XML for new record
	$newRecord = "<record><type>A</type><name>$subDomain</name><data>$ipAddress</data><ttl>30</ttl></record>"
	
	# Make API Call
	$dmeClient = New-Object DmeTools.DmeClient($apiKey, $secretKey)
	$httpResponse = $dmeClient.Post("domains/$domain/records",$newRecord)
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

function Get-Records()
{
	Param(
		[parameter(Mandatory=$true)] [string] $apiKey,
		[parameter(Mandatory=$true)] [string] $secretKey,
		[parameter(Mandatory=$true)] [string] $domain
	)
	
	$dmeClient = New-Object DmeTools.DmeClient($apiKey, $secretKey)
	$httpResponse = $dmeClient.Get("domains/$domain/records")
	$httpResponseXml = [DmeTools.Helpers]::GetResponseContentXml($httpResponse)
	$httpResponseXml.records
}

function Remove-Record()
{
	Param(
		[parameter(Mandatory=$true)] [string] $apiKey,
		[parameter(Mandatory=$true)] [string] $secretKey,
		[parameter(Mandatory=$true)] [string] $domain,
		[parameter(Mandatory=$true)] [string] $dnsId
	)
	
	$dmeClient = New-Object DmeTools.DmeClient($apiKey, $secretKey)
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