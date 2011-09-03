# ------------------------
# Functions
# ------------------------

function Add-DmeTools()
{

$code = @"
using System;
using System.IO;
using System.Linq;
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

        private HttpWebRequest _apiRequest;

        public DmeClient (string apiKey, string secretKey)  {
            SecretKey = secretKey;
            ApiKey = apiKey;
            BaseUri= "http://api.dnsmadeeasy.com/V1.2/";
        }
 
        public void AddDmeHeaders() {    
            var rfcDate = Helpers.GetDateTimeRfc822;

            // Add Headers
            _apiRequest.Headers = new WebHeaderCollection {
                            {"x-dnsme-apiKey", ApiKey},
                            {"x-dnsme-requestDate", rfcDate},
                            {"x-dnsme-hmac", Helpers.GenerateDnsMeHash(SecretKey, rfcDate)},
                        };
            _apiRequest.ContentType = "application/xml";
            _apiRequest.Accept = "application/xml";
        }

        public HttpWebResponse Get(string url) {
            return DoWebRequest(url, "GET");
        }

        public HttpWebResponse Delete (string url) {
            return DoWebRequest(url, "DELETE");
        }

        public HttpWebResponse DoWebRequest (string url, string method)
        {
            _apiRequest = (HttpWebRequest) Create(BaseUri + url);
            _apiRequest.Method = method;

            AddDmeHeaders();

            return GetApiResponse();
        }

        private HttpWebResponse GetApiResponse() {
            HttpWebResponse response;

            try {
                response = (HttpWebResponse) _apiRequest.GetResponse();
            }
            catch (WebException webException) {
                response = (HttpWebResponse)webException.Response;
            }

            return response;
        }

        public HttpWebResponse Post(string url, string postData) {

            // Create request url
            _apiRequest = (HttpWebRequest) Create(BaseUri + url);
            _apiRequest.Method = "POST";
            AddDmeHeaders();

            // Add POST data
            var byteArray = Encoding.UTF8.GetBytes(postData);
            _apiRequest.ContentLength = byteArray.Length;
            var dataStream = _apiRequest.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            return GetApiResponse();
        }
    }


    public class Helpers {
        public static string GetDateTimeRfc822 {
            get { return DateTime.Now.ToUniversalTime().ToString("ddd, dd MMM yyyy HH':'mm':'ss 'GMT'"); }
        }

        public static string GenerateDnsMeHash(string key, string message) {
            var encoding = new ASCIIEncoding();

            var myhash = new HMACSHA1(encoding.GetBytes(key), false);
            var hashmessage = myhash.ComputeHash(encoding.GetBytes(message));

            return ByteToString(hashmessage);
        }

        public static string ByteToString(byte[] byteArray) {
            var byteString = byteArray.Aggregate("", (current, byteValue) => current + byteValue.ToString("X2").ToLower());

            return (byteString);
        }

        public static XmlDocument GetResponseContentXml(HttpWebResponse response) { 
            var httpContent = new StreamReader(response.GetResponseStream()).ReadToEnd();

            return String.IsNullOrEmpty(httpContent) ? null : new XmlDocument {InnerXml = httpContent};
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

function Delete-Record()
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