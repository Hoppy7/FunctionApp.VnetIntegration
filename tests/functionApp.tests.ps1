param
(
    [parameter(mandatory=$true)]
    [string]$baseUri
)

describe "functionApp" {
    it "GET $baseUri" {
        $request = Invoke-WebRequest -Uri $baseUri -Method GET; #-SkipHttpErrorCheck;
        $request.StatusCode | should Be 200;
    }

    it "GET /api/getsalmon" {
        $request = Invoke-WebRequest -Uri $($baseUri + "/api/getsalmon") -Method GET; #-SkipHttpErrorCheck;
        $request.StatusCode | should Be 200;
    }
}