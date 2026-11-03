$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $projectRoot "config.ini"
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "Fichier de configuration absent : $configPath"
}

$config = @{}
foreach ($line in Get-Content -LiteralPath $configPath) {
    $clean = ($line -split "[#;]", 2)[0].Trim()
    if ($clean -match "^(Host|Port)\s*=\s*(.+)$") {
        $config[$matches[1]] = $matches[2].Trim()
    }
}
$hostName = $config["Host"]
if ($hostName -notin @("localhost", "127.0.0.1")) {
    throw "Le serveur est limité à localhost/127.0.0.1."
}
if ($config["Port"] -notmatch "^\d{1,5}$") {
    throw "Port invalide dans config.ini."
}
$port = [int]$config["Port"]
if ($port -lt 1024 -or $port -gt 65535) {
    throw "Port invalide dans config.ini (valeur attendue : 1024-65535)."
}

$webRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "web"))
$backendRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "backend"))
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$port/")
$listener.Start()
Write-Host "VBA Audit disponible sur http://127.0.0.1:$port"

$types = @{
    ".html" = "text/html; charset=utf-8"
    ".css" = "text/css; charset=utf-8"
    ".js" = "text/javascript; charset=utf-8"
    ".mjs" = "text/javascript; charset=utf-8"
    ".json" = "application/json; charset=utf-8"
    ".py" = "text/x-python; charset=utf-8"
    ".wasm" = "application/wasm"
    ".svg" = "image/svg+xml"
    ".woff2" = "font/woff2"
}
$csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self' data:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $response = $context.Response
        try {
            $method = $context.Request.HttpMethod
            if ($method -notin @("GET", "HEAD")) {
                $response.StatusCode = 405
                $response.Headers.Add("Allow", "GET, HEAD")
                continue
            }

            $route = [Uri]::UnescapeDataString($context.Request.Url.AbsolutePath)
            if ($route -eq "/") {
                $route = "/index.html"
            } elseif ($route -eq "/docs") {
                $route = "/docs.html"
            }
            if ($route.StartsWith("/backend/")) {
                $base = $backendRoot
                $relative = $route.Substring(9)
            } else {
                $base = $webRoot
                $relative = $route.TrimStart("/")
            }
            $candidate = [IO.Path]::GetFullPath((Join-Path $base $relative))
            $basePrefix = $base.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
            if (-not $candidate.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $response.StatusCode = 404
                $body = [Text.Encoding]::UTF8.GetBytes("Not Found")
                $response.ContentType = "text/plain; charset=utf-8"
            } else {
                $file = Get-Item -LiteralPath $candidate
                if ($file.Length -gt 60MB) {
                    $response.StatusCode = 413
                    $body = [Text.Encoding]::UTF8.GetBytes("Content Too Large")
                } else {
                    $body = [IO.File]::ReadAllBytes($candidate)
                    $extension = [IO.Path]::GetExtension($candidate).ToLowerInvariant()
                    $response.ContentType = $types[$extension]
                    if (-not $response.ContentType) {
                        $response.ContentType = "application/octet-stream"
                    }
                }
            }

            $response.Headers.Add("Cache-Control", "no-store")
            $response.Headers.Add("X-Content-Type-Options", "nosniff")
            $response.Headers.Add("Referrer-Policy", "no-referrer")
            $response.Headers.Add("Content-Security-Policy", $csp)
            $response.ContentLength64 = $body.Length
            if ($method -ne "HEAD") {
                $response.OutputStream.Write($body, 0, $body.Length)
            }
        } finally {
            $response.Close()
        }
    }
} finally {
    $listener.Stop()
    $listener.Close()
}
