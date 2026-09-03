[CmdletBinding()]
param(
    [ValidateSet('Short', 'Default')]
    [string] $Job = 'Short',
    [switch] $WithPostgreSql
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = $PSScriptRoot
$project = Join-Path $repositoryRoot 'Mrbr.Encryption.Data.Identity.Benchmarks\Mrbr.Encryption.Data.Identity.Benchmarks.csproj'
$composeFile = Join-Path $repositoryRoot 'docker-compose.postgresql.yml'
$previousConnectionString = $env:MRBR_TEST_POSTGRES_CONNECTION_STRING

try {
    if ($WithPostgreSql) {
        docker compose --file $composeFile up --detach --wait
        if ($LASTEXITCODE -ne 0) {
            throw 'PostgreSQL benchmark container did not start successfully.'
        }
        $env:MRBR_TEST_POSTGRES_CONNECTION_STRING =
            'Host=127.0.0.1;Port=55432;Database=postgres;Username=mrbr_test;Password=mrbr_test_password;Include Error Detail=false'
    }

    $jobArgument = if ($Job -eq 'Short') { 'short' } else { 'default' }
    dotnet run --project $project --configuration Release -- --job $jobArgument --filter '*IdentityToken*' --artifacts (Join-Path $repositoryRoot 'BenchmarkDotNet.Artifacts')
    if ($LASTEXITCODE -ne 0) {
        throw 'Identity token benchmarks failed.'
    }
}
finally {
    $env:MRBR_TEST_POSTGRES_CONNECTION_STRING = $previousConnectionString
    if ($WithPostgreSql) {
        docker compose --file $composeFile down --volumes
    }
}
