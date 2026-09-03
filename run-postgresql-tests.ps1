[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = $PSScriptRoot
$composeFile = Join-Path $repositoryRoot 'docker-compose.postgresql.yml'
$testProject = Join-Path $repositoryRoot 'Mrbr.Encryption.Data.Identity.Tests\Mrbr.Encryption.Data.Identity.Tests.csproj'
$previousConnectionString = $env:MRBR_TEST_POSTGRES_CONNECTION_STRING

try {
    docker compose --file $composeFile up --detach --wait
    if ($LASTEXITCODE -ne 0) {
        throw 'PostgreSQL test container did not start successfully.'
    }

    $env:MRBR_TEST_POSTGRES_CONNECTION_STRING =
        'Host=127.0.0.1;Port=55432;Database=postgres;Username=mrbr_test;Password=mrbr_test_password;Include Error Detail=false'

    dotnet test $testProject --filter 'FullyQualifiedName~PostgreSql' --logger 'console;verbosity=normal'
    if ($LASTEXITCODE -ne 0) {
        throw 'PostgreSQL integration tests failed.'
    }
}
finally {
    $env:MRBR_TEST_POSTGRES_CONNECTION_STRING = $previousConnectionString
    docker compose --file $composeFile down --volumes
}
