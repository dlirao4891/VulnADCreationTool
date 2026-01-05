<#
.SYNOPSIS
    Generates a structured JSON file for AD object creation.

.DESCRIPTION
    Parses source text files (names, surnames, group names, passwords) and generates 
    a 'users_and_groups.json' file. The resulting JSON is used by GenerateIdentities.ps1.
#>

# Fix line breaking and encoding issues by enforcing UTF8.
$DataFiles = @("group_names.txt", "name.txt", "surname.txt", "passwords.txt")
foreach ($file in $DataFiles) {
    $path = "$PSScriptRoot\Data\$file"
    if (Test-Path $path) {
        $content = Get-Content $path -Encoding UTF8
        [System.IO.File]::WriteAllLines($path, $content)
    }
}

# Create ArrayLists using existing files.
$group_names = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\Data\group_names.txt")
$first_names = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\Data\name.txt")
$last_names = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\Data\surname.txt")
$passwords = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\Data\passwords.txt")

# Create empty arrays for users and groups.
$groups = @()
$users = @()

# Create a list of 7 groups from the existing ones and makes sure they are unique.
$num_groups = 7
for ( $i = 0; $i -lt $num_groups; $i++ ){
    $new_group = (Get-Random -InputObject $group_names)
    $groups += @{ "name" = $new_group }
    $group_names.Remove($new_group)
}

# Create a list of 50 users containing first_name, last_name and password and makes sure they are unique.
$num_users = 50
for ( $i = 0; $i -lt $num_users; $i++ ){
    $first_name = (Get-Random -InputObject $first_names)     
    $last_name = (Get-Random -InputObject $last_names)
    $password = (Get-Random -InputObject $passwords)
    
    $new_user = @{
        "name" = "$first_name $last_name"
        "password" = "$password"
        "groups" = @( (Get-Random -InputObject $groups.name) )
    }

    $users += $new_user
    $first_names.Remove($first_name)
    $last_names.Remove($last_name)
    $passwords.Remove($password)
}
# Get domain name
$domain = (Get-ADDomain).Name

# Write the file out
echo @{
    "domain" = "$domain"
    "groups" = $groups
    "users" = $users
} | ConvertTo-Json | Out-File $PSScriptRoot/Data/users_and_groups.json -Encoding UTF8