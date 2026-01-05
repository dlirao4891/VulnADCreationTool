<#
.SYNOPSIS
    Populates Active Directory with users and groups based on a JSON definition.

.DESCRIPTION
    Reads 'Data/users_and_groups.json' and creates the specified AD groups and users.
    It also implements a weak password policy (disabling complexity and minimum age/length) 
    to facilitate the use of simple passwords in the training environment.
#>

function CreateADGroup(){
    <#
    .SYNOPSIS
        Creates a new Global Security Group.
    .PARAMETER groupObject
        An object from the JSON containing the 'name' property.
    #>
    param( [Parameter(Mandatory=$true)] $groupObject )

    # Pulls the name of the group from JSON file
    $name = $groupObject.name

    # Creates the domain group
    New-ADGroup -name $name -GroupScope Global | Out-Null
    Write-Host "Created group: $name" -ForegroundColor Cyan

}

function CreateADUser(){
    <#
    .SYNOPSIS
        Creates a new AD User with a generated SamAccountName.
    .PARAMETER userObject
        An object from the JSON containing 'name', 'password', and 'groups'.
    #>
    param( [Parameter(Mandatory=$true)] $userObject )
    
    #Pulls the name and password from JSON file
    $name = $userObject.name
    $password = $userObject.password

    #Defines firstname and lastname
    $firstname, $lastname = $name.Split(" ")

    # Generate account name based on first name, three initial letters from lastname, with a dot in between.
    $lnameShort = if ($lastname.Length -ge 3) { $lastname.Substring(0, 3) } else { $lastname }
    $username = ("$firstname.$lnameShort").ToLower()
    $SamAccountName = $username
    $principalname = $username

    # Create the domain account
    try {
    New-ADUser -Name "$name" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru -ErrorAction SilentlyContinue | Enable-ADAccount  -ErrorAction SilentlyContinue | Out-Null 
    Write-Host "Created user: $name with username: $username" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Failed to create user: $name. Error Detail: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    # Add user to its group
    foreach($group_name in $userObject.groups){

        try {
            Get-ADGroup -Identity "$group_name" | Out-Null
            Add-ADGroupMember -Identity $group_name -Members $username | Out-Null
            Write-Host "Added $name to group $group_name" -ForegroundColor Cyan
            Write-Host ""
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
            {
                Write-Warning "AD group $group_name not found. $name not added to $group_name." -ForegroundColor Yellow
            }
    }
}   

function PasswdPolicy(){
    <#
    .SYNOPSIS
        Weakens the domain password policy via secedit.
    #>
    secedit /export /cfg c:\Windows\Tasks\secpol.cfg
    (Get-Content C:\Windows\Tasks\secpol.cfg).
        replace("PasswordComplexity = 1", "PasswordComplexity = 0").
        replace("MinimumPasswordLength = 7", "MinimumPasswordLength = 0").
        replace("MinimumPasswordAge = 1", "MinimumPasswordAge = 0") | 
        Out-File C:\Windows\Tasks\secpol.cfg
    secedit /configure /db c:\windows\security\local.sdb /cfg C:\Windows\Tasks\secpol.cfg /areas SECURITYPOLICY
    rm -force C:\Windows\Tasks\secpol.cfg -confirm:$false
}

Write-Host "Modifying password policy to allow simple passwords..." -ForegroundColor Yellow
Write-Host ""
PasswdPolicy

# Get the contents of the JSON file and convert it
$json = ( Get-Content $PSScriptRoot/Data/users_and_groups.json | ConvertFrom-Json)

# Get the domain name from the JSON file
$Global:Domain = $json.domain

# Run the functions to create groups and users
foreach ( $group in $json.groups ){
    CreateADGroup $group
}

# Check if IT Department group exists, if not create it
$itGroup = Get-ADGroup -Filter { Name -eq "IT Department" }
if (-not $itGroup) {
    Write-Host "IT Department group not found. Creating the group..." -ForegroundColor Yellow
    New-ADGroup -name "IT Department" -GroupScope Global | Out-Null
    Write-Host "Created group: IT Department" -ForegroundColor Cyan
}

foreach ( $user in $json.users ){
    CreateADUSer $user
}
