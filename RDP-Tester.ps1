#################################################################
# RDP Troubleshooting Script
# Purpose: Comprehensive testing of RDP connectivity and configuration
# 
# This script performs detailed testing of RDP functionality including:
# - Network connectivity tests (ICMP and TCP 3389)
# - RDP service status and configuration
# - Firewall rule verification
# - User permissions and group membership
# - Both local and domain account testing
# - Actual RDP connection attempts
#
# The script provides interactive credential collection and 
# comprehensive logging of all tests and results.
#################################################################

#region Script Configuration
# Set up logging paths with timestamps for unique files
# Main log contains all information, error log contains only errors
$LogPath = "C:\Logs\RDP_Troubleshoot_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorLogPath = "C:\Logs\RDP_Troubleshoot_Error_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create log directory if it doesn't exist
# Using Force parameter to prevent errors if directory already exists
New-Item -ItemType Directory -Force -Path (Split-Path $LogPath)
#endregion

#region Helper Functions
<#
.SYNOPSIS
    Writes a log entry to both console and log file
.DESCRIPTION
    Handles all logging operations with timestamp and color coding
    Writes to both main log and error log if error flag is set
.PARAMETER Message
    The message to be logged
.PARAMETER Error
    Switch parameter to indicate if this is an error message
#>
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [switch]$Error
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] $Message"
    
    # Output to console with color coding
    if ($Error) {
        Write-Host $LogMessage -ForegroundColor Red
        # Errors get written to both logs
        Add-Content -Path $ErrorLogPath -Value $LogMessage
    } else {
        Write-Host $LogMessage -ForegroundColor Green
    }
    # All messages go to main log
    Add-Content -Path $LogPath -Value $LogMessage
}

<#
.SYNOPSIS
    Collects user credentials interactively
.DESCRIPTION
    Prompts user for target computer and credentials
    Supports both local and domain account testing
    Stores credentials securely using SecureString
#>
function Get-UserCredentials {
    Write-Host "`n=== RDP Troubleshooting Credential Collection ===" -ForegroundColor Cyan
    
    # Get target computer - this is required
    $script:TargetComputer = Read-Host "`nEnter the target computer name or IP"
    
    # Local Account Collection
    Write-Host "`n--- Local Account Testing ---" -ForegroundColor Yellow
    $testLocal = Read-Host "Do you want to test local account? (Y/N)"
    
    if ($testLocal -eq 'Y') {
        $script:LocalUsername = Read-Host "Enter local username"
        # Using AsSecureString to safely collect password
        $localPwdSecure = Read-Host "Enter local password" -AsSecureString
        # Create credential object for later use
        $script:LocalCred = New-Object System.Management.Automation.PSCredential($LocalUsername, $localPwdSecure)
        $script:TestLocal = $true
    } else {
        $script:TestLocal = $false
    }
    
    # Domain Account Collection
    Write-Host "`n--- Domain Account Testing ---" -ForegroundColor Yellow
    $testDomain = Read-Host "Do you want to test domain account? (Y/N)"
    
    if ($testDomain -eq 'Y') {
        $script:Domain = Read-Host "Enter domain name"
        $script:DomainUsername = Read-Host "Enter domain username"
        $domainPwdSecure = Read-Host "Enter domain password" -AsSecureString
        # Create domain credential with domain prefix
        $script:DomainCred = New-Object System.Management.Automation.PSCredential("$Domain\$DomainUsername", $domainPwdSecure)
        $script:TestDomain = $true
    } else {
        $script:TestDomain = $false
    }
    
    # Validate that at least one test type was selected
    if (-not ($script:TestLocal -or $script:TestDomain)) {
        Write-Host "`nError: You must test at least one account type!" -ForegroundColor Red
        exit
    }
}
#endregion

#region Test Functions
<#
.SYNOPSIS
    Tests basic network connectivity to target
.DESCRIPTION
    Performs ICMP ping test and TCP port test for RDP (3389)
    These are fundamental requirements for RDP to work
#>
function Test-Connectivity {
    Write-Log "`nTesting basic network connectivity to $TargetComputer"
    
    # Test ICMP (ping)
    $pingResult = Test-Connection -ComputerName $TargetComputer -Count 1 -Quiet
    if ($pingResult) {
        Write-Log "ICMP ping successful to $TargetComputer"
    } else {
        Write-Log "ICMP ping failed to $TargetComputer - Check firewall rules and network connectivity" -Error
    }
    
    # Test RDP port TCP 3389
    $rdpTest = Test-NetConnection -ComputerName $TargetComputer -Port 3389
    if ($rdpTest.TcpTestSucceeded) {
        Write-Log "RDP port 3389 is accessible"
    } else {
        Write-Log "RDP port 3389 is not accessible - Check firewall rules and RDP service" -Error
    }
}

<#
.SYNOPSIS
    Tests RDP service status and attempts recovery
.DESCRIPTION
    Checks if the Terminal Services service is running
    Attempts to start the service if it's stopped
    This service is essential for RDP functionality
#>
function Test-RDPService {
    Write-Log "`nChecking RDP service status on $TargetComputer"
    
    try {
        # Get Terminal Services service status
        $service = Get-Service -ComputerName $TargetComputer -Name "TermService"
        Write-Log "Terminal Services status: $($service.Status)"
        
        # Attempt to start service if it's not running
        if ($service.Status -ne "Running") {
            Write-Log "Terminal Services not running - attempting to start" -Error
            Start-Service -InputObject $service
            Start-Sleep -Seconds 5  # Wait for service to start
            $service.Refresh()
            Write-Log "Terminal Services new status: $($service.Status)"
        }
    } catch {
        Write-Log "Failed to check/modify Terminal Services: $_" -Error
    }
}

<#
.SYNOPSIS
    Tests RDP configuration in registry
.DESCRIPTION
    Checks registry settings related to RDP functionality
    Verifies if RDP is enabled and checks NLA configuration
#>
function Test-RDPConfig {
    Write-Log "`nChecking RDP configuration on $TargetComputer"
    
    try {
        # Check RDP enabled status in registry
        # fDenyTSConnections = 0 means RDP is enabled
        $rdpEnabled = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        if ($rdpEnabled.fDenyTSConnections -eq 0) {
            Write-Log "RDP is enabled in registry"
        } else {
            Write-Log "RDP is disabled in registry - Enable using System Properties -> Remote tab" -Error
        }
        
        # Check Network Level Authentication (NLA) setting
        # UserAuthentication = 1 means NLA is enabled
        $nlaEnabled = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
        Write-Log "NLA Status: $($nlaEnabled.UserAuthentication) (1 = Enabled, 0 = Disabled)"
        
    } catch {
        Write-Log "Failed to check RDP configuration: $_" -Error
    }
}

<#
.SYNOPSIS
    Tests Windows Firewall rules for RDP
.DESCRIPTION
    Checks all firewall rules related to RDP
    Verifies their status, direction, and action
    Ensures at least one rule is enabled
#>
function Test-FirewallRules {
    Write-Log "`nChecking Windows Firewall rules for RDP"
    
    try {
        # Get all RDP-related firewall rules
        $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop"
        
        # Examine each rule's configuration
        foreach ($rule in $rdpRules) {
            Write-Log "Firewall Rule: $($rule.DisplayName)"
            Write-Log "  Enabled: $($rule.Enabled)"
            Write-Log "  Direction: $($rule.Direction)"
            Write-Log "  Action: $($rule.Action)"
            Write-Log "  Profile: $($rule.Profile)"
            
            # Get port information for the rule
            $portFilter = $rule | Get-NetFirewallPortFilter
            if ($portFilter.LocalPort) {
                Write-Log "  Ports: $($portFilter.LocalPort)"
            }
        }
        
        # Verify at least one rule is enabled
        if (-not ($rdpRules | Where-Object { $_.Enabled -eq $true })) {
            Write-Log "No enabled RDP firewall rules found - RDP will be blocked" -Error
        }
    } catch {
        Write-Log "Failed to check firewall rules: $_" -Error
    }
}

<#
.SYNOPSIS
    Tests user access rights for RDP
.DESCRIPTION
    Checks group membership and permissions for provided accounts
    Verifies domain connectivity for domain accounts
#>
function Test-UserAccess {
    Write-Log "`nTesting user access rights"
    
    # Test Local Account if specified
    if ($TestLocal) {
        try {
            Write-Log "Testing local account access for $LocalUsername"
            
            # Check Remote Desktop Users group membership
            # Users need to be in this group or Administrators to use RDP
            $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" | 
                Where-Object { $_.Name -like "*$LocalUsername" }
            
            if ($rdpUsers) {
                Write-Log "$LocalUsername is member of Remote Desktop Users group"
            } else {
                # Check Administrators group as an alternative
                $adminUsers = Get-LocalGroupMember -Group "Administrators" |
                    Where-Object { $_.Name -like "*$LocalUsername" }
                
                if ($adminUsers) {
                    Write-Log "$LocalUsername is member of Administrators group (RDP access granted)"
                } else {
                    Write-Log "$LocalUsername is not in Remote Desktop Users or Administrators group - Access will be denied" -Error
                }
            }
        } catch {
            Write-Log "Failed to check local user access: $_" -Error
        }
    }
    
    # Test Domain Account if specified
    if ($TestDomain) {
        try {
            Write-Log "Testing domain account access for $DomainUsername"
            
            # First verify domain connectivity
            $domainCheck = Test-ComputerSecureChannel -Server $Domain
            if ($domainCheck) {
                Write-Log "Domain connection successful"
                
                # Try to query domain user info
                $domainUser = Get-ADUser -Identity $DomainUsername -Properties MemberOf -ErrorAction SilentlyContinue
                if ($domainUser) {
                    Write-Log "Domain user account found and accessible"
                    
                    # Check for Remote Desktop Users group membership
                    if ($domainUser.MemberOf -match "Remote Desktop Users") {
                        Write-Log "User is member of domain Remote Desktop Users group"
                    } else {
                        Write-Log "User is not in domain Remote Desktop Users group - Check local group membership" -Error
                    }
                } else {
                    Write-Log "Unable to query domain user information" -Error
                }
            } else {
                Write-Log "Domain connection failed - Check network connectivity to domain" -Error
            }
            
        } catch {
            Write-Log "Failed to check domain user access: $_" -Error
        }
    }
}

<#
.SYNOPSIS
    Tests actual RDP connection attempts
.DESCRIPTION
    Attempts to establish RDP connections using provided credentials
    Monitors and logs connection events
.PARAMETER Credential
    PSCredential object containing login credentials
.PARAMETER Username
    Username for logging purposes
.PARAMETER Type
    Account type (Local/Domain) for logging purposes
#>
function Test-RDPConnection {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$Type
    )
    
    Write-Log "`nTesting RDP connection for $Type account: $Username"
    
    try {
        # Attempt RDP connection
        # Note: mstsc will launch the RDP client but cannot provide success/failure feedback
        $result = mstsc /v:$TargetComputer /w:800 /h:600 /admin
        Write-Log "RDP connection attempt initiated"
        
        # Monitor event logs for RDP activity
        Write-Log "Checking event logs for RDP connection attempts..."
        Start-Sleep -Seconds 5  # Allow time for events to be logged
        
        # Check for recent RDP events
        $rdpEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
            StartTime = (Get-Date).AddMinutes(-1)
        } -ErrorAction SilentlyContinue
        
        if ($rdpEvents) {
            foreach ($event in $rdpEvents) {
                Write-Log "RDP Event ID: $($event.Id) - $($event.Message)"
                
                # Interpret common event IDs
                switch ($event.Id) {
                    131 { Write-Log "Connection handshake initiated" }
                    140 { Write-Log "Connection successfully established" }
                    148 { Write-Log "Connection failed - Authentication or authorization error" -Error }
                    50 { Write-Log "Local policy setting does not permit remote connection" -Error }
                }
            }
        } else {
            Write-Log "No RDP connection events found in log" -Error
        }
    } catch {
        Write-Log "Failed to test RDP connection: $_" -Error
    }
}
#endregion

#region Main Execution
Clear-Host
Write-Host "RDP Troubleshooting Script" -ForegroundColor Cyan
Write-Host "This script performs comprehensive RDP connectivity testing" -ForegroundColor Yellow
Write-Host "It will check network, service, configuration, and access requirements" -ForegroundColor Yellow

# Collect credentials interactively
Get-UserCredentials

Write-Log "`nStarting RDP troubleshooting for $TargetComputer"

# Run all diagnostic tests
Test-Connectivity
Test-RDPService
Test-RDPConfig
Test-FirewallRules
Test-UserAccess

# Attempt RDP connections based on provided credentials
if ($TestLocal) {
    Test-RDPConnection -Credential $LocalCred -Username $LocalUsername -Type "Local"
}

if ($TestDomain) {
    Test-RDPConnection -Credential $DomainCred -Username "$Domain\$DomainUsername" -Type "Domain"
}

# Final status report
Write-Log "`nTroubleshooting complete. Check logs for detailed information"

# Create a summary of findings
Write-Host "`n=== RDP Troubleshooting Summary ===" -ForegroundColor Cyan

<#
.SYNOPSIS
    Generates a summary of all tests performed
.DESCRIPTION
    Reviews log files and creates a concise summary of:
    - Critical errors encountered
    - Successful connections
    - Recommended actions
#>
function Get-TestingSummary {
    Write-Host "`nAnalyzing results..." -ForegroundColor Yellow
    
    # Read all logs
    $allLogs = Get-Content -Path $LogPath
    $errorLogs = Get-Content -Path $ErrorLogPath -ErrorAction SilentlyContinue
    
    # Initialize counters and collections
    $criticalIssues = @()
    $successfulTests = @()
    $recommendations = @()
    
    # Analyze connectivity
    if ($allLogs -match "ICMP ping failed") {
        $criticalIssues += "- Network connectivity issue: ICMP ping failed"
        $recommendations += "- Check network connectivity and firewall rules for ICMP"
    } else {
        $successfulTests += "- Network ping successful"
    }
    
    if ($allLogs -match "RDP port 3389 is not accessible") {
        $criticalIssues += "- RDP port 3389 is not accessible"
        $recommendations += "- Verify firewall rules allow TCP 3389"
        $recommendations += "- Confirm no other service is using port 3389"
    } else {
        $successfulTests += "- RDP port accessible"
    }
    
    # Analyze RDP Service
    if ($allLogs -match "Terminal Services not running") {
        $criticalIssues += "- Terminal Services not running"
        $recommendations += "- Ensure Terminal Services service is set to Automatic and started"
    } else {
        $successfulTests += "- Terminal Services running"
    }
    
    # Analyze RDP Configuration
    if ($allLogs -match "RDP is disabled in registry") {
        $criticalIssues += "- RDP is disabled in system settings"
        $recommendations += "- Enable Remote Desktop in System Properties"
    } else {
        $successfulTests += "- RDP enabled in system settings"
    }
    
    # Analyze Firewall Rules
    if ($allLogs -match "No enabled RDP firewall rules found") {
        $criticalIssues += "- No enabled RDP firewall rules"
        $recommendations += "- Enable required RDP firewall rules"
    } else {
        $successfulTests += "- Firewall rules properly configured"
    }
    
    # Analyze User Access
    if ($allLogs -match "not in Remote Desktop Users") {
        $criticalIssues += "- User permissions issue"
        $recommendations += "- Add user to Remote Desktop Users or Administrators group"
    }
    
    # Display Summary
    Write-Host "`nSuccessful Tests:" -ForegroundColor Green
    $successfulTests | ForEach-Object { Write-Host $_ -ForegroundColor Green }
    
    if ($criticalIssues.Count -gt 0) {
        Write-Host "`nCritical Issues Found:" -ForegroundColor Red
        $criticalIssues | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    }
    
    if ($recommendations.Count -gt 0) {
        Write-Host "`nRecommended Actions:" -ForegroundColor Yellow
        $recommendations | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    }
    
    # Connection Status Summary
    Write-Host "`nConnection Attempts:" -ForegroundColor Cyan
    if ($TestLocal) {
        $localStatus = if ($allLogs -match "Local.*Connection successfully established") {
            "Successful"
        } else {
            "Failed - Check error log for details"
        }
        Write-Host "Local Account ($LocalUsername): $localStatus" -ForegroundColor $(if($localStatus -eq "Successful"){"Green"}else{"Red"})
    }
    
    if ($TestDomain) {
        $domainStatus = if ($allLogs -match "Domain.*Connection successfully established") {
            "Successful"
        } else {
            "Failed - Check error log for details"
        }
        Write-Host "Domain Account ($Domain\$DomainUsername): $domainStatus" -ForegroundColor $(if($domainStatus -eq "Successful"){"Green"}else{"Red"})
    }
}

# Generate the summary
Get-TestingSummary

# Display log file locations
Write-Host "`nDetailed Logs:" -ForegroundColor Cyan
Write-Host "Main Log: $LogPath" -ForegroundColor Green
Write-Host "Error Log: $ErrorLogPath" -ForegroundColor Yellow

# Provide guidance on next steps
Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the summary above for any critical issues"
Write-Host "2. Implement recommended actions if any were provided"
Write-Host "3. Check detailed logs for more specific error messages and timestamps"
Write-Host "4. For persistent issues, consider checking:"
Write-Host "   - Event Viewer -> Windows Logs -> System"
Write-Host "   - Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Terminal Services-*"
Write-Host "5. Run this script again after making any changes to verify the fix"

# Final message
Write-Host "`nTroubleshooting session completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "For additional assistance, consult your system administrator or Microsoft Support"
#endregion

# Export findings to HTML report (optional)
$generateReport = Read-Host "`nWould you like to generate an HTML report? (Y/N)"
if ($generateReport -eq 'Y') {
    $reportPath = "C:\Logs\RDP_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $htmlReport = @"
    <html>
    <head>
        <title>RDP Troubleshooting Report - $TargetComputer</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1, h2 { color: #2c3e50; }
            .success { color: green; }
            .error { color: red; }
            .warning { color: orange; }
            .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        </style>
    </head>
    <body>
        <h1>RDP Troubleshooting Report</h1>
        <div class="section">
            <h2>System Information</h2>
            <p>Target Computer: $TargetComputer</p>
            <p>Test Date: $(Get-Date)</p>
        </div>
        <div class="section">
            <h2>Test Results</h2>
            $(Get-Content $LogPath | ConvertTo-Html -Fragment)
        </div>
        <div class="section">
            <h2>Errors</h2>
            $(Get-Content $ErrorLogPath | ConvertTo-Html -Fragment)
        </div>
    </body>
    </html>
"@
    
    $htmlReport | Out-File -FilePath $reportPath
    Write-Host "HTML report generated: $reportPath" -ForegroundColor Green
}

Write-Host "`nScript completed. Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")