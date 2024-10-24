# RDP Troubleshooter Script

A comprehensive PowerShell script for diagnosing and troubleshooting Remote Desktop Protocol (RDP) connectivity issues in Windows environments. This tool performs extensive testing of RDP components and provides detailed reporting of findings.

## Features

- **Interactive Credential Collection**
  - Support for both local and domain accounts
  - Secure password handling using SecureString
  - Flexible testing options for different account types

- **Comprehensive Testing**
  - Network connectivity (ICMP and TCP 3389)
  - RDP service status and configuration
  - Windows Firewall rules
  - User permissions and group membership
  - Registry settings
  - Actual RDP connection attempts

- **Detailed Logging and Reporting**
  - Real-time color-coded console output
  - Comprehensive logging with timestamps
  - Separate error logging
  - Optional HTML report generation
  - Test result summary and analysis

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrative privileges on the local machine
- Network access to target machine
- Appropriate credentials for testing

## Installation

1. Clone this repository or download the script:
```powershell
git clone [https://github.com/yourusername/rdp-troubleshooter.git](https://github.com/NEXTGEN-CyberLAB/RDP-Tester.git)
```

2. Ensure PowerShell execution policy allows script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Usage

1. Run the script from PowerShell:
```powershell
.\RDP-Troubleshooter.ps1
```

2. Follow the interactive prompts:
   - Enter target computer name/IP
   - Choose whether to test local account
   - Provide local credentials if testing local account
   - Choose whether to test domain account
   - Provide domain credentials if testing domain account

3. Review the results:
   - Console output provides real-time test results
   - Summary section shows critical issues and recommendations
   - Detailed logs are available for review
   - Optional HTML report can be generated

## Log Locations

- Main Log: `C:\Logs\RDP_Troubleshoot_[timestamp].log`
- Error Log: `C:\Logs\RDP_Troubleshoot_Error_[timestamp].log`
- HTML Report (optional): `C:\Logs\RDP_Report_[timestamp].html`

## Testing Components

### 1. Network Connectivity
- ICMP ping test
- TCP port 3389 accessibility
- Basic network route testing

### 2. RDP Service
- Terminal Services service status
- Automatic start attempt if service is stopped
- Service dependency verification

### 3. Windows Configuration
- Registry settings verification
- Network Level Authentication (NLA) status
- RDP feature enablement check

### 4. Firewall Rules
- RDP-related rule identification
- Rule status verification
- Port configuration checking
- Profile assignment verification

### 5. User Access Rights
- Remote Desktop Users group membership
- Administrative rights verification
- Domain connectivity (for domain accounts)
- Group policy application

### 6. Connection Testing
- Actual RDP connection attempts
- Event log monitoring
- Connection failure analysis
- Detailed error reporting

## Common Issues and Solutions

### Network Connectivity Issues
- Ensure firewall allows ICMP and TCP 3389
- Verify network routing to target
- Check for VPN interference

### Service Issues
- Verify Terminal Services is running
- Check service dependencies
- Review event logs for service errors

### Permission Issues
- Add user to Remote Desktop Users group
- Verify group policy settings
- Check local security policy

### Firewall Issues
- Enable RDP firewall rules
- Verify rule directions (inbound/outbound)
- Check rule profiles match network type

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Error Codes

Common RDP error codes and their meanings:
- Event ID 131: Connection handshake initiated
- Event ID 140: Connection successfully established
- Event ID 148: Authentication/authorization error
- Event ID 50: Local policy blocking connection

## Best Practices

1. Always run with administrative privileges
2. Use domain accounts when possible
3. Keep logs for troubleshooting history
4. Generate HTML reports for documentation
5. Review all test results before making changes

## Security Considerations

- Credentials are handled securely using SecureString
- Logs may contain sensitive information
- Clean up logs and reports after troubleshooting
- Use least-privilege accounts when possible

## License

This project is licensed under the MIT License - see the LICENSE file for details

## Acknowledgments

- Microsoft RDP documentation
- PowerShell community contributions
- Security best practices guidelines

## Support

For issues, questions, or contributions, please:
1. Check existing issues on GitHub
2. Create a new issue with detailed description
3. Include log files and error messages
4. Specify your environment details

---
**Note**: This script is meant for diagnostic purposes only. Always follow your organization's security policies and best practices when testing RDP connectivity.
