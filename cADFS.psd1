@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'cADFS.psm1'

    # Version number of this module.
    ModuleVersion = '1.7.0.0'

    # ID used to uniquely identify this module
    GUID = '2be44be7-93cf-4c08-8a63-f2a77823ca6b'

    # Author of this module
    Author = 'Trevor Sullivan <pcgeek86@gmail.com>'

    # Company or vendor of this module
    CompanyName = 'Trevor Sullivan <pcgeek86@gmail.com>'

    # Copyright statement for this module
    Copyright = '(c) 2015 Trevor Sullivan. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'This module contains DSC resources that enable management of the Windows Server Active Directory Federation Services (ADFS) role.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.0'

    FunctionsToExport = @()

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Required for DSC to detect PS class-based resources.
    DscResourcesToExport = @(
        'cADFSFarm'
        'cADFSGlobalAuthenticationPolicy'
        'cADFSRelyingPartyTrust'
        'cADFSSamlEndpoint'
        'cADFSNode'
        'cADFSDeviceRegistration'
        )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/ChrisLGardner/cADFS/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/ChrisLGardner/cADFS'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    } # End of PrivateData hashtable
}
