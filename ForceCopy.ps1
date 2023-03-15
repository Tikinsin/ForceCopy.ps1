[CmdletBinding()]
Param(
    [Parameter(
        Mandatory = $true,
        HelpMessage = "Source Path of files to copy from"
    )]
    [ValidateNotNull()]
    [string] $SourcePath,

    [Parameter(
        Mandatory = $true,
        HelpMessage = "Destination Path of files to copy from"
    )]
    [ValidateNotNull()]
    [string] $DestinationPath,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Amount of time to wait between Stop and Kill (in seconds)"
    )]
    [int32] $StopToKillWaitTime = 10,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "Amount of time to wait between Stop and Kill (in seconds)"
    )]
    [int32] $NoActionWaitTime = 0
)

function Main {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Source Path of files to copy from"
        )]
        [ValidateNotNull()]
        [string] $SourcePath,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "Destination Path of files to copy from"
        )]
        [ValidateNotNull()]
        [string] $DestinationPath,

        [Parameter(
            Mandatory = $false,
            HelpMessage = "Amount of time to wait between Stop and Kill (in seconds)"
        )]
        [int32] $StopToKillWaitTime = 10,
    
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Amount of time to wait between Stop and Kill (in seconds)"
        )]
        [int32] $NoActionWaitTime = 0
    )

    $filesToCopy = Get-ChildItem $SourcePath -Recurse | Where-Object { $_.PsIsContainer -eq $false }
    Write-Host $filesToCopy

    foreach ($file in $filesToCopy) {
        $sourceFile = $file.FullName
        Write-Host $sourceFile
        $destinationFile = $sourceFile -replace [regex]::Escape($SourcePath), $DestinationPath
        Write-Host $destinationFile

        $fileHandle = $null
        $processId = $null

        # Test if file in destination exists
        if (Test-Path -Path $destinationFile -PathType Leaf) {
            Write-Host "Destination File found $($destinationFile), testing for locks"

            try {
                $fileHandle = New-Object IO.FileStream ($destinationFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            }
            catch {
                if($NoActionWaitTime -gt 0) {
                    Write-Host "Waiting $($NoActionWaitTime) seconds before checking if stop command is necessary."
                    Start-Sleep -Seconds $NoActionWaitTime
                }

                $fileHandleStop = $null

                try {
                    $fileHandleStop = New-Object IO.FileStream ($destinationFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                }
                catch {
                    $processId = Get-ProcessID -Process $(Get-FileLockProcess -FilePath $destinationFile)

                    if($processId){
                        Write-Host "Found locked file $($destinationFile). Killing process ID: $($processId)"
                        # Stop-Process -Id $process.PID
                        Stop-Process -Id $processId

                        if ($StopToKillWaitTime -gt 0) {
                            Write-Host "Waiting $($StopToKillWaitTime) seconds before checking force kill is necessary."
                            Start-Sleep -Seconds $StopToKillWaitTime
                        }
                        
                        $fileHandleForce = $null

                        try {
                            $fileHandleForce = New-Object IO.FileStream ($destinationFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                        }
                        catch {
                            $processId = Get-ProcessID -Process $(Get-FileLockProcess -FilePath $destinationFile)
                
                            if($processId){
                                Write-Host "Still found locked file $($destinationFile) after waiting 10 seconds. Killing process ID: $($processId)"
                                Stop-Process -Id $processId -Force
                            }
                        }
                        finally {
                            if($fileHandleForce){
                                $fileHandleForce.Close()
                                $fileHandleForce.Dispose()
                            }
                        }
                    }
                }
                finally {
                    if($fileHandleStop){
                        $fileHandleStop.Close()
                        $fileHandleStop.Dispose()
                    }
                }
            }
            finally {
                if($fileHandle){
                    $fileHandle.Close()
                    $fileHandle.Dispose()
                }
            }
        }

        Write-Host "Copying $($sourceFile) to $($destinationFile)"

        try {
            # Copy-Item $sourceFile $destinationFile -Force -Recurse
            Copy-Item-Recurse $sourceFile $destinationFile
        }
        catch {
            Write-Host "Copy Failed || Source: $($sourceFile)  ||  Destination: $($destinationFile)"
        }
    }
}

function Get-ProcessID {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Source Path of files to copy from"
        )]
        [ValidateNotNull()]
        [System.Object] $Process
    )
    # $Process = $args[0]

    if ($Process -eq $null) {
        return $null
    }

    Write-Host "Process Info Found: $($Process)"

    if ($Process.PID -ne $null) {
        return $Process.PID
    }
    
    if ($Process.Id -ne $null) {
        return $Process.Id
    }

    return $null
}

function Copy-Item-Recurse {
    $SourceFilePath = $args[0]
    $DestinationFilePath = $args[1]
  
    If (-not (Test-Path $DestinationFilePath)) {
        New-Item -ItemType File -Path $DestinationFilePath -Force
    } 
    Copy-Item -Path $SourceFilePath -Destination $DestinationFilePath
}

function Get-FileLockProcess {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$FilePath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (! $(Test-Path $FilePath)) {
        Write-Error "The path $FilePath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or 
    $($PSVersionTable.PSVersion.Major -le 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
        $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    
        $AssembliesFullInfo = $CurrentlyLoadedAssemblies | Where-Object {
            $_.GetName().Name -eq "Microsoft.CSharp" -or
            $_.GetName().Name -eq "mscorlib" -or
            $_.GetName().Name -eq "System" -or
            $_.GetName().Name -eq "System.Collections" -or
            $_.GetName().Name -eq "System.Core" -or
            $_.GetName().Name -eq "System.IO" -or
            $_.GetName().Name -eq "System.Linq" -or
            $_.GetName().Name -eq "System.Runtime" -or
            $_.GetName().Name -eq "System.Runtime.Extensions" -or
            $_.GetName().Name -eq "System.Runtime.InteropServices"
        }
        $AssembliesFullInfo = $AssembliesFullInfo | Where-Object {$_.IsDynamic -eq $False}
  
        $ReferencedAssemblies = $AssembliesFullInfo.FullName | Sort-Object | Get-Unique

        $usingStatementsAsString = @"
        using Microsoft.CSharp;
        using System.Collections.Generic;
        using System.Collections;
        using System.IO;
        using System.Linq;
        using System.Runtime.InteropServices;
        using System.Runtime;
        using System;
        using System.Diagnostics;
"@
        
        $TypeDefinition = @"
        $usingStatementsAsString
        
        namespace MyCore.Utils
        {
            static public class FileLockUtil
            {
                [StructLayout(LayoutKind.Sequential)]
                struct RM_UNIQUE_PROCESS
                {
                    public int dwProcessId;
                    public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
                }
        
                const int RmRebootReasonNone = 0;
                const int CCH_RM_MAX_APP_NAME = 255;
                const int CCH_RM_MAX_SVC_NAME = 63;
        
                enum RM_APP_TYPE
                {
                    RmUnknownApp = 0,
                    RmMainWindow = 1,
                    RmOtherWindow = 2,
                    RmService = 3,
                    RmExplorer = 4,
                    RmConsole = 5,
                    RmCritical = 1000
                }
        
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                struct RM_PROCESS_INFO
                {
                    public RM_UNIQUE_PROCESS Process;
        
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
                    public string strAppName;
        
                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
                    public string strServiceShortName;
        
                    public RM_APP_TYPE ApplicationType;
                    public uint AppStatus;
                    public uint TSSessionId;
                    [MarshalAs(UnmanagedType.Bool)]
                    public bool bRestartable;
                }
        
                [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
                static extern int RmRegisterResources(uint pSessionHandle,
                                                    UInt32 nFiles,
                                                    string[] rgsFilenames,
                                                    UInt32 nApplications,
                                                    [In] RM_UNIQUE_PROCESS[] rgApplications,
                                                    UInt32 nServices,
                                                    string[] rgsServiceNames);
        
                [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
                static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
        
                [DllImport("rstrtmgr.dll")]
                static extern int RmEndSession(uint pSessionHandle);
        
                [DllImport("rstrtmgr.dll")]
                static extern int RmGetList(uint dwSessionHandle,
                                            out uint pnProcInfoNeeded,
                                            ref uint pnProcInfo,
                                            [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
                                            ref uint lpdwRebootReasons);
        
                /// <summary>
                /// Find out what process(es) have a lock on the specified file.
                /// </summary>
                /// <param name="path">Path of the file.</param>
                /// <returns>Processes locking the file</returns>
                /// <remarks>See also:
                /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa373661(v=vs.85).aspx
                /// http://wyupdate.googlecode.com/svn-history/r401/trunk/frmFilesInUse.cs (no copyright in code at time of viewing)
                /// 
                /// </remarks>
                static public List<Process> WhoIsLocking(string path)
                {
                    uint handle;
                    string key = Guid.NewGuid().ToString();
                    List<Process> processes = new List<Process>();
        
                    int res = RmStartSession(out handle, 0, key);
                    if (res != 0) throw new Exception("Could not begin restart session.  Unable to determine file locker.");
        
                    try
                    {
                        const int ERROR_MORE_DATA = 234;
                        uint pnProcInfoNeeded = 0,
                            pnProcInfo = 0,
                            lpdwRebootReasons = RmRebootReasonNone;
        
                        string[] resources = new string[] { path }; // Just checking on one resource.
        
                        res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);
        
                        if (res != 0) throw new Exception("Could not register resource.");                                    
        
                        //Note: there's a race condition here -- the first call to RmGetList() returns
                        //      the total number of process. However, when we call RmGetList() again to get
                        //      the actual processes this number may have increased.
                        res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);
        
                        if (res == ERROR_MORE_DATA)
                        {
                            // Create an array to store the process results
                            RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                            pnProcInfo = pnProcInfoNeeded;
        
                            // Get the list
                            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                            if (res == 0)
                            {
                                processes = new List<Process>((int)pnProcInfo);
        
                                // Enumerate all of the results and add them to the 
                                // list to be returned
                                for (int i = 0; i < pnProcInfo; i++)
                                {
                                    try
                                    {
                                        processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                                    }
                                    // catch the error -- in case the process is no longer running
                                    catch (ArgumentException) { }
                                }
                            }
                            else throw new Exception("Could not list processes locking resource.");                    
                        }
                        else if (res != 0) throw new Exception("Could not list processes locking resource. Failed to get size of result.");                    
                    }
                    finally
                    {
                        RmEndSession(handle);
                    }
        
                    return processes;
                }
            }
        }
"@

        $CheckMyCoreUtilsFileLockUtilLoaded = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.FileLockUtil*"}
        if ($CheckMyCoreUtilsFileLockUtilLoaded -eq $null) {
            Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition
        }
        else {
            Write-Verbose "The Namespace MyCore.Utils Class FileLockUtil is already loaded and available!"
        }

        $Result = [MyCore.Utils.FileLockUtil]::WhoIsLocking($FilePath)
    }
    if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") {
        $lsofOutput = lsof $FilePath

        function Parse-lsofStrings ($lsofOutput, $Index) {
            $($lsofOutput[$Index] -split " " | foreach {
                if (![String]::IsNullOrWhiteSpace($_)) {
                    $_
                }
            }).Trim()
        }

        $lsofOutputHeaders = Parse-lsofStrings -lsofOutput $lsofOutput -Index 0
        $lsofOutputValues = Parse-lsofStrings -lsofOutput $lsofOutput -Index 1

        $Result = [pscustomobject]@{}
        for ($i=0; $i -lt $lsofOutputHeaders.Count; $i++) {
            $Result | Add-Member -MemberType NoteProperty -Name $lsofOutputHeaders[$i] -Value $lsofOutputValues[$i]
        }
    }

    $Result
    
    ##### END Main Body #####

}

Main -SourcePath $SourcePath -DestinationPath $DestinationPath -StopToKillWaitTime $StopToKillWaitTime -NoActionWaitTime $NoActionWaitTime
