# -*- mode: ruby -*-
# vi: set ft=ruby :

# ## Overview
# Configuration and definition file for Windows 11 Vagrant environment
# to build and test memcached with MSVC and CMake.
#
# ## Usage
# vagrant up
# vagrant provision

repo_root = File.expand_path(".", __dir__)
auto_win_msvc_path = File.expand_path("../auto-win-msvc", __dir__)
vm_name = "windows-11-msvc-memcached"

Vagrant.configure("2") do |config|
  config.vm.define vm_name do |t|
    t.vm.box = "bento/windows-11"
    t.vm.box_version = "0"

    t.vm.guest = :windows
    t.vm.communicator = :winssh

    t.winssh.username = "vagrant"
    t.winssh.insert_key = false
    t.winssh.private_key_path = File.expand_path("~/.vagrant.d/insecure_private_key")
    t.winssh.shell = "powershell"

    t.ssh.username = "vagrant"
    t.ssh.insert_key = false
    t.ssh.private_key_path = File.expand_path("~/.vagrant.d/insecure_private_key")
    t.ssh.shell = "powershell"

    t.vm.provider "qemu" do |qe|
      qe.net_mode = :user
      qe.ssh_port = 50022 + rand(1000)
      qe.smp = "4"
      qe.memory = "8192M"
    end

    t.vm.provider "libvirt" do |lv|
      lv.cpus = 4
      lv.memory = 8192
    end

    t.vm.synced_folder ".", "/vagrant", disabled: true
    t.vm.allowed_synced_folder_types = [:rsync]

    # Sync the repository root directory into C:\memcached
    t.vm.synced_folder repo_root, "/cygdrive/c/memcached", type: "rsync",
      rsync_exclude: [".git/", "build*/", "build_msvc/", "tests_tmp/", "vagrant/"]

    if Dir.exist?(auto_win_msvc_path)
      t.vm.synced_folder auto_win_msvc_path, "/cygdrive/c/auto-win-msvc", type: "rsync",
        rsync_exclude: [".git/", "build*/"]
    end

    t.vm.provision "shell", privileged: false, upload_path: 'C:\tmp\vagrant-shell.ps1', inline: <<-'POWERSHELL'
      $ErrorActionPreference = "Stop"
      $ProgressPreference = "SilentlyContinue"

      Write-Host "=========================================================="
      Write-Host " Provisioning Windows 11 environment for memcached (MSVC) "
      Write-Host "=========================================================="

      # ------------------------------------------------------------
      # 1. Install MSVC (Smallest version / components needed)
      # ------------------------------------------------------------
      Write-Host "[1/5] Checking MSVC installation..."
      $vswhereCandidates = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
      )
      $vswhere = $vswhereCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

      $msvcFound = $false
      if ($vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not $vsPath) {
          $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.ARM64 -property installationPath
        }
        if ($vsPath -and (Test-Path $vsPath)) {
          Write-Host "MSVC installation already present at: $vsPath"
          $msvcFound = $true
        }
      }

      if (-not $msvcFound) {
        Write-Host "Installing MSVC (minimal Visual Studio 2022 Build Tools)..."
        # Minimal components to build memcached:
        # - Microsoft.VisualStudio.Workload.VCTools (C++ compiler, headers, linkers)
        # - ARM64 toolset for native Windows on ARM64
        # - Windows 11 SDK (22621) for system headers and import libraries
        $vsOverride = "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621"
        if (Get-Command winget -ErrorAction SilentlyContinue) {
          winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget --accept-source-agreements --accept-package-agreements --override $vsOverride
        } else {
          $vsUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
          $installerPath = "$env:TEMP\vs_buildtools.exe"
          [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
          Invoke-WebRequest -Uri $vsUrl -OutFile $installerPath -UseBasicParsing
          $vsArgs = @(
            "--quiet", "--wait", "--norestart", "--nocache",
            "--add", "Microsoft.VisualStudio.Workload.VCTools",
            "--add", "Microsoft.VisualStudio.Component.VC.Tools.ARM64",
            "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621"
          )
          $process = Start-Process -FilePath $installerPath -ArgumentList $vsArgs -Wait -PassThru
          if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
            Write-Error "VS Build Tools installation failed with exit code $($process.ExitCode)"
            exit $process.ExitCode
          }
        }
        Write-Host "MSVC installed successfully."
      }

      # ------------------------------------------------------------
      # 2. Install CMake
      # ------------------------------------------------------------
      Write-Host "[2/5] Checking CMake installation..."
      $cmakeFound = $false
      if (Get-Command cmake -ErrorAction SilentlyContinue) {
        $cmakeFound = $true
      } elseif (Test-Path "C:\Program Files\CMake\bin\cmake.exe") {
        $cmakeFound = $true
        $env:PATH = "C:\Program Files\CMake\bin;" + $env:PATH
      }

      if (-not $cmakeFound) {
        Write-Host "Installing CMake..."
        $installed = $false
        if (Get-Command winget -ErrorAction SilentlyContinue) {
          try {
            Write-Host "Attempting winget install of Kitware.CMake..."
            winget install --id Kitware.CMake -e --source winget --accept-source-agreements --accept-package-agreements --silent
            if (Test-Path "C:\Program Files\CMake\bin\cmake.exe") {
              $installed = $true
            }
          } catch {
            Write-Host "winget installation failed, falling back to direct MSI download..."
          }
        }

        if (-not $installed) {
          Write-Host "Downloading CMake MSI directly..."
          $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x86_64" }
          $cmakeMsi = "$env:TEMP\cmake.msi"
          $cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v3.31.5/cmake-3.31.5-windows-$arch.msi"
          Invoke-WebRequest -Uri $cmakeUrl -OutFile $cmakeMsi -UseBasicParsing
          Start-Process msiexec.exe -ArgumentList "/i", $cmakeMsi, "/quiet", "/qn", "/norestart", "ADD_CMAKE_TO_PATH=System" -Wait
        }

        if (Test-Path "C:\Program Files\CMake\bin") {
          $env:PATH = "C:\Program Files\CMake\bin;" + $env:PATH
        }
      }

      # Refresh PATH from registry
      $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
      $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
      $env:PATH = "$machinePath;$userPath;C:\Program Files\CMake\bin;C:\Program Files\Git\cmd;$env:PATH"

      Write-Host "CMake Version:"
      & cmake --version

      # ------------------------------------------------------------
      # 3. Ensure Git is available (for CMake FetchContent)
      # ------------------------------------------------------------
      Write-Host "[3/5] Checking Git installation..."
      if (-not (Get-Command git -ErrorAction SilentlyContinue) -and -not (Test-Path "C:\Program Files\Git\cmd\git.exe")) {
        Write-Host "Installing Git..."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
          winget install --id Git.Git -e --source winget --accept-source-agreements --accept-package-agreements --silent
        }
      }
      if (Test-Path "C:\Program Files\Git\cmd") {
        $env:PATH = "C:\Program Files\Git\cmd;" + $env:PATH
      }
      Write-Host "Git Version:"
      & git --version

      # ------------------------------------------------------------
      # 4. Configure & Build memcached with MSVC
      # ------------------------------------------------------------
      Write-Host "[4/5] Building memcached..."
      $srcDir = "C:\memcached"
      $buildDir = "C:\memcached\build_win"

      Set-Location $srcDir

      if (Test-Path $buildDir) {
        Remove-Item -Recurse -Force $buildDir
      }

      $targetArch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "ARM64" } else { "x64" }
      Write-Host "Configuring CMake (Visual Studio 17 2022, Arch: $targetArch)..."
      & cmake -S $srcDir -B $buildDir -G "Visual Studio 17 2022" -A $targetArch -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
      if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake configure step failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
      }

      Write-Host "Compiling memcached targets..."
      & cmake --build $buildDir --config Release --target memcached --target testapp --target sizes --target timedrun --parallel
      if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake build step failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
      }

      # ------------------------------------------------------------
      # 5. Run tests starting with --version
      # ------------------------------------------------------------
      Write-Host "[5/5] Running tests..."
      $memcachedExe = "$buildDir\Release\memcached.exe"
      if (-not (Test-Path $memcachedExe)) {
        $memcachedExe = "$buildDir\memcached.exe"
      }

      if (-not (Test-Path $memcachedExe)) {
        Write-Error "memcached binary was not found at $memcachedExe"
        exit 1
      }

      Write-Host "Running Test: memcached.exe --version"
      $versionOutput = & $memcachedExe --version 2>&1
      Write-Host "Output: $versionOutput"
      if ($LASTEXITCODE -ne 0) {
        Write-Error "memcached.exe --version exited with code $LASTEXITCODE"
        exit $LASTEXITCODE
      }
      if ($versionOutput -notmatch "memcached \d+\.\d+") {
        Write-Error "memcached --version output does not contain expected version string: $versionOutput"
        exit 1
      }
      Write-Host "PASS: memcached.exe --version test passed successfully!"

      Write-Host "Running Test: memcached.exe -h (Help test)"
      $helpOutput = & $memcachedExe -h 2>&1
      if ($LASTEXITCODE -ne 0) {
        Write-Error "memcached.exe -h exited with code $LASTEXITCODE"
        exit $LASTEXITCODE
      }
      Write-Host "PASS: memcached.exe -h test passed successfully!"

      Write-Host "Running Test: sizes.exe test"
      $sizesExe = "$buildDir\Release\sizes.exe"
      if (Test-Path $sizesExe) {
        & $sizesExe
        if ($LASTEXITCODE -ne 0) {
          Write-Error "sizes.exe failed with exit code $LASTEXITCODE"
          exit $LASTEXITCODE
        }
        Write-Host "PASS: sizes.exe test passed successfully!"
      }

      Write-Host "Running CTest test suite for memcached..."
      Set-Location $buildDir
      & ctest -C Release -R "^sizes$" --output-on-failure
      if ($LASTEXITCODE -ne 0) {
        Write-Error "CTest suite failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
      }
      Write-Host "PASS: All tests completed successfully!"
    POWERSHELL
  end
end
