# ============================================
# PowerShell 多功能脚本集合
# ============================================
# 版权信息
# 开发者: 黑客驰 (HackerChi)
# 网站: https://hackerchi.top
# 版本: 3.0
# 功能: 90个系统管理、安全、优化、监控功能
# ============================================
#
# 包含：系统信息、网络探测、文件下载、文件处理、端口扫描、WiFi密码显示、
#       进程管理、服务管理、磁盘空间分析、注册表查询、系统日志查看、环境变量管理、
#       用户账户信息、防火墙规则查看、系统更新检查、硬件详细信息、计划任务管理、
#       网络连接监控、文件权限检查、系统性能监控、软件安装列表、DNS缓存管理、
#       ARP表查看、系统启动项管理、文件哈希计算、打开系统功能、批量文件操作、
#       可疑文件检测、系统安全扫描、恶意软件检测等功能
# ============================================

# ============================================
# 1. 系统信息功能
# ============================================
function Get-SystemInfo {
    Write-Host "`n========== 系统信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $infoFile = Join-Path $desktop "system_info.txt"
    
    $info = @"
计算机名称: $env:COMPUTERNAME
用户名: $env:USERNAME
操作系统: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
系统版本: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version)
处理器: $(Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name)
内存总量: $([math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB
可用内存: $([math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)) GB
系统启动时间: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)
当前时间: $(Get-Date)
"@
    
    $info | Out-File -FilePath $infoFile -Encoding UTF8
    Write-Host $info
    Write-Host "`n系统信息已保存到: $infoFile" -ForegroundColor Green
}

# ============================================
# 2. 网络探测功能
# ============================================
function Test-NetworkProbe {
    Write-Host "`n========== 网络探测 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $networkFile = Join-Path $desktop "network_probe.txt"
    
    $results = @()
    $results += "========== 网络配置信息 =========="
    $results += Get-NetIPConfiguration | Format-List | Out-String
    
    $results += "`n========== 网络适配器信息 =========="
    $results += Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, LinkSpeed | Out-String
    
    $results += "`n========== 测试连接 hackerchi.top =========="
    try {
        $ping = Test-Connection -ComputerName "hackerchi.top" -Count 4 -ErrorAction Stop
        $results += "Ping 结果: 成功"
        $results += "平均延迟: $([math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average, 2)) ms"
    } catch {
        $results += "Ping 结果: 失败 - $_"
    }
    
    try {
        $dns = Resolve-DnsName -Name "hackerchi.top" -ErrorAction Stop
        $results += "DNS 解析: 成功"
        $results += "IP 地址: $($dns[0].IPAddress)"
    } catch {
        $results += "DNS 解析: 失败 - $_"
    }
    
    $results += "`n========== 路由表 =========="
    $results += Get-NetRoute | Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric | Out-String
    
    $results | Out-File -FilePath $networkFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n网络探测结果已保存到: $networkFile" -ForegroundColor Green
}

# ============================================
# 3. 常见格式文件下载功能
# ============================================
function Get-FileDownload {
    Write-Host "`n========== 文件下载 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $downloadDir = Join-Path $desktop "Downloads"
    
    if (-not (Test-Path $downloadDir)) {
        New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
    }
    
    # 创建示例文件用于测试
    $testFiles = @(
        @{Name="test.txt"; Content="黑客驰 - 这是一个测试文本文件`n内容包含 hackerchi.top 相关信息"},
        @{Name="test.json"; Content='{"name":"黑客驰","website":"hackerchi.top","description":"测试JSON文件"}'},
        @{Name="test.csv"; Content="姓名,网站,描述`n黑客驰,hackerchi.top,测试CSV文件"},
        @{Name="test.xml"; Content='<?xml version="1.0"?><root><name>黑客驰</name><website>hackerchi.top</website></root>'}
    )
    
    Write-Host "正在创建测试文件..." -ForegroundColor Yellow
    foreach ($file in $testFiles) {
        $filePath = Join-Path $downloadDir $file.Name
        $file.Content | Out-File -FilePath $filePath -Encoding UTF8
        Write-Host "已创建: $filePath" -ForegroundColor Green
    }
    
    # 尝试从网络下载文件（示例）
    $url = "https://hackerchi.top"
    $downloadFile = Join-Path $downloadDir "hackerchi_webpage.html"
    
    try {
        Write-Host "`n正在尝试下载网页: $url" -ForegroundColor Yellow
        Invoke-WebRequest -Uri $url -OutFile $downloadFile -ErrorAction Stop
        Write-Host "下载成功: $downloadFile" -ForegroundColor Green
    } catch {
        Write-Host "下载失败: $_" -ForegroundColor Red
        # 创建占位文件
        "<!DOCTYPE html><html><head><title>黑客驰 - hackerchi.top</title></head><body><h1>黑客驰</h1><p>网站: hackerchi.top</p></body></html>" | Out-File -FilePath $downloadFile -Encoding UTF8
        Write-Host "已创建占位文件: $downloadFile" -ForegroundColor Yellow
    }
    
    Write-Host "`n所有文件已保存到: $downloadDir" -ForegroundColor Green
}

# ============================================
# 4. 文件处理功能
# ============================================
function Invoke-FileProcessing {
    Write-Host "`n========== 文件处理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $processDir = Join-Path $desktop "FileProcessing"
    
    if (-not (Test-Path $processDir)) {
        New-Item -ItemType Directory -Path $processDir -Force | Out-Null
    }
    
    # 创建源文件
    $sourceFile = Join-Path $processDir "source.txt"
    $content = @"
黑客驰技术文档
网站地址: hackerchi.top
这是一个关于黑客驰的文件处理示例
包含多行文本内容
用于演示文件处理功能
"@
    $content | Out-File -FilePath $sourceFile -Encoding UTF8
    Write-Host "已创建源文件: $sourceFile" -ForegroundColor Green
    
    # 文件读取和统计
    $fileContent = Get-Content -Path $sourceFile -Encoding UTF8
    $stats = @{
        "总行数" = $fileContent.Count
        "总字符数" = ($fileContent -join "`n").Length
        "包含'黑客驰'的行数" = ($fileContent | Select-String -Pattern "黑客驰").Count
        "包含'hackerchi.top'的行数" = ($fileContent | Select-String -Pattern "hackerchi.top").Count
    }
    
    Write-Host "`n文件统计信息:" -ForegroundColor Yellow
    $stats.GetEnumerator() | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor Cyan
    }
    
    # 创建处理后的文件
    $processedFile = Join-Path $processDir "processed.txt"
    $processedContent = @"
========== 处理后的文件 ==========
原始内容:
$($fileContent -join "`n")

统计信息:
$($stats.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" } | Out-String)

处理时间: $(Get-Date)
"@
    $processedContent | Out-File -FilePath $processedFile -Encoding UTF8
    Write-Host "`n已创建处理文件: $processedFile" -ForegroundColor Green
    
    # 文件搜索功能
    $searchFile = Join-Path $processDir "search_results.txt"
    $searchResults = Get-ChildItem -Path $processDir -Filter "*.txt" | ForEach-Object {
        $lines = Get-Content $_.FullName -Encoding UTF8
        $matches = $lines | Select-String -Pattern "黑客驰|hackerchi.top"
        if ($matches) {
            [PSCustomObject]@{
                File = $_.Name
                Matches = $matches.Count
                Lines = ($matches | ForEach-Object { $_.LineNumber }) -join ", "
            }
        }
    }
    
    if ($searchResults) {
        $searchResults | Format-Table | Out-File -FilePath $searchFile -Encoding UTF8
        Write-Host "`n搜索结果已保存到: $searchFile" -ForegroundColor Green
        $searchResults | Format-Table
    }
    
    Write-Host "`n所有处理文件已保存到: $processDir" -ForegroundColor Green
}

# ============================================
# 5. 端口扫描功能
# ============================================
function Test-PortScan {
    Write-Host "`n========== 端口扫描 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $portScanFile = Join-Path $desktop "port_scan.txt"
    
    # 常见端口列表
    $commonPorts = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080)
    $targetHost = "hackerchi.top"
    
    Write-Host "正在扫描目标: $targetHost" -ForegroundColor Yellow
    Write-Host "扫描端口: $($commonPorts -join ', ')" -ForegroundColor Yellow
    
    $results = @()
    $results += "========== 端口扫描结果 =========="
    $results += "目标主机: $targetHost"
    $results += "扫描时间: $(Get-Date)"
    $results += "`n"
    
    $openPorts = @()
    $closedPorts = @()
    
    foreach ($port in $commonPorts) {
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($targetHost, $port, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(1000, $false)
            
            if ($wait) {
                try {
                    $tcpClient.EndConnect($connection)
                    $status = "开放"
                    $openPorts += $port
                    Write-Host "端口 $port : 开放" -ForegroundColor Green
                } catch {
                    $status = "关闭"
                    $closedPorts += $port
                    Write-Host "端口 $port : 关闭" -ForegroundColor Red
                }
            } else {
                $status = "关闭/过滤"
                $closedPorts += $port
                Write-Host "端口 $port : 关闭/过滤" -ForegroundColor Red
            }
            $tcpClient.Close()
            
            $results += "端口 $port : $status"
        } catch {
            $status = "错误"
            $closedPorts += $port
            $results += "端口 $port : 错误 - $_"
            Write-Host "端口 $port : 错误" -ForegroundColor Yellow
        }
    }
    
    # 扫描本地端口
    $results += "`n========== 本地监听端口 =========="
    $listeningPorts = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, State, OwningProcess | Sort-Object LocalPort
    $results += ($listeningPorts | Format-Table | Out-String)
    
    $results += "`n========== 扫描统计 =========="
    $results += "开放端口数: $($openPorts.Count)"
    $results += "关闭端口数: $($closedPorts.Count)"
    if ($openPorts.Count -gt 0) {
        $results += "开放的端口: $($openPorts -join ', ')"
    }
    
    $results | Out-File -FilePath $portScanFile -Encoding UTF8
    Write-Host "`n端口扫描结果已保存到: $portScanFile" -ForegroundColor Green
}

# ============================================
# 6. 显示WiFi密码功能
# ============================================
function Get-WiFiPasswords {
    Write-Host "`n========== WiFi密码显示 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $wifiFile = Join-Path $desktop "wifi_passwords.txt"
    
    $results = @()
    $results += "========== 已保存的WiFi密码 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    try {
        # 获取所有WiFi配置文件
        $profiles = netsh wlan show profiles | Select-String "所有用户配置文件|所有用户配置文件" | ForEach-Object {
            $_.Line -replace ".*所有用户配置文件\s*:\s*", ""
        }
        
        if (-not $profiles) {
            # 尝试英文系统
            $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
                $_.Line -replace ".*All User Profile\s*:\s*", ""
            }
        }
        
        if ($profiles) {
            $wifiList = @()
            
            foreach ($profile in $profiles) {
                $profile = $profile.Trim()
                if ([string]::IsNullOrWhiteSpace($profile)) { continue }
                
                Write-Host "正在获取: $profile" -ForegroundColor Yellow
                
                # 获取密码
                $passwordInfo = netsh wlan show profile name="$profile" key=clear | Select-String "关键内容|Key Content"
                
                if (-not $passwordInfo) {
                    $passwordInfo = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content"
                }
                
                $password = ""
                if ($passwordInfo) {
                    $password = ($passwordInfo.Line -replace ".*关键内容\s*:\s*", "").Trim()
                    if ([string]::IsNullOrWhiteSpace($password)) {
                        $password = ($passwordInfo.Line -replace ".*Key Content\s*:\s*", "").Trim()
                    }
                }
                
                if ([string]::IsNullOrWhiteSpace($password)) {
                    $password = "无密码或无法获取"
                }
                
                $wifiInfo = [PSCustomObject]@{
                    WiFi名称 = $profile
                    密码 = $password
                }
                
                $wifiList += $wifiInfo
                
                $results += "WiFi名称: $profile"
                $results += "密码: $password"
                $results += "---"
            }
            
            if ($wifiList.Count -gt 0) {
                Write-Host "`n找到 $($wifiList.Count) 个WiFi配置:" -ForegroundColor Green
                $wifiList | Format-Table -AutoSize
            }
        } else {
            $results += "未找到已保存的WiFi配置文件"
            Write-Host "未找到已保存的WiFi配置文件" -ForegroundColor Yellow
        }
    } catch {
        $results += "获取WiFi密码时出错: $_"
        Write-Host "获取WiFi密码时出错: $_" -ForegroundColor Red
    }
    
    # 获取当前连接的WiFi信息
    $results += "`n========== 当前WiFi连接信息 =========="
    try {
        $currentWiFi = netsh wlan show interfaces | Select-String "SSID|信号|Signal"
        if ($currentWiFi) {
            $results += ($currentWiFi | Out-String)
            Write-Host "`n当前WiFi连接信息:" -ForegroundColor Cyan
            $currentWiFi | ForEach-Object { Write-Host $_.Line }
        }
    } catch {
        $results += "无法获取当前WiFi连接信息"
    }
    
    $results | Out-File -FilePath $wifiFile -Encoding UTF8
    Write-Host "`nWiFi密码信息已保存到: $wifiFile" -ForegroundColor Green
}

# ============================================
# 7. 进程管理功能
# ============================================
function Get-ProcessManagement {
    Write-Host "`n========== 进程管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $processFile = Join-Path $desktop "process_management.txt"
    
    $results = @()
    $results += "========== 进程管理信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 所有进程信息
    $results += "========== 所有运行进程 =========="
    $allProcesses = Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, StartTime | Sort-Object CPU -Descending
    $results += ($allProcesses | Format-Table -AutoSize | Out-String)
    
    # CPU占用最高的10个进程
    $results += "`n========== CPU占用最高的10个进程 =========="
    $topCPU = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 ProcessName, Id, @{Name="CPU(秒)";Expression={[math]::Round($_.CPU, 2)}}, @{Name="内存(MB)";Expression={[math]::Round($_.WorkingSet/1MB, 2)}}
    $results += ($topCPU | Format-Table -AutoSize | Out-String)
    
    # 内存占用最高的10个进程
    $results += "`n========== 内存占用最高的10个进程 =========="
    $topMemory = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 ProcessName, Id, @{Name="内存(MB)";Expression={[math]::Round($_.WorkingSet/1MB, 2)}}, @{Name="CPU(秒)";Expression={[math]::Round($_.CPU, 2)}}
    $results += ($topMemory | Format-Table -AutoSize | Out-String)
    
    # 进程统计
    $results += "`n========== 进程统计 =========="
    $results += "总进程数: $((Get-Process).Count)"
    $results += "总内存使用: $([math]::Round((Get-Process | Measure-Object WorkingSet -Sum).Sum / 1GB, 2)) GB"
    $results += "总CPU时间: $([math]::Round((Get-Process | Measure-Object CPU -Sum).Sum, 2)) 秒"
    
    $results | Out-File -FilePath $processFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n进程管理信息已保存到: $processFile" -ForegroundColor Green
}

# ============================================
# 8. 服务管理功能
# ============================================
function Get-ServiceManagement {
    Write-Host "`n========== 服务管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $serviceFile = Join-Path $desktop "service_management.txt"
    
    $results = @()
    $results += "========== 服务管理信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 所有服务
    $results += "========== 所有服务状态 =========="
    $allServices = Get-Service | Select-Object Name, DisplayName, Status, StartType | Sort-Object Status, Name
    $results += ($allServices | Format-Table -AutoSize | Out-String)
    
    # 运行中的服务
    $results += "`n========== 运行中的服务 =========="
    $runningServices = Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, StartType
    $results += "运行中服务数量: $($runningServices.Count)"
    $results += ($runningServices | Format-Table -AutoSize | Out-String)
    
    # 停止的服务
    $results += "`n========== 已停止的服务 =========="
    $stoppedServices = Get-Service | Where-Object {$_.Status -eq 'Stopped'} | Select-Object Name, DisplayName, StartType
    $results += "已停止服务数量: $($stoppedServices.Count)"
    $results += ($stoppedServices | Format-Table -AutoSize | Out-String)
    
    # 服务统计
    $results += "`n========== 服务统计 =========="
    $results += "总服务数: $((Get-Service).Count)"
    $results += "运行中: $((Get-Service | Where-Object {$_.Status -eq 'Running'}).Count)"
    $results += "已停止: $((Get-Service | Where-Object {$_.Status -eq 'Stopped'}).Count)"
    
    $results | Out-File -FilePath $serviceFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n服务管理信息已保存到: $serviceFile" -ForegroundColor Green
}

# ============================================
# 9. 磁盘空间分析
# ============================================
function Get-DiskSpaceAnalysis {
    Write-Host "`n========== 磁盘空间分析 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $diskFile = Join-Path $desktop "disk_space_analysis.txt"
    
    $results = @()
    $results += "========== 磁盘空间分析 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 所有磁盘信息
    $results += "========== 所有磁盘使用情况 =========="
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null}
    foreach ($drive in $drives) {
        $usedGB = [math]::Round($drive.Used / 1GB, 2)
        $freeGB = [math]::Round($drive.Free / 1GB, 2)
        $totalGB = [math]::Round(($drive.Used + $drive.Free) / 1GB, 2)
        $percentUsed = [math]::Round(($drive.Used / ($drive.Used + $drive.Free)) * 100, 2)
        
        $results += "驱动器: $($drive.Name)"
        $results += "  总容量: $totalGB GB"
        $results += "  已使用: $usedGB GB ($percentUsed%)"
        $results += "  可用空间: $freeGB GB"
        $results += "  根路径: $($drive.Root)"
        $results += ""
    }
    
    # 查找大文件（前20个）
    $results += "`n========== 最大的20个文件 =========="
    try {
        $largeFiles = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue | 
            Where-Object {-not $_.PSIsContainer} | 
            Sort-Object Length -Descending | 
            Select-Object -First 20 FullName, @{Name="大小(MB)";Expression={[math]::Round($_.Length/1MB, 2)}}
        
        if ($largeFiles) {
            $results += ($largeFiles | Format-Table -AutoSize | Out-String)
        }
    } catch {
        $results += "无法扫描大文件: $_"
    }
    
    $results | Out-File -FilePath $diskFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n磁盘空间分析已保存到: $diskFile" -ForegroundColor Green
}

# ============================================
# 10. 注册表查询功能
# ============================================
function Get-RegistryQuery {
    Write-Host "`n========== 注册表查询 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $registryFile = Join-Path $desktop "registry_query.txt"
    
    $results = @()
    $results += "========== 注册表查询信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # Windows版本信息
    $results += "========== Windows版本信息 =========="
    try {
        $winVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
        if ($winVersion) {
            $results += "产品名称: $($winVersion.ProductName)"
            $results += "版本号: $($winVersion.CurrentVersion)"
            $results += "构建号: $($winVersion.CurrentBuild)"
            $results += "发布ID: $($winVersion.ReleaseId)"
        }
    } catch {
        $results += "无法读取Windows版本信息: $_"
    }
    
    # 已安装程序列表（从注册表）
    $results += "`n========== 已安装程序（注册表） =========="
    try {
        $programs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
            Where-Object {$_.DisplayName} | 
            Select-Object DisplayName, DisplayVersion, Publisher | 
            Sort-Object DisplayName
        
        $results += "程序数量: $($programs.Count)"
        $results += ($programs | Select-Object -First 50 | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取已安装程序: $_"
    }
    
    # 启动项
    $results += "`n========== 启动项 =========="
    try {
        $startup = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        if ($startup) {
            $startup.PSObject.Properties | Where-Object {$_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath'} | ForEach-Object {
                $results += "$($_.Name): $($_.Value)"
            }
        }
    } catch {
        $results += "无法读取启动项: $_"
    }
    
    $results | Out-File -FilePath $registryFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n注册表查询信息已保存到: $registryFile" -ForegroundColor Green
}

# ============================================
# 11. 系统日志查看
# ============================================
function Get-SystemLogs {
    Write-Host "`n========== 系统日志查看 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $logFile = Join-Path $desktop "system_logs.txt"
    
    $results = @()
    $results += "========== 系统日志信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 系统日志（最近50条）
    $results += "========== 系统日志（最近50条） =========="
    try {
        $systemLogs = Get-EventLog -LogName System -Newest 50 -ErrorAction SilentlyContinue | 
            Select-Object TimeGenerated, EntryType, Source, Message
        $results += ($systemLogs | Format-Table TimeGenerated, EntryType, Source -AutoSize | Out-String)
    } catch {
        $results += "无法读取系统日志: $_"
    }
    
    # 错误日志
    $results += "`n========== 错误日志（最近20条） =========="
    try {
        $errorLogs = Get-EventLog -LogName System -EntryType Error -Newest 20 -ErrorAction SilentlyContinue | 
            Select-Object TimeGenerated, Source, Message
        $results += ($errorLogs | Format-Table TimeGenerated, Source -AutoSize | Out-String)
    } catch {
        $results += "无法读取错误日志: $_"
    }
    
    # 警告日志
    $results += "`n========== 警告日志（最近20条） =========="
    try {
        $warningLogs = Get-EventLog -LogName System -EntryType Warning -Newest 20 -ErrorAction SilentlyContinue | 
            Select-Object TimeGenerated, Source, Message
        $results += ($warningLogs | Format-Table TimeGenerated, Source -AutoSize | Out-String)
    } catch {
        $results += "无法读取警告日志: $_"
    }
    
    # 日志统计
    $results += "`n========== 日志统计 =========="
    try {
        $logStats = Get-EventLog -LogName System -ErrorAction SilentlyContinue | 
            Group-Object EntryType | 
            Select-Object Name, Count
        $results += ($logStats | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法统计日志: $_"
    }
    
    $results | Out-File -FilePath $logFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统日志信息已保存到: $logFile" -ForegroundColor Green
}

# ============================================
# 12. 环境变量管理
# ============================================
function Get-EnvironmentVariables {
    Write-Host "`n========== 环境变量管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $envFile = Join-Path $desktop "environment_variables.txt"
    
    $results = @()
    $results += "========== 环境变量信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 所有环境变量
    $results += "========== 所有环境变量 =========="
    $envVars = Get-ChildItem Env: | Sort-Object Name
    foreach ($var in $envVars) {
        $results += "$($var.Name) = $($var.Value)"
    }
    
    # 常用环境变量
    $results += "`n========== 常用环境变量 =========="
    $commonVars = @("PATH", "TEMP", "TMP", "USERPROFILE", "COMPUTERNAME", "USERNAME", "OS", "PROCESSOR_ARCHITECTURE")
    foreach ($varName in $commonVars) {
        $var = Get-Item "Env:$varName" -ErrorAction SilentlyContinue
        if ($var) {
            $results += "$($var.Name) = $($var.Value)"
        }
    }
    
    $results | Out-File -FilePath $envFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n环境变量信息已保存到: $envFile" -ForegroundColor Green
}

# ============================================
# 13. 用户账户信息
# ============================================
function Get-UserAccounts {
    Write-Host "`n========== 用户账户信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $userFile = Join-Path $desktop "user_accounts.txt"
    
    $results = @()
    $results += "========== 用户账户信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 本地用户
    $results += "========== 本地用户账户 =========="
    try {
        $localUsers = Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon
        $results += ($localUsers | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取本地用户: $_"
    }
    
    # 用户组
    $results += "`n========== 本地用户组 =========="
    try {
        $localGroups = Get-LocalGroup | Select-Object Name, Description
        $results += ($localGroups | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取用户组: $_"
    }
    
    # 管理员组成员
    $results += "`n========== 管理员组成员 =========="
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($admins) {
            $results += ($admins | Format-Table -AutoSize | Out-String)
        }
    } catch {
        $results += "无法读取管理员组: $_"
    }
    
    # 当前用户信息
    $results += "`n========== 当前用户信息 =========="
    $results += "当前用户: $env:USERNAME"
    $results += "用户配置文件: $env:USERPROFILE"
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $results += "管理员权限: $isAdmin"
    
    $results | Out-File -FilePath $userFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n用户账户信息已保存到: $userFile" -ForegroundColor Green
}

# ============================================
# 14. 防火墙规则查看
# ============================================
function Get-FirewallRules {
    Write-Host "`n========== 防火墙规则查看 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $firewallFile = Join-Path $desktop "firewall_rules.txt"
    
    $results = @()
    $results += "========== 防火墙规则信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 所有防火墙规则
    $results += "========== 防火墙规则（前50条） =========="
    try {
        $rules = Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action, Profile | Select-Object -First 50
        $results += ($rules | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取防火墙规则: $_"
    }
    
    # 启用的入站规则
    $results += "`n========== 启用的入站规则 =========="
    try {
        $inboundRules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 'Inbound'} | Select-Object DisplayName, Action, Profile
        $results += "数量: $($inboundRules.Count)"
        $results += ($inboundRules | Select-Object -First 20 | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取入站规则: $_"
    }
    
    # 启用的出站规则
    $results += "`n========== 启用的出站规则 =========="
    try {
        $outboundRules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq 'Outbound'} | Select-Object DisplayName, Action, Profile
        $results += "数量: $($outboundRules.Count)"
        $results += ($outboundRules | Select-Object -First 20 | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取出站规则: $_"
    }
    
    # 防火墙状态
    $results += "`n========== 防火墙状态 =========="
    try {
        $fwProfile = Get-NetFirewallProfile
        foreach ($profile in $fwProfile) {
            $results += "$($profile.Name) 配置文件:"
            $results += "  启用: $($profile.Enabled)"
            $results += "  默认入站操作: $($profile.DefaultInboundAction)"
            $results += "  默认出站操作: $($profile.DefaultOutboundAction)"
            $results += ""
        }
    } catch {
        $results += "无法读取防火墙状态: $_"
    }
    
    $results | Out-File -FilePath $firewallFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n防火墙规则信息已保存到: $firewallFile" -ForegroundColor Green
}

# ============================================
# 15. 系统更新检查
# ============================================
function Get-SystemUpdates {
    Write-Host "`n========== 系统更新检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $updateFile = Join-Path $desktop "system_updates.txt"
    
    $results = @()
    $results += "========== 系统更新信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 已安装的更新
    $results += "========== 已安装的更新（最近50个） =========="
    try {
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 50 HotFixID, Description, InstalledOn, InstalledBy
        $results += ($hotfixes | Format-Table -AutoSize | Out-String)
        
        $results += "`n总更新数量: $((Get-HotFix).Count)"
    } catch {
        $results += "无法读取系统更新: $_"
    }
    
    # 最近的更新
    $results += "`n========== 最近的更新（最近10个） =========="
    try {
        $recentUpdates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
        foreach ($update in $recentUpdates) {
            $results += "$($update.HotFixID) - $($update.Description)"
            $results += "  安装时间: $($update.InstalledOn)"
            $results += "  安装者: $($update.InstalledBy)"
            $results += ""
        }
    } catch {
        $results += "无法读取最近更新: $_"
    }
    
    $results | Out-File -FilePath $updateFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统更新信息已保存到: $updateFile" -ForegroundColor Green
}

# ============================================
# 16. 硬件详细信息
# ============================================
function Get-HardwareInfo {
    Write-Host "`n========== 硬件详细信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $hardwareFile = Join-Path $desktop "hardware_info.txt"
    
    $results = @()
    $results += "========== 硬件详细信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 处理器信息
    $results += "========== 处理器信息 =========="
    try {
        $processors = Get-CimInstance Win32_Processor
        foreach ($proc in $processors) {
            $results += "名称: $($proc.Name)"
            $results += "制造商: $($proc.Manufacturer)"
            $results += "核心数: $($proc.NumberOfCores)"
            $results += "逻辑处理器: $($proc.NumberOfLogicalProcessors)"
            $results += "最大频率: $($proc.MaxClockSpeed) MHz"
            $results += ""
        }
    } catch {
        $results += "无法读取处理器信息: $_"
    }
    
    # 内存信息
    $results += "`n========== 内存信息 =========="
    try {
        $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        $results += "总内存: $([math]::Round($memory.Sum / 1GB, 2)) GB"
        $results += "内存条数: $($memory.Count)"
    } catch {
        $results += "无法读取内存信息: $_"
    }
    
    # 显卡信息
    $results += "`n========== 显卡信息 =========="
    try {
        $gpus = Get-CimInstance Win32_VideoController
        foreach ($gpu in $gpus) {
            $results += "名称: $($gpu.Name)"
            $results += "显存: $([math]::Round($gpu.AdapterRAM / 1GB, 2)) GB"
            $results += "驱动版本: $($gpu.DriverVersion)"
            $results += ""
        }
    } catch {
        $results += "无法读取显卡信息: $_"
    }
    
    # 磁盘信息
    $results += "`n========== 磁盘信息 =========="
    try {
        $disks = Get-CimInstance Win32_DiskDrive
        foreach ($disk in $disks) {
            $results += "型号: $($disk.Model)"
            $results += "大小: $([math]::Round($disk.Size / 1GB, 2)) GB"
            $results += "接口: $($disk.InterfaceType)"
            $results += ""
        }
    } catch {
        $results += "无法读取磁盘信息: $_"
    }
    
    # PnP设备
    $results += "`n========== PnP设备（正常状态） =========="
    try {
        $pnpDevices = Get-PnpDevice | Where-Object {$_.Status -eq 'OK'} | Select-Object FriendlyName, Class, Status | Select-Object -First 30
        $results += ($pnpDevices | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取PnP设备: $_"
    }
    
    $results | Out-File -FilePath $hardwareFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n硬件信息已保存到: $hardwareFile" -ForegroundColor Green
}

# ============================================
# 17. 计划任务管理
# ============================================
function Get-ScheduledTasks {
    Write-Host "`n========== 计划任务管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $taskFile = Join-Path $desktop "scheduled_tasks.txt"
    
    $results = @()
    $results += "========== 计划任务信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 所有计划任务
    $results += "========== 所有计划任务 =========="
    try {
        $tasks = Get-ScheduledTask | Select-Object TaskName, State, TaskPath
        $results += "总任务数: $($tasks.Count)"
        $results += ($tasks | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取计划任务: $_"
    }
    
    # 运行中的任务
    $results += "`n========== 运行中的任务 =========="
    try {
        $runningTasks = Get-ScheduledTask | Where-Object {$_.State -eq 'Running'} | Select-Object TaskName, TaskPath
        $results += "运行中任务数: $($runningTasks.Count)"
        $results += ($runningTasks | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取运行中任务: $_"
    }
    
    # 就绪的任务
    $results += "`n========== 就绪的任务 =========="
    try {
        $readyTasks = Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName, TaskPath | Select-Object -First 30
        $results += ($readyTasks | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取就绪任务: $_"
    }
    
    $results | Out-File -FilePath $taskFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n计划任务信息已保存到: $taskFile" -ForegroundColor Green
}

# ============================================
# 18. 网络连接监控
# ============================================
function Get-NetworkConnections {
    Write-Host "`n========== 网络连接监控 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $connectionFile = Join-Path $desktop "network_connections.txt"
    
    $results = @()
    $results += "========== 网络连接信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # TCP连接
    $results += "========== TCP连接 =========="
    try {
        $tcpConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
            Where-Object {$_.State -eq 'Established'} | 
            Select-Object -First 50
        $results += "已建立连接数: $($tcpConnections.Count)"
        $results += ($tcpConnections | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取TCP连接: $_"
    }
    
    # 监听端口
    $results += "`n========== 监听端口 =========="
    try {
        $listeningPorts = Get-NetTCPConnection -State Listen | 
            Select-Object LocalAddress, LocalPort, State, OwningProcess | 
            Sort-Object LocalPort | 
            Select-Object -First 50
        $results += ($listeningPorts | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取监听端口: $_"
    }
    
    # UDP连接
    $results += "`n========== UDP连接 =========="
    try {
        $udpConnections = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | Select-Object -First 30
        $results += ($udpConnections | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取UDP连接: $_"
    }
    
    # 连接统计
    $results += "`n========== 连接统计 =========="
    try {
        $connectionStats = Get-NetTCPConnection | Group-Object State | Select-Object Name, Count
        $results += ($connectionStats | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法统计连接: $_"
    }
    
    $results | Out-File -FilePath $connectionFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n网络连接信息已保存到: $connectionFile" -ForegroundColor Green
}

# ============================================
# 19. 文件权限检查
# ============================================
function Get-FilePermissions {
    Write-Host "`n========== 文件权限检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $permissionFile = Join-Path $desktop "file_permissions.txt"
    
    $results = @()
    $results += "========== 文件权限信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 系统目录权限
    $results += "========== 系统目录权限 =========="
    $systemPaths = @("C:\Windows", "C:\Program Files", "C:\Program Files (x86)", "C:\Users")
    
    foreach ($path in $systemPaths) {
        if (Test-Path $path) {
            try {
                $acl = Get-Acl $path
                $results += "路径: $path"
                $results += "所有者: $($acl.Owner)"
                $results += "访问规则数: $($acl.Access.Count)"
                $results += ""
            } catch {
                $results += "无法读取 $path 的权限: $_"
            }
        }
    }
    
    # 当前用户目录权限
    $results += "`n========== 当前用户目录权限 =========="
    $userPath = $env:USERPROFILE
    if (Test-Path $userPath) {
        try {
            $acl = Get-Acl $userPath
            $results += "路径: $userPath"
            $results += "所有者: $($acl.Owner)"
            $results += "访问规则:"
            foreach ($rule in $acl.Access) {
                $results += "  $($rule.IdentityReference) - $($rule.FileSystemRights) - $($rule.AccessControlType)"
            }
        } catch {
            $results += "无法读取用户目录权限: $_"
        }
    }
    
    $results | Out-File -FilePath $permissionFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n文件权限信息已保存到: $permissionFile" -ForegroundColor Green
}

# ============================================
# 20. 系统性能监控
# ============================================
function Get-SystemPerformance {
    Write-Host "`n========== 系统性能监控 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $performanceFile = Join-Path $desktop "system_performance.txt"
    
    $results = @()
    $results += "========== 系统性能信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # CPU使用率
    $results += "========== CPU使用率 =========="
    try {
        $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue
        if ($cpu) {
            $cpuValue = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
            $results += "CPU使用率: $cpuValue%"
        }
    } catch {
        $results += "无法读取CPU使用率: $_"
    }
    
    # 内存使用情况
    $results += "`n========== 内存使用情况 =========="
    try {
        $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        $freeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
        $usedMemory = $totalMemory - $freeMemory
        $memoryPercent = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
        
        $results += "总内存: $([math]::Round($totalMemory / 1GB, 2)) GB"
        $results += "已使用: $([math]::Round($usedMemory / 1GB, 2)) GB ($memoryPercent%)"
        $results += "可用: $([math]::Round($freeMemory / 1GB, 2)) GB"
    } catch {
        $results += "无法读取内存信息: $_"
    }
    
    # 磁盘IO
    $results += "`n========== 磁盘IO =========="
    try {
        $diskIO = Get-Counter "\PhysicalDisk(_Total)\Disk Reads/sec", "\PhysicalDisk(_Total)\Disk Writes/sec" -ErrorAction SilentlyContinue
        if ($diskIO) {
            $readsPerSec = [math]::Round($diskIO.CounterSamples[0].CookedValue, 2)
            $writesPerSec = [math]::Round($diskIO.CounterSamples[1].CookedValue, 2)
            $results += "磁盘读取: $readsPerSec 次/秒"
            $results += "磁盘写入: $writesPerSec 次/秒"
        }
    } catch {
        $results += "无法读取磁盘IO: $_"
    }
    
    # 网络IO
    $results += "`n========== 网络IO =========="
    try {
        $networkIO = Get-Counter "\Network Interface(*)\Bytes Sent/sec", "\Network Interface(*)\Bytes Received/sec" -ErrorAction SilentlyContinue
        if ($networkIO) {
            $sentBytes = ($networkIO.CounterSamples | Where-Object {$_.Path -like "*Bytes Sent*"} | Measure-Object -Property CookedValue -Sum).Sum
            $receivedBytes = ($networkIO.CounterSamples | Where-Object {$_.Path -like "*Bytes Received*"} | Measure-Object -Property CookedValue -Sum).Sum
            $results += "发送: $([math]::Round($sentBytes / 1MB, 2)) MB/秒"
            $results += "接收: $([math]::Round($receivedBytes / 1MB, 2)) MB/秒"
        }
    } catch {
        $results += "无法读取网络IO: $_"
    }
    
    $results | Out-File -FilePath $performanceFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统性能信息已保存到: $performanceFile" -ForegroundColor Green
}

# ============================================
# 21. 软件安装列表
# ============================================
function Get-InstalledSoftware {
    Write-Host "`n========== 软件安装列表 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $softwareFile = Join-Path $desktop "installed_software.txt"
    
    $results = @()
    $results += "========== 已安装软件列表 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 从注册表获取已安装程序
    $results += "========== 已安装程序（注册表） =========="
    try {
        $programs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
            Where-Object {$_.DisplayName} | 
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
            Sort-Object DisplayName
        
        $results += "程序数量: $($programs.Count)"
        $results += ($programs | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法读取已安装程序: $_"
    }
    
    # 从WMI获取（如果可用）
    $results += "`n========== 已安装程序（WMI） =========="
    try {
        $wmiPrograms = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | 
            Select-Object Name, Version, Vendor | 
            Sort-Object Name | 
            Select-Object -First 50
        
        if ($wmiPrograms) {
            $results += ($wmiPrograms | Format-Table -AutoSize | Out-String)
        }
    } catch {
        $results += "无法通过WMI读取程序（可能需要管理员权限）"
    }
    
    $results | Out-File -FilePath $softwareFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n软件安装列表已保存到: $softwareFile" -ForegroundColor Green
}

# ============================================
# 22. DNS缓存管理
# ============================================
function Get-DNSCache {
    Write-Host "`n========== DNS缓存管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $dnsFile = Join-Path $desktop "dns_cache.txt"
    
    $results = @()
    $results += "========== DNS缓存信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # DNS缓存内容
    $results += "========== DNS缓存内容 =========="
    try {
        $dnsCache = ipconfig /displaydns 2>&1
        $results += ($dnsCache | Out-String)
    } catch {
        $results += "无法读取DNS缓存: $_"
    }
    
    # DNS服务器
    $results += "`n========== DNS服务器配置 =========="
    try {
        $dnsServers = Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses.Count -gt 0}
        foreach ($dns in $dnsServers) {
            $results += "接口: $($dns.InterfaceAlias)"
            $results += "DNS服务器: $($dns.ServerAddresses -join ', ')"
            $results += ""
        }
    } catch {
        $results += "无法读取DNS服务器: $_"
    }
    
    # 清除DNS缓存选项（仅显示，不执行）
    $results += "`n========== DNS缓存管理 =========="
    $results += "要清除DNS缓存，请运行: ipconfig /flushdns"
    
    $results | Out-File -FilePath $dnsFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nDNS缓存信息已保存到: $dnsFile" -ForegroundColor Green
}

# ============================================
# 23. ARP表查看
# ============================================
function Get-ARPTable {
    Write-Host "`n========== ARP表查看 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $arpFile = Join-Path $desktop "arp_table.txt"
    
    $results = @()
    $results += "========== ARP表信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # ARP表
    $results += "========== ARP表 =========="
    try {
        $arpTable = Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | Sort-Object IPAddress
        $results += ($arpTable | Format-Table -AutoSize | Out-String)
        
        $results += "`n总条目数: $($arpTable.Count)"
    } catch {
        $results += "无法读取ARP表: $_"
    }
    
    # ARP表统计
    $results += "`n========== ARP表统计 =========="
    try {
        $arpStats = Get-NetNeighbor | Group-Object State | Select-Object Name, Count
        $results += ($arpStats | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法统计ARP表: $_"
    }
    
    $results | Out-File -FilePath $arpFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nARP表信息已保存到: $arpFile" -ForegroundColor Green
}

# ============================================
# 24. 系统启动项管理
# ============================================
function Get-StartupItems {
    Write-Host "`n========== 系统启动项管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $startupFile = Join-Path $desktop "startup_items.txt"
    
    $results = @()
    $results += "========== 系统启动项信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 注册表启动项
    $results += "========== 注册表启动项（HKLM） =========="
    try {
        $hklmStartup = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        if ($hklmStartup) {
            $hklmStartup.PSObject.Properties | Where-Object {$_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath'} | ForEach-Object {
                $results += "$($_.Name): $($_.Value)"
            }
        }
    } catch {
        $results += "无法读取HKLM启动项: $_"
    }
    
    # 当前用户启动项
    $results += "`n========== 当前用户启动项（HKCU） =========="
    try {
        $hkcuStartup = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        if ($hkcuStartup) {
            $hkcuStartup.PSObject.Properties | Where-Object {$_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath'} | ForEach-Object {
                $results += "$($_.Name): $($_.Value)"
            }
        }
    } catch {
        $results += "无法读取HKCU启动项: $_"
    }
    
    # WMI启动项
    $results += "`n========== WMI启动项 =========="
    try {
        $wmiStartup = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
        if ($wmiStartup) {
            $results += ($wmiStartup | Format-Table -AutoSize | Out-String)
        }
    } catch {
        $results += "无法读取WMI启动项: $_"
    }
    
    # 启动文件夹
    $results += "`n========== 启动文件夹 =========="
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $results += "文件夹: $folder"
            $files = Get-ChildItem $folder -ErrorAction SilentlyContinue
            if ($files) {
                foreach ($file in $files) {
                    $results += "  - $($file.Name)"
                }
            } else {
                $results += "  (空)"
            }
            $results += ""
        }
    }
    
    $results | Out-File -FilePath $startupFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n启动项信息已保存到: $startupFile" -ForegroundColor Green
}

# ============================================
# 25. 文件哈希计算
# ============================================
function Get-FileHashInfo {
    Write-Host "`n========== 文件哈希计算 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $hashFile = Join-Path $desktop "file_hashes.txt"
    $hashDir = Join-Path $desktop "FileHashes"
    
    if (-not (Test-Path $hashDir)) {
        New-Item -ItemType Directory -Path $hashDir -Force | Out-Null
    }
    
    # 创建测试文件
    $testFile = Join-Path $hashDir "hackerchi_test.txt"
    $testContent = @"
黑客驰技术文档
网站: hackerchi.top
这是一个用于测试文件哈希计算的文件
生成时间: $(Get-Date)
"@
    $testContent | Out-File -FilePath $testFile -Encoding UTF8
    Write-Host "已创建测试文件: $testFile" -ForegroundColor Green
    
    $results = @()
    $results += "========== 文件哈希计算结果 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 计算不同算法的哈希值
    $algorithms = @("MD5", "SHA1", "SHA256", "SHA512")
    
    foreach ($algorithm in $algorithms) {
        try {
            $hash = Microsoft.PowerShell.Utility\Get-FileHash -Path $testFile -Algorithm $algorithm
            $results += "算法: $algorithm"
            $results += "哈希值: $($hash.Hash)"
            $results += "文件: $($hash.Path)"
            $results += ""
            
            Write-Host "$algorithm 哈希: $($hash.Hash)" -ForegroundColor Cyan
        } catch {
            $results += "无法计算 $algorithm 哈希: $_"
        }
    }
    
    # 批量计算桌面文件的哈希
    $results += "`n========== 桌面文件哈希（前10个） =========="
    try {
        $desktopFiles = Get-ChildItem -Path $desktop -File -ErrorAction SilentlyContinue | Select-Object -First 10
        foreach ($file in $desktopFiles) {
            try {
                $hash = Microsoft.PowerShell.Utility\Get-FileHash -Path $file.FullName -Algorithm SHA256
                $results += "$($file.Name): $($hash.Hash)"
            } catch {
                $results += "$($file.Name): 无法计算哈希"
            }
        }
    } catch {
        $results += "无法读取桌面文件: $_"
    }
    
    $results | Out-File -FilePath $hashFile -Encoding UTF8
    Write-Host "`n文件哈希信息已保存到: $hashFile" -ForegroundColor Green
    Write-Host "测试文件已保存到: $hashDir" -ForegroundColor Green
}

# ============================================
# 26. 打开系统指定功能
# ============================================
function Open-SystemFeatures {
    Write-Host "`n========== 打开系统功能 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $systemFeaturesFile = Join-Path $desktop "system_features.txt"
    
    $results = @()
    $results += "========== 系统功能快捷方式 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 系统功能列表
    $features = @{
        "控制面板" = "control"
        "系统设置" = "ms-settings:"
        "网络设置" = "ms-settings:network"
        "显示设置" = "ms-settings:display"
        "声音设置" = "ms-settings:sound"
        "电源选项" = "powercfg.cpl"
        "程序和功能" = "appwiz.cpl"
        "防火墙" = "wf.msc"
        "服务" = "services.msc"
        "任务管理器" = "taskmgr"
        "注册表编辑器" = "regedit"
        "组策略编辑器" = "gpedit.msc"
        "本地安全策略" = "secpol.msc"
        "事件查看器" = "eventvwr.msc"
        "磁盘管理" = "diskmgmt.msc"
        "设备管理器" = "devmgmt.msc"
        "计算机管理" = "compmgmt.msc"
        "系统信息" = "msinfo32"
        "资源监视器" = "resmon"
        "性能监视器" = "perfmon"
    }
    
    $results += "可用系统功能列表:"
    $index = 1
    foreach ($feature in $features.GetEnumerator()) {
        $results += "$index. $($feature.Key) - 命令: $($feature.Value)"
        $index++
    }
    
    $results += "`n提示: 使用 Start-Process '$($features['控制面板'])' 来打开功能"
    
    $results | Out-File -FilePath $systemFeaturesFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统功能列表已保存到: $systemFeaturesFile" -ForegroundColor Green
    
    # 示例：打开控制面板
    Write-Host "`n正在打开控制面板..." -ForegroundColor Yellow
    Start-Process "control" -ErrorAction SilentlyContinue
}

# ============================================
# 27. 批量文件操作
# ============================================
function Invoke-BatchFileOperations {
    Write-Host "`n========== 批量文件操作 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $batchOpsDir = Join-Path $desktop "BatchFileOperations"
    $batchOpsFile = Join-Path $desktop "batch_file_operations.txt"
    
    if (-not (Test-Path $batchOpsDir)) {
        New-Item -ItemType Directory -Path $batchOpsDir -Force | Out-Null
    }
    
    $results = @()
    $results += "========== 批量文件操作 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 批量创建文件
    $results += "========== 批量创建文件 =========="
    $testFiles = @("hackerchi_1.txt", "hackerchi_2.txt", "hackerchi_3.txt", "test_黑客驰.log", "test_hackerchi.dat")
    $createdCount = 0
    foreach ($fileName in $testFiles) {
        $filePath = Join-Path $batchOpsDir $fileName
        try {
            "黑客驰测试文件 - hackerchi.top`n创建时间: $(Get-Date)" | Out-File -FilePath $filePath -Encoding UTF8
            $createdCount++
            $results += "已创建: $fileName"
        } catch {
            $results += "创建失败: $fileName - $_"
        }
    }
    $results += "成功创建 $createdCount 个文件"
    
    # 批量重命名文件
    $results += "`n========== 批量重命名文件 =========="
    $files = Get-ChildItem -Path $batchOpsDir -File | Select-Object -First 3
    $renameCount = 0
    foreach ($file in $files) {
        $newName = "renamed_$($file.Name)"
        $newPath = Join-Path $batchOpsDir $newName
        try {
            Rename-Item -Path $file.FullName -NewName $newName -ErrorAction Stop
            $renameCount++
            $results += "已重命名: $($file.Name) -> $newName"
        } catch {
            $results += "重命名失败: $($file.Name) - $_"
        }
    }
    $results += "成功重命名 $renameCount 个文件"
    
    # 批量查找文件
    $results += "`n========== 批量查找文件 =========="
    $searchPatterns = @("*hackerchi*", "*黑客驰*", "*.txt", "*.log")
    foreach ($pattern in $searchPatterns) {
        $foundFiles = Get-ChildItem -Path $batchOpsDir -Filter $pattern -ErrorAction SilentlyContinue
        $results += "搜索模式: $pattern"
        $results += "找到文件数: $($foundFiles.Count)"
        if ($foundFiles) {
            foreach ($file in $foundFiles) {
                $results += "  - $($file.Name) ($([math]::Round($file.Length/1KB, 2)) KB)"
            }
        }
        $results += ""
    }
    
    # 批量删除文件（仅删除测试文件）
    $results += "`n========== 批量删除文件（测试） =========="
    $testDeleteFiles = Get-ChildItem -Path $batchOpsDir -Filter "*test*" -ErrorAction SilentlyContinue
    $deleteCount = 0
    foreach ($file in $testDeleteFiles) {
        try {
            Remove-Item -Path $file.FullName -ErrorAction Stop
            $deleteCount++
            $results += "已删除: $($file.Name)"
        } catch {
            $results += "删除失败: $($file.Name) - $_"
        }
    }
    $results += "成功删除 $deleteCount 个测试文件"
    
    $results | Out-File -FilePath $batchOpsFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n批量文件操作结果已保存到: $batchOpsFile" -ForegroundColor Green
    Write-Host "操作文件目录: $batchOpsDir" -ForegroundColor Green
}

# ============================================
# 28. 可疑文件检测
# ============================================
function Find-SuspiciousFiles {
    Write-Host "`n========== 可疑文件检测 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $suspiciousFile = Join-Path $desktop "suspicious_files.txt"
    
    $results = @()
    $results += "========== 可疑文件检测报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 可疑文件扩展名
    $suspiciousExtensions = @(".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".ps1", ".dll", ".sys")
    
    # 可疑文件名模式
    $suspiciousPatterns = @("*temp*", "*tmp*", "*~*", "*.tmp", "*.temp")
    
    # 可疑位置
    $suspiciousLocations = @(
        "$env:TEMP",
        "$env:APPDATA",
        "$env:LOCALAPPDATA\Temp",
        "C:\Windows\Temp"
    )
    
    $suspiciousFiles = @()
    
    # 扫描可疑位置
    $results += "========== 扫描可疑位置 =========="
    foreach ($location in $suspiciousLocations) {
        if (Test-Path $location) {
            $results += "扫描: $location"
            try {
                $files = Get-ChildItem -Path $location -File -ErrorAction SilentlyContinue | 
                    Where-Object {$_.Extension -in $suspiciousExtensions -or $_.Name -like "*temp*" -or $_.Name -like "*tmp*"} |
                    Select-Object -First 20
                
                if ($files) {
                    $results += "  找到 $($files.Count) 个可疑文件:"
                    foreach ($file in $files) {
                        $fileInfo = [PSCustomObject]@{
                            Path = $file.FullName
                            Name = $file.Name
                            Size = "$([math]::Round($file.Length/1KB, 2)) KB"
                            Modified = $file.LastWriteTime
                            Extension = $file.Extension
                        }
                        $suspiciousFiles += $fileInfo
                        $results += "    - $($file.Name) ($($fileInfo.Size)) - $($file.LastWriteTime)"
                    }
                } else {
                    $results += "  未找到可疑文件"
                }
            } catch {
                $results += "  扫描失败: $_"
            }
            $results += ""
        }
    }
    
    # 检查隐藏文件
    $results += "`n========== 检查隐藏文件 =========="
    try {
        $hiddenFiles = Get-ChildItem -Path $env:USERPROFILE -File -Force -ErrorAction SilentlyContinue | 
            Where-Object {$_.Attributes -match "Hidden"} | 
            Select-Object -First 10
        
        if ($hiddenFiles) {
            $results += "找到 $($hiddenFiles.Count) 个隐藏文件:"
            foreach ($file in $hiddenFiles) {
                $results += "  - $($file.Name) ($([math]::Round($file.Length/1KB, 2)) KB)"
            }
        }
    } catch {
        $results += "检查隐藏文件失败: $_"
    }
    
    # 检查最近修改的可执行文件
    $results += "`n========== 最近修改的可执行文件 =========="
    try {
        $recentExe = Get-ChildItem -Path "C:\Users\$env:USERNAME\Downloads" -Filter "*.exe" -ErrorAction SilentlyContinue | 
            Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 10
        
        if ($recentExe) {
            $results += "找到 $($recentExe.Count) 个最近下载/修改的exe文件:"
            foreach ($file in $recentExe) {
                $results += "  - $($file.Name) - 修改时间: $($file.LastWriteTime)"
            }
        }
    } catch {
        $results += "检查最近exe文件失败: $_"
    }
    
    # 可疑文件统计
    $results += "`n========== 可疑文件统计 =========="
    $results += "总可疑文件数: $($suspiciousFiles.Count)"
    if ($suspiciousFiles.Count -gt 0) {
        $results += "`n建议: 请仔细检查这些文件，确认是否为正常文件"
    }
    
    $results | Out-File -FilePath $suspiciousFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n可疑文件检测报告已保存到: $suspiciousFile" -ForegroundColor Green
}

# ============================================
# 29. 系统安全扫描
# ============================================
function Invoke-SecurityScan {
    Write-Host "`n========== 系统安全扫描 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $securityFile = Join-Path $desktop "security_scan.txt"
    
    $results = @()
    $results += "========== 系统安全扫描报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    $securityIssues = @()
    $securityWarnings = @()
    
    # 检查可疑进程
    $results += "========== 可疑进程检测 =========="
    $suspiciousProcessNames = @("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
    $runningSuspicious = Get-Process -ErrorAction SilentlyContinue | 
        Where-Object {$_.ProcessName -in $suspiciousProcessNames} |
        Select-Object ProcessName, Id, Path, StartTime
    
    if ($runningSuspicious) {
        $results += "发现可疑进程:"
        foreach ($proc in $runningSuspicious) {
            $results += "  - $($proc.ProcessName) (PID: $($proc.Id))"
            $securityWarnings += "可疑进程: $($proc.ProcessName)"
        }
    } else {
        $results += "未发现可疑进程"
    }
    
    # 检查异常网络连接
    $results += "`n========== 异常网络连接检测 =========="
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
            Where-Object {$_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1"} |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
        
        $results += "活动的外部连接数: $($connections.Count)"
        if ($connections.Count -gt 50) {
            $securityWarnings += "网络连接数异常: $($connections.Count)"
            $results += "警告: 网络连接数较多，可能存在异常"
        }
        
        # 检查可疑端口
        $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)
        $suspiciousConnections = $connections | Where-Object {$_.LocalPort -in $suspiciousPorts -or $_.RemotePort -in $suspiciousPorts}
        if ($suspiciousConnections) {
            $results += "发现可疑端口连接:"
            foreach ($conn in $suspiciousConnections) {
                $results += "  端口 $($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
                $securityWarnings += "可疑端口连接: $($conn.LocalPort)"
            }
        }
    } catch {
        $results += "检查网络连接失败: $_"
    }
    
    # 检查异常启动项
    $results += "`n========== 异常启动项检测 =========="
    try {
        $startupItems = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue
        $suspiciousStartup = $startupItems | Where-Object {
            $_.Command -like "*temp*" -or 
            $_.Command -like "*tmp*" -or
            $_.Location -like "*Startup*"
        }
        
        if ($suspiciousStartup) {
            $results += "发现可疑启动项:"
            foreach ($item in $suspiciousStartup) {
                $results += "  - $($item.Name): $($item.Command)"
                $securityWarnings += "可疑启动项: $($item.Name)"
            }
        } else {
            $results += "未发现异常启动项"
        }
    } catch {
        $results += "检查启动项失败: $_"
    }
    
    # 检查UAC状态
    $results += "`n========== UAC状态检查 =========="
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue
        if ($uac.EnableLUA -eq 0) {
            $securityIssues += "UAC已禁用 - 安全风险高"
            $results += "警告: UAC已禁用，存在安全风险"
        } else {
            $results += "UAC已启用 - 正常"
        }
    } catch {
        $results += "无法检查UAC状态"
    }
    
    # 检查Windows Defender状态
    $results += "`n========== Windows Defender状态 =========="
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            $results += "实时保护: $($defender.RealTimeProtectionEnabled)"
            $results += "防病毒启用: $($defender.AntivirusEnabled)"
            if (-not $defender.RealTimeProtectionEnabled) {
                $securityWarnings += "Windows Defender实时保护未启用"
            }
        } else {
            $results += "无法获取Windows Defender状态（可能需要管理员权限）"
        }
    } catch {
        $results += "无法检查Windows Defender状态"
    }
    
    # 检查防火墙状态
    $results += "`n========== 防火墙状态检查 =========="
    try {
        $fwProfiles = Get-NetFirewallProfile
        foreach ($profile in $fwProfiles) {
            $results += "$($profile.Name) 配置文件: $($profile.Enabled)"
            if (-not $profile.Enabled) {
                $securityWarnings += "防火墙 $($profile.Name) 未启用"
            }
        }
    } catch {
        $results += "无法检查防火墙状态"
    }
    
    # 安全评分
    $results += "`n========== 安全评分 =========="
    $score = 100
    $score -= $securityIssues.Count * 20
    $score -= $securityWarnings.Count * 5
    if ($score -lt 0) { $score = 0 }
    
    $results += "安全评分: $score/100"
    if ($score -ge 80) {
        $results += "状态: 良好"
    } elseif ($score -ge 60) {
        $results += "状态: 一般"
    } else {
        $results += "状态: 需要关注"
    }
    
    if ($securityIssues.Count -gt 0) {
        $results += "`n严重问题: $($securityIssues.Count)"
        foreach ($issue in $securityIssues) {
            $results += "  - $issue"
        }
    }
    
    if ($securityWarnings.Count -gt 0) {
        $results += "`n警告: $($securityWarnings.Count)"
        foreach ($warning in $securityWarnings) {
            $results += "  - $warning"
        }
    }
    
    $results | Out-File -FilePath $securityFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统安全扫描报告已保存到: $securityFile" -ForegroundColor Green
}

# ============================================
# 30. 恶意软件检测
# ============================================
function Find-MalwareIndicators {
    Write-Host "`n========== 恶意软件检测 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $malwareFile = Join-Path $desktop "malware_detection.txt"
    
    $results = @()
    $results += "========== 恶意软件检测报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    $malwareIndicators = @()
    
    # 检查已知恶意文件名
    $knownMalwareNames = @("*svchost*", "*csrss*", "*lsass*", "*explorer*", "*winlogon*")
    $results += "========== 检查已知恶意文件名模式 =========="
    $tempPath = $env:TEMP
    try {
        $suspiciousFiles = Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue | 
            Where-Object {
                $_.Name -like "*svchost*" -or 
                $_.Name -like "*csrss*" -or
                $_.Name -like "*lsass*"
            }
        
        if ($suspiciousFiles) {
            $results += "警告: 在临时目录发现可疑文件名:"
            foreach ($file in $suspiciousFiles) {
                $results += "  - $($file.FullName)"
                $malwareIndicators += "可疑文件名: $($file.FullName)"
            }
        }
    } catch {
        $results += "检查失败: $_"
    }
    
    # 检查进程注入
    $results += "`n========== 检查进程异常 =========="
    try {
        $systemProcesses = Get-Process -ErrorAction SilentlyContinue | 
            Where-Object {$_.ProcessName -in @("svchost", "explorer", "winlogon", "csrss", "lsass")}
        
        foreach ($proc in $systemProcesses) {
            $modules = $proc.Modules | Where-Object {
                $_.FileName -notlike "C:\Windows\*" -and 
                $_.FileName -notlike "C:\Program Files*"
            }
            
            if ($modules) {
                $results += "警告: $($proc.ProcessName) 加载了非系统模块:"
                foreach ($mod in $modules) {
                    $results += "  - $($mod.FileName)"
                    $malwareIndicators += "进程注入: $($proc.ProcessName) -> $($mod.FileName)"
                }
            }
        }
    } catch {
        $results += "检查进程异常失败（可能需要管理员权限）"
    }
    
    # 检查注册表中的恶意项
    $results += "`n========== 检查注册表恶意项 =========="
    $suspiciousRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($regPath in $suspiciousRegPaths) {
        try {
            $items = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($items) {
                $items.PSObject.Properties | Where-Object {
                    $_.Name -ne 'PSPath' -and 
                    $_.Name -ne 'PSParentPath' -and
                    ($_.Value -like "*temp*" -or $_.Value -like "*tmp*" -or $_.Value -notlike "*Program Files*")
                } | ForEach-Object {
                    $results += "可疑注册表项: $($_.Name) = $($_.Value)"
                    $malwareIndicators += "可疑注册表项: $regPath\$($_.Name)"
                }
            }
        } catch {
            # 忽略错误
        }
    }
    
    # 检查异常计划任务
    $results += "`n========== 检查异常计划任务 =========="
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | 
            Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'}
        
        $suspiciousTasks = $tasks | Where-Object {
            $_.TaskName -like "*temp*" -or
            $_.TaskName -like "*tmp*" -or
            $_.TaskName -like "*update*"
        } | Select-Object -First 10
        
        if ($suspiciousTasks) {
            $results += "发现可疑计划任务:"
            foreach ($task in $suspiciousTasks) {
                $results += "  - $($task.TaskName)"
            }
        }
    } catch {
        $results += "检查计划任务失败"
    }
    
    # 总结
    $results += "`n========== 检测总结 =========="
    $results += "发现可疑指标: $($malwareIndicators.Count)"
    if ($malwareIndicators.Count -gt 0) {
        $results += "`n建议: 使用专业杀毒软件进行全盘扫描"
        $results += "建议: 检查上述可疑文件和进程"
    } else {
        $results += "未发现明显的恶意软件指标"
    }
    
    $results | Out-File -FilePath $malwareFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n恶意软件检测报告已保存到: $malwareFile" -ForegroundColor Green
}

# ============================================
# 系统优化功能
# ============================================

# 31. 清理临时文件
function Clear-TempFiles {
    Write-Host "`n========== 清理临时文件 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $cleanupFile = Join-Path $desktop "temp_cleanup.txt"
    
    $results = @()
    $results += "========== 临时文件清理报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    $totalSize = 0
    $cleanedFiles = 0
    
    # 清理系统临时文件
    $tempPaths = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "C:\Windows\Temp",
        "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache"
    )
    
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                $size = ($files | Measure-Object -Property Length -Sum).Sum
                $count = $files.Count
                
                $results += "路径: $path"
                $results += "  文件数: $count"
                $results += "  大小: $([math]::Round($size / 1GB, 2)) GB"
                
                # 仅显示，不实际删除（安全考虑）
                $results += "  状态: 已分析（未删除，请手动确认后删除）"
                $results += ""
                
                $totalSize += $size
                $cleanedFiles += $count
            } catch {
                $results += "  错误: $_"
            }
        }
    }
    
    $results += "`n总计: $cleanedFiles 个文件，$([math]::Round($totalSize / 1GB, 2)) GB"
    $results += "`n提示: 请手动确认后删除，或使用系统自带的磁盘清理工具"
    
    $results | Out-File -FilePath $cleanupFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n临时文件分析已保存到: $cleanupFile" -ForegroundColor Green
}

# 32. 磁盘碎片分析
function Get-DiskFragmentation {
    Write-Host "`n========== 磁盘碎片分析 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $fragFile = Join-Path $desktop "disk_fragmentation.txt"
    
    $results = @()
    $results += "========== 磁盘碎片分析报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null}
    
    foreach ($drive in $drives) {
        $results += "驱动器: $($drive.Name)"
        $results += "  总容量: $([math]::Round(($drive.Used + $drive.Free) / 1GB, 2)) GB"
        $results += "  已使用: $([math]::Round($drive.Used / 1GB, 2)) GB"
        $results += "  可用: $([math]::Round($drive.Free / 1GB, 2)) GB"
        
        # 检查碎片情况（需要管理员权限）
        try {
            $defragInfo = defrag $drive.Name /A 2>&1
            $results += "  碎片分析: 请运行 'defrag $($drive.Name) /A' 查看详细信息"
        } catch {
            $results += "  碎片分析: 需要管理员权限"
        }
        
        # 建议
        $usedPercent = [math]::Round(($drive.Used / ($drive.Used + $drive.Free)) * 100, 2)
        if ($usedPercent -gt 90) {
            $results += "  建议: 磁盘空间不足，建议清理文件"
        } elseif ($usedPercent -gt 80) {
            $results += "  建议: 磁盘空间较紧张，建议整理"
        } else {
            $results += "  建议: 磁盘空间充足"
        }
        $results += ""
    }
    
    $results += "`n提示: 使用 'defrag C: /O' 进行优化（需要管理员权限）"
    
    $results | Out-File -FilePath $fragFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n磁盘碎片分析已保存到: $fragFile" -ForegroundColor Green
}

# 33. 启动项优化
function Optimize-StartupItems {
    Write-Host "`n========== 启动项优化 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $startupOptFile = Join-Path $desktop "startup_optimization.txt"
    
    $results = @()
    $results += "========== 启动项优化建议 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 获取所有启动项
    $allStartupItems = @()
    
    # 注册表启动项
    try {
        $hklmStartup = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        if ($hklmStartup) {
            $hklmStartup.PSObject.Properties | Where-Object {$_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath'} | ForEach-Object {
                $allStartupItems += [PSCustomObject]@{
                    Name = $_.Name
                    Command = $_.Value
                    Location = "HKLM Run"
                    Type = "注册表"
                }
            }
        }
    } catch {}
    
    try {
        $hkcuStartup = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        if ($hkcuStartup) {
            $hkcuStartup.PSObject.Properties | Where-Object {$_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath'} | ForEach-Object {
                $allStartupItems += [PSCustomObject]@{
                    Name = $_.Name
                    Command = $_.Value
                    Location = "HKCU Run"
                    Type = "注册表"
                }
            }
        }
    } catch {}
    
    # 启动文件夹
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $files = Get-ChildItem $folder -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $allStartupItems += [PSCustomObject]@{
                    Name = $file.Name
                    Command = $file.FullName
                    Location = $folder
                    Type = "启动文件夹"
                }
            }
        }
    }
    
    $results += "总启动项数: $($allStartupItems.Count)"
    $results += "`n所有启动项:"
    foreach ($item in $allStartupItems) {
        $results += "  - $($item.Name)"
        $results += "    命令: $($item.Command)"
        $results += "    位置: $($item.Location)"
        $results += ""
    }
    
    # 优化建议
    $results += "`n优化建议:"
    $results += "1. 禁用不必要的启动项可以加快系统启动速度"
    $results += "2. 建议保留系统必需和常用软件的启动项"
    $results += "3. 可以通过任务管理器 > 启动 来管理启动项"
    
    $results | Out-File -FilePath $startupOptFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n启动项优化建议已保存到: $startupOptFile" -ForegroundColor Green
}

# 34. 服务优化
function Optimize-Services {
    Write-Host "`n========== 服务优化 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $serviceOptFile = Join-Path $desktop "service_optimization.txt"
    
    $results = @()
    $results += "========== 服务优化建议 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 获取所有服务
    $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
    
    # 分析可优化的服务
    $optimizableServices = $services | Where-Object {
        $_.Status -eq 'Running' -and 
        ($_.StartType -eq 'Automatic' -or $_.StartType -eq 'AutomaticDelayedStart') -and
        $_.DisplayName -notlike "*Windows*" -and
        $_.DisplayName -notlike "*Microsoft*"
    } | Select-Object -First 20
    
    $results += "运行中的服务总数: $((Get-Service | Where-Object {$_.Status -eq 'Running'}).Count)"
    $results += "`n可能可优化的服务（非系统服务）:"
    
    if ($optimizableServices) {
        foreach ($svc in $optimizableServices) {
            $results += "  - $($svc.DisplayName)"
            $results += "    名称: $($svc.Name)"
            $results += "    启动类型: $($svc.StartType)"
            $results += ""
        }
    } else {
        $results += "  未找到明显的可优化服务"
    }
    
    $results += "`n优化建议:"
    $results += "1. 仔细检查每个服务的作用，不要随意禁用"
    $results += "2. 可以尝试将某些服务的启动类型改为'手动'"
    $results += "3. 禁用服务前请先了解其功能"
    $results += "4. 建议使用 'services.msc' 来管理服务"
    
    $results | Out-File -FilePath $serviceOptFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n服务优化建议已保存到: $serviceOptFile" -ForegroundColor Green
}

# ============================================
# 网络管理功能
# ============================================

# 35. 网络速度测试
function Test-NetworkSpeed {
    Write-Host "`n========== 网络速度测试 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $speedFile = Join-Path $desktop "network_speed.txt"
    
    $results = @()
    $results += "========== 网络速度测试 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 测试连接到hackerchi.top
    $testUrl = "https://hackerchi.top"
    $results += "测试目标: $testUrl"
    
    try {
        $ping = Test-Connection -ComputerName "hackerchi.top" -Count 4 -ErrorAction Stop
        $avgLatency = [math]::Round(($ping | Measure-Object -Property ResponseTime -Average).Average, 2)
        $results += "平均延迟: $avgLatency ms"
        
        if ($avgLatency -lt 50) {
            $results += "网络延迟: 优秀"
        } elseif ($avgLatency -lt 100) {
            $results += "网络延迟: 良好"
        } elseif ($avgLatency -lt 200) {
            $results += "网络延迟: 一般"
        } else {
            $results += "网络延迟: 较差"
        }
    } catch {
        $results += "Ping测试失败: $_"
    }
    
    # 测试下载速度（简单测试）
    try {
        $testFile = "https://hackerchi.top"
        $startTime = Get-Date
        $response = Invoke-WebRequest -Uri $testFile -Method Head -TimeoutSec 10 -ErrorAction Stop
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        
        if ($response.Headers.'Content-Length') {
            $size = [int]$response.Headers.'Content-Length'
            $speed = [math]::Round(($size / $duration) / 1KB, 2)
            $results += "`n下载速度测试: $speed KB/s"
        }
    } catch {
        $results += "`n下载速度测试: 无法完成（可能需要实际下载文件）"
    }
    
    # 网络适配器信息
    $results += "`n========== 网络适配器信息 =========="
    try {
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}
        foreach ($adapter in $adapters) {
            $results += "适配器: $($adapter.Name)"
            $results += "  状态: $($adapter.Status)"
            $results += "  速度: $($adapter.LinkSpeed)"
            $results += ""
        }
    } catch {
        $results += "无法获取网络适配器信息"
    }
    
    $results | Out-File -FilePath $speedFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n网络速度测试已保存到: $speedFile" -ForegroundColor Green
}

# 36. 网络流量监控
function Monitor-NetworkTraffic {
    Write-Host "`n========== 网络流量监控 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $trafficFile = Join-Path $desktop "network_traffic.txt"
    
    $results = @()
    $results += "========== 网络流量监控 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 获取网络连接
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
            Where-Object {$_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1"}
        
        $results += "活动连接数: $($connections.Count)"
        
        # 按进程统计
        $processTraffic = $connections | Group-Object OwningProcess | 
            Select-Object Name, Count | 
            Sort-Object Count -Descending | 
            Select-Object -First 10
        
        $results += "`n按进程统计（前10个）:"
        foreach ($proc in $processTraffic) {
            try {
                $procInfo = Get-Process -Id $proc.Name -ErrorAction SilentlyContinue
                if ($procInfo) {
                    $results += "  $($procInfo.ProcessName): $($proc.Count) 个连接"
                }
            } catch {
                $results += "  PID $($proc.Name): $($proc.Count) 个连接"
            }
        }
        
        # 按远程地址统计
        $results += "`n按远程地址统计（前10个）:"
        $remoteTraffic = $connections | Group-Object RemoteAddress | 
            Select-Object Name, Count | 
            Sort-Object Count -Descending | 
            Select-Object -First 10
        
        foreach ($remote in $remoteTraffic) {
            $results += "  $($remote.Name): $($remote.Count) 个连接"
        }
        
    } catch {
        $results += "无法获取网络流量信息: $_"
    }
    
    $results | Out-File -FilePath $trafficFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n网络流量监控已保存到: $trafficFile" -ForegroundColor Green
}

# 37. Hosts文件管理
function Manage-HostsFile {
    Write-Host "`n========== Hosts文件管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $hostsFile = Join-Path $desktop "hosts_file.txt"
    
    $results = @()
    $results += "========== Hosts文件内容 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    
    if (Test-Path $hostsPath) {
        try {
            $hostsContent = Get-Content -Path $hostsPath -ErrorAction Stop
            $results += "Hosts文件路径: $hostsPath"
            $results += "`n文件内容:"
            $results += ($hostsContent | Out-String)
            
            # 统计
            $activeEntries = $hostsContent | Where-Object {
                $_ -notmatch '^#' -and 
                $_ -notmatch '^\s*$' -and
                $_ -match '\S+'
            }
            $results += "`n活动条目数: $($activeEntries.Count)"
            
            # 检查hackerchi.top
            if ($hostsContent -match "hackerchi.top") {
                $results += "`n发现hackerchi.top条目:"
                $hostsContent | Where-Object {$_ -match "hackerchi.top"} | ForEach-Object {
                    $results += "  $_"
                }
            }
        } catch {
            $results += "无法读取Hosts文件: $_（可能需要管理员权限）"
        }
    } else {
        $results += "Hosts文件不存在: $hostsPath"
    }
    
    $results += "`n提示: 编辑Hosts文件需要管理员权限"
    $results += "提示: 可以使用记事本以管理员身份打开: notepad $hostsPath"
    
    $results | Out-File -FilePath $hostsFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nHosts文件信息已保存到: $hostsFile" -ForegroundColor Green
}

# 38. 代理设置检查
function Get-ProxySettings {
    Write-Host "`n========== 代理设置检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $proxyFile = Join-Path $desktop "proxy_settings.txt"
    
    $results = @()
    $results += "========== 代理设置信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 检查系统代理设置
    try {
        $proxyReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($proxyReg) {
            $results += "代理启用: $($proxyReg.ProxyEnable)"
            $results += "代理服务器: $($proxyReg.ProxyServer)"
            $results += "代理覆盖: $($proxyReg.ProxyOverride)"
            $results += "自动配置脚本: $($proxyReg.AutoConfigURL)"
        }
    } catch {
        $results += "无法读取代理设置: $_"
    }
    
    # 检查环境变量
    $results += "`n环境变量代理设置:"
    $proxyVars = @("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY")
    foreach ($var in $proxyVars) {
        $value = [Environment]::GetEnvironmentVariable($var)
        if ($value) {
            $results += "  $var = $value"
        }
    }
    
    # 检查网络配置
    $results += "`n网络代理配置:"
    try {
        $netshProxy = netsh winhttp show proxy 2>&1
        $results += ($netshProxy | Out-String)
    } catch {
        $results += "无法获取网络代理配置"
    }
    
    $results | Out-File -FilePath $proxyFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n代理设置信息已保存到: $proxyFile" -ForegroundColor Green
}

# ============================================
# 备份与恢复功能
# ============================================

# 39. 注册表备份
function Backup-Registry {
    Write-Host "`n========== 注册表备份 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $backupDir = Join-Path $desktop "RegistryBackup"
    $backupFile = Join-Path $desktop "registry_backup.txt"
    
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }
    
    $results = @()
    $results += "========== 注册表备份报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 重要注册表项
    $importantKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    )
    
    $backupCount = 0
    foreach ($key in $importantKeys) {
        try {
            $keyName = $key.Replace(":", "").Replace("\", "_")
            $backupPath = Join-Path $backupDir "$keyName.reg"
            
            # 导出注册表
            reg export $key.Replace("HKCU:", "HKEY_CURRENT_USER").Replace("HKLM:", "HKEY_LOCAL_MACHINE") $backupPath /y 2>&1 | Out-Null
            
            if (Test-Path $backupPath) {
                $backupCount++
                $results += "已备份: $key -> $backupPath"
            }
        } catch {
            $results += "备份失败: $key - $_"
        }
    }
    
    $results += "`n成功备份 $backupCount 个注册表项"
    $results += "备份位置: $backupDir"
    
    $results | Out-File -FilePath $backupFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n注册表备份信息已保存到: $backupFile" -ForegroundColor Green
}

# 40. 系统配置备份
function Backup-SystemConfig {
    Write-Host "`n========== 系统配置备份 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $configBackupDir = Join-Path $desktop "SystemConfigBackup"
    $configFile = Join-Path $desktop "system_config_backup.txt"
    
    if (-not (Test-Path $configBackupDir)) {
        New-Item -ItemType Directory -Path $configBackupDir -Force | Out-Null
    }
    
    $results = @()
    $results += "========== 系统配置备份报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 备份环境变量
    $envBackup = Join-Path $configBackupDir "environment_variables.txt"
    Get-ChildItem Env: | Sort-Object Name | Out-File -FilePath $envBackup -Encoding UTF8
    $results += "已备份环境变量: $envBackup"
    
    # 备份网络配置
    $netBackup = Join-Path $configBackupDir "network_config.txt"
    Get-NetIPConfiguration | Out-File -FilePath $netBackup -Encoding UTF8
    $results += "已备份网络配置: $netBackup"
    
    # 备份服务配置
    $svcBackup = Join-Path $configBackupDir "services.txt"
    Get-Service | Select-Object Name, Status, StartType | Out-File -FilePath $svcBackup -Encoding UTF8
    $results += "已备份服务配置: $svcBackup"
    
    $results += "`n备份位置: $configBackupDir"
    
    $results | Out-File -FilePath $configFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统配置备份信息已保存到: $configFile" -ForegroundColor Green
}

# 41. 文件备份
function Backup-Files {
    Write-Host "`n========== 文件备份 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $fileBackupDir = Join-Path $desktop "FileBackup"
    $backupFile = Join-Path $desktop "file_backup.txt"
    
    if (-not (Test-Path $fileBackupDir)) {
        New-Item -ItemType Directory -Path $fileBackupDir -Force | Out-Null
    }
    
    $results = @()
    $results += "========== 文件备份报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 备份重要文件（示例）
    $importantFiles = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop"
    )
    
    $backupCount = 0
    foreach ($source in $importantFiles) {
        if (Test-Path $source) {
            try {
                $destName = Split-Path $source -Leaf
                $destPath = Join-Path $fileBackupDir $destName
                
                # 仅创建文件列表（不实际复制，避免占用空间）
                $fileList = Get-ChildItem -Path $source -Recurse -File -ErrorAction SilentlyContinue | 
                    Select-Object FullName, Length, LastWriteTime
                
                $listFile = Join-Path $fileBackupDir "${destName}_filelist.txt"
                $fileList | Out-File -FilePath $listFile -Encoding UTF8
                
                $results += "已创建文件列表: $source -> $listFile ($($fileList.Count) 个文件)"
                $backupCount++
            } catch {
                $results += "备份失败: $source - $_"
            }
        }
    }
    
    $results += "`n提示: 实际文件备份需要手动复制或使用专业备份工具"
    $results += "备份位置: $fileBackupDir"
    
    $results | Out-File -FilePath $backupFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n文件备份信息已保存到: $backupFile" -ForegroundColor Green
}

# 42. 系统还原点管理
function Manage-SystemRestorePoints {
    Write-Host "`n========== 系统还原点管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $restoreFile = Join-Path $desktop "system_restore_points.txt"
    
    $results = @()
    $results += "========== 系统还原点信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    try {
        # 获取还原点
        $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($restorePoints) {
            $results += "系统还原点数量: $($restorePoints.Count)"
            $results += "`n还原点列表:"
            foreach ($rp in $restorePoints | Sort-Object CreationTime -Descending) {
                $results += "  序列号: $($rp.SequenceNumber)"
                $results += "  创建时间: $($rp.CreationTime)"
                $results += "  描述: $($rp.Description)"
                $results += "  类型: $($rp.RestorePointType)"
                $results += ""
            }
        } else {
            $results += "未找到系统还原点"
            $results += "提示: 系统还原可能未启用，请在系统属性中启用"
        }
    } catch {
        $results += "无法获取系统还原点: $_（可能需要管理员权限）"
    }
    
    $results += "`n提示: 使用 'Get-ComputerRestorePoint' 查看还原点"
    $results += "提示: 使用 'Restore-Computer -RestorePoint <序列号>' 执行还原"
    
    $results | Out-File -FilePath $restoreFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统还原点信息已保存到: $restoreFile" -ForegroundColor Green
}

# ============================================
# 隐私保护功能
# ============================================

# 43. 浏览器历史清理
function Clear-BrowserHistory {
    Write-Host "`n========== 浏览器历史清理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $browserFile = Join-Path $desktop "browser_history_cleanup.txt"
    
    $results = @()
    $results += "========== 浏览器历史清理报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # Chrome历史位置
    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    )
    
    # Edge历史位置
    $edgePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    )
    
    $results += "Chrome数据位置:"
    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            $size = (Get-Item $path -ErrorAction SilentlyContinue).Length
            $results += "  $path - $([math]::Round($size / 1MB, 2)) MB"
        }
    }
    
    $results += "`nEdge数据位置:"
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            $size = (Get-Item $path -ErrorAction SilentlyContinue).Length
            $results += "  $path - $([math]::Round($size / 1MB, 2)) MB"
        }
    }
    
    $results += "`n提示: 请使用浏览器自带的清理功能或专业清理工具"
    $results += "提示: 直接删除浏览器数据文件可能导致数据丢失"
    
    $results | Out-File -FilePath $browserFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n浏览器历史清理信息已保存到: $browserFile" -ForegroundColor Green
}

# 44. 最近文件清理
function Clear-RecentFiles {
    Write-Host "`n========== 最近文件清理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $recentFile = Join-Path $desktop "recent_files_cleanup.txt"
    
    $results = @()
    $results += "========== 最近文件清理报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 最近文件位置
    $recentPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Office\Recent"
    )
    
    $totalFiles = 0
    foreach ($path in $recentPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                $totalFiles += $files.Count
                $results += "路径: $path"
                $results += "  文件数: $($files.Count)"
                $results += "  大小: $([math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 2)) MB"
                $results += ""
            } catch {
                $results += "无法访问: $path"
            }
        }
    }
    
    $results += "总计: $totalFiles 个最近文件"
    $results += "`n提示: 可以手动删除这些文件来清理最近文件记录"
    $results += "提示: 删除后，文件资源管理器中的'最近使用的文件'将被清空"
    
    $results | Out-File -FilePath $recentFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n最近文件清理信息已保存到: $recentFile" -ForegroundColor Green
}

# 45. 隐私设置检查
function Check-PrivacySettings {
    Write-Host "`n========== 隐私设置检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $privacyFile = Join-Path $desktop "privacy_settings.txt"
    
    $results = @()
    $results += "========== 隐私设置检查报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 检查隐私相关注册表项
    $privacyKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    )
    
    foreach ($key in $privacyKeys) {
        try {
            $values = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if ($values) {
                $results += "注册表项: $key"
                $values.PSObject.Properties | Where-Object {
                    $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath'
                } | ForEach-Object {
                    $results += "  $($_.Name) = $($_.Value)"
                }
                $results += ""
            }
        } catch {
            # 忽略不存在的项
        }
    }
    
    # 检查位置服务
    $results += "位置服务:"
    try {
        $location = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -ErrorAction SilentlyContinue
        if ($location) {
            $results += "  位置服务注册表项存在"
        }
    } catch {
        $results += "  无法检查位置服务"
    }
    
    $results += "`n提示: 可以在Windows设置 > 隐私 中管理隐私设置"
    $results += "提示: 建议定期检查和调整隐私设置"
    
    $results | Out-File -FilePath $privacyFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n隐私设置信息已保存到: $privacyFile" -ForegroundColor Green
}

# 46. 位置服务管理
function Manage-LocationServices {
    Write-Host "`n========== 位置服务管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $locationFile = Join-Path $desktop "location_services.txt"
    
    $results = @()
    $results += "========== 位置服务信息 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $locationKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        $location = Get-ItemProperty $locationKey -ErrorAction SilentlyContinue
        
        if ($location) {
            $results += "位置服务注册表项: $locationKey"
            $location.PSObject.Properties | Where-Object {
                $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath'
            } | ForEach-Object {
                $results += "  $($_.Name) = $($_.Value)"
            }
        } else {
            $results += "无法读取位置服务设置"
        }
    } catch {
        $results += "检查位置服务失败: $_"
    }
    
    $results += "`n提示: 可以在Windows设置 > 隐私 > 位置 中管理位置服务"
    $results += "提示: 禁用位置服务可以提高隐私保护"
    
    $results | Out-File -FilePath $locationFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n位置服务信息已保存到: $locationFile" -ForegroundColor Green
}

# ============================================
# 系统监控功能
# ============================================

# 47. 实时性能监控
function Monitor-SystemPerformance {
    Write-Host "`n========== 实时性能监控 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $perfFile = Join-Path $desktop "realtime_performance.txt"
    
    $results = @()
    $results += "========== 实时性能监控 =========="
    $results += "监控时间: $(Get-Date)"
    $results += "`n"
    
    # CPU使用率
    try {
        $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue
        if ($cpu) {
            $cpuValue = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
            $results += "CPU使用率: $cpuValue%"
        }
    } catch {
        $results += "CPU使用率: 无法获取"
    }
    
    # 内存使用
    $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    $freeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
    $usedMemory = $totalMemory - $freeMemory
    $memoryPercent = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
    $results += "内存使用: $memoryPercent% ($([math]::Round($usedMemory / 1GB, 2)) GB / $([math]::Round($totalMemory / 1GB, 2)) GB)"
    
    # 磁盘使用
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null}
    foreach ($drive in $drives) {
        $usedPercent = [math]::Round(($drive.Used / ($drive.Used + $drive.Free)) * 100, 2)
        $results += "$($drive.Name)盘使用: $usedPercent%"
    }
    
    $results | Out-File -FilePath $perfFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n实时性能监控已保存到: $perfFile" -ForegroundColor Green
}

# 48. 温度监控
function Monitor-Temperature {
    Write-Host "`n========== 温度监控 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $tempFile = Join-Path $desktop "temperature_monitor.txt"
    
    $results = @()
    $results += "========== 温度监控 =========="
    $results += "监控时间: $(Get-Date)"
    $results += "`n"
    
    # 尝试获取温度信息（需要WMI支持）
    try {
        $temps = Get-WmiObject -Namespace "root\wmi" -Class "MSAcpi_ThermalZoneTemperature" -ErrorAction SilentlyContinue
        if ($temps) {
            foreach ($temp in $temps) {
                $celsius = ($temp.CurrentTemperature / 10) - 273.15
                $results += "温度传感器: $([math]::Round($celsius, 2))°C"
            }
        } else {
            $results += "无法获取温度信息（可能需要特定硬件支持）"
        }
    } catch {
        $results += "温度监控: 需要硬件支持或管理员权限"
    }
    
    $results += "`n提示: 可以使用第三方工具如HWiNFO、Core Temp等监控温度"
    
    $results | Out-File -FilePath $tempFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n温度监控信息已保存到: $tempFile" -ForegroundColor Green
}

# 49. 电池状态
function Get-BatteryStatus {
    Write-Host "`n========== 电池状态 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $batteryFile = Join-Path $desktop "battery_status.txt"
    
    $results = @()
    $results += "========== 电池状态 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $battery = Get-WmiObject -Class Win32_Battery -ErrorAction SilentlyContinue
        if ($battery) {
            foreach ($bat in $battery) {
                $results += "电池状态: $($bat.BatteryStatus)"
                $results += "电量百分比: $($bat.EstimatedChargeRemaining)%"
                $results += "设计容量: $($bat.DesignCapacity) mWh"
                $results += "当前容量: $($bat.FullChargeCapacity) mWh"
                $results += "健康状态: $($bat.BatteryStatus)"
            }
        } else {
            $results += "未检测到电池（可能是台式机）"
        }
    } catch {
        $results += "无法获取电池信息"
    }
    
    $results | Out-File -FilePath $batteryFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n电池状态信息已保存到: $batteryFile" -ForegroundColor Green
}

# 50. 系统资源警报
function Get-SystemResourceAlerts {
    Write-Host "`n========== 系统资源警报 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $alertFile = Join-Path $desktop "system_resource_alerts.txt"
    
    $results = @()
    $results += "========== 系统资源警报 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    $alerts = @()
    
    # CPU检查
    try {
        $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue
        if ($cpu) {
            $cpuValue = $cpu.CounterSamples[0].CookedValue
            if ($cpuValue -gt 90) {
                $alerts += "警告: CPU使用率过高 ($([math]::Round($cpuValue, 2))%)"
            }
        }
    } catch {}
    
    # 内存检查
    $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    $freeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
    $memoryPercent = ($totalMemory - $freeMemory) / $totalMemory * 100
    if ($memoryPercent -gt 90) {
        $alerts += "警告: 内存使用率过高 ($([math]::Round($memoryPercent, 2))%)"
    }
    
    # 磁盘检查
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null}
    foreach ($drive in $drives) {
        $usedPercent = ($drive.Used / ($drive.Used + $drive.Free)) * 100
        if ($usedPercent -gt 90) {
            $alerts += "警告: $($drive.Name)盘空间不足 ($([math]::Round($usedPercent, 2))%)"
        }
    }
    
    if ($alerts.Count -gt 0) {
        $results += "发现 $($alerts.Count) 个警报:"
        foreach ($alert in $alerts) {
            $results += "  - $alert"
        }
    } else {
        $results += "系统资源正常，未发现警报"
    }
    
    $results | Out-File -FilePath $alertFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统资源警报已保存到: $alertFile" -ForegroundColor Green
}

# ============================================
# 软件管理功能
# ============================================

# 51. 软件卸载
function Uninstall-Software {
    Write-Host "`n========== 软件卸载 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $uninstallFile = Join-Path $desktop "software_uninstall.txt"
    
    $results = @()
    $results += "========== 可卸载软件列表 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $programs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
            Where-Object {$_.DisplayName} | 
            Select-Object DisplayName, DisplayVersion, Publisher, UninstallString | 
            Sort-Object DisplayName
        
        $results += "已安装程序总数: $($programs.Count)"
        $results += "`n程序列表（前50个）:"
        $programs | Select-Object -First 50 | ForEach-Object {
            $results += "  - $($_.DisplayName) $($_.DisplayVersion)"
            if ($_.UninstallString) {
                $results += "    卸载命令: $($_.UninstallString)"
            }
        }
        
        $results += "`n提示: 使用 'Get-Package | Uninstall-Package' 或控制面板卸载程序"
    } catch {
        $results += "无法获取软件列表: $_"
    }
    
    $results | Out-File -FilePath $uninstallFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n软件卸载信息已保存到: $uninstallFile" -ForegroundColor Green
}

# 52. 软件更新检查
function Check-SoftwareUpdates {
    Write-Host "`n========== 软件更新检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $updateFile = Join-Path $desktop "software_updates.txt"
    
    $results = @()
    $results += "========== 软件更新检查 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # Windows更新
    $results += "Windows更新:"
    try {
        $winUpdates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
        $results += "最近安装的更新:"
        foreach ($update in $winUpdates) {
            $results += "  - $($update.HotFixID) - $($update.InstalledOn)"
        }
    } catch {
        $results += "无法检查Windows更新"
    }
    
    $results += "`n提示: 使用Windows Update检查系统更新"
    $results += "提示: 各软件请使用其自带的更新功能"
    
    $results | Out-File -FilePath $updateFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n软件更新信息已保存到: $updateFile" -ForegroundColor Green
}

# 53. 重复文件查找
function Find-DuplicateFiles {
    Write-Host "`n========== 重复文件查找 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $duplicateFile = Join-Path $desktop "duplicate_files.txt"
    $searchDir = Join-Path $desktop "DuplicateSearch"
    
    if (-not (Test-Path $searchDir)) {
        New-Item -ItemType Directory -Path $searchDir -Force | Out-Null
    }
    
    $results = @()
    $results += "========== 重复文件查找 =========="
    $results += "搜索时间: $(Get-Date)"
    $results += "`n"
    
    # 在指定目录查找重复文件（示例：桌面）
    try {
        $files = Get-ChildItem -Path $desktop -File -ErrorAction SilentlyContinue | 
            Where-Object {$_.Length -gt 0}
        
        # 按文件大小和名称分组
        $duplicates = $files | Group-Object Length | 
            Where-Object {$_.Count -gt 1} |
            Select-Object -First 10
        
        if ($duplicates) {
            $results += "发现可能的重复文件组:"
            foreach ($group in $duplicates) {
                $results += "`n大小: $([math]::Round($group.Name / 1KB, 2)) KB - $($group.Count) 个文件"
                foreach ($file in $group.Group) {
                    $results += "  - $($file.Name)"
                }
            }
        } else {
            $results += "未发现明显的重复文件"
        }
        
        $results += "`n提示: 完整重复文件检测需要计算文件哈希值"
    } catch {
        $results += "查找重复文件失败: $_"
    }
    
    $results | Out-File -FilePath $duplicateFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n重复文件查找结果已保存到: $duplicateFile" -ForegroundColor Green
}

# 54. 大文件查找
function Find-LargeFiles {
    Write-Host "`n========== 大文件查找 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $largeFile = Join-Path $desktop "large_files.txt"
    
    $results = @()
    $results += "========== 大文件查找 =========="
    $results += "搜索时间: $(Get-Date)"
    $results += "`n"
    
    # 查找大于100MB的文件
    $minSize = 100MB
    $searchPaths = @("C:\Users\$env:USERNAME\Downloads", "C:\Users\$env:USERNAME\Documents")
    
    $largeFiles = @()
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object {$_.Length -gt $minSize} | 
                    Sort-Object Length -Descending | 
                    Select-Object -First 20
                
                if ($files) {
                    $results += "路径: $path"
                    foreach ($file in $files) {
                        $results += "  $($file.Name) - $([math]::Round($file.Length / 1MB, 2)) MB"
                        $largeFiles += $file
                    }
                    $results += ""
                }
            } catch {
                $results += "搜索 $path 失败: $_"
            }
        }
    }
    
    if ($largeFiles.Count -eq 0) {
        $results += "未找到大于 $([math]::Round($minSize / 1MB, 2)) MB 的文件"
    }
    
    $results | Out-File -FilePath $largeFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n大文件查找结果已保存到: $largeFile" -ForegroundColor Green
}

# ============================================
# 系统修复功能
# ============================================

# 55. 系统文件检查
function Check-SystemFiles {
    Write-Host "`n========== 系统文件检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $sfcFile = Join-Path $desktop "system_file_check.txt"
    
    $results = @()
    $results += "========== 系统文件检查 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    $results += "系统文件检查器 (SFC):"
    $results += "命令: sfc /scannow"
    $results += "状态: 需要管理员权限运行"
    $results += "`n提示: 以管理员身份运行 'sfc /scannow' 检查系统文件完整性"
    $results += "提示: 检查结果会显示在命令窗口中"
    
    # 检查是否有已知的系统文件问题
    $results += "`n已知系统文件位置检查:"
    $systemFiles = @(
        "$env:SystemRoot\System32\kernel32.dll",
        "$env:SystemRoot\System32\ntdll.dll",
        "$env:SystemRoot\System32\user32.dll"
    )
    
    foreach ($file in $systemFiles) {
        if (Test-Path $file) {
            $results += "  ✓ $file 存在"
        } else {
            $results += "  ✗ $file 缺失"
        }
    }
    
    $results | Out-File -FilePath $sfcFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统文件检查信息已保存到: $sfcFile" -ForegroundColor Green
}

# 56. DISM修复
function Repair-DISM {
    Write-Host "`n========== DISM修复 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $dismFile = Join-Path $desktop "dism_repair.txt"
    
    $results = @()
    $results += "========== DISM修复工具 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    $results += "DISM (部署映像服务和管理):"
    $results += "`n常用DISM命令:"
    $results += "1. DISM /Online /Cleanup-Image /CheckHealth - 检查映像健康状态"
    $results += "2. DISM /Online /Cleanup-Image /ScanHealth - 扫描映像完整性"
    $results += "3. DISM /Online /Cleanup-Image /RestoreHealth - 修复映像"
    $results += "`n提示: 需要管理员权限运行"
    $results += "提示: 修复过程可能需要较长时间"
    
    $results | Out-File -FilePath $dismFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nDISM修复信息已保存到: $dismFile" -ForegroundColor Green
}

# 57. 网络重置
function Reset-Network {
    Write-Host "`n========== 网络重置 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $networkResetFile = Join-Path $desktop "network_reset.txt"
    
    $results = @()
    $results += "========== 网络重置工具 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    $results += "网络重置命令:"
    $results += "`n1. 重置TCP/IP栈:"
    $results += "   netsh int ip reset"
    $results += "`n2. 重置Winsock:"
    $results += "   netsh winsock reset"
    $results += "`n3. 刷新DNS缓存:"
    $results += "   ipconfig /flushdns"
    $results += "`n4. 释放和续订IP:"
    $results += "   ipconfig /release"
    $results += "   ipconfig /renew"
    $results += "`n提示: 需要管理员权限"
    $results += "提示: 重置后可能需要重启计算机"
    
    # 当前网络状态
    $results += "`n当前网络配置:"
    try {
        $ipConfig = Get-NetIPConfiguration
        foreach ($config in $ipConfig) {
            $results += "  接口: $($config.InterfaceAlias)"
            $results += "  IP地址: $($config.IPv4Address.IPAddress)"
            $results += ""
        }
    } catch {
        $results += "无法获取网络配置"
    }
    
    $results | Out-File -FilePath $networkResetFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n网络重置信息已保存到: $networkResetFile" -ForegroundColor Green
}

# 58. Windows更新修复
function Repair-WindowsUpdate {
    Write-Host "`n========== Windows更新修复 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $updateRepairFile = Join-Path $desktop "windows_update_repair.txt"
    
    $results = @()
    $results += "========== Windows更新修复 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    $results += "Windows更新修复步骤:"
    $results += "`n1. 停止Windows Update服务:"
    $results += "   net stop wuauserv"
    $results += "   net stop cryptSvc"
    $results += "   net stop bits"
    $results += "   net stop msiserver"
    $results += "`n2. 重命名SoftwareDistribution文件夹:"
    $results += "   ren C:\Windows\SoftwareDistribution SoftwareDistribution.old"
    $results += "`n3. 重命名Catroot2文件夹:"
    $results += "   ren C:\Windows\System32\catroot2 catroot2.old"
    $results += "`n4. 重新启动服务:"
    $results += "   net start wuauserv"
    $results += "   net start cryptSvc"
    $results += "   net start bits"
    $results += "   net start msiserver"
    $results += "`n提示: 需要管理员权限"
    $results += "提示: 执行前请备份重要数据"
    
    # 检查更新服务状态
    $results += "`n更新服务状态:"
    try {
        $wuauserv = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuauserv) {
            $results += "  Windows Update服务: $($wuauserv.Status)"
        }
    } catch {
        $results += "  无法检查服务状态"
    }
    
    $results | Out-File -FilePath $updateRepairFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nWindows更新修复信息已保存到: $updateRepairFile" -ForegroundColor Green
}

# ============================================
# 密码管理功能
# ============================================

# 59. 密码强度检查
function Check-PasswordPolicy {
    Write-Host "`n========== 密码强度检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $passwordFile = Join-Path $desktop "password_policy.txt"
    
    $results = @()
    $results += "========== 密码策略检查 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $policy = Get-LocalUser | Where-Object {$_.Name -eq $env:USERNAME} -ErrorAction SilentlyContinue
        if ($policy) {
            $results += "当前用户: $($policy.Name)"
            $results += "密码过期: $($policy.PasswordExpires)"
            $results += "密码可更改: $($policy.PasswordChangeable)"
        }
        
        # 检查本地安全策略
        $results += "`n密码策略（需要管理员权限）:"
        $results += "提示: 使用 'secpol.msc' 查看本地安全策略"
        $results += "提示: 使用 'net accounts' 查看账户策略"
        
        # 尝试获取策略
        try {
            $netAccounts = net accounts 2>&1
            $results += "`n账户策略:"
            $results += ($netAccounts | Out-String)
        } catch {
            $results += "无法获取账户策略（可能需要管理员权限）"
        }
    } catch {
        $results += "无法检查密码策略: $_"
    }
    
    $results | Out-File -FilePath $passwordFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n密码策略信息已保存到: $passwordFile" -ForegroundColor Green
}

# 60. 密码过期提醒
function Get-PasswordExpiration {
    Write-Host "`n========== 密码过期提醒 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $expirationFile = Join-Path $desktop "password_expiration.txt"
    
    $results = @()
    $results += "========== 密码过期信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $user = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
        if ($user) {
            $results += "用户名: $($user.Name)"
            $results += "密码过期时间: $($user.PasswordExpires)"
            
            if ($user.PasswordExpires) {
                $expirationDate = $user.PasswordExpires
                $daysUntilExpiry = ($expirationDate - (Get-Date)).Days
                
                if ($daysUntilExpiry -gt 0) {
                    $results += "距离过期还有: $daysUntilExpiry 天"
                    if ($daysUntilExpiry -lt 7) {
                        $results += "警告: 密码即将过期，请及时更改"
                    }
                } elseif ($daysUntilExpiry -eq 0) {
                    $results += "警告: 密码今天过期"
                } else {
                    $results += "警告: 密码已过期"
                }
            } else {
                $results += "密码永不过期"
            }
        }
    } catch {
        $results += "无法检查密码过期信息: $_"
    }
    
    $results | Out-File -FilePath $expirationFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n密码过期信息已保存到: $expirationFile" -ForegroundColor Green
}

# 61. 密码生成器
function New-PasswordGenerator {
    Write-Host "`n========== 密码生成器 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $passwordGenFile = Join-Path $desktop "password_generator.txt"
    
    $results = @()
    $results += "========== 生成的密码 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    function Generate-Password {
        param([int]$Length = 16)
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        $password = ""
        for ($i = 0; $i -lt $Length; $i++) {
            $password += $chars[(Get-Random -Maximum $chars.Length)]
        }
        return $password
    }
    
    $results += "生成的强密码（16位）:"
    for ($i = 1; $i -le 5; $i++) {
        $pwd = Generate-Password -Length 16
        $results += "$i. $pwd"
        Write-Host "密码 $i : $pwd" -ForegroundColor Cyan
    }
    
    $results += "`n提示: 请妥善保管生成的密码"
    $results += "提示: 建议使用密码管理器存储密码"
    
    $results | Out-File -FilePath $passwordGenFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n密码生成信息已保存到: $passwordGenFile" -ForegroundColor Green
}

# 62. 密码管理器集成
function Get-PasswordManagerInfo {
    Write-Host "`n========== 密码管理器信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $pwdMgrFile = Join-Path $desktop "password_manager.txt"
    
    $results = @()
    $results += "========== 密码管理器信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查常见的密码管理器
    $passwordManagers = @(
        @{Name="1Password"; Path="$env:LOCALAPPDATA\1Password"},
        @{Name="LastPass"; Path="$env:APPDATA\LastPass"},
        @{Name="Bitwarden"; Path="$env:APPDATA\Bitwarden"},
        @{Name="KeePass"; Path="$env:APPDATA\KeePass"}
    )
    
    $results += "已安装的密码管理器:"
    $found = $false
    foreach ($pwdMgr in $passwordManagers) {
        if (Test-Path $pwdMgr.Path) {
            $results += "  ✓ $($pwdMgr.Name) - 已安装"
            $found = $true
        }
    }
    
    if (-not $found) {
        $results += "  未检测到常见的密码管理器"
    }
    
    $results += "`n推荐的密码管理器:"
    $results += "  - 1Password"
    $results += "  - LastPass"
    $results += "  - Bitwarden"
    $results += "  - KeePass"
    $results += "  - Windows Hello (Windows内置)"
    
    $results | Out-File -FilePath $pwdMgrFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n密码管理器信息已保存到: $pwdMgrFile" -ForegroundColor Green
}

# ============================================
# 远程管理功能
# ============================================

# 63. 远程桌面配置
function Get-RemoteDesktopConfig {
    Write-Host "`n========== 远程桌面配置 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $rdpFile = Join-Path $desktop "remote_desktop_config.txt"
    
    $results = @()
    $results += "========== 远程桌面配置 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $rdpEnabled = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
        if ($rdpEnabled) {
            $results += "远程桌面状态: $($rdpEnabled.fDenyTSConnections)"
            if ($rdpEnabled.fDenyTSConnections -eq 0) {
                $results += "远程桌面: 已启用"
            } else {
                $results += "远程桌面: 已禁用"
            }
        } else {
            $results += "无法读取远程桌面配置（可能需要管理员权限）"
        }
    } catch {
        $results += "检查远程桌面配置失败: $_"
    }
    
    $results += "`n提示: 可以在 系统属性 > 远程 中配置远程桌面"
    $results += "提示: 使用 'mstsc' 命令打开远程桌面连接"
    
    $results | Out-File -FilePath $rdpFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n远程桌面配置信息已保存到: $rdpFile" -ForegroundColor Green
}

# 64. SSH配置
function Get-SSHConfig {
    Write-Host "`n========== SSH配置 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $sshFile = Join-Path $desktop "ssh_config.txt"
    
    $results = @()
    $results += "========== SSH配置信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查OpenSSH
    $sshPaths = @(
        "$env:ProgramFiles\OpenSSH",
        "$env:ProgramFiles(x86)\OpenSSH",
        "$env:USERPROFILE\.ssh"
    )
    
    $results += "SSH相关路径:"
    foreach ($path in $sshPaths) {
        if (Test-Path $path) {
            $results += "  ✓ $path 存在"
        }
    }
    
    # 检查SSH服务
    try {
        $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($sshService) {
            $results += "`nSSH服务状态: $($sshService.Status)"
        } else {
            $results += "`nSSH服务: 未安装或未运行"
        }
    } catch {
        $results += "`n无法检查SSH服务"
    }
    
    # SSH配置文件
    $sshConfigPath = "$env:USERPROFILE\.ssh\config"
    if (Test-Path $sshConfigPath) {
        $results += "`nSSH配置文件存在: $sshConfigPath"
        try {
            $configContent = Get-Content $sshConfigPath -ErrorAction SilentlyContinue
            $results += "配置文件内容:"
            $results += ($configContent | Out-String)
        } catch {
            $results += "无法读取配置文件"
        }
    }
    
    $results | Out-File -FilePath $sshFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nSSH配置信息已保存到: $sshFile" -ForegroundColor Green
}

# 65. VPN连接管理
function Get-VPNConnections {
    Write-Host "`n========== VPN连接管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $vpnFile = Join-Path $desktop "vpn_connections.txt"
    
    $results = @()
    $results += "========== VPN连接信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
        if ($vpnConnections) {
            $results += "VPN连接数: $($vpnConnections.Count)"
            foreach ($vpn in $vpnConnections) {
                $results += "`n连接名称: $($vpn.Name)"
                $results += "  服务器地址: $($vpn.ServerAddress)"
                $results += "  连接状态: $($vpn.ConnectionStatus)"
                $results += "  隧道类型: $($vpn.TunnelType)"
            }
        } else {
            $results += "未找到VPN连接"
        }
    } catch {
        $results += "无法获取VPN连接信息: $_"
    }
    
    $results += "`n提示: 可以在 设置 > 网络和Internet > VPN 中管理VPN连接"
    
    $results | Out-File -FilePath $vpnFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nVPN连接信息已保存到: $vpnFile" -ForegroundColor Green
}

# 66. 远程文件访问
function Get-RemoteFileAccess {
    Write-Host "`n========== 远程文件访问 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $remoteFile = Join-Path $desktop "remote_file_access.txt"
    
    $results = @()
    $results += "========== 远程文件访问 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查网络共享
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        if ($shares) {
            $results += "本地共享文件夹:"
            foreach ($share in $shares) {
                $results += "  - $($share.Name) - 路径: $($share.Path)"
            }
        }
    } catch {
        $results += "无法获取共享文件夹（可能需要管理员权限）"
    }
    
    # 检查映射的网络驱动器
    $results += "`n映射的网络驱动器:"
    try {
        $mappedDrives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DisplayRoot -like "\\*"}
        if ($mappedDrives) {
            foreach ($drive in $mappedDrives) {
                $results += "  $($drive.Name): -> $($drive.DisplayRoot)"
            }
        } else {
            $results += "  未找到映射的网络驱动器"
        }
    } catch {
        $results += "无法检查映射驱动器"
    }
    
    $results += "`n提示: 使用 'net use' 查看网络连接"
    $results += "提示: 使用 'net share' 查看共享资源"
    
    $results | Out-File -FilePath $remoteFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n远程文件访问信息已保存到: $remoteFile" -ForegroundColor Green
}

# ============================================
# 日志分析功能
# ============================================

# 67. 日志聚合
function Aggregate-Logs {
    Write-Host "`n========== 日志聚合 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $logAggFile = Join-Path $desktop "log_aggregation.txt"
    
    $results = @()
    $results += "========== 日志聚合报告 =========="
    $results += "聚合时间: $(Get-Date)"
    $results += "`n"
    
    # 聚合系统日志
    $results += "========== 系统日志汇总 =========="
    try {
        $systemLogs = Get-EventLog -LogName System -Newest 20 -ErrorAction SilentlyContinue
        $results += "系统日志条目数: $($systemLogs.Count)"
        $logSummary = $systemLogs | Group-Object EntryType | Select-Object Name, Count
        $results += ($logSummary | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法聚合系统日志: $_"
    }
    
    # 聚合应用程序日志
    $results += "`n========== 应用程序日志汇总 =========="
    try {
        $appLogs = Get-EventLog -LogName Application -Newest 20 -ErrorAction SilentlyContinue
        $results += "应用程序日志条目数: $($appLogs.Count)"
        $appSummary = $appLogs | Group-Object EntryType | Select-Object Name, Count
        $results += ($appSummary | Format-Table -AutoSize | Out-String)
    } catch {
        $results += "无法聚合应用程序日志: $_"
    }
    
    $results | Out-File -FilePath $logAggFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n日志聚合报告已保存到: $logAggFile" -ForegroundColor Green
}

# 68. 日志搜索
function Search-Logs {
    Write-Host "`n========== 日志搜索 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $logSearchFile = Join-Path $desktop "log_search.txt"
    
    $results = @()
    $results += "========== 日志搜索结果 =========="
    $results += "搜索时间: $(Get-Date)"
    $results += "`n"
    
    # 搜索关键词
    $searchTerms = @("错误", "Error", "失败", "Failed", "警告", "Warning")
    
    $results += "搜索关键词: $($searchTerms -join ', ')"
    $results += "`n系统日志搜索结果:"
    
    foreach ($term in $searchTerms) {
        try {
            $matches = Get-EventLog -LogName System -Newest 100 -ErrorAction SilentlyContinue | 
                Where-Object {$_.Message -like "*$term*"}
            
            if ($matches) {
                $results += "`n'$term' 找到 $($matches.Count) 条记录:"
                $matches | Select-Object -First 5 | ForEach-Object {
                    $results += "  - $($_.TimeGenerated): $($_.Source)"
                }
            }
        } catch {
            # 忽略错误
        }
    }
    
    $results | Out-File -FilePath $logSearchFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n日志搜索结果已保存到: $logSearchFile" -ForegroundColor Green
}

# 69. 日志导出
function Export-Logs {
    Write-Host "`n========== 日志导出 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $logExportDir = Join-Path $desktop "LogExports"
    $logExportFile = Join-Path $desktop "log_export.txt"
    
    if (-not (Test-Path $logExportDir)) {
        New-Item -ItemType Directory -Path $logExportDir -Force | Out-Null
    }
    
    $results = @()
    $results += "========== 日志导出报告 =========="
    $results += "导出时间: $(Get-Date)"
    $results += "`n"
    
    # 导出系统日志
    try {
        $systemLogs = Get-EventLog -LogName System -Newest 50 -ErrorAction SilentlyContinue
        $exportPath = Join-Path $logExportDir "system_logs.csv"
        $systemLogs | Select-Object TimeGenerated, EntryType, Source, Message | 
            Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
        $results += "已导出系统日志: $exportPath ($($systemLogs.Count) 条)"
    } catch {
        $results += "导出系统日志失败: $_"
    }
    
    # 导出应用程序日志
    try {
        $appLogs = Get-EventLog -LogName Application -Newest 50 -ErrorAction SilentlyContinue
        $exportPath = Join-Path $logExportDir "application_logs.csv"
        $appLogs | Select-Object TimeGenerated, EntryType, Source, Message | 
            Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
        $results += "已导出应用程序日志: $exportPath ($($appLogs.Count) 条)"
    } catch {
        $results += "导出应用程序日志失败: $_"
    }
    
    $results += "`n导出位置: $logExportDir"
    
    $results | Out-File -FilePath $logExportFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n日志导出信息已保存到: $logExportFile" -ForegroundColor Green
}

# 70. 异常模式识别
function Find-LogAnomalies {
    Write-Host "`n========== 异常模式识别 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $anomalyFile = Join-Path $desktop "log_anomalies.txt"
    
    $results = @()
    $results += "========== 日志异常模式识别 =========="
    $results += "分析时间: $(Get-Date)"
    $results += "`n"
    
    # 识别频繁出现的错误
    try {
        $recentErrors = Get-EventLog -LogName System -EntryType Error -Newest 100 -ErrorAction SilentlyContinue
        $errorPatterns = $recentErrors | Group-Object Source | 
            Sort-Object Count -Descending | 
            Select-Object -First 10
        
        if ($errorPatterns) {
            $results += "频繁出现的错误源:"
            foreach ($pattern in $errorPatterns) {
                $results += "  - $($pattern.Name): $($pattern.Count) 次"
            }
        }
    } catch {
        $results += "无法分析错误模式: $_"
    }
    
    # 识别异常时间模式
    $results += "`n异常时间分析:"
    try {
        $recentLogs = Get-EventLog -LogName System -Newest 200 -ErrorAction SilentlyContinue
        $hourlyPattern = $recentLogs | Group-Object {$_.TimeGenerated.Hour} | 
            Sort-Object Count -Descending | 
            Select-Object -First 5
        
        $results += "错误最频繁的小时:"
        foreach ($pattern in $hourlyPattern) {
            $results += "  - $($pattern.Name)时: $($pattern.Count) 次"
        }
    } catch {
        $results += "无法分析时间模式"
    }
    
    $results | Out-File -FilePath $anomalyFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n异常模式识别结果已保存到: $anomalyFile" -ForegroundColor Green
}

# ============================================
# 自动化功能
# ============================================

# 71. 定时任务创建
function New-ScheduledTaskExample {
    Write-Host "`n========== 定时任务创建示例 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $taskFile = Join-Path $desktop "scheduled_task_example.txt"
    
    $results = @()
    $results += "========== 定时任务创建示例 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    $results += "创建定时任务的PowerShell命令示例:"
    $results += "`n1. 每天运行:"
    $results += "`$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-File C:\Scripts\script.ps1'"
    $results += "`$trigger = New-ScheduledTaskTrigger -Daily -At 9am"
    $results += "Register-ScheduledTask -TaskName 'MyTask' -Action `$action -Trigger `$trigger"
    
    $results += "`n2. 每周运行:"
    $results += "`$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 8am"
    
    $results += "`n3. 开机运行:"
    $results += "`$trigger = New-ScheduledTaskTrigger -AtStartup"
    
    $results += "`n提示: 需要管理员权限创建系统级任务"
    $results += "提示: 使用 Get-ScheduledTask 查看现有任务"
    
    $results | Out-File -FilePath $taskFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n定时任务示例已保存到: $taskFile" -ForegroundColor Green
}

# 72. 自动化脚本生成
function New-AutomationScript {
    Write-Host "`n========== 自动化脚本生成 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $autoScriptDir = Join-Path $desktop "AutomationScripts"
    $autoFile = Join-Path $desktop "automation_script_generator.txt"
    
    if (-not (Test-Path $autoScriptDir)) {
        New-Item -ItemType Directory -Path $autoScriptDir -Force | Out-Null
    }
    
    $results = @()
    $results += "========== 自动化脚本生成 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    # 生成示例自动化脚本
    $scriptContent = @"
# 自动化脚本示例
# 生成时间: $(Get-Date)

# 清理临时文件
Write-Host "清理临时文件..."
Get-ChildItem `$env:TEMP -Recurse -File | Remove-Item -Force -ErrorAction SilentlyContinue

# 系统信息收集
Write-Host "收集系统信息..."
Get-SystemInfo

# 网络检查
Write-Host "检查网络连接..."
Test-Connection -ComputerName "hackerchi.top" -Count 2
"@
    
    $scriptPath = Join-Path $autoScriptDir "example_automation.ps1"
    $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    $results += "已生成示例自动化脚本: $scriptPath"
    
    $results += "`n脚本内容:"
    $results += $scriptContent
    
    $results | Out-File -FilePath $autoFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n自动化脚本生成信息已保存到: $autoFile" -ForegroundColor Green
}

# 73. 批处理工具
function Invoke-BatchProcessing {
    Write-Host "`n========== 批处理工具 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $batchFile = Join-Path $desktop "batch_processing.txt"
    
    $results = @()
    $results += "========== 批处理工具 =========="
    $results += "处理时间: $(Get-Date)"
    $results += "`n"
    
    # 批处理示例：批量重命名
    $results += "批处理示例 - 批量重命名文件:"
    $results += "`$files = Get-ChildItem -Path 'C:\Path' -Filter '*.txt'"
    $results += "foreach (`$file in `$files) {"
    $results += "    Rename-Item -Path `$file.FullName -NewName (`$file.Name -replace 'old', 'new')"
    $results += "}"
    
    $results += "`n批处理示例 - 批量转换文件:"
    $results += "Get-ChildItem -Path 'C:\Path' -Filter '*.txt' | ForEach-Object {"
    $results += "    `$content = Get-Content `$_.FullName"
    $results += "    `$content | Set-Content (`$_.FullName -replace '.txt', '.bak')"
    $results += "}"
    
    $results | Out-File -FilePath $batchFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n批处理工具信息已保存到: $batchFile" -ForegroundColor Green
}

# 74. 工作流管理
function Get-WorkflowInfo {
    Write-Host "`n========== 工作流管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $workflowFile = Join-Path $desktop "workflow_management.txt"
    
    $results = @()
    $results += "========== 工作流管理 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查PowerShell工作流
    $results += "PowerShell工作流:"
    $results += "PowerShell工作流允许创建长时间运行的任务和并行执行"
    $results += "`n工作流示例:"
    $results += "workflow MyWorkflow {"
    $results += "    parallel {"
    $results += "        Get-Process"
    $results += "        Get-Service"
    $results += "    }"
    $results += "}"
    
    $results += "`n提示: 工作流功能在PowerShell 5.1中可用"
    $results += "提示: 可以使用计划任务管理工作流"
    
    $results | Out-File -FilePath $workflowFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n工作流管理信息已保存到: $workflowFile" -ForegroundColor Green
}

# ============================================
# 系统信息增强
# ============================================

# 75. 系统健康报告
function Get-SystemHealthReport {
    Write-Host "`n========== 系统健康报告 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $healthFile = Join-Path $desktop "system_health_report.txt"
    
    $results = @()
    $results += "========== 系统健康报告 =========="
    $results += "生成时间: $(Get-Date)"
    $results += "`n"
    
    $healthScore = 100
    $issues = @()
    
    # CPU健康
    try {
        $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue
        if ($cpu) {
            $cpuValue = $cpu.CounterSamples[0].CookedValue
            if ($cpuValue -gt 90) {
                $healthScore -= 10
                $issues += "CPU使用率过高"
            }
        }
    } catch {}
    
    # 内存健康
    $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
    $freeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
    $memoryPercent = (($totalMemory - $freeMemory) / $totalMemory) * 100
    if ($memoryPercent -gt 90) {
        $healthScore -= 10
        $issues += "内存使用率过高"
    }
    
    # 磁盘健康
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne $null}
    foreach ($drive in $drives) {
        $usedPercent = ($drive.Used / ($drive.Used + $drive.Free)) * 100
        if ($usedPercent -gt 90) {
            $healthScore -= 5
            $issues += "$($drive.Name)盘空间不足"
        }
    }
    
    # 服务健康
    $stoppedServices = (Get-Service | Where-Object {$_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic'}).Count
    if ($stoppedServices -gt 0) {
        $healthScore -= 5
        $issues += "$stoppedServices 个自动启动服务未运行"
    }
    
    $results += "系统健康评分: $healthScore/100"
    if ($healthScore -ge 90) {
        $results += "状态: 优秀"
    } elseif ($healthScore -ge 70) {
        $results += "状态: 良好"
    } elseif ($healthScore -ge 50) {
        $results += "状态: 一般"
    } else {
        $results += "状态: 需要关注"
    }
    
    if ($issues.Count -gt 0) {
        $results += "`n发现的问题:"
        foreach ($issue in $issues) {
            $results += "  - $issue"
        }
    }
    
    $results | Out-File -FilePath $healthFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统健康报告已保存到: $healthFile" -ForegroundColor Green
}

# 76. 硬件兼容性检查
function Check-HardwareCompatibility {
    Write-Host "`n========== 硬件兼容性检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $compatFile = Join-Path $desktop "hardware_compatibility.txt"
    
    $results = @()
    $results += "========== 硬件兼容性检查 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查硬件驱动
    $results += "硬件驱动状态:"
    try {
        $devices = Get-PnpDevice | Where-Object {$_.Status -ne 'OK'} | Select-Object -First 10
        if ($devices) {
            $results += "发现 $($devices.Count) 个设备问题:"
            foreach ($device in $devices) {
                $results += "  - $($device.FriendlyName): $($device.Status)"
            }
        } else {
            $results += "所有设备状态正常"
        }
    } catch {
        $results += "无法检查设备状态"
    }
    
    # 检查Windows版本兼容性
    $results += "`nWindows版本:"
    $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    $results += "  版本: $osVersion"
    $results += "  提示: 检查硬件制造商网站了解兼容性信息"
    
    $results | Out-File -FilePath $compatFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n硬件兼容性信息已保存到: $compatFile" -ForegroundColor Green
}

# 77. 驱动更新检查
function Check-DriverUpdates {
    Write-Host "`n========== 驱动更新检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $driverFile = Join-Path $desktop "driver_updates.txt"
    
    $results = @()
    $results += "========== 驱动更新检查 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查驱动版本
    $results += "主要硬件驱动:"
    try {
        $drivers = Get-WmiObject Win32_PnPEntity | 
            Where-Object {$_.Name -like "*显卡*" -or $_.Name -like "*Audio*" -or $_.Name -like "*Network*"} |
            Select-Object -First 10 Name, DeviceID
        
        foreach ($driver in $drivers) {
            $results += "  - $($driver.Name)"
        }
    } catch {
        $results += "无法获取驱动信息"
    }
    
    $results += "`n提示: 使用设备管理器检查驱动更新"
    $results += "提示: 访问硬件制造商网站获取最新驱动"
    $results += "提示: Windows Update也会提供驱动更新"
    
    $results | Out-File -FilePath $driverFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n驱动更新信息已保存到: $driverFile" -ForegroundColor Green
}

# 78. BIOS/UEFI信息
function Get-BIOSInfo {
    Write-Host "`n========== BIOS/UEFI信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $biosFile = Join-Path $desktop "bios_info.txt"
    
    $results = @()
    $results += "========== BIOS/UEFI信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    try {
        $bios = Get-CimInstance Win32_BIOS
        $results += "BIOS信息:"
        $results += "  制造商: $($bios.Manufacturer)"
        $results += "  版本: $($bios.Version)"
        $results += "  发布日期: $($bios.ReleaseDate)"
        $results += "  SMBIOS版本: $($bios.SMBIOSBIOSVersion)"
        
        # 检查UEFI
        $results += "`n固件类型:"
        $firmwareType = (Get-CimInstance Win32_ComputerSystem).BootupState
        $results += "  启动状态: $firmwareType"
        
        # 检查安全启动
        try {
            $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($secureBoot) {
                $results += "  安全启动: 已启用"
            } else {
                $results += "  安全启动: 未启用"
            }
        } catch {
            $results += "  安全启动: 无法检测（可能不是UEFI）"
        }
    } catch {
        $results += "无法获取BIOS信息: $_"
    }
    
    $results | Out-File -FilePath $biosFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nBIOS/UEFI信息已保存到: $biosFile" -ForegroundColor Green
}

# ============================================
# 安全增强功能
# ============================================

# 79. 文件完整性检查
function Test-FileIntegrity {
    Write-Host "`n========== 文件完整性检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $integrityFile = Join-Path $desktop "file_integrity_check.txt"
    
    $results = @()
    $results += "========== 文件完整性检查 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查系统关键文件
    $criticalFiles = @(
        "$env:SystemRoot\System32\kernel32.dll",
        "$env:SystemRoot\System32\ntdll.dll",
        "$env:SystemRoot\System32\user32.dll"
    )
    
    $results += "系统关键文件完整性:"
    foreach ($file in $criticalFiles) {
        if (Test-Path $file) {
            try {
                $hash = Get-FileHash -Path $file -Algorithm SHA256
                $results += "  ✓ $file"
                $results += "    哈希值: $($hash.Hash)"
            } catch {
                $results += "  ✗ $file - 无法计算哈希"
            }
        } else {
            $results += "  ✗ $file - 文件不存在"
        }
    }
    
    $results += "`n提示: 使用文件哈希值可以验证文件完整性"
    $results += "提示: 文件被修改后哈希值会改变"
    
    $results | Out-File -FilePath $integrityFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n文件完整性检查已保存到: $integrityFile" -ForegroundColor Green
}

# 80. 数字签名验证
function Test-DigitalSignature {
    Write-Host "`n========== 数字签名验证 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $signatureFile = Join-Path $desktop "digital_signature_verification.txt"
    
    $results = @()
    $results += "========== 数字签名验证 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查系统文件的数字签名
    $systemFiles = @(
        "$env:SystemRoot\System32\kernel32.dll",
        "$env:SystemRoot\System32\cmd.exe",
        "$env:SystemRoot\System32\powershell.exe"
    )
    
    $results += "系统文件数字签名验证:"
    foreach ($file in $systemFiles) {
        if (Test-Path $file) {
            try {
                $signature = Get-AuthenticodeSignature -FilePath $file
                $results += "`n文件: $file"
                $results += "  状态: $($signature.Status)"
                $results += "  签名者: $($signature.SignerCertificate.Subject)"
            } catch {
                $results += "`n文件: $file - 无法验证签名"
            }
        }
    }
    
    $results += "`n提示: 使用 Get-AuthenticodeSignature 验证文件签名"
    $results += "提示: Valid状态表示签名有效"
    
    $results | Out-File -FilePath $signatureFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n数字签名验证信息已保存到: $signatureFile" -ForegroundColor Green
}

# 81. 证书管理
function Get-CertificateInfo {
    Write-Host "`n========== 证书管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $certFile = Join-Path $desktop "certificate_management.txt"
    
    $results = @()
    $results += "========== 证书管理 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 获取用户证书
    try {
        $userCerts = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue
        if ($userCerts) {
            $results += "用户证书数量: $($userCerts.Count)"
            $results += "`n用户证书列表:"
            foreach ($cert in $userCerts | Select-Object -First 10) {
                $results += "  - $($cert.Subject)"
                $results += "    有效期至: $($cert.NotAfter)"
            }
        }
    } catch {
        $results += "无法获取用户证书"
    }
    
    # 获取计算机证书
    try {
        $computerCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
        if ($computerCerts) {
            $results += "`n计算机证书数量: $($computerCerts.Count)"
        }
    } catch {
        $results += "无法获取计算机证书（可能需要管理员权限）"
    }
    
    $results += "`n提示: 使用 certmgr.msc 管理证书"
    $results += "提示: 使用 Get-ChildItem Cert:\ 查看所有证书存储"
    
    $results | Out-File -FilePath $certFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n证书管理信息已保存到: $certFile" -ForegroundColor Green
}

# 82. 安全策略检查
function Check-SecurityPolicy {
    Write-Host "`n========== 安全策略检查 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $policyFile = Join-Path $desktop "security_policy.txt"
    
    $results = @()
    $results += "========== 安全策略检查 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查密码策略
    try {
        $netAccounts = net accounts 2>&1
        $results += "账户策略:"
        $results += ($netAccounts | Out-String)
    } catch {
        $results += "无法获取账户策略（可能需要管理员权限）"
    }
    
    # 检查UAC
    try {
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue
        if ($uac) {
            $results += "`nUAC状态: $($uac.EnableLUA)"
            if ($uac.EnableLUA -eq 0) {
                $results += "警告: UAC已禁用"
            }
        }
    } catch {
        $results += "无法检查UAC状态"
    }
    
    $results += "`n提示: 使用 secpol.msc 查看本地安全策略"
    $results += "提示: 使用 gpedit.msc 查看组策略"
    
    $results | Out-File -FilePath $policyFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n安全策略信息已保存到: $policyFile" -ForegroundColor Green
}

# ============================================
# 开发工具功能
# ============================================

# 83. 环境变量管理增强
function Manage-EnvironmentVariablesAdvanced {
    Write-Host "`n========== 环境变量管理增强 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $envAdvFile = Join-Path $desktop "environment_variables_advanced.txt"
    
    $results = @()
    $results += "========== 环境变量管理增强 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 分类显示环境变量
    $results += "系统环境变量:"
    $systemVars = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)
    $results += "  数量: $($systemVars.Count)"
    
    $results += "`n用户环境变量:"
    $userVars = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)
    $results += "  数量: $($userVars.Count)"
    
    $results += "`n进程环境变量:"
    $processVars = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
    $results += "  数量: $($processVars.Count)"
    
    # 检查PATH变量
    $results += "`nPATH变量分析:"
    $pathValue = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
    if ($pathValue) {
        $pathEntries = $pathValue -split ';'
        $results += "  用户PATH条目数: $($pathEntries.Count)"
        $results += "  前10个条目:"
        $pathEntries | Select-Object -First 10 | ForEach-Object {
            $results += "    - $_"
        }
    }
    
    $results | Out-File -FilePath $envAdvFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n环境变量管理信息已保存到: $envAdvFile" -ForegroundColor Green
}

# 84. PATH管理
function Manage-PATH {
    Write-Host "`n========== PATH管理 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $pathFile = Join-Path $desktop "path_management.txt"
    
    $results = @()
    $results += "========== PATH环境变量管理 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 用户PATH
    $userPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
    $results += "用户PATH:"
    if ($userPath) {
        $userPathEntries = $userPath -split ';' | Where-Object {$_ -ne ''}
        $results += "  条目数: $($userPathEntries.Count)"
        $results += "  所有条目:"
        foreach ($entry in $userPathEntries) {
            $exists = Test-Path $entry
            $status = if ($exists) { "✓" } else { "✗" }
            $results += "    $status $entry"
        }
    }
    
    # 系统PATH
    $systemPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
    $results += "`n系统PATH:"
    if ($systemPath) {
        $systemPathEntries = $systemPath -split ';' | Where-Object {$_ -ne ''}
        $results += "  条目数: $($systemPathEntries.Count)"
    }
    
    $results += "`n提示: 使用 [Environment]::SetEnvironmentVariable() 修改PATH"
    $results += "提示: 修改后需要重启PowerShell才能生效"
    
    $results | Out-File -FilePath $pathFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`nPATH管理信息已保存到: $pathFile" -ForegroundColor Green
}

# 85. 开发工具检测
function Get-DevelopmentTools {
    Write-Host "`n========== 开发工具检测 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $devToolsFile = Join-Path $desktop "development_tools.txt"
    
    $results = @()
    $results += "========== 开发工具检测 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查常见开发工具
    $devTools = @(
        @{Name="Visual Studio"; Paths=@("$env:ProgramFiles\Microsoft Visual Studio", "$env:ProgramFiles(x86)\Microsoft Visual Studio")},
        @{Name="Visual Studio Code"; Path="$env:LOCALAPPDATA\Programs\Microsoft VS Code"},
        @{Name="Git"; Path="$env:ProgramFiles\Git"},
        @{Name="Node.js"; Path="$env:ProgramFiles\nodejs"},
        @{Name="Python"; Path="$env:LOCALAPPDATA\Programs\Python"},
        @{Name="Java"; Path="$env:ProgramFiles\Java"}
    )
    
    $results += "已安装的开发工具:"
    $foundTools = @()
    foreach ($tool in $devTools) {
        $found = $false
        if ($tool.Paths) {
            foreach ($path in $tool.Paths) {
                if (Test-Path $path) {
                    $found = $true
                    break
                }
            }
        } elseif ($tool.Path) {
            if (Test-Path $tool.Path) {
                $found = $true
            }
        }
        
        if ($found) {
            $results += "  ✓ $($tool.Name)"
            $foundTools += $tool.Name
        }
    }
    
    if ($foundTools.Count -eq 0) {
        $results += "  未检测到常见的开发工具"
    }
    
    # 检查PowerShell版本
    $results += "`nPowerShell版本:"
    $results += "  $($PSVersionTable.PSVersion)"
    
    # 检查.NET版本
    $results += "`n.NET版本:"
    try {
        $dotnetVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction SilentlyContinue).Release
        if ($dotnetVersion) {
            $results += "  .NET Framework 4.x (Release: $dotnetVersion)"
        }
    } catch {
        $results += "  无法检测.NET版本"
    }
    
    $results | Out-File -FilePath $devToolsFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n开发工具检测信息已保存到: $devToolsFile" -ForegroundColor Green
}

# 86. 版本控制工具
function Get-VersionControlTools {
    Write-Host "`n========== 版本控制工具 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $vcsFile = Join-Path $desktop "version_control_tools.txt"
    
    $results = @()
    $results += "========== 版本控制工具 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查Git
    try {
        $gitVersion = git --version 2>&1
        if ($gitVersion -notmatch "error|not found") {
            $results += "Git: 已安装"
            $results += "  版本: $gitVersion"
        } else {
            $results += "Git: 未安装"
        }
    } catch {
        $results += "Git: 未安装"
    }
    
    # 检查SVN
    try {
        $svnVersion = svn --version 2>&1
        if ($svnVersion -notmatch "error|not found") {
            $results += "`nSVN: 已安装"
            $results += "  版本信息: $($svnVersion[0])"
        } else {
            $results += "`nSVN: 未安装"
        }
    } catch {
        $results += "`nSVN: 未安装"
    }
    
    # 检查Mercurial
    try {
        $hgVersion = hg --version 2>&1
        if ($hgVersion -notmatch "error|not found") {
            $results += "`nMercurial: 已安装"
        } else {
            $results += "`nMercurial: 未安装"
        }
    } catch {
        $results += "`nMercurial: 未安装"
    }
    
    # Git配置
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $results += "`nGit配置:"
        try {
            $gitUser = git config user.name 2>&1
            $gitEmail = git config user.email 2>&1
            if ($gitUser -notmatch "error") {
                $results += "  用户名: $gitUser"
            }
            if ($gitEmail -notmatch "error") {
                $results += "  邮箱: $gitEmail"
            }
        } catch {
            $results += "  无法获取Git配置"
        }
    }
    
    $results | Out-File -FilePath $vcsFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n版本控制工具信息已保存到: $vcsFile" -ForegroundColor Green
}

# ============================================
# 数据恢复功能
# ============================================

# 87. 文件恢复
function Get-FileRecoveryInfo {
    Write-Host "`n========== 文件恢复信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $recoveryFile = Join-Path $desktop "file_recovery.txt"
    
    $results = @()
    $results += "========== 文件恢复信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查回收站
    $results += "回收站信息:"
    try {
        $recycleBin = Get-ChildItem "$env:SystemDrive\`$Recycle.Bin" -Force -ErrorAction SilentlyContinue
        if ($recycleBin) {
            $results += "  回收站中有 $($recycleBin.Count) 个项目"
        } else {
            $results += "  回收站为空或无法访问"
        }
    } catch {
        $results += "  无法访问回收站"
    }
    
    # 检查卷影副本
    $results += "`n卷影副本（系统还原点）:"
    try {
        $shadowCopies = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($shadowCopies) {
            $results += "  找到 $($shadowCopies.Count) 个还原点"
            $results += "  可以使用这些还原点恢复文件"
        } else {
            $results += "  未找到还原点"
        }
    } catch {
        $results += "  无法检查还原点（可能需要管理员权限）"
    }
    
    $results += "`n文件恢复建议:"
    $results += "  1. 检查回收站"
    $results += "  2. 使用文件历史记录（如果已启用）"
    $results += "  3. 使用卷影副本"
    $results += "  4. 使用专业数据恢复软件"
    $results += "  5. 从备份恢复"
    
    $results | Out-File -FilePath $recoveryFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n文件恢复信息已保存到: $recoveryFile" -ForegroundColor Green
}

# 88. 注册表恢复
function Get-RegistryRecoveryInfo {
    Write-Host "`n========== 注册表恢复信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $regRecoveryFile = Join-Path $desktop "registry_recovery.txt"
    
    $results = @()
    $results += "========== 注册表恢复信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查注册表备份
    $backupPaths = @(
        "$env:SystemRoot\System32\config\RegBack",
        "$env:USERPROFILE\Desktop\RegistryBackup"
    )
    
    $results += "注册表备份位置:"
    foreach ($path in $backupPaths) {
        if (Test-Path $path) {
            $results += "  ✓ $path 存在"
        } else {
            $results += "  ✗ $path 不存在"
        }
    }
    
    $results += "`n注册表恢复方法:"
    $results += "  1. 使用之前导出的.reg文件恢复"
    $results += "  2. 使用系统还原点恢复"
    $results += "  3. 使用注册表编辑器导入备份"
    $results += "  4. 从系统备份恢复"
    
    $results += "`n提示: 修改注册表前请先备份"
    $results += "提示: 错误的注册表修改可能导致系统无法启动"
    
    $results | Out-File -FilePath $regRecoveryFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n注册表恢复信息已保存到: $regRecoveryFile" -ForegroundColor Green
}

# 89. 系统还原
function Get-SystemRestoreInfo {
    Write-Host "`n========== 系统还原信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $restoreInfoFile = Join-Path $desktop "system_restore_info.txt"
    
    $results = @()
    $results += "========== 系统还原信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查系统还原状态
    try {
        $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($restorePoints) {
            $results += "系统还原点数量: $($restorePoints.Count)"
            $results += "`n最近的还原点:"
            $restorePoints | Sort-Object CreationTime -Descending | Select-Object -First 5 | ForEach-Object {
                $results += "  - 序列号: $($_.SequenceNumber)"
                $results += "    创建时间: $($_.CreationTime)"
                $results += "    描述: $($_.Description)"
                $results += ""
            }
        } else {
            $results += "未找到系统还原点"
            $results += "提示: 系统还原可能未启用"
        }
    } catch {
        $results += "无法检查系统还原点（可能需要管理员权限）"
    }
    
    $results += "`n系统还原方法:"
    $results += "  1. 使用 rstrui.exe 打开系统还原向导"
    $results += "  2. 使用 Restore-Computer -RestorePoint <序列号>"
    $results += "  3. 在系统属性中配置系统还原"
    
    $results | Out-File -FilePath $restoreInfoFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n系统还原信息已保存到: $restoreInfoFile" -ForegroundColor Green
}

# 90. 备份恢复
function Get-BackupRecoveryInfo {
    Write-Host "`n========== 备份恢复信息 ==========" -ForegroundColor Cyan
    $desktop = [Environment]::GetFolderPath("Desktop")
    $backupRecoveryFile = Join-Path $desktop "backup_recovery.txt"
    
    $results = @()
    $results += "========== 备份恢复信息 =========="
    $results += "检查时间: $(Get-Date)"
    $results += "`n"
    
    # 检查Windows备份
    $results += "Windows备份位置:"
    $backupLocations = @(
        "$env:USERPROFILE\Desktop\RegistryBackup",
        "$env:USERPROFILE\Desktop\SystemConfigBackup",
        "$env:USERPROFILE\Desktop\FileBackup"
    )
    
    foreach ($location in $backupLocations) {
        if (Test-Path $location) {
            $files = Get-ChildItem -Path $location -Recurse -ErrorAction SilentlyContinue
            $results += "  ✓ $location - $($files.Count) 个文件"
        }
    }
    
    $results += "`n备份恢复方法:"
    $results += "  1. 从文件备份恢复: 复制备份文件到原位置"
    $results += "  2. 从注册表备份恢复: 双击.reg文件或使用reg import"
    $results += "  3. 使用Windows备份和还原工具"
    $results += "  4. 使用第三方备份软件恢复"
    
    $results += "`n提示: 恢复前请确认备份文件的完整性"
    $results += "提示: 重要操作前请创建新的备份"
    
    $results | Out-File -FilePath $backupRecoveryFile -Encoding UTF8
    Write-Host ($results -join "`n")
    Write-Host "`n备份恢复信息已保存到: $backupRecoveryFile" -ForegroundColor Green
}

# ============================================
# 单独功能调用（注释掉，按需取消注释）
# ============================================

# Get-SystemInfo
# Test-NetworkProbe
# Get-FileDownload
# Invoke-FileProcessing
# Test-PortScan
# Get-WiFiPasswords
# Get-ProcessManagement
# Get-ServiceManagement
# Get-DiskSpaceAnalysis
# Get-RegistryQuery
# Get-SystemLogs
# Get-EnvironmentVariables
# Get-UserAccounts
# Get-FirewallRules
# Get-SystemUpdates
# Get-HardwareInfo
# Get-ScheduledTasks
# Get-NetworkConnections
# Get-FilePermissions
# Get-SystemPerformance
# Get-InstalledSoftware
# Get-DNSCache
# Get-ARPTable
# Get-StartupItems
# Get-FileHashInfo
# Open-SystemFeatures
# Invoke-BatchFileOperations
# Find-SuspiciousFiles
# Invoke-SecurityScan
# Find-MalwareIndicators

# ============================================
# 显示版权信息
# ============================================
function Show-CopyrightInfo {
    Write-Host ""
    Write-Host "┌────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "│" -ForegroundColor DarkGray -NoNewline
    Write-Host "  版权信息: " -ForegroundColor Gray -NoNewline
    Write-Host "© 2026 黑客驰 (HackerChi)" -ForegroundColor Green -NoNewline
    Write-Host "                    │" -ForegroundColor DarkGray
    Write-Host "│" -ForegroundColor DarkGray -NoNewline
    Write-Host "  官方网站: " -ForegroundColor Gray -NoNewline
    Write-Host "https://hackerchi.top" -ForegroundColor Yellow -NoNewline
    Write-Host "                              │" -ForegroundColor DarkGray
    Write-Host "│" -ForegroundColor DarkGray -NoNewline
    Write-Host "  版本: " -ForegroundColor Gray -NoNewline
    Write-Host "v3.0" -ForegroundColor Magenta -NoNewline
    Write-Host " | 功能数: " -ForegroundColor Gray -NoNewline
    Write-Host "90个" -ForegroundColor Magenta -NoNewline
    Write-Host "                                    │" -ForegroundColor DarkGray
    Write-Host "└────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================
# 整合版 - 一键运行所有功能
# ============================================
function Invoke-AllFunctions {
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "          PowerShell 多功能脚本集合 v3.0                      " -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  开发者: " -ForegroundColor Gray -NoNewline
    Write-Host "黑客驰 (HackerChi)" -ForegroundColor Green -NoNewline
    Write-Host "                                    ║" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  网站:   " -ForegroundColor Gray -NoNewline
    Write-Host "https://hackerchi.top" -ForegroundColor Yellow -NoNewline
    Write-Host "                              ║" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  版本:   " -ForegroundColor Gray -NoNewline
    Write-Host "v3.0" -ForegroundColor Magenta -NoNewline
    Write-Host " | 功能数: " -ForegroundColor Gray -NoNewline
    Write-Host "90个" -ForegroundColor Magenta -NoNewline
    Write-Host "                                    ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "正在执行所有功能，请稍候..." -ForegroundColor Yellow
    Write-Host ""
    
    $startTime = Get-Date
    
    # 执行所有功能
    Get-SystemInfo
    Start-Sleep -Seconds 1
    
    Test-NetworkProbe
    Start-Sleep -Seconds 1
    
    Get-FileDownload
    Start-Sleep -Seconds 1
    
    Invoke-FileProcessing
    Start-Sleep -Seconds 1
    
    Test-PortScan
    Start-Sleep -Seconds 1
    
    Get-WiFiPasswords
    Start-Sleep -Seconds 1
    
    Get-ProcessManagement
    Start-Sleep -Seconds 1
    
    Get-ServiceManagement
    Start-Sleep -Seconds 1
    
    Get-DiskSpaceAnalysis
    Start-Sleep -Seconds 1
    
    Get-RegistryQuery
    Start-Sleep -Seconds 1
    
    Get-SystemLogs
    Start-Sleep -Seconds 1
    
    Get-EnvironmentVariables
    Start-Sleep -Seconds 1
    
    Get-UserAccounts
    Start-Sleep -Seconds 1
    
    Get-FirewallRules
    Start-Sleep -Seconds 1
    
    Get-SystemUpdates
    Start-Sleep -Seconds 1
    
    Get-HardwareInfo
    Start-Sleep -Seconds 1
    
    Get-ScheduledTasks
    Start-Sleep -Seconds 1
    
    Get-NetworkConnections
    Start-Sleep -Seconds 1
    
    Get-FilePermissions
    Start-Sleep -Seconds 1
    
    Get-SystemPerformance
    Start-Sleep -Seconds 1
    
    Get-InstalledSoftware
    Start-Sleep -Seconds 1
    
    Get-DNSCache
    Start-Sleep -Seconds 1
    
    Get-ARPTable
    Start-Sleep -Seconds 1
    
    Get-StartupItems
    Start-Sleep -Seconds 1
    
    Get-FileHashInfo
    Start-Sleep -Seconds 1
    
    Open-SystemFeatures
    Start-Sleep -Seconds 1
    
    Invoke-BatchFileOperations
    Start-Sleep -Seconds 1
    
    Find-SuspiciousFiles
    Start-Sleep -Seconds 1
    
    Invoke-SecurityScan
    Start-Sleep -Seconds 1
    
    Find-MalwareIndicators
    Start-Sleep -Seconds 1
    
    # 系统优化功能
    Clear-TempFiles
    Start-Sleep -Seconds 1
    Get-DiskFragmentation
    Start-Sleep -Seconds 1
    Optimize-StartupItems
    Start-Sleep -Seconds 1
    Optimize-Services
    Start-Sleep -Seconds 1
    
    # 网络管理功能
    Test-NetworkSpeed
    Start-Sleep -Seconds 1
    Monitor-NetworkTraffic
    Start-Sleep -Seconds 1
    Manage-HostsFile
    Start-Sleep -Seconds 1
    Get-ProxySettings
    Start-Sleep -Seconds 1
    
    # 备份与恢复功能
    Backup-Registry
    Start-Sleep -Seconds 1
    Backup-SystemConfig
    Start-Sleep -Seconds 1
    Backup-Files
    Start-Sleep -Seconds 1
    Manage-SystemRestorePoints
    Start-Sleep -Seconds 1
    
    # 隐私保护功能
    Clear-BrowserHistory
    Start-Sleep -Seconds 1
    Clear-RecentFiles
    Start-Sleep -Seconds 1
    Check-PrivacySettings
    Start-Sleep -Seconds 1
    Manage-LocationServices
    Start-Sleep -Seconds 1
    
    # 系统监控功能
    Monitor-SystemPerformance
    Start-Sleep -Seconds 1
    Monitor-Temperature
    Start-Sleep -Seconds 1
    Get-BatteryStatus
    Start-Sleep -Seconds 1
    Get-SystemResourceAlerts
    Start-Sleep -Seconds 1
    
    # 软件管理功能
    Uninstall-Software
    Start-Sleep -Seconds 1
    Check-SoftwareUpdates
    Start-Sleep -Seconds 1
    Find-DuplicateFiles
    Start-Sleep -Seconds 1
    Find-LargeFiles
    Start-Sleep -Seconds 1
    
    # 系统修复功能
    Check-SystemFiles
    Start-Sleep -Seconds 1
    Repair-DISM
    Start-Sleep -Seconds 1
    Reset-Network
    Start-Sleep -Seconds 1
    Repair-WindowsUpdate
    Start-Sleep -Seconds 1
    
    # 密码管理功能
    Check-PasswordPolicy
    Start-Sleep -Seconds 1
    Get-PasswordExpiration
    Start-Sleep -Seconds 1
    New-PasswordGenerator
    Start-Sleep -Seconds 1
    Get-PasswordManagerInfo
    Start-Sleep -Seconds 1
    
    # 远程管理功能
    Get-RemoteDesktopConfig
    Start-Sleep -Seconds 1
    Get-SSHConfig
    Start-Sleep -Seconds 1
    Get-VPNConnections
    Start-Sleep -Seconds 1
    Get-RemoteFileAccess
    Start-Sleep -Seconds 1
    
    # 日志分析功能
    Aggregate-Logs
    Start-Sleep -Seconds 1
    Search-Logs
    Start-Sleep -Seconds 1
    Export-Logs
    Start-Sleep -Seconds 1
    Find-LogAnomalies
    Start-Sleep -Seconds 1
    
    # 自动化功能
    New-ScheduledTaskExample
    Start-Sleep -Seconds 1
    New-AutomationScript
    Start-Sleep -Seconds 1
    Invoke-BatchProcessing
    Start-Sleep -Seconds 1
    Get-WorkflowInfo
    Start-Sleep -Seconds 1
    
    # 系统信息增强
    Get-SystemHealthReport
    Start-Sleep -Seconds 1
    Check-HardwareCompatibility
    Start-Sleep -Seconds 1
    Check-DriverUpdates
    Start-Sleep -Seconds 1
    Get-BIOSInfo
    Start-Sleep -Seconds 1
    
    # 安全增强功能
    Test-FileIntegrity
    Start-Sleep -Seconds 1
    Test-DigitalSignature
    Start-Sleep -Seconds 1
    Get-CertificateInfo
    Start-Sleep -Seconds 1
    Check-SecurityPolicy
    Start-Sleep -Seconds 1
    
    # 开发工具功能
    Manage-EnvironmentVariablesAdvanced
    Start-Sleep -Seconds 1
    Manage-PATH
    Start-Sleep -Seconds 1
    Get-DevelopmentTools
    Start-Sleep -Seconds 1
    Get-VersionControlTools
    Start-Sleep -Seconds 1
    
    # 数据恢复功能
    Get-FileRecoveryInfo
    Start-Sleep -Seconds 1
    Get-RegistryRecoveryInfo
    Start-Sleep -Seconds 1
    Get-SystemRestoreInfo
    Start-Sleep -Seconds 1
    Get-BackupRecoveryInfo
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "                    所有功能执行完成！                           " -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Green
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "  总耗时: " -ForegroundColor Gray -NoNewline
    Write-Host "$([math]::Round($duration, 2)) 秒" -ForegroundColor Yellow -NoNewline
    Write-Host "                                        ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    # 显示版权信息
    Show-CopyrightInfo
    
    # 生成汇总报告
    $desktop = [Environment]::GetFolderPath("Desktop")
    $summaryFile = Join-Path $desktop "script_summary.txt"
    $summary = @"
PowerShell 脚本执行汇总报告
生成时间: $(Get-Date)

执行的功能:
1. 系统信息收集
2. 网络探测
3. 文件下载
4. 文件处理
5. 端口扫描
6. WiFi密码显示
7. 进程管理
8. 服务管理
9. 磁盘空间分析
10. 注册表查询
11. 系统日志查看
12. 环境变量管理
13. 用户账户信息
14. 防火墙规则查看
15. 系统更新检查
16. 硬件详细信息
17. 计划任务管理
18. 网络连接监控
19. 文件权限检查
20. 系统性能监控
21. 软件安装列表
22. DNS缓存管理
23. ARP表查看
24. 系统启动项管理
25. 文件哈希计算
26. 打开系统指定功能
27. 批量文件操作
28. 可疑文件检测
29. 系统安全扫描
30. 恶意软件检测
31. 清理临时文件
32. 磁盘碎片分析
33. 启动项优化
34. 服务优化
35. 网络速度测试
36. 网络流量监控
37. Hosts文件管理
38. 代理设置检查
39. 注册表备份
40. 系统配置备份
41. 文件备份
42. 系统还原点管理
43. 浏览器历史清理
44. 最近文件清理
45. 隐私设置检查
46. 位置服务管理
47. 实时性能监控
48. 温度监控
49. 电池状态
50. 系统资源警报
51. 软件卸载
52. 软件更新检查
53. 重复文件查找
54. 大文件查找
55. 系统文件检查
56. DISM修复
57. 网络重置
58. Windows更新修复
59. 密码强度检查
60. 密码过期提醒
61. 密码生成器
62. 密码管理器集成
63. 远程桌面配置
64. SSH配置
65. VPN连接管理
66. 远程文件访问
67. 日志聚合
68. 日志搜索
69. 日志导出
70. 异常模式识别
71. 定时任务创建
72. 自动化脚本生成
73. 批处理工具
74. 工作流管理
75. 系统健康报告
76. 硬件兼容性检查
77. 驱动更新检查
78. BIOS/UEFI信息
79. 文件完整性检查
80. 数字签名验证
81. 证书管理
82. 安全策略检查
83. 环境变量管理增强
84. PATH管理
85. 开发工具检测
86. 版本控制工具
87. 文件恢复
88. 注册表恢复
89. 系统还原
90. 备份恢复

生成的文件位置:
- 系统信息: $(Join-Path $desktop "system_info.txt")
- 网络探测: $(Join-Path $desktop "network_probe.txt")
- 下载文件: $(Join-Path $desktop "Downloads")
- 处理文件: $(Join-Path $desktop "FileProcessing")
- 端口扫描: $(Join-Path $desktop "port_scan.txt")
- WiFi密码: $(Join-Path $desktop "wifi_passwords.txt")
- 进程管理: $(Join-Path $desktop "process_management.txt")
- 服务管理: $(Join-Path $desktop "service_management.txt")
- 磁盘空间: $(Join-Path $desktop "disk_space_analysis.txt")
- 注册表查询: $(Join-Path $desktop "registry_query.txt")
- 系统日志: $(Join-Path $desktop "system_logs.txt")
- 环境变量: $(Join-Path $desktop "environment_variables.txt")
- 用户账户: $(Join-Path $desktop "user_accounts.txt")
- 防火墙规则: $(Join-Path $desktop "firewall_rules.txt")
- 系统更新: $(Join-Path $desktop "system_updates.txt")
- 硬件信息: $(Join-Path $desktop "hardware_info.txt")
- 计划任务: $(Join-Path $desktop "scheduled_tasks.txt")
- 网络连接: $(Join-Path $desktop "network_connections.txt")
- 文件权限: $(Join-Path $desktop "file_permissions.txt")
- 系统性能: $(Join-Path $desktop "system_performance.txt")
- 软件列表: $(Join-Path $desktop "installed_software.txt")
- DNS缓存: $(Join-Path $desktop "dns_cache.txt")
- ARP表: $(Join-Path $desktop "arp_table.txt")
- 启动项: $(Join-Path $desktop "startup_items.txt")
- 文件哈希: $(Join-Path $desktop "file_hashes.txt")
- 系统功能: $(Join-Path $desktop "system_features.txt")
- 批量操作: $(Join-Path $desktop "batch_file_operations.txt")
- 可疑文件: $(Join-Path $desktop "suspicious_files.txt")
- 安全扫描: $(Join-Path $desktop "security_scan.txt")
- 恶意软件检测: $(Join-Path $desktop "malware_detection.txt")
- 临时文件清理: $(Join-Path $desktop "temp_cleanup.txt")
- 磁盘碎片: $(Join-Path $desktop "disk_fragmentation.txt")
- 启动项优化: $(Join-Path $desktop "startup_optimization.txt")
- 服务优化: $(Join-Path $desktop "service_optimization.txt")
- 网络速度: $(Join-Path $desktop "network_speed.txt")
- 网络流量: $(Join-Path $desktop "network_traffic.txt")
- Hosts文件: $(Join-Path $desktop "hosts_file.txt")
- 代理设置: $(Join-Path $desktop "proxy_settings.txt")
- 注册表备份: $(Join-Path $desktop "RegistryBackup")
- 系统配置备份: $(Join-Path $desktop "SystemConfigBackup")
- 文件备份: $(Join-Path $desktop "FileBackup")
- 系统还原点: $(Join-Path $desktop "system_restore_points.txt")
- 浏览器清理: $(Join-Path $desktop "browser_history_cleanup.txt")
- 最近文件清理: $(Join-Path $desktop "recent_files_cleanup.txt")
- 隐私设置: $(Join-Path $desktop "privacy_settings.txt")
- 位置服务: $(Join-Path $desktop "location_services.txt")
- 实时性能: $(Join-Path $desktop "realtime_performance.txt")
- 温度监控: $(Join-Path $desktop "temperature_monitor.txt")
- 电池状态: $(Join-Path $desktop "battery_status.txt")
- 资源警报: $(Join-Path $desktop "system_resource_alerts.txt")
- 软件卸载: $(Join-Path $desktop "software_uninstall.txt")
- 软件更新: $(Join-Path $desktop "software_updates.txt")
- 重复文件: $(Join-Path $desktop "duplicate_files.txt")
- 大文件: $(Join-Path $desktop "large_files.txt")
- 系统文件检查: $(Join-Path $desktop "system_file_check.txt")
- DISM修复: $(Join-Path $desktop "dism_repair.txt")
- 网络重置: $(Join-Path $desktop "network_reset.txt")
- 更新修复: $(Join-Path $desktop "windows_update_repair.txt")
- 密码策略: $(Join-Path $desktop "password_policy.txt")
- 密码过期: $(Join-Path $desktop "password_expiration.txt")
- 密码生成: $(Join-Path $desktop "password_generator.txt")
- 密码管理器: $(Join-Path $desktop "password_manager.txt")
- 远程桌面: $(Join-Path $desktop "remote_desktop_config.txt")
- SSH配置: $(Join-Path $desktop "ssh_config.txt")
- VPN连接: $(Join-Path $desktop "vpn_connections.txt")
- 远程文件: $(Join-Path $desktop "remote_file_access.txt")
- 日志聚合: $(Join-Path $desktop "log_aggregation.txt")
- 日志搜索: $(Join-Path $desktop "log_search.txt")
- 日志导出: $(Join-Path $desktop "LogExports")
- 异常模式: $(Join-Path $desktop "log_anomalies.txt")
- 定时任务: $(Join-Path $desktop "scheduled_task_example.txt")
- 自动化脚本: $(Join-Path $desktop "AutomationScripts")
- 批处理: $(Join-Path $desktop "batch_processing.txt")
- 工作流: $(Join-Path $desktop "workflow_management.txt")
- 系统健康: $(Join-Path $desktop "system_health_report.txt")
- 硬件兼容性: $(Join-Path $desktop "hardware_compatibility.txt")
- 驱动更新: $(Join-Path $desktop "driver_updates.txt")
- BIOS信息: $(Join-Path $desktop "bios_info.txt")
- 文件完整性: $(Join-Path $desktop "file_integrity_check.txt")
- 数字签名: $(Join-Path $desktop "digital_signature_verification.txt")
- 证书管理: $(Join-Path $desktop "certificate_management.txt")
- 安全策略: $(Join-Path $desktop "security_policy.txt")
- 环境变量增强: $(Join-Path $desktop "environment_variables_advanced.txt")
- PATH管理: $(Join-Path $desktop "path_management.txt")
- 开发工具: $(Join-Path $desktop "development_tools.txt")
- 版本控制: $(Join-Path $desktop "version_control_tools.txt")
- 文件恢复: $(Join-Path $desktop "file_recovery.txt")
- 注册表恢复: $(Join-Path $desktop "registry_recovery.txt")
- 系统还原: $(Join-Path $desktop "system_restore_info.txt")
- 备份恢复: $(Join-Path $desktop "backup_recovery.txt")

执行耗时: $([math]::Round($duration, 2)) 秒

关键词: 黑客驰, hackerchi.top

版权信息:
© 2026 黑客驰 (HackerChi)
官方网站: https://hackerchi.top
版本: v3.0
功能数: 90个
"@
    $summary | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Host "`n汇总报告已保存到: $summaryFile" -ForegroundColor Green
}

# ============================================
# 交互式菜单系统
# ============================================
function Show-MainMenu {
    Clear-Host
    
    # 显示版权信息和标题
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "          PowerShell 多功能脚本集合 v3.0                      " -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  开发者: " -ForegroundColor Gray -NoNewline
    Write-Host "黑客驰 (HackerChi)" -ForegroundColor Green -NoNewline
    Write-Host "                                    ║" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  网站:   " -ForegroundColor Gray -NoNewline
    Write-Host "https://hackerchi.top" -ForegroundColor Yellow -NoNewline
    Write-Host "                              ║" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  功能数: " -ForegroundColor Gray -NoNewline
    Write-Host "90个强大功能" -ForegroundColor Magenta -NoNewline
    Write-Host "                                    ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # 主菜单选项
    Write-Host "┌────────────────────────────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "│" -ForegroundColor Green -NoNewline
    Write-Host "  主菜单选项:                                                 " -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "├────────────────────────────────────────────────────────────┤" -ForegroundColor Green
    Write-Host "│" -ForegroundColor Green -NoNewline
    Write-Host "  [1] " -ForegroundColor Yellow -NoNewline
    Write-Host "执行所有功能 (一键运行全部90个功能)                          " -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "│" -ForegroundColor Green -NoNewline
    Write-Host "  [2] " -ForegroundColor Yellow -NoNewline
    Write-Host "选择功能执行 (自定义选择要执行的功能)                        " -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "│" -ForegroundColor Green -NoNewline
    Write-Host "  [3] " -ForegroundColor Yellow -NoNewline
    Write-Host "按分类执行 (按功能分类选择执行)                              " -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "│" -ForegroundColor Green -NoNewline
    Write-Host "  [4] " -ForegroundColor Yellow -NoNewline
    Write-Host "查看功能列表 (显示所有可用功能)                              " -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "│" -ForegroundColor Green -NoNewline
    Write-Host "  [0] " -ForegroundColor Yellow -NoNewline
    Write-Host "退出程序                                                      " -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "└────────────────────────────────────────────────────────────┘" -ForegroundColor Green
    Write-Host ""
    
    $choice = Read-Host "请选择操作 [0-4]"
    return $choice
}

# 显示功能分类菜单
function Show-CategoryMenu {
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "                    功能分类菜单                                 " -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $categories = @(
        @{Name="系统信息类"; Functions=@("Get-SystemInfo", "Get-HardwareInfo", "Get-BIOSInfo", "Get-SystemHealthReport")},
        @{Name="网络管理类"; Functions=@("Test-NetworkProbe", "Test-PortScan", "Test-NetworkSpeed", "Monitor-NetworkTraffic", "Manage-HostsFile", "Get-ProxySettings", "Get-DNSCache", "Get-ARPTable")},
        @{Name="文件操作类"; Functions=@("Get-FileDownload", "Invoke-FileProcessing", "Invoke-BatchFileOperations", "Find-DuplicateFiles", "Find-LargeFiles", "Get-FileHashInfo")},
        @{Name="系统安全类"; Functions=@("Invoke-SecurityScan", "Find-MalwareIndicators", "Find-SuspiciousFiles", "Test-FileIntegrity", "Test-DigitalSignature", "Get-CertificateInfo", "Check-SecurityPolicy")},
        @{Name="系统优化类"; Functions=@("Clear-TempFiles", "Get-DiskFragmentation", "Optimize-StartupItems", "Optimize-Services")},
        @{Name="进程服务类"; Functions=@("Get-ProcessManagement", "Get-ServiceManagement", "Get-ScheduledTasks")},
        @{Name="备份恢复类"; Functions=@("Backup-Registry", "Backup-SystemConfig", "Backup-Files", "Manage-SystemRestorePoints", "Get-FileRecoveryInfo", "Get-RegistryRecoveryInfo", "Get-SystemRestoreInfo", "Get-BackupRecoveryInfo")},
        @{Name="隐私保护类"; Functions=@("Clear-BrowserHistory", "Clear-RecentFiles", "Check-PrivacySettings", "Manage-LocationServices")},
        @{Name="系统监控类"; Functions=@("Monitor-SystemPerformance", "Monitor-Temperature", "Get-BatteryStatus", "Get-SystemResourceAlerts", "Get-SystemPerformance")},
        @{Name="软件管理类"; Functions=@("Get-InstalledSoftware", "Uninstall-Software", "Check-SoftwareUpdates")},
        @{Name="系统修复类"; Functions=@("Check-SystemFiles", "Repair-DISM", "Reset-Network", "Repair-WindowsUpdate")},
        @{Name="密码管理类"; Functions=@("Check-PasswordPolicy", "Get-PasswordExpiration", "New-PasswordGenerator", "Get-PasswordManagerInfo")},
        @{Name="远程管理类"; Functions=@("Get-RemoteDesktopConfig", "Get-SSHConfig", "Get-VPNConnections", "Get-RemoteFileAccess")},
        @{Name="日志分析类"; Functions=@("Get-SystemLogs", "Aggregate-Logs", "Search-Logs", "Export-Logs", "Find-LogAnomalies")},
        @{Name="其他功能类"; Functions=@("Get-WiFiPasswords", "Open-SystemFeatures", "Get-UserAccounts", "Get-FirewallRules", "Get-SystemUpdates", "Get-NetworkConnections", "Get-FilePermissions", "Get-EnvironmentVariables", "Get-RegistryQuery", "Get-DiskSpaceAnalysis", "Get-StartupItems")}
    )
    
    $index = 1
    foreach ($category in $categories) {
        Write-Host "  [$index] " -ForegroundColor Yellow -NoNewline
        Write-Host "$($category.Name) " -ForegroundColor Cyan -NoNewline
        Write-Host "($($category.Functions.Count) 个功能)" -ForegroundColor Gray
        $index++
    }
    Write-Host ""
    Write-Host "  [0] " -ForegroundColor Yellow -NoNewline
    Write-Host "返回主菜单" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "请选择分类 [0-$($categories.Count)]"
    return $choice, $categories
}

# 显示功能选择菜单
function Show-FunctionMenu {
    param([array]$Functions)
    
    # 初始化变量
    $choice = ""
    
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "                    功能选择菜单                                 " -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # 创建完整的中文功能映射（90个功能）
    $functionMap = @{
        # 1-30: 基础功能
        "Get-SystemInfo" = "系统信息收集"
        "Test-NetworkProbe" = "网络探测"
        "Get-FileDownload" = "文件下载"
        "Invoke-FileProcessing" = "文件处理"
        "Test-PortScan" = "端口扫描"
        "Get-WiFiPasswords" = "WiFi密码显示"
        "Get-ProcessManagement" = "进程管理"
        "Get-ServiceManagement" = "服务管理"
        "Get-DiskSpaceAnalysis" = "磁盘空间分析"
        "Get-RegistryQuery" = "注册表查询"
        "Get-SystemLogs" = "系统日志查看"
        "Get-EnvironmentVariables" = "环境变量管理"
        "Get-UserAccounts" = "用户账户信息"
        "Get-FirewallRules" = "防火墙规则查看"
        "Get-SystemUpdates" = "系统更新检查"
        "Get-HardwareInfo" = "硬件详细信息"
        "Get-ScheduledTasks" = "计划任务管理"
        "Get-NetworkConnections" = "网络连接监控"
        "Get-FilePermissions" = "文件权限检查"
        "Get-SystemPerformance" = "系统性能监控"
        "Get-InstalledSoftware" = "软件安装列表"
        "Get-DNSCache" = "DNS缓存管理"
        "Get-ARPTable" = "ARP表查看"
        "Get-StartupItems" = "系统启动项管理"
        "Get-FileHashInfo" = "文件哈希计算"
        "Open-SystemFeatures" = "打开系统指定功能"
        "Invoke-BatchFileOperations" = "批量文件操作"
        "Find-SuspiciousFiles" = "可疑文件检测"
        "Invoke-SecurityScan" = "系统安全扫描"
        "Find-MalwareIndicators" = "恶意软件检测"
        # 31-34: 系统优化
        "Clear-TempFiles" = "清理临时文件"
        "Get-DiskFragmentation" = "磁盘碎片分析"
        "Optimize-StartupItems" = "启动项优化"
        "Optimize-Services" = "服务优化"
        # 35-38: 网络管理
        "Test-NetworkSpeed" = "网络速度测试"
        "Monitor-NetworkTraffic" = "网络流量监控"
        "Manage-HostsFile" = "Hosts文件管理"
        "Get-ProxySettings" = "代理设置检查"
        # 39-42: 备份恢复
        "Backup-Registry" = "注册表备份"
        "Backup-SystemConfig" = "系统配置备份"
        "Backup-Files" = "文件备份"
        "Manage-SystemRestorePoints" = "系统还原点管理"
        # 43-46: 隐私保护
        "Clear-BrowserHistory" = "浏览器历史清理"
        "Clear-RecentFiles" = "最近文件清理"
        "Check-PrivacySettings" = "隐私设置检查"
        "Manage-LocationServices" = "位置服务管理"
        # 47-50: 系统监控
        "Monitor-SystemPerformance" = "实时性能监控"
        "Monitor-Temperature" = "温度监控"
        "Get-BatteryStatus" = "电池状态"
        "Get-SystemResourceAlerts" = "系统资源警报"
        # 51-54: 软件管理
        "Uninstall-Software" = "软件卸载"
        "Check-SoftwareUpdates" = "软件更新检查"
        "Find-DuplicateFiles" = "重复文件查找"
        "Find-LargeFiles" = "大文件查找"
        # 55-58: 系统修复
        "Check-SystemFiles" = "系统文件检查"
        "Repair-DISM" = "DISM修复"
        "Reset-Network" = "网络重置"
        "Repair-WindowsUpdate" = "Windows更新修复"
        # 59-62: 密码管理
        "Check-PasswordPolicy" = "密码强度检查"
        "Get-PasswordExpiration" = "密码过期提醒"
        "New-PasswordGenerator" = "密码生成器"
        "Get-PasswordManagerInfo" = "密码管理器集成"
        # 63-66: 远程管理
        "Get-RemoteDesktopConfig" = "远程桌面配置"
        "Get-SSHConfig" = "SSH配置"
        "Get-VPNConnections" = "VPN连接管理"
        "Get-RemoteFileAccess" = "远程文件访问"
        # 67-70: 日志分析
        "Aggregate-Logs" = "日志聚合"
        "Search-Logs" = "日志搜索"
        "Export-Logs" = "日志导出"
        "Find-LogAnomalies" = "异常模式识别"
        # 71-74: 自动化
        "New-ScheduledTaskExample" = "定时任务创建"
        "New-AutomationScript" = "自动化脚本生成"
        "Invoke-BatchProcessing" = "批处理工具"
        "Get-WorkflowInfo" = "工作流管理"
        # 75-78: 系统信息增强
        "Get-SystemHealthReport" = "系统健康报告"
        "Check-HardwareCompatibility" = "硬件兼容性检查"
        "Check-DriverUpdates" = "驱动更新检查"
        "Get-BIOSInfo" = "BIOS/UEFI信息"
        # 79-82: 安全增强
        "Test-FileIntegrity" = "文件完整性检查"
        "Test-DigitalSignature" = "数字签名验证"
        "Get-CertificateInfo" = "证书管理"
        "Check-SecurityPolicy" = "安全策略检查"
        # 83-86: 开发工具
        "Manage-EnvironmentVariablesAdvanced" = "环境变量管理增强"
        "Manage-PATH" = "PATH管理"
        "Get-DevelopmentTools" = "开发工具检测"
        "Get-VersionControlTools" = "版本控制工具"
        # 87-90: 数据恢复
        "Get-FileRecoveryInfo" = "文件恢复"
        "Get-RegistryRecoveryInfo" = "注册表恢复"
        "Get-SystemRestoreInfo" = "系统还原"
        "Get-BackupRecoveryInfo" = "备份恢复"
    }
    
    # 显示所有90个功能
    Write-Host "可用功能列表 (共90个):" -ForegroundColor Yellow
    Write-Host ""
    
    # 所有90个功能的完整列表
    $allFunctions = @(
        # 1-30: 基础功能
        "Get-SystemInfo", "Test-NetworkProbe", "Get-FileDownload", "Invoke-FileProcessing",
        "Test-PortScan", "Get-WiFiPasswords", "Get-ProcessManagement", "Get-ServiceManagement",
        "Get-DiskSpaceAnalysis", "Get-RegistryQuery", "Get-SystemLogs", "Get-EnvironmentVariables",
        "Get-UserAccounts", "Get-FirewallRules", "Get-SystemUpdates", "Get-HardwareInfo",
        "Get-ScheduledTasks", "Get-NetworkConnections", "Get-FilePermissions", "Get-SystemPerformance",
        "Get-InstalledSoftware", "Get-DNSCache", "Get-ARPTable", "Get-StartupItems",
        "Get-FileHashInfo", "Open-SystemFeatures", "Invoke-BatchFileOperations", "Find-SuspiciousFiles",
        "Invoke-SecurityScan", "Find-MalwareIndicators",
        # 31-34: 系统优化
        "Clear-TempFiles", "Get-DiskFragmentation", "Optimize-StartupItems", "Optimize-Services",
        # 35-38: 网络管理
        "Test-NetworkSpeed", "Monitor-NetworkTraffic", "Manage-HostsFile", "Get-ProxySettings",
        # 39-42: 备份恢复
        "Backup-Registry", "Backup-SystemConfig", "Backup-Files", "Manage-SystemRestorePoints",
        # 43-46: 隐私保护
        "Clear-BrowserHistory", "Clear-RecentFiles", "Check-PrivacySettings", "Manage-LocationServices",
        # 47-50: 系统监控
        "Monitor-SystemPerformance", "Monitor-Temperature", "Get-BatteryStatus", "Get-SystemResourceAlerts",
        # 51-54: 软件管理
        "Uninstall-Software", "Check-SoftwareUpdates", "Find-DuplicateFiles", "Find-LargeFiles",
        # 55-58: 系统修复
        "Check-SystemFiles", "Repair-DISM", "Reset-Network", "Repair-WindowsUpdate",
        # 59-62: 密码管理
        "Check-PasswordPolicy", "Get-PasswordExpiration", "New-PasswordGenerator", "Get-PasswordManagerInfo",
        # 63-66: 远程管理
        "Get-RemoteDesktopConfig", "Get-SSHConfig", "Get-VPNConnections", "Get-RemoteFileAccess",
        # 67-70: 日志分析
        "Aggregate-Logs", "Search-Logs", "Export-Logs", "Find-LogAnomalies",
        # 71-74: 自动化
        "New-ScheduledTaskExample", "New-AutomationScript", "Invoke-BatchProcessing", "Get-WorkflowInfo",
        # 75-78: 系统信息增强
        "Get-SystemHealthReport", "Check-HardwareCompatibility", "Check-DriverUpdates", "Get-BIOSInfo",
        # 79-82: 安全增强
        "Test-FileIntegrity", "Test-DigitalSignature", "Get-CertificateInfo", "Check-SecurityPolicy",
        # 83-86: 开发工具
        "Manage-EnvironmentVariablesAdvanced", "Manage-PATH", "Get-DevelopmentTools", "Get-VersionControlTools",
        # 87-90: 数据恢复
        "Get-FileRecoveryInfo", "Get-RegistryRecoveryInfo", "Get-SystemRestoreInfo", "Get-BackupRecoveryInfo"
    )
    
    # 显示功能列表（分页显示，每页25个）
    $pageSize = 25
    $totalPages = [math]::Ceiling($allFunctions.Count / $pageSize)
    
    for ($page = 0; $page -lt $totalPages; $page++) {
        $startIndex = $page * $pageSize
        $endIndex = [math]::Min($startIndex + $pageSize - 1, $allFunctions.Count - 1)
        $isLastPage = ($page -eq $totalPages - 1)
        
        if ($page -gt 0) {
            Write-Host ""
            Write-Host "按Enter键查看下一页..." -ForegroundColor Gray
            $null = Read-Host
            Clear-Host
            Write-Host ""
            Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
            Write-Host "║" -ForegroundColor Cyan -NoNewline
            Write-Host "                    功能选择菜单                                 " -ForegroundColor White -NoNewline
            Write-Host "║" -ForegroundColor Cyan
            Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
            Write-Host ""
        }
        
        Write-Host "功能列表 (全局编号 $($startIndex + 1)-$($endIndex + 1)，共 $($allFunctions.Count) 个):" -ForegroundColor Cyan
        Write-Host ""
        
        for ($i = $startIndex; $i -le $endIndex; $i++) {
            $func = $allFunctions[$i]
            if ($func) {
                $displayName = if ($functionMap.ContainsKey($func)) { 
                    $functionMap[$func] 
                } else { 
                    "$func" 
                }
                Write-Host "  [$($i + 1)] " -ForegroundColor Yellow -NoNewline
                Write-Host $displayName -ForegroundColor White
            }
        }
        
        # 如果是最后一页，直接读取用户输入，不再需要额外的Enter
        if ($isLastPage) {
            Write-Host ""
            Write-Host "提示: 输入功能编号（全局编号 1-$($allFunctions.Count)，用逗号分隔，如: 1,3,5）" -ForegroundColor Gray
            Write-Host "提示: 或输入 all 执行全部功能" -ForegroundColor Gray
            Write-Host ""
            
            $choice = Read-Host "请选择要执行的功能"
            break
        }
    }
    
    # 如果不是最后一页（理论上不应该到这里），确保有默认值
    if ($null -eq $choice) {
        $choice = ""
    }
    
    # 确保返回值不为空
    if ($null -eq $choice) {
        $choice = ""
    }
    
    # 调试：检查输入值
    # Write-Host "调试: Read-Host返回值为: '$choice' (长度: $($choice.Length))" -ForegroundColor Magenta
    
    return @($choice, $allFunctions)
}

# 执行选定的功能
function Invoke-SelectedFunctions {
    param([array]$SelectedFunctions)
    
    # 中文功能名称映射
    $functionNameMap = @{
        "Get-SystemInfo" = "系统信息收集"
        "Test-NetworkProbe" = "网络探测"
        "Get-FileDownload" = "文件下载"
        "Invoke-FileProcessing" = "文件处理"
        "Test-PortScan" = "端口扫描"
        "Get-WiFiPasswords" = "WiFi密码显示"
        "Get-ProcessManagement" = "进程管理"
        "Get-ServiceManagement" = "服务管理"
        "Get-DiskSpaceAnalysis" = "磁盘空间分析"
        "Get-RegistryQuery" = "注册表查询"
        "Get-SystemLogs" = "系统日志查看"
        "Get-EnvironmentVariables" = "环境变量管理"
        "Get-UserAccounts" = "用户账户信息"
        "Get-FirewallRules" = "防火墙规则查看"
        "Get-SystemUpdates" = "系统更新检查"
        "Get-HardwareInfo" = "硬件详细信息"
        "Get-ScheduledTasks" = "计划任务管理"
        "Get-NetworkConnections" = "网络连接监控"
        "Get-FilePermissions" = "文件权限检查"
        "Get-SystemPerformance" = "系统性能监控"
        "Get-InstalledSoftware" = "软件安装列表"
        "Get-DNSCache" = "DNS缓存管理"
        "Get-ARPTable" = "ARP表查看"
        "Get-StartupItems" = "系统启动项管理"
        "Get-FileHashInfo" = "文件哈希计算"
        "Open-SystemFeatures" = "打开系统指定功能"
        "Invoke-BatchFileOperations" = "批量文件操作"
        "Find-SuspiciousFiles" = "可疑文件检测"
        "Invoke-SecurityScan" = "系统安全扫描"
        "Find-MalwareIndicators" = "恶意软件检测"
        "Clear-TempFiles" = "清理临时文件"
        "Get-DiskFragmentation" = "磁盘碎片分析"
        "Optimize-StartupItems" = "启动项优化"
        "Optimize-Services" = "服务优化"
        "Test-NetworkSpeed" = "网络速度测试"
        "Monitor-NetworkTraffic" = "网络流量监控"
        "Manage-HostsFile" = "Hosts文件管理"
        "Get-ProxySettings" = "代理设置检查"
        "Backup-Registry" = "注册表备份"
        "Backup-SystemConfig" = "系统配置备份"
        "Backup-Files" = "文件备份"
        "Manage-SystemRestorePoints" = "系统还原点管理"
        "Clear-BrowserHistory" = "浏览器历史清理"
        "Clear-RecentFiles" = "最近文件清理"
        "Check-PrivacySettings" = "隐私设置检查"
        "Manage-LocationServices" = "位置服务管理"
        "Monitor-SystemPerformance" = "实时性能监控"
        "Monitor-Temperature" = "温度监控"
        "Get-BatteryStatus" = "电池状态"
        "Get-SystemResourceAlerts" = "系统资源警报"
        "Uninstall-Software" = "软件卸载"
        "Check-SoftwareUpdates" = "软件更新检查"
        "Find-DuplicateFiles" = "重复文件查找"
        "Find-LargeFiles" = "大文件查找"
        "Check-SystemFiles" = "系统文件检查"
        "Repair-DISM" = "DISM修复"
        "Reset-Network" = "网络重置"
        "Repair-WindowsUpdate" = "Windows更新修复"
        "Check-PasswordPolicy" = "密码强度检查"
        "Get-PasswordExpiration" = "密码过期提醒"
        "New-PasswordGenerator" = "密码生成器"
        "Get-PasswordManagerInfo" = "密码管理器集成"
        "Get-RemoteDesktopConfig" = "远程桌面配置"
        "Get-SSHConfig" = "SSH配置"
        "Get-VPNConnections" = "VPN连接管理"
        "Get-RemoteFileAccess" = "远程文件访问"
        "Aggregate-Logs" = "日志聚合"
        "Search-Logs" = "日志搜索"
        "Export-Logs" = "日志导出"
        "Find-LogAnomalies" = "异常模式识别"
        "New-ScheduledTaskExample" = "定时任务创建"
        "New-AutomationScript" = "自动化脚本生成"
        "Invoke-BatchProcessing" = "批处理工具"
        "Get-WorkflowInfo" = "工作流管理"
        "Get-SystemHealthReport" = "系统健康报告"
        "Check-HardwareCompatibility" = "硬件兼容性检查"
        "Check-DriverUpdates" = "驱动更新检查"
        "Get-BIOSInfo" = "BIOS/UEFI信息"
        "Test-FileIntegrity" = "文件完整性检查"
        "Test-DigitalSignature" = "数字签名验证"
        "Get-CertificateInfo" = "证书管理"
        "Check-SecurityPolicy" = "安全策略检查"
        "Manage-EnvironmentVariablesAdvanced" = "环境变量管理增强"
        "Manage-PATH" = "PATH管理"
        "Get-DevelopmentTools" = "开发工具检测"
        "Get-VersionControlTools" = "版本控制工具"
        "Get-FileRecoveryInfo" = "文件恢复"
        "Get-RegistryRecoveryInfo" = "注册表恢复"
        "Get-SystemRestoreInfo" = "系统还原"
        "Get-BackupRecoveryInfo" = "备份恢复"
    }
    
    Clear-Host
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "                    开始执行功能                                " -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    $startTime = Get-Date
    $successCount = 0
    $failCount = 0
    
    foreach ($func in $SelectedFunctions) {
        try {
            # 检查函数名是否为空
            if ($null -eq $func -or $func -eq "" -or $func.Trim() -eq "") {
                throw "函数名为空"
            }
            
            # 获取中文名称
            $displayName = if ($functionNameMap.ContainsKey($func)) {
                $functionNameMap[$func]
            } else {
                $func
            }
            
            Write-Host "正在执行: " -ForegroundColor Yellow -NoNewline
            Write-Host $displayName -ForegroundColor Cyan
            
            # 验证函数是否存在
            $command = Get-Command -Name $func -ErrorAction Stop
            if ($command.CommandType -eq "Function") {
                # 调用函数
                & $func
                $successCount++
                Write-Host "✓ 完成" -ForegroundColor Green
            } else {
                throw "命令 '$func' 不是函数类型"
            }
            Write-Host ""
            Start-Sleep -Milliseconds 500
        } catch {
            $errorMsg = if ($_.Exception.Message) { $_.Exception.Message } else { $_ }
            Write-Host "✗ 失败: $errorMsg" -ForegroundColor Red
            $failCount++
            Write-Host ""
        }
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "                    执行完成                                     " -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  成功: " -ForegroundColor Gray -NoNewline
    Write-Host "$successCount 个功能" -ForegroundColor Green -NoNewline
    Write-Host "                                    ║" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  失败: " -ForegroundColor Gray -NoNewline
    Write-Host "$failCount 个功能" -ForegroundColor Red -NoNewline
    Write-Host "                                    ║" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "  总耗时: " -ForegroundColor Gray -NoNewline
    Write-Host "$([math]::Round($duration, 2)) 秒" -ForegroundColor Yellow -NoNewline
    Write-Host "                                  ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # 显示版权信息
    Show-CopyrightInfo
    
    Read-Host "按Enter键返回主菜单"
}

# 主程序入口
function Start-InteractiveMenu {
    while ($true) {
        $choice = Show-MainMenu
        
        switch ($choice) {
            "1" {
                Clear-Host
                Show-CopyrightInfo
                Write-Host "正在执行所有功能..." -ForegroundColor Yellow
                Write-Host ""
                Invoke-AllFunctions
                Write-Host ""
                Read-Host "按Enter键返回主菜单"
            }
            "2" {
                $result = Show-FunctionMenu
                if ($null -eq $result -or $result.Count -lt 2) {
                    Write-Host "错误: Show-FunctionMenu返回值异常！" -ForegroundColor Red
                    Read-Host "按Enter键继续"
                    continue
                }
                
                $funcChoice = $result[0]
                $allFunctions = $result[1]
                
                # 检查返回值
                if ($null -eq $funcChoice) {
                    $funcChoice = ""
                }
                
                # 清理输入（去除空格）
                $funcChoice = $funcChoice.Trim()
                
                if ($funcChoice -eq "all" -or $funcChoice -eq "ALL") {
                    Invoke-AllFunctions
                } else {
                    
                    # 尝试解析为数字（支持单个数字或多个数字用逗号/空格分隔）
                    $inputNumbers = @()
                    $isValidInput = $false
                    
                    # 检查是否为纯数字
                    if ($funcChoice -match "^\d+$") {
                        $inputNumbers = @([int]$funcChoice)
                        $isValidInput = $true
                    }
                    # 检查是否为多个数字（用逗号或空格分隔）
                    elseif ($funcChoice -match "^\d+([,\s]+\d+)+$") {
                        $inputNumbers = $funcChoice -split "[,\s]+" | Where-Object {$_ -ne "" -and $_ -match "^\d+$"} | ForEach-Object {[int]$_}
                        $isValidInput = $inputNumbers.Count -gt 0
                    }
                    
                    if ($isValidInput) {
                        # 解析用户输入的数字（全局索引，从1开始）
                        $selectedFunctions = @()
                        $invalidSelections = @()
                        
                        foreach ($num in $inputNumbers) {
                            # 转换为数组索引（从0开始）
                            $arrayIndex = $num - 1
                            
                            if ($arrayIndex -ge 0 -and $arrayIndex -lt $allFunctions.Count) {
                                $funcName = $allFunctions[$arrayIndex]
                                
                                # 检查函数名是否为空
                                if ($funcName -and $funcName.Trim() -ne "") {
                                    # 验证函数是否存在
                                    $command = Get-Command -Name $funcName -ErrorAction SilentlyContinue
                                    if ($command -and $command.CommandType -eq "Function") {
                                        $selectedFunctions += $funcName
                                    } else {
                                        $invalidSelections += "功能 $num ($funcName - 函数不存在)"
                                    }
                                } else {
                                    $invalidSelections += "功能 $num (函数名为空)"
                                }
                            } else {
                                $invalidSelections += "功能 $num (索引超出范围，有效范围: 1-$($allFunctions.Count))"
                            }
                        }
                        
                        # 显示无效选择的警告
                        if ($invalidSelections.Count -gt 0) {
                            Write-Host ""
                            Write-Host "警告: 以下选择无效，已跳过:" -ForegroundColor Yellow
                            foreach ($invalid in $invalidSelections) {
                                Write-Host "  - $invalid" -ForegroundColor Yellow
                            }
                            Write-Host ""
                        }
                        
                        if ($selectedFunctions.Count -gt 0) {
                            Invoke-SelectedFunctions -SelectedFunctions $selectedFunctions
                        } else {
                            Write-Host "错误: 没有找到有效的功能！" -ForegroundColor Red
                            Write-Host "提示: 请确保输入的功能编号在 1-$($allFunctions.Count) 范围内" -ForegroundColor Gray
                            Read-Host "按Enter键继续"
                        }
                    } else {
                        Write-Host "无效的输入！请输入数字编号（如: 1 或 1,3,5）或 all" -ForegroundColor Red
                        Write-Host "您输入的是: '$funcChoice'" -ForegroundColor Yellow
                        Read-Host "按Enter键继续"
                    }
                }
            }
            "3" {
                $catChoice, $categories = Show-CategoryMenu
                
                if ($catChoice -eq "0") {
                    continue
                } elseif ($catChoice -match "^\d+$" -and [int]$catChoice -ge 1 -and [int]$catChoice -le $categories.Count) {
                    $selectedCategory = $categories[[int]$catChoice - 1]
                    Write-Host ""
                    Write-Host "已选择分类: " -ForegroundColor Yellow -NoNewline
                    Write-Host $selectedCategory.Name -ForegroundColor Cyan
                    Write-Host "包含功能: $($selectedCategory.Functions.Count) 个" -ForegroundColor Gray
                    Write-Host ""
                    $confirm = Read-Host "是否执行此分类的所有功能? (Y/N)"
                    if ($confirm -eq "Y" -or $confirm -eq "y") {
                        # 验证分类中的函数是否存在
                        $validFunctions = @()
                        foreach ($func in $selectedCategory.Functions) {
                            if (Get-Command -Name $func -ErrorAction SilentlyContinue) {
                                $validFunctions += $func
                            } else {
                                Write-Host "警告: 函数 '$func' 不存在，已跳过" -ForegroundColor Yellow
                            }
                        }
                        
                        if ($validFunctions.Count -gt 0) {
                            Invoke-SelectedFunctions -SelectedFunctions $validFunctions
                        } else {
                            Write-Host "错误: 该分类中没有有效的功能！" -ForegroundColor Red
                            Read-Host "按Enter键继续"
                        }
                    }
                } else {
                    Write-Host "无效的选择！" -ForegroundColor Red
                    Read-Host "按Enter键继续"
                }
            }
            "4" {
                Clear-Host
                Show-CopyrightInfo
                Write-Host "所有可用功能列表 (共90个):" -ForegroundColor Yellow
                Write-Host ""
                
                $allFuncs = @(
                    "1-30: 基础功能 (系统信息、网络、文件、安全等)",
                    "31-34: 系统优化功能",
                    "35-38: 网络管理功能",
                    "39-42: 备份与恢复功能",
                    "43-46: 隐私保护功能",
                    "47-50: 系统监控功能",
                    "51-54: 软件管理功能",
                    "55-58: 系统修复功能",
                    "59-62: 密码管理功能",
                    "63-66: 远程管理功能",
                    "67-70: 日志分析功能",
                    "71-74: 自动化功能",
                    "75-78: 系统信息增强",
                    "79-82: 安全增强功能",
                    "83-86: 开发工具功能",
                    "87-90: 数据恢复功能"
                )
                
                foreach ($func in $allFuncs) {
                    Write-Host "  • $func" -ForegroundColor White
                }
                
                Write-Host ""
                Read-Host "按Enter键返回主菜单"
            }
            "0" {
                Clear-Host
                Show-CopyrightInfo
                Write-Host "感谢使用！再见！" -ForegroundColor Green
                Write-Host ""
                exit
            }
            default {
                Write-Host "无效的选择，请重新输入！" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ============================================
# 主程序入口
# ============================================
# 取消下面的注释以运行交互式菜单
Start-InteractiveMenu

# 取消下面的注释以直接运行整合版（不显示菜单）
# Invoke-AllFunctions
