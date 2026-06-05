# Defender EASM データをCSVにエクスポートするPowerShellスクリプト（ページネーション対応）
#
# 使用例:
#   ./Export_EASMVuln_CSV.ps1                 # デフォルト（最大20ページ）で取得
#   ./Export_EASMVuln_CSV.ps1 -MaxPages 50    # 最大50ページまで取得
#   ./Export_EASMVuln_CSV.ps1 -MaxPages 0     # ページ上限なし（全件取得）

param(
    # 取得する最大ページ数。デフォルト 20。1 以上を指定。'0' を指定すると上限なし（全ページ取得）。
    [int]$MaxPages = 20
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Defender EASM データエクスポートツール" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. アクセストークン取得
Write-Host "`n[1/5] アクセストークンを取得中..." -ForegroundColor Yellow
try {
    $tokenJson = az account get-access-token --scope 'https://easm.defender.microsoft.com/.default' 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ トークン取得に失敗しました" -ForegroundColor Red
        exit 1
    }
    $token = ($tokenJson | ConvertFrom-Json).accessToken
    Write-Host "✓ トークン取得成功" -ForegroundColor Green
}
catch {
    Write-Host "❌ エラー: $_" -ForegroundColor Red
    exit 1
}

# 2. サブスクリプションID取得
Write-Host "`n[2/5] サブスクリプション情報を取得中..." -ForegroundColor Yellow
$subscriptionId = az account show --query id -o tsv
Write-Host "✓ サブスクリプションID: $subscriptionId" -ForegroundColor Green

# 3. Defender EASM リソース情報取得
Write-Host "`n[3/5] Defender EASM リソースを検索中..." -ForegroundColor Yellow
$easmResourcesJson = az resource list --resource-type "Microsoft.Easm/workspaces" 2>&1
$easmResources = $easmResourcesJson | ConvertFrom-Json

if ($easmResources.Count -eq 0) {
    Write-Host "❌ Defender EASM リソースが見つかりません" -ForegroundColor Red
    exit 1
}

$resource = $easmResources[0]
$workspaceName = $resource.name
$resourceGroup = $resource.resourceGroup
$location = $resource.location

Write-Host "✓ リソース発見" -ForegroundColor Green
Write-Host "  ワークスペース名: $workspaceName" -ForegroundColor Gray
Write-Host "  リソースグループ: $resourceGroup" -ForegroundColor Gray
Write-Host "  リージョン: $location" -ForegroundColor Gray

# 4. アセットデータ取得（ページネーション対応）
if ($MaxPages -le 0) {
    Write-Host "`n[4/5] アセットデータを取得中（ページ上限なし）..." -ForegroundColor Yellow
}
else {
    Write-Host "`n[4/5] アセットデータを取得中（最大 $MaxPages ページ）..." -ForegroundColor Yellow
}

$endpoint = "https://$location.easm.defender.microsoft.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/workspaces/$workspaceName/assets?api-version=2024-10-01-preview"

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$allAssets = @()
$pageCount = 0

try {
    do {
        $pageCount++
        Write-Host "  ページ $pageCount を取得中..." -ForegroundColor Gray
        
        $response = Invoke-RestMethod -Uri $endpoint -Headers $headers -Method Get -ErrorAction Stop
        $allAssets += $response.value
        Write-Host "    → $($response.value.Count) 件のアセットを取得" -ForegroundColor Gray
        
        # 次のページがある場合
        $endpoint = $response.nextLink
        
        # 最大ページ数チェック（MaxPages が 1 以上のときのみ適用。'0' は上限なし）
        if ($MaxPages -gt 0 -and $pageCount -ge $MaxPages) {
            if ($endpoint) {
                Write-Host "  ⚠ 最大ページ数 ($MaxPages) に到達しました。さらにデータがある可能性があります（-MaxPages で上限を変更できます）" -ForegroundColor Yellow
            }
            break
        }
        
        # レート制限対策
        if ($endpoint) {
            Start-Sleep -Milliseconds 500
        }
        
    } while ($endpoint)
    
    $assets = $allAssets
    Write-Host "✓ 合計 $($assets.Count) 件のアセットを取得しました（$pageCount ページ）" -ForegroundColor Green
}
catch {
    Write-Host "❌ API呼び出しエラー: $_" -ForegroundColor Red
    Write-Host "エンドポイント: $endpoint" -ForegroundColor Gray
    exit 1
}

# 5. CSVデータ準備
Write-Host "`n[5/5] CSVデータを準備中..." -ForegroundColor Yellow

$csvData = @()
$vulnerabilityCount = 0
$componentCount = 0

foreach ($asset in $assets) {
    $assetName = $asset.name
    $assetKind = $asset.kind
    $assetState = $asset.state
    $assetUuid = $asset.uuid
    
    # asset オブジェクト内のデータを取得
    $assetData = $asset.asset
    $assetFirstSeen = $assetData.firstSeen
    $assetLastSeen = $assetData.lastSeen
    $assetCreated = $asset.createdDate
    $assetUpdated = $asset.updatedDate
    
    # Web Componentsの処理（asset.asset.webComponents から取得）
    if ($assetData.webComponents -and $assetData.webComponents.Count -gt 0) {
        foreach ($component in $assetData.webComponents) {
            $componentCount++
            
            $cveList = ""
            if ($component.cve -and $component.cve.Count -gt 0) {
                # CVEオブジェクトからnameプロパティを取得
                $cveNames = $component.cve | ForEach-Object { $_.name }
                $cveList = $cveNames -join ", "
                $vulnerabilityCount++
            }
            
            $portList = ""
            if ($component.ports -and $component.ports.Count -gt 0) {
                $portList = $component.ports -join ", "
            }
            
            $csvRow = [PSCustomObject]@{
                'Asset Name' = $assetName
                'Asset Kind' = $assetKind
                'Asset State' = $assetState
                'Asset UUID' = $assetUuid
                'Asset First Seen' = $assetFirstSeen
                'Asset Last Seen' = $assetLastSeen
                'Asset Created' = $assetCreated
                'Asset Updated' = $assetUpdated
                'Component Category' = $component.category
                'Component Name' = $component.name
                'Component Version' = $component.version
                'Component CVEs' = $cveList
                'Component First Seen' = $component.firstSeen
                'Component Last Seen' = $component.lastSeen
                'Component Recent' = if ($component.recent) { "Yes" } else { "No" }
                'Component Ports' = $portList
            }
            $csvData += $csvRow
        }
    }
    else {
        # Web Componentsがない場合も基本情報を出力
        $csvRow = [PSCustomObject]@{
            'Asset Name' = $assetName
            'Asset Kind' = $assetKind
            'Asset State' = $assetState
            'Asset UUID' = $assetUuid
            'Asset First Seen' = $assetFirstSeen
            'Asset Last Seen' = $assetLastSeen
            'Asset Created' = $assetCreated
            'Asset Updated' = $assetUpdated
            'Component Category' = ""
            'Component Name' = ""
            'Component Version' = ""
            'Component CVEs' = ""
            'Component First Seen' = ""
            'Component Last Seen' = ""
            'Component Recent' = ""
            'Component Ports' = ""
        }
        $csvData += $csvRow
    }
}

Write-Host "✓ $($csvData.Count) 行のデータを準備しました" -ForegroundColor Green

# 6. CSV出力
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "EASM_Assets_$timestamp.csv"

Write-Host "`n[出力] CSVファイルを作成中..." -ForegroundColor Yellow
$csvData | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "✓ CSVファイル作成完了: $outputFile" -ForegroundColor Green
Write-Host "  総行数: $($csvData.Count + 1) (ヘッダー含む)" -ForegroundColor Gray

# 統計情報表示
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "📊 統計情報" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "総アセット数: $($assets.Count)" -ForegroundColor White
Write-Host "Web Componentsを持つアセット: $componentCount 件" -ForegroundColor White
Write-Host "CVEが検出されたコンポーネント: $vulnerabilityCount 件" -ForegroundColor $(if ($vulnerabilityCount -gt 0) { "Yellow" } else { "Green" })

# アセット種別の集計
$assetKindGroups = $assets | Group-Object kind
Write-Host "`nアセット種別:" -ForegroundColor White
foreach ($group in $assetKindGroups) {
    Write-Host "  $($group.Name): $($group.Count) 件" -ForegroundColor Gray
}

# State別の集計
$assetStateGroups = $assets | Group-Object state
Write-Host "`nアセット状態:" -ForegroundColor White
foreach ($group in $assetStateGroups) {
    Write-Host "  $($group.Name): $($group.Count) 件" -ForegroundColor Gray
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "✓ 処理完了" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "`n出力ファイル: $((Get-Item $outputFile).FullName)" -ForegroundColor Cyan

