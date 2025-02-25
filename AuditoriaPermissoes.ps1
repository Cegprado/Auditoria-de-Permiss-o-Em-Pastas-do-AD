# Função para registrar mensagens em um arquivo de log
function Log-Mensagem {
    param (
        [string]$mensagem,
        [string]$cor = "White",
        [string]$nivel = "INFO"
    )
    $caminhoLog = "C:\Logs\AuditoriaPermissoes.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$nivel] $mensagem"
    Write-Host $logEntry -ForegroundColor $cor
    if (-not (Test-Path (Split-Path $caminhoLog))) {
        New-Item -ItemType Directory -Path (Split-Path $caminhoLog) | Out-Null
    }
    Add-Content -Path $caminhoLog -Value $logEntry
}

# Função para exibir o menu
function Mostrar-Menu {
    Clear-Host
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "       AUDITORIA DE PERMISSÕES DE ARQUIVOS     " -ForegroundColor Yellow
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "1. Listar permissões de uma pasta" -ForegroundColor Green
    Write-Host "2. Identificar permissões inseguras (Everyone/Full Control)" -ForegroundColor Green
    Write-Host "3. Gerar relatório em CSV" -ForegroundColor Green
    Write-Host "4. Corrigir permissões herdadas quebradas" -ForegroundColor Green
    Write-Host "5. Exibir caminho do log" -ForegroundColor Green
    Write-Host "6. Sair" -ForegroundColor Red
    Write-Host "==============================================" -ForegroundColor Cyan
}

# Função para validar caminho
function Validar-Caminho {
    param ([string]$caminho)
    if (-not (Test-Path $caminho)) {
        Log-Mensagem "Caminho inválido: $caminho" -cor "Red" -nivel "ERROR"
        return $false
    }
    return $true
}

# Função 1: Listar permissões de uma pasta
function Get-PermissoesPasta {
    param ([string]$caminhoPasta)
    if (-not (Validar-Caminho $caminhoPasta)) {
        Write-Host "Caminho inválido ou sem acesso!" -ForegroundColor Red
        return
    }
    try {
        $acl = Get-Acl -Path $caminhoPasta
        
        # Cores para formatação
        $corTitulo = "Cyan"
        $corDestaque = "Yellow"
        $corPermissao = "Green"
        $corHerdado = "DarkGray"

        # Cabeçalho
        Write-Host "`n"
        Write-Host ("=" * 60) -ForegroundColor $corTitulo
        Write-Host "PERMISSÕES DA PASTA: $caminhoPasta" -ForegroundColor $corTitulo
        Write-Host ("=" * 60) -ForegroundColor $corTitulo
        Write-Host "`n"

        # Função para traduzir permissões
        function Traduzir-Permissao($rights) {
            switch -Wildcard ($rights.ToString()) {
                "FullControl"   { "Controle total" }
                "Modify"        { "Editar/Renomear/Apagar" }
                "ReadAndExecute" { "Ler e Executar" }
                "Write"         { "Criar e Modificar" }
                "AppendData"     { "Adicionar dados" }
                "CreateFiles"    { "Criar arquivos" }
                "268435456"      { "Controle para dono do arquivo" }  # CREATOR OWNER
                default          { $rights }
            }
        }

        # Processar cada permissão
        $acl.Access | Group-Object IdentityReference | ForEach-Object {
            $grupo = $_.Name
            $permissoes = $_.Group | ForEach-Object {
                $traducao = Traduzir-Permissao $_.FileSystemRights
                $tipoAcesso = if ($_.AccessControlType -eq "Allow") { " Permitido" } else { " Negado" }
                $heranca = if ($_.IsInherited) { "(Herdado)" } else { "(Definido aqui)" }
                
                # Formatar linha
                "  → $traducao".PadRight(35) + " | $tipoAcesso $heranca"
            }

            # Exibir grupo
            Write-Host " $grupo" -ForegroundColor $corDestaque
            Write-Host ("─" * 60) -ForegroundColor $corHerdado
            $permissoes | ForEach-Object { Write-Host $_ -ForegroundColor $corPermissao }
            Write-Host "`n"
        }

        Log-Mensagem "Permissões listadas para: $caminhoPasta" -cor "Green" -nivel "INFO"

    } catch {
        Log-Mensagem "Erro ao listar permissões: $_" -cor "Red" -nivel "ERROR"
        Write-Host "Erro ao listar permissões!" -ForegroundColor Red
    }
}

# Função 2: Identificar permissões inseguras
function Find-PermissoesInseguras {
    param ([string]$caminhoPasta)
    if (-not (Validar-Caminho $caminhoPasta)) {
        Write-Host "Caminho inválido ou sem acesso!" -ForegroundColor Red
        return
    }
    try {
        $arquivos = Get-ChildItem -Path $caminhoPasta -Recurse -File
        $resultados = @()

        foreach ($arquivo in $arquivos) {
            $acl = Get-Acl -Path $arquivo.FullName
            foreach ($regra in $acl.Access) {
                $direitos = [System.Security.AccessControl.FileSystemRights]$regra.FileSystemRights
                if ($regra.IdentityReference -like "*Everyone*" -or $direitos -match "FullControl") {
                    $resultados += [PSCustomObject]@{
                        Caminho = $arquivo.FullName
                        Permissao = "★ Controle Total"
                        Identidade = $regra.IdentityReference
                    }
                }
            }
        }

        if ($resultados.Count -gt 0) {
            Write-Host "`n============================================================"
            Write-Host "|          PERMISSÕES INSEGURAS IDENTIFICADAS              |"
            Write-Host "============================================================"
            Write-Host " Pasta Analisada: $caminhoPasta`n"
            
            # Tabela de itens críticos
            Write-Host " $corAlerta**Itens com Risco:**$corReset"
            Write-Host "┌──────────────────────────────────────────────────────────┐"
            Write-Host "| Caminho do Arquivo       | Permissão         | Identidade |"
            Write-Host "├──────────────────────────────────────────────────────────┤"
            $resultados | ForEach-Object {
                Write-Host ("| {0} | {1} | {2}$corAlerta |" -f 
                    ($_.Caminho.ToString().PadRight(22)),
                    ($_.Permissao.ToString().PadRight(17)),
                    ($_.Identidade.ToString().PadRight(10)))
            }
            Write-Host "└──────────────────────────────────────────────────────────┘`n"

            Log-Mensagem "Permissões inseguras encontradas em: $caminhoPasta" -cor "Yellow" -nivel "WARNING"
        } else {
            Write-Host "Nenhuma permissão insegura encontrada!" -ForegroundColor Green
        }
    } catch {
        Log-Mensagem "Erro na auditoria: $_" -cor "Red" -nivel "ERROR"
    }
}

# Função 3: Gerar relatório CSV (com direitos legíveis)
function Exportar-RelatorioCSV {
    param ([string]$caminhoPasta, [string]$caminhoCSV)
    if (-not (Validar-Caminho $caminhoPasta)) {
        Write-Host "Caminho inválido ou sem acesso!" -ForegroundColor Red
        return
    }
    try {
        $aclData = Get-ChildItem -Path $caminhoPasta -Recurse | ForEach-Object {
            $acl = Get-Acl -Path $_.FullName
            foreach ($regra in $acl.Access) {
                [PSCustomObject]@{
                    Caminho = $_.FullName
                    Permissao = [System.Security.AccessControl.FileSystemRights]$regra.FileSystemRights
                    Identidade = $regra.IdentityReference
                    Herdado = $regra.IsInherited
                }
            }
        }
        $aclData | Export-Csv -Path $caminhoCSV -NoTypeInformation -Encoding UTF8
        Write-Host "Relatório gerado em: $caminhoCSV" -ForegroundColor Green
        Log-Mensagem "Relatório CSV gerado: $caminhoCSV" -cor "Green" -nivel "INFO"
    } catch {
        Log-Mensagem "Erro ao gerar relatório: $_" -cor "Red" -nivel "ERROR"
    }
}

# Função 4: Corrigir herança de permissões 
function Repair-HerancaPermissoes {
    param ([string]$caminhoPasta)
    if (-not (Validar-Caminho $caminhoPasta)) {
        Write-Host "Caminho inválido ou sem acesso!" -ForegroundColor Red
        return
    }
    try {
        $acl = Get-Acl -Path $caminhoPasta
        if ($acl.AreAccessRulesProtected) {
            # Remove proteção e restaura herança
            $acl.SetAccessRuleProtection($false, $true)
            Set-Acl -Path $caminhoPasta -AclObject $acl
            Write-Host "Herança de permissões restaurada com sucesso!" -ForegroundColor Green
            Log-Mensagem "Herança corrigida em: $caminhoPasta" -cor "Green" -nivel "INFO"
        } else {
            Write-Host "As permissões já estão herdadas corretamente!" -ForegroundColor Yellow
        }
    } catch {
        Log-Mensagem "Erro ao corrigir herança: $_" -cor "Red" -nivel "ERROR"
    }
}

# Loop principal
while ($true) {
    Mostrar-Menu
    $opcao = Read-Host "`nEscolha uma opção (1-6)"

    switch ($opcao) {
        "1" {
            $pasta = Read-Host "Digite o caminho da pasta"
            Get-PermissoesPasta -caminhoPasta $pasta
            Read-Host "`nPressione Enter para continuar..."
        }
        "2" {
            $pasta = Read-Host "Digite o caminho da pasta"
            Find-PermissoesInseguras -caminhoPasta $pasta
            Read-Host "`nPressione Enter para continuar..."
        }
        "3" {
            $pasta = Read-Host "Digite o caminho da pasta"
            $csv = Read-Host "Digite o caminho do arquivo CSV (ex: C:\Relatorio.csv)"
            Exportar-RelatorioCSV -caminhoPasta $pasta -caminhoCSV $csv
            Read-Host "`nPressione Enter para continuar..."
        }
        "4" {
            $pasta = Read-Host "Digite o caminho da pasta"
            Repair-HerancaPermissoes -caminhoPasta $pasta
            Read-Host "`nPressione Enter para continuar..."
        }
        "5" {
            Write-Host "Caminho do log: C:\Logs\AuditoriaPermissoes.log" -ForegroundColor Cyan
            Read-Host "`nPressione Enter para continuar..."
        }
        "6" { exit }
        default {
            Write-Host "Opção inválida!" -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}