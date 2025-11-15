🛡️ Guide Pratique : Sécuriser un Poste Windows 10/11

📋 Table des Matières
1. [Prérequis]
2. [Configuration de Base]
3. [Gestion des Comptes]
4. [Pare-feu et Réseau]
5. [Antivirus et Protection]
6. [Mises à Jour et Patches]
7. [Chiffrement]
8. [Logs et Audit]
9. [Scripts d'Automatisation]
10. [Checklist de Vérification]

---
🎯 Prérequis

- Windows 10 (build 1903+) ou Windows 11
- Droits administrateur
- PowerShell 5.1+ (en mode administrateur)
- Sauvegarde complète du système avant modifications

---

⚙️ Configuration de Base

 1. Vérifier la version de Windows

powershell
# Afficher les informations système
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber

# Vérifier l'édition (Pro/Enterprise requis pour certaines fonctionnalités)
Get-WindowsEdition -Online

2. Activer les fonctionnalités de sécurité essentielles

```powershell
# Activer Windows Defender (si désactivé)
Set-MpPreference -DisableRealtimeMonitoring $false

# Activer la protection cloud
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Activer la protection contre les PUA (Potentially Unwanted Applications)
Set-MpPreference -PUAProtection Enabled
```

---

👥 Gestion des Comptes

1. Désactiver le compte Administrateur intégré

```powershell
# Désactiver le compte Administrator
net user Administrator /active:no

# Vérifier les comptes actifs
Get-LocalUser | Where-Object {$_.Enabled -eq $true}
```

2. Configurer les politiques de mot de passe

```powershell
# Via secpol.msc (GUI) ou PowerShell
# Longueur minimale : 12 caractères
net accounts /minpwlen:12

# Durée de validité : 90 jours
net accounts /maxpwage:90

# Historique des mots de passe : 5 derniers
net accounts /uniquepw:5
```

3. Activer le verrouillage de compte

```powershell
# Verrouiller après 5 tentatives échouées
net accounts /lockoutthreshold:5

# Durée de verrouillage : 30 minutes
net accounts /lockoutduration:30

# Réinitialiser le compteur après : 30 minutes
net accounts /lockoutwindow:30
```
4. Désactiver les comptes invités

```powershell
net user Guest /active:no
```

---

🔥 Pare-feu et Réseau

1. Activer le pare-feu Windows sur tous les profils

```powershell
# Activer le pare-feu
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Bloquer les connexions entrantes par défaut
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

# Vérifier l'état
Get-NetFirewallProfile | Format-Table Name, Enabled
```

2. Bloquer les protocoles dangereux

```powershell
# Bloquer SMBv1 (vulnérable à WannaCry)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Vérifier que SMBv1 est désactivé
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Désactiver NetBIOS sur TCP/IP (si non utilisé)
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) # 2 = Désactivé
}
```

3. Désactiver les services réseau non nécessaires

```powershell
# Liste des services à désactiver (adapter selon vos besoins)
$servicesToDisable = @(
    "RemoteRegistry",      # Registre distant
    "RemoteAccess",        # Accès distant
    "SSDPSRV",            # Découverte SSDP
    "upnphost",           # Hôte de périphérique UPnP
    "WMPNetworkSvc"       # Partage réseau Windows Media Player
)

foreach($service in $servicesToDisable) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "Service $service désactivé" -ForegroundColor Green
}
```

---

🦠 Antivirus et Protection
1. Configuration avancée de Windows Defender

```powershell
# Activer la protection anti-ransomware (Controlled Folder Access)
Set-MpPreference -EnableControlledFolderAccess Enabled

# Activer la protection réseau
Set-MpPreference -EnableNetworkProtection Enabled

# Activer l'analyse des scripts PowerShell
Set-MpPreference -DisableScriptScanning $false

# Activer Attack Surface Reduction Rules (ASR)
# Bloquer les exécutables depuis les emails
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled

# Bloquer JavaScript/VBScript depuis Internet
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
```

2. Planifier des analyses régulières

```powershell
# Analyse rapide quotidienne à 12h
$action = New-ScheduledTaskAction -Execute "C:\Program Files\Windows Defender\MpCmdRun.exe" -Argument "-Scan -ScanType 1"
$trigger = New-ScheduledTaskTrigger -Daily -At 12:00PM
Register-ScheduledTask -TaskName "Defender Quick Scan" -Action $action -Trigger $trigger -User "SYSTEM"

# Lancer une analyse complète maintenant
Start-MpScan -ScanType FullScan
```

---

🔄 Mises à Jour et Patches

1. Configurer Windows Update

```powershell
# Installer le module PSWindowsUpdate
Install-Module PSWindowsUpdate -Force

# Vérifier les mises à jour disponibles
Get-WindowsUpdate

# Installer toutes les mises à jour
Install-WindowsUpdate -AcceptAll -AutoReboot

# Vérifier l'historique
Get-WUHistory | Select-Object -First 10
```

2. Activer les mises à jour automatiques

```powershell
# Via la registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4
```

---

🔐 Chiffrement

1. Activer BitLocker (Windows Pro/Enterprise)

```powershell
# Vérifier si BitLocker est supporté
Get-BitLockerVolume

# Activer BitLocker sur le lecteur C:
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector

# Sauvegarder la clé de récupération
(Get-BitLockerVolume -MountPoint "C:").KeyProtector | Out-File "C:\BitLocker_Recovery_Key.txt"

# IMPORTANT : Déplacer ce fichier vers un emplacement sécurisé !
```

2. Chiffrer les fichiers sensibles (EFS)

```powershell
# Chiffrer un dossier
$folder = "C:\Documents\Confidentiel"
(Get-Item $folder).Encrypt()

# Vérifier le chiffrement
Get-Item $folder | Select-Object Name, Attributes
```

---

📊 Logs et Audit

1. Activer les logs d'audit

```powershell
# Activer l'audit des connexions
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Activer l'audit des modifications de fichiers
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Activer l'audit des modifications de registre
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Voir toutes les politiques d'audit
auditpol /get /category:*
```

2. Augmenter la taille des logs

```powershell
# Augmenter la taille du log Sécurité à 100 MB
wevtutil sl Security /ms:104857600

# Augmenter la taille du log Système
wevtutil sl System /ms:104857600

# Augmenter la taille du log Application
wevtutil sl Application /ms:104857600
```

3. Exporter les logs pour analyse

```powershell
# Exporter les événements de sécurité des 24 dernières heures
$date = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$date} | Export-Csv "C:\Logs\Security_Events.csv" -NoTypeInformation
```

---

🤖 Scripts d'Automatisation

Script 1 : Audit de Sécurité Complet

Fichier : `scripts\audit\Security-Audit.ps1`

```powershell
# Security-Audit.ps1
# Description : Vérifie la configuration de sécurité du système Windows
# Auteur : Windows Hardening Guide
# Version : 1.0

#Requires -RunAsAdministrator

function Get-SecurityAudit {
    Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║          AUDIT DE SÉCURITÉ WINDOWS 10/11                  ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    
    # 1. Vérifier Windows Defender
    Write-Host "`n[1/6] Windows Defender" -ForegroundColor Yellow
    try {
        $defender = Get-MpComputerStatus
        Write-Host "  ✓ Protection en temps réel : $($defender.RealTimeProtectionEnabled)" -ForegroundColor $(if($defender.RealTimeProtectionEnabled){"Green"}else{"Red"})
        Write-Host "  ✓ Protection cloud : $($defender.MAPSReporting)" -ForegroundColor Green
        Write-Host "  ✓ Dernière analyse : $($defender.QuickScanEndTime)" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Erreur lors de la vérification de Defender" -ForegroundColor Red
    }
    
     2. Vérifier le pare-feu
    Write-Host "`n[2/6] Pare-feu Windows" -ForegroundColor Yellow
    $firewall = Get-NetFirewallProfile
    foreach($profile in $firewall) {
        $color = if($profile.Enabled){"Green"}else{"Red"}
        $status = if($profile.Enabled){"✓"}else{"✗"}
        Write-Host "  $status $($profile.Name) : $($profile.Enabled)" -ForegroundColor $color
    }
    
    3. Vérifier BitLocker
    Write-Host "`n[3/6] BitLocker" -ForegroundColor Yellow
    try {
        $bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if($bitlocker) {
            foreach($vol in $bitlocker) {
                $color = if($vol.ProtectionStatus -eq "On"){"Green"}else{"Yellow"}
                $status = if($vol.ProtectionStatus -eq "On"){"✓"}else{"⚠"}
                Write-Host "  $status Volume $($vol.MountPoint) : $($vol.ProtectionStatus)" -ForegroundColor $color
            }
        } else {
            Write-Host "  ⚠ BitLocker non disponible (Windows Home)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ⚠ BitLocker non disponible" -ForegroundColor Yellow
    }
    
     4. Vérifier les mises à jour
    Write-Host "`n[4/6] Mises à Jour" -ForegroundColor Yellow
    $updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
    Write-Host "  ✓ Dernières mises à jour installées :"
    $updates | ForEach-Object { Write-Host "    - $($_.HotFixID) installé le $($_.InstalledOn)" -ForegroundColor Green }
    
    5. Comptes utilisateurs
    Write-Host "`n[5/6] Comptes Utilisateurs" -ForegroundColor Yellow
    $users = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
    $adminUser = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Write-Host "  ✓ Comptes actifs : $($users.Count)"
    $users | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Green }
    
    if($adminUser -and $adminUser.Enabled) {
        Write-Host "  ✗ ATTENTION : Compte Administrator activé (risque de sécurité)" -ForegroundColor Red
    } else {
        Write-Host "  ✓ Compte Administrator désactivé" -ForegroundColor Green
    }
    
     6. Vérifier les protocoles obsolètes
    Write-Host "`n[6/6] Protocoles Obsolètes" -ForegroundColor Yellow
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if($smb1) {
        $color = if($smb1.State -eq "Disabled"){"Green"}else{"Red"}
        $status = if($smb1.State -eq "Disabled"){"✓"}else{"✗"}
        Write-Host "  $status SMBv1 : $($smb1.State)" -ForegroundColor $color
    }
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              AUDIT TERMINÉ                                ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

 Exécuter l'audit
Get-SecurityAudit
```

Script 2 : Durcissement Automatique

```powershell
# Nom : Auto-Hardening.ps1
# Description : Applique automatiquement les configurations de sécurité
# ATTENTION : Exécuter en tant qu'administrateur

Write-Host "=== SCRIPT DE DURCISSEMENT AUTOMATIQUE ===" -ForegroundColor Cyan
Write-Host "Ce script va modifier la configuration de sécurité de votre système.`n" -ForegroundColor Yellow

$confirmation = Read-Host "Continuer ? (O/N)"
if($confirmation -ne "O") { 
    Write-Host "Opération annulée." -ForegroundColor Red
    exit 
}

 1. Activer Windows Defender
Write-Host "`n[1/10] Configuration de Windows Defender..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -PUAProtection Enabled
Write-Host "  ✓ Windows Defender configuré" -ForegroundColor Green

 2. Activer le pare-feu
Write-Host "`n[2/10] Configuration du pare-feu..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "  ✓ Pare-feu activé sur tous les profils" -ForegroundColor Green

 3. Désactiver SMBv1
Write-Host "`n[3/10] Désactivation de SMBv1..." -ForegroundColor Yellow
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
Write-Host "  ✓ SMBv1 désactivé" -ForegroundColor Green

 4. Désactiver les services non nécessaires
Write-Host "`n[4/10] Désactivation des services non nécessaires..." -ForegroundColor Yellow
$services = @("RemoteRegistry", "SSDPSRV", "upnphost")
foreach($svc in $services) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "  ✓ Service $svc désactivé" -ForegroundColor Green
}

5. Configurer les politiques de mot de passe
Write-Host "`n[5/10] Configuration des politiques de mot de passe..." -ForegroundColor Yellow
net accounts /minpwlen:12 /maxpwage:90 /uniquepw:5 | Out-Null
Write-Host "  ✓ Politiques de mot de passe configurées" -ForegroundColor Green

6. Configurer le verrouillage de compte
Write-Host "`n[6/10] Configuration du verrouillage de compte..." -ForegroundColor Yellow
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
Write-Host "  ✓ Verrouillage de compte configuré" -ForegroundColor Green

 7. Désactiver les comptes par défaut
Write-Host "`n[7/10] Désactivation des comptes par défaut..." -ForegroundColor Yellow
net user Administrator /active:no 2>$null
net user Guest /active:no 2>$null
Write-Host "  ✓ Comptes Administrator et Guest désactivés" -ForegroundColor Green

 8. Activer l'audit
Write-Host "`n[8/10] Activation de l'audit..." -ForegroundColor Yellow
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
Write-Host "  ✓ Audit activé" -ForegroundColor Green

 9. Augmenter la taille des logs
Write-Host "`n[9/10] Augmentation de la taille des logs..." -ForegroundColor Yellow
wevtutil sl Security /ms:104857600
wevtutil sl System /ms:104857600
Write-Host "  ✓ Taille des logs augmentée" -ForegroundColor Green

 10. Mettre à jour Windows Defender
Write-Host "`n[10/10] Mise à jour de Windows Defender..." -ForegroundColor Yellow
Update-MpSignature
Write-Host "  ✓ Signatures Windows Defender mises à jour" -ForegroundColor Green

Write-Host "`n=== DURCISSEMENT TERMINÉ ===" -ForegroundColor Cyan
Write-Host "Redémarrage recommandé pour appliquer tous les changements." -ForegroundColor Yellow
```

---

✅ Checklist de Vérification

### Sécurité de Base
- [ ] Windows Defender activé et à jour
- [ ] Pare-feu activé sur tous les profils
- [ ] Compte Administrator désactivé
- [ ] Compte Guest désactivé
- [ ] SMBv1 désactivé
- [ ] Politiques de mot de passe configurées (12 caractères min)
- [ ] Verrouillage de compte après 5 tentatives
- [ ] Mises à jour Windows installées

### Sécurité Avancée
- [ ] BitLocker activé (si disponible)
- [ ] Controlled Folder Access activé
- [ ] Attack Surface Reduction configuré
- [ ] Audit des événements activé
- [ ] Logs augmentés à 100 MB
- [ ] Services non nécessaires désactivés
- [ ] NetBIOS désactivé (si non utilisé)
- [ ] Analyses antivirus planifiées

### Bonnes Pratiques
- [ ] Sauvegarde régulière configurée
- [ ] Clé de récupération BitLocker sauvegardée
- [ ] Utilisateur standard pour usage quotidien
- [ ] UAC (User Account Control) activé
- [ ] Télémétrie minimale configurée

---

📚 Ressources Complémentaires

### Documentation Microsoft
- [Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [BitLocker Documentation](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview)
- [Windows Defender ATP](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/microsoft-defender-advanced-threat-protection)

### Outils Recommandés
- HardenTools: Outil de durcissement automatique
- O&O ShutUp10 : Contrôle de la confidentialité Windows
- Autoruns : Gestion des programmes au démarrage (Sysinternals)
- Process Monitor : Surveillance en temps réel (Sysinternals)

### Standards et Benchmarks
- CIS Benchmarks : Guides de configuration sécurisée
- NIST Cybersecurity Framework
- ANSSI : Recommandations de sécurité pour Windows 10

---

🔍 Tests et Validation

 Vérifier la configuration avec PowerShell

```powershell
# Script de validation rapide
function Test-SecurityConfiguration {
    $results = @()
    
    # Test Defender
    $defender = (Get-MpComputerStatus).RealTimeProtectionEnabled
    $results += [PSCustomObject]@{Check="Windows Defender"; Status=$defender}
    
    # Test Firewall
    $firewall = (Get-NetFirewallProfile -Profile Domain).Enabled
    $results += [PSCustomObject]@{Check="Pare-feu"; Status=$firewall}
    
    # Test SMBv1
    $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -eq "Disabled"
    $results += [PSCustomObject]@{Check="SMBv1 Désactivé"; Status=$smb1}
    
    # Test BitLocker
    $bitlocker = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus -eq "On"
    $results += [PSCustomObject]@{Check="BitLocker"; Status=$bitlocker}
    
    $results | Format-Table -AutoSize
}

Test-SecurityConfiguration
```

---

 ⚠️ Avertissements

1. Sauvegarde : Créez toujours une sauvegarde complète avant d'appliquer ces modifications
2. Test : Testez dans un environnement de développement avant la production
3. Compatibilité : Certaines configurations peuvent affecter des applications anciennes
4. Support : Vérifiez la compatibilité avec votre infrastructure IT

---

 📝 Licence

Ce guide est fourni à des fins éducatives. Utilisez-le à vos propres risques.

Version : 1.0  
Dernière mise à jour : Novembre 2025  
**Auteur** : Guide de Sécurité Windows
