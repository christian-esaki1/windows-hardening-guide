# ⚙️ Configuration

## Windows Defender
\\\powershell
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Update-MpSignature
\\\

## Pare-feu
\\\powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow
\\\

## SMBv1
\\\powershell
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
\\\
"@ | Out-File -FilePath "docs\configuration.md" -Encoding UTF8

# Créer troubleshooting.md
@"
# 🔧 Résolution de Problèmes

## Scripts désactivés
\\\powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
\\\

## Defender non actif
1. Vérifiez si un autre antivirus est installé
2. Désinstallez-le complètement
3. Redémarrez le PC

## Accès refusé
Ouvrez PowerShell en tant qu'administrateur (clic droit → Exécuter en tant qu'administrateur)
