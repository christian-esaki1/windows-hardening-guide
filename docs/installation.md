# 📥 Guide d'Installation

## Prérequis
- Windows 10/11
- PowerShell 5.1+
- Droits administrateur

## Installation
\\\powershell
git clone https://github.com/christian-esaki1/windows-hardening-guide.git
cd windows-hardening-guide
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
\\\

## Lancer l'audit
\\\powershell
.\scripts\audit\Security-Audit.ps1
\\\

## Prochaines étapes
- [Configuration](configuration.md)
- [Résolution de problèmes](troubleshooting.md)
