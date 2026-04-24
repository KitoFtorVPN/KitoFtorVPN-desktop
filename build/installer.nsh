; installer.nsh — custom NSIS hooks for KitoFtorVPN
; Runs during uninstall to clean up the autostart scheduled task.

!macro customUnInstall
  ExecWait 'schtasks /Delete /TN "KitoFtorVPNAutostart" /F'
!macroend
