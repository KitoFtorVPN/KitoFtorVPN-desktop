; installer.nsh — custom NSIS hooks for KitoFtorVPN
; Runs during uninstall to clean up the autostart scheduled task.

!include "LogicLib.nsh"

Var kftv_lnkFound
Var kftv_targetExe
Var kftv_findHandle
Var kftv_findName
Var kftv_resolvedTarget

!ifndef CLSID_ShellLink
  !define CLSID_ShellLink {00021401-0000-0000-C000-000000000046}
  !define IID_IShellLinkA {000214EE-0000-0000-C000-000000000046}
  !define IID_IShellLinkW {000214F9-0000-0000-C000-000000000046}
  !define IID_IPersistFile {0000010b-0000-0000-c000-000000000046}
!endif
!ifdef NSIS_UNICODE
  !define IID_IShellLink ${IID_IShellLinkW}
!else
  !define IID_IShellLink ${IID_IShellLinkA}
!endif

!macro customUnInstall
  ExecWait 'schtasks /Delete /TN "KitoFtorVPNAutostart" /F'
!macroend

; ───────────────────────────────────────────────────────────
; customInit: runs at the very start of .onInit, before electron-builder's
; built-in "app is already running" check. Stops the same two things the
; app's own tray "Выход" stops (see quitApp() in main.js: tunnelExec('stop')
; then tunnelExec('service-stop')) — the VPN tunnel's background Windows
; service, and the Electron app process itself — so that by the time
; electron-builder runs its check, nothing is left running and the user
; never sees the "app is running, click OK to close it" dialog, let alone
; needs to stop the service manually via Task Manager → Services.
;
; "sc stop" is used instead of calling kitoftor-tunnel.exe directly: the
; previously-installed exe is what's actually running, and during an
; update/reinstall it's about to be overwritten/removed anyway, so driving
; the stop through the service name (a fixed identifier, independent of
; the exe's install path) is the more robust order of operations here.
; ───────────────────────────────────────────────────────────
!macro customInit
  ExecWait 'sc stop KitoFtorVPNTunnel'
  ExecWait 'taskkill /F /IM "${APP_EXECUTABLE_FILENAME}"'
!macroend

; ───────────────────────────────────────────────────────────
; ResolveShortcutTarget: reads the real target path a .lnk file points to,
; via the standard IShellLink/IPersistFile COM interfaces. No third-party
; NSIS plugin needed (those aren't bundled by electron-builder's NSIS and
; would need extra setup on the build machine) — only the System plugin,
; which ships with NSIS itself.
;
; This is a macro, not a Function: electron-builder's generated installer
; only ever calls customInstall as a macro expansion inside its own Section,
; and a separate Function that's only Call'd from inside that macro is not
; reliably seen as "referenced" by NSIS's static analysis in that setup —
; it gets zeroed out with a warning, which electron-builder then treats as
; a hard build error (see electron-userland/electron-builder #1122, #3871).
; Inlining as a macro sidesteps that entirely: there's no separate function
; to "not reference", the code just becomes part of customInstall itself.
;
;   Args: lnkPath (the .lnk file to read), outVar (variable to receive the
;         resolved target path, or "" if it couldn't be read)
; vtable indices used: IUnknown::QueryInterface=0, IUnknown::Release=2,
; IShellLink::GetPath=3, IPersistFile::Load=5 (all stable, documented COM
; interfaces — see learn.microsoft.com/windows/win32/api/shobjidl_core).
; ───────────────────────────────────────────────────────────
!macro ResolveShortcutTarget lnkPath outVar
  StrCpy ${outVar} ""

  System::Call "ole32::CoCreateInstance(g'${CLSID_ShellLink}',i0,i1,g'${IID_IShellLink}',*i.r1)i.r0"
  ${If} $0 = 0
    System::Call "$1->0(g'${IID_IPersistFile}',*i.r2)i.r0" ; QueryInterface -> IPersistFile
    ${If} $0 = 0
      System::Call "$2->5(w '${lnkPath}',i 0)i.r0" ; IPersistFile::Load
      ${If} $0 = 0
        !ifdef NSIS_UNICODE
          System::Call "*(&w1024)i.r4" ; buffer for the resolved path (Unicode build)
        !else
          System::Call "*(&t1024)i.r4" ; buffer for the resolved path (ANSI build)
        !endif
        ; WIN32_FIND_DATA is ~592 bytes (W) / ~318 bytes (A); allocate 600 to
        ; be safe. GetPath fills it in but we don't read it — we only need a
        ; valid non-null pointer here, some Windows builds return S_FALSE
        ; with an empty path if pfd is NULL even though MSDN marks it as
        ; usable with 0 for "no extra data needed".
        System::Call "*(&t600)i.r6"
        System::Call "$1->3(i r4,i 1024,i r6,i0)i.r0" ; IShellLink::GetPath
        ${If} $0 = 0
          !ifdef NSIS_UNICODE
            System::Call "*$4(&w1024 .r5)"
          !else
            System::Call "*$4(&t1024 .r5)"
          !endif
          StrCpy ${outVar} $5
        ${EndIf}
        System::Free $6
        System::Free $4
      ${EndIf}
      System::Call "$2->2()" ; IPersistFile::Release
    ${EndIf}
    System::Call "$1->2()" ; IShellLink::Release
  ${EndIf}
!macroend

; ───────────────────────────────────────────────────────────
; customInstall: only create a desktop shortcut if no existing .lnk on the
; desktop already points at our exe. This matters specifically for
; reinstalling over an existing install — electron-builder's built-in
; createDesktopShortcut option has known issues creating a duplicate in
; that case (see electron-userland/electron-builder #2725, #2358), and a
; plain filename check ("does KitoFtorVPN.lnk exist") misses the case where
; the user renamed their existing shortcut. Reading the actual target makes
; this robust to renaming: any .lnk on the desktop that resolves to our
; installed exe counts as "already has a shortcut", regardless of its name.
; ───────────────────────────────────────────────────────────
!macro customInstall
  StrCpy $kftv_lnkFound "0"
  StrCpy $kftv_targetExe "$INSTDIR\${APP_EXECUTABLE_FILENAME}"

  ; perMachine install runs elevated, so $DESKTOP here resolves to the
  ; all-users (Public) desktop. The user's personal desktop is a separate
  ; physical folder that Explorer merges into one visual "Desktop" — so an
  ; existing shortcut can live in either location and must be checked in
  ; both, or a duplicate gets created in Public while the original sits
  ; untouched in the user's own profile folder.
  !insertmacro KFTV_ScanDesktopFolder "$DESKTOP"
  !insertmacro KFTV_ScanDesktopFolder "$PROFILE\Desktop"

  ${If} $kftv_lnkFound == "0"
    CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
  ${EndIf}
!macroend

!macro KFTV_ScanDesktopFolder folder
  FindFirst $kftv_findHandle $kftv_findName "${folder}\*.lnk"
  ${DoWhile} $kftv_findName != ""
    !insertmacro ResolveShortcutTarget "${folder}\$kftv_findName" $kftv_resolvedTarget
    ${If} $kftv_resolvedTarget == $kftv_targetExe
      StrCpy $kftv_lnkFound "1"
    ${EndIf}
    FindNext $kftv_findHandle $kftv_findName
  ${Loop}
  FindClose $kftv_findHandle
!macroend
