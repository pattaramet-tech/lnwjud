; Electron-builder calls customInit from .onInit *after* initMultiUser selected
; the installation mode and *before* installSection uninstalls or extracts files.
; A silent per-user install cannot enroll the protected LocalSystem containment
; service. Reject before touching an existing installation or creating new files.
!macro customInit
  Call lnwjudVerifyFreshInstall
  ${if} $installMode == "CurrentUser"
    ${if} ${Silent}
      SetErrorLevel 125
      Abort
    ${endif}
  ${endif}
!macroend

; The interactive mode can change after customInit. Electron-builder inserts
; this page after scope/directory selection and before the install section can
; uninstall an existing version or extract files. Refusal never requests UAC.
!macro customPageAfterChangeDir
  Page custom lnwjudVerifyInstallScope
  Function lnwjudVerifyInstallScope
    ${if} $installMode != "all"
      MessageBox MB_ICONSTOP|MB_OK "Current-user mode cannot install the protected Windows containment service. Setup cannot continue. Restart setup and explicitly select All Users after preserving your runtime data."
      SetErrorLevel 125
      Quit
    ${endif}
    Call lnwjudVerifyFreshInstall
    ; Protected all-users scope may continue to the normal installation page.
    Abort
  FunctionEnd
!macroend

; Fresh-only policy: inspect before electron-builder can uninstall or extract.
; Registry views are explicit and keys come from the builder's generated app GUID.
!ifndef BUILD_UNINSTALLER
!macro lnwjudRequireAbsentKey ROOT KEY ACCESS TAG
  StrCpy $0 0
  StrCpy $1 -1
  System::Call 'advapi32::RegOpenKeyExW(p ${ROOT}, w "${KEY}", i 0, i ${ACCESS}, *p .r0) i.r1'
  StrCmp $1 0 ${TAG}_present
  StrCmp $1 2 ${TAG}_absent
  StrCmp $1 3 ${TAG}_absent
  StrCpy $2 "INSTALL_SCOPE_INSPECTION_UNAVAILABLE"
  Goto lnwjudFreshInstallRefused
  ${TAG}_present:
    System::Call 'advapi32::RegCloseKey(p r0) i.r3'
    StrCpy $2 "INSTALL_EXISTING_SCOPE_MIGRATION_UNSUPPORTED"
    Goto lnwjudFreshInstallRefused
  ${TAG}_absent:
!macroend

; Custom includes precede multiUser/UAC declarations. Emit this function only
; when the builder expands customHeader after those declarations are available.
!macro customHeader
Function lnwjudVerifyFreshInstall
  Push $0
  Push $1
  Push $2
  Push $3
  StrCmp $installMode "all" 0 lnwjudFreshInstallDone
  ; An elevated inner instance may have another user's HKCU. Do not guess/adopt it.
  ${if} ${UAC_IsInnerInstance}
    StrCpy $2 "INSTALL_ORIGINAL_USER_CONTEXT_UNVERIFIED"
    Goto lnwjudFreshInstallRefused
  ${endif}
  !insertmacro lnwjudRequireAbsentKey 0x80000001 ${INSTALL_REGISTRY_KEY} 0x20119 cu_install_64
  !insertmacro lnwjudRequireAbsentKey 0x80000001 ${UNINSTALL_REGISTRY_KEY} 0x20119 cu_uninstall_64
  !insertmacro lnwjudRequireAbsentKey 0x80000001 ${INSTALL_REGISTRY_KEY} 0x20219 cu_install_32
  !insertmacro lnwjudRequireAbsentKey 0x80000001 ${UNINSTALL_REGISTRY_KEY} 0x20219 cu_uninstall_32
  !insertmacro lnwjudRequireAbsentKey 0x80000002 ${INSTALL_REGISTRY_KEY} 0x20119 lm_install_64
  !insertmacro lnwjudRequireAbsentKey 0x80000002 ${UNINSTALL_REGISTRY_KEY} 0x20119 lm_uninstall_64
  !insertmacro lnwjudRequireAbsentKey 0x80000002 ${INSTALL_REGISTRY_KEY} 0x20219 lm_install_32
  !insertmacro lnwjudRequireAbsentKey 0x80000002 ${UNINSTALL_REGISTRY_KEY} 0x20219 lm_uninstall_32

  ; Read-only SCM probe also fences an existing service with missing registration.
  StrCpy $0 0
  System::Call 'advapi32::OpenSCManagerW(p 0, p 0, i 1) p.r0 ?e'
  Pop $1
  StrCmp $0 0 lnwjudFreshScmUnavailable
  StrCpy $2 0
  System::Call 'advapi32::OpenServiceW(p r0, w "LnwjudContainment", i 4) p.r2 ?e'
  Pop $1
  StrCmp $2 0 lnwjudFreshCheckAbsence
  System::Call 'advapi32::CloseServiceHandle(p r2) i.r3'
  System::Call 'advapi32::CloseServiceHandle(p r0) i.r3'
  StrCpy $2 "SERVICE_INSTALL_EXISTING_SERVICE_UPDATE_UNSUPPORTED"
  Goto lnwjudFreshInstallRefused
  lnwjudFreshCheckAbsence:
    StrCpy $3 0
    System::Call 'advapi32::CloseServiceHandle(p r0) i.r3'
    StrCmp $3 0 lnwjudFreshScmUnavailable
    StrCmp $1 1060 lnwjudFreshInstallDone
  lnwjudFreshScmUnavailable:
    StrCpy $2 "SERVICE_INSTALL_FRESH_PREFLIGHT_UNAVAILABLE"
  lnwjudFreshInstallRefused:
    IfSilent lnwjudFreshInstallQuit
    MessageBox MB_ICONSTOP|MB_OK "Setup cannot continue ($2). In-place migration and existing-service updates are unsupported. Preserve runtime data and use the reviewed offline maintenance plan. Fresh setup must run in a verified administrator user context."
  lnwjudFreshInstallQuit:
    SetErrorLevel 125
    Quit
  lnwjudFreshInstallDone:
    Pop $3
    Pop $2
    Pop $1
    Pop $0
FunctionEnd
!macroend
!endif

!macro customInstall
  ; The LocalSystem containment service belongs only to a protected all-users install.
  ${if} $installMode == "all"
    ; Capture a stable, path-free native failure code for troubleshooting.
    nsExec::ExecToStack '"$INSTDIR\resources\native-containment\lnwjud-containment.exe" service-install'
    Pop $0
    Pop $1
    ${if} $0 == "error"
      StrCpy $0 "125"
    ${endIf}
    ${if} $0 != 0
      ${if} $1 == ""
        StrCpy $1 "SERVICE_INSTALL_UNEXPECTED"
      ${endIf}
      IfSilent silentInstallFailure 0
      MessageBox MB_ICONSTOP|MB_OK "Windows containment service installation failed (exit code $0, reason $1). lnwjud requires this protected service for managed tasks."
      Abort
      silentInstallFailure:
        SetErrorLevel $0
        Abort
    ${endIf}
  ${else}
    ; Per-user installs cannot register the required LocalSystem containment service.
    ; Defensive fallback: no path may report a successful degraded installation.
    IfSilent unsupportedPerUserSilent 0
    MessageBox MB_ICONSTOP|MB_OK "Current-user mode cannot install the protected Windows containment service. Setup cannot continue. Restart setup and explicitly select All Users after preserving your runtime data."
    unsupportedPerUserSilent:
      SetErrorLevel 125
      Abort
  ${endIf}

  ; Resolve the shortcut from the actual end-user install directory at install time.
  SetOutPath "$INSTDIR"
  CreateDirectory "$SMPROGRAMS"
  CreateShortCut "$SMPROGRAMS\lnwjud.lnk" "$INSTDIR\lnwjud.exe" "" "$INSTDIR\lnwjud.exe" 0

  ; electron-builder writes "Uninstall ${PRODUCT_FILENAME}.exe" before customInstall.
  ; Keep the standard registry integration, but expose a shorter stable filename to users.
  Delete "$INSTDIR\uninstall.exe"
  ClearErrors
  Rename "$INSTDIR\Uninstall ${PRODUCT_FILENAME}.exe" "$INSTDIR\uninstall.exe"
  ${ifNot} ${Errors}
    ${if} $installMode == "all"
      StrCpy $0 "/allusers"
    ${else}
      StrCpy $0 "/currentuser"
    ${endIf}
    StrCpy $2 "$INSTDIR\uninstall.exe"
    WriteRegStr SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}" UninstallString '"$2" $0'
    WriteRegStr SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}" QuietUninstallString '"$2" $0 /S'
  ${endIf}
!macroend

!macro customUnInstall
  ${if} $installMode == "all"
    nsExec::ExecToStack '"$INSTDIR\resources\native-containment\lnwjud-containment.exe" service-uninstall'
    Pop $0
    Pop $1
    ${if} $0 == "error"
      StrCpy $0 "125"
    ${endIf}
    ${if} $0 != 0
      ${if} $1 == ""
        StrCpy $1 "SERVICE_REMOVE_UNEXPECTED"
      ${endIf}
      IfSilent silentUninstallFailure 0
      MessageBox MB_ICONSTOP|MB_OK "Windows containment service removal failed (exit code $0, reason $1). The application files were left in place."
      Abort
      silentUninstallFailure:
        SetErrorLevel $0
        Abort
    ${endIf}
  ${endIf}
  Delete "$SMPROGRAMS\lnwjud.lnk"
  ; Silent updates/uninstalls must never block on an interactive prompt. Preserve user data by default.
  IfSilent keepData 0
  MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to keep your user settings and workspaces data?$\n$\n(กด 'Yes' เพื่อเก็บข้อมูลการตั้งค่าและ Workspace ไว้$\nกด 'No' เพื่อลบข้อมูลผู้ใช้ทั้งหมดออกจากเครื่อง)" IDYES keepData
    RMDir /r "$APPDATA\lnwjud"
    RMDir /r "$LOCALAPPDATA\lnwjud"
    RMDir /r "$LOCALAPPDATA\lnwjud-updater"
  keepData:
!macroend
