; W7 — Windows Defender Firewall rule for the DOM Wallet P2P listener.
;
; Since v0.4.0 the embedded node listens on all interfaces (0.0.0.0) so the
; wallet can accept connections from the DOM network. Without a firewall
; rule Windows shows its permission dialog on first listen; if the user
; closes or denies it, inbound connections stay blocked and the wallet
; remains an outbound-only leaf (UPnP may still map the port, but dial-back
; fails). The rule is keyed to the EXECUTABLE PATH, not a port, because the
; P2P port can move (W2: 33369 preferred, 33370-33379 fallback, then
; ephemeral).
;
; The bundle's effective installMode is currentUser (Tauri's default; the
; wallet does not override it), so the DEFAULT installation runs without
; elevation: `netsh` fails there, the exit code is popped and ignored, the
; installation continues, and Windows shows its standard firewall dialog
; once on first listen. An elevated installation creates the rule, which
; applies to ALL network profiles (no profile= filter), and the elevated
; uninstaller removes it. Documented in docs/RELEASE_V0.4.0.md.

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="DOM Wallet P2P"'
  Pop $0
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="DOM Wallet P2P" dir=in action=allow program="$INSTDIR\${MAINBINARYNAME}.exe" protocol=TCP enable=yes'
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="DOM Wallet P2P"'
  Pop $0
!macroend
