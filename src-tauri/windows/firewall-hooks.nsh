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
; A per-user installation without elevation cannot create machine firewall
; rules; `netsh` then fails and the `| 0` below swallows the error, so the
; standard Windows dialog appears once instead. That degraded path is
; documented in docs/RELEASE_V0.4.0.md.

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
